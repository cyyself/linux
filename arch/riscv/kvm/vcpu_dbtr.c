// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Ventana Micro Systems, Inc.
 *
 * Authors:
 *     Himanshu Chauhan <hchauhan@ventanamicro.com>
 */

#define pr_fmt(fmt)	"riscv-kvm-dbtr: " fmt
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/sbi.h>
#include <asm/hw_breakpoint.h>
#include <asm/kvm_vcpu_sbi.h>
#include <asm/kvm_vcpu_dbtr.h>
#include <linux/bitops.h>

static int kvm_riscv_vcpu_dbtr_shmem_disabled(struct kvm_vcpu *vcpu)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);

	return ((vdbtr->sbi_shmem == SBI_DBTR_SHMEM_INVALID_ADDR) ? 1 : 0);
}

static inline unsigned int dbtr_get_bptype(struct kvm_sbi_dbtr_trig_info *trig)
{
	if (_test_bit(RV_DBTR_BIT(MC6, LOAD), &trig->tdata1) &&
	    _test_bit(RV_DBTR_BIT(MC6, STORE), &trig->tdata1))
		return HW_BREAKPOINT_RW;
	else if (_test_bit(RV_DBTR_BIT(MC6, LOAD), &trig->tdata1))
		return HW_BREAKPOINT_R;
	else if (_test_bit(RV_DBTR_BIT(MC6, STORE), &trig->tdata1))
		return HW_BREAKPOINT_W;
	else if (_test_bit(RV_DBTR_BIT(MC6, EXEC), &trig->tdata1))
		return HW_BREAKPOINT_X;

	pr_err("Error: Unknown trigger type! (tdata1: 0x%lx)", trig->tdata1);

	return -1;
}

static int dbtr_vcpu_create_perf_event(struct kvm_vcpu *vcpu,
				       struct kvm_sbi_dbtr_trig_info *trig)
{
	struct perf_event *event;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	struct perf_event_attr attr = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(struct perf_event_attr),
		.pinned = true,
		.bp_addr = trig->bp_addr,
		.bp_type = trig->bp_type,
		.bp_len	= trig->bp_len,
		.exclude_host = true,
		.exclude_hv = true,
		.exclude_user = false,
		.exclude_kernel = false,
		.config3 = RISCV_DBTR_CONFIG3_GUEST_EVENTS,
	};

	event = perf_event_create_kernel_counter(&attr, -1, current,
						 NULL, vdbtr);
	if (IS_ERR(event)) {
		pr_err("kvm dbtr event creation failed\n");
		return PTR_ERR(event);
	}

	trig->perf_event = event; wmb();
	perf_event_enable(trig->perf_event);
	return 0;
}

static int dbtr_vcpu_destroy_perf_event(struct kvm_sbi_dbtr_trig_info *trig)
{
	if (trig->perf_event) {
		perf_event_disable(trig->perf_event);
		perf_event_release_kernel(trig->perf_event);
		trig->perf_event = NULL;
		return 0;
	}

	return -1;
}

static struct kvm_sbi_dbtr_trig_info *dbtr_alloc_trigger(struct kvm_vcpu *vcpu)
{
	unsigned long fti;
	struct kvm_sbi_dbtr_trig_info *trig;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);

	fti = find_first_zero_bit(vdbtr->triggers_in_use,
				  RISCV_KVM_MAX_DBTR_TRIGGERS);

	/* no triggers are free */
	if (fti == RISCV_KVM_MAX_DBTR_TRIGGERS)
		return NULL;

	trig = &vdbtr->triggers[fti];

	if (trig->state & RV_DBTR_BIT_MASK(TS, MAPPED)) {
		pr_err("%s: Error: trigger %ld is free but state is not.",
		       __func__, fti);
		pr_err("trigger state: 0x%lx\n", trig->state);
		return NULL;
	}

	/* mark the trigger as being used */
	set_bit(RV_DBTR_BIT(TS, MAPPED), &trig->state);
	set_bit(fti, vdbtr->triggers_in_use);

	return trig;
}

static void dbtr_free_trigger(struct kvm_sbi_dbtr_trig_info *trig)
{
	struct kvm_dbtr *vdbtr = trig_to_dbtr(trig);

	clear_bit(RV_DBTR_BIT(TS, MAPPED), &trig->state);
	clear_bit(trig->index, vdbtr->triggers_in_use);
}

static void dbtr_trigger_init(struct kvm_sbi_dbtr_trig_info *trig,
			      struct kvm_sbi_dbtr_data_msg *recv)
{
	unsigned long tdata1;

	if (!trig)
		return;

	trig->tdata1 = lle_to_cpu(recv->tdata1);
	trig->tdata2 = lle_to_cpu(recv->tdata2);
	trig->tdata3 = lle_to_cpu(recv->tdata3);

	tdata1 = lle_to_cpu(recv->tdata1);

	trig->state = 0;

	set_bit(RV_DBTR_BIT(TS, MAPPED), &trig->state);

	trig->bp_type = dbtr_get_bptype(trig);
	trig->bp_addr = trig->tdata2;

	switch (RV_DBTR_GET_TDATA1_TYPE(tdata1)) {
	case RISCV_DBTR_TRIG_MCONTROL:
		if (test_bit(RV_DBTR_BIT(MC, U), &tdata1))
			set_bit(RV_DBTR_BIT(TS, U), &trig->state);

		if (test_bit(RV_DBTR_BIT(MC, S), &tdata1))
			set_bit(RV_DBTR_BIT(TS, S), &trig->state);

		/* TODO: get the length from MC sizelo/hi */
		trig->bp_len = 1;
		break;
	case RISCV_DBTR_TRIG_MCONTROL6:
		if (test_bit(RV_DBTR_BIT(MC6, U), &tdata1))
			set_bit(RV_DBTR_BIT(TS, U), &trig->state);

		if (test_bit(RV_DBTR_BIT(MC6, S), &tdata1))
			set_bit(RV_DBTR_BIT(TS, S), &trig->state);

		if (test_bit(RV_DBTR_BIT(MC6, VU), &tdata1))
			set_bit(RV_DBTR_BIT(TS, VU), &trig->state);

		if (test_bit(RV_DBTR_BIT(MC6, VS), &tdata1))
			set_bit(RV_DBTR_BIT(TS, VS), &trig->state);

		trig->bp_len = RV_DBTR_GET_MC6_SIZE(trig->tdata1);
		break;
	default:
		pr_err("Unknown type (tdata1: 0x%lx Type: %ld)\n",
		       tdata1, RV_DBTR_GET_TDATA1_TYPE(tdata1));
		break;
	}
}

static inline void update_bit(unsigned long new, int nr,
			      volatile unsigned long *addr)
{
	if (new)
		set_bit(nr, addr);
	else
		clear_bit(nr, addr);
}

static void dbtr_trigger_enable(struct kvm_sbi_dbtr_trig_info *trig)
{
	unsigned long state;
	unsigned long tdata1;

	if (!trig && !(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED)))
		return;

	if (trig->perf_event == NULL || IS_TRIGGER_ENABLED(trig))
		return;

	state = trig->state;
	tdata1 = trig->tdata1;

	switch (RV_DBTR_GET_TDATA1_TYPE(tdata1)) {
	case RISCV_DBTR_TRIG_MCONTROL:
		update_bit(state & RV_DBTR_BIT_MASK(TS, U),
			   RV_DBTR_BIT(MC, U), &trig->tdata1);
		update_bit(state & RV_DBTR_BIT_MASK(TS, S),
			   RV_DBTR_BIT(MC, S), &trig->tdata1);
		break;
	case RISCV_DBTR_TRIG_MCONTROL6:
		update_bit(state & RV_DBTR_BIT_MASK(TS, VU),
			   RV_DBTR_BIT(MC6, VU), &trig->tdata1);
		update_bit(state & RV_DBTR_BIT_MASK(TS, VS),
			   RV_DBTR_BIT(MC6, VS), &trig->tdata1);
		update_bit(state & RV_DBTR_BIT_MASK(TS, U),
			   RV_DBTR_BIT(MC6, U), &trig->tdata1);
		update_bit(state & RV_DBTR_BIT_MASK(TS, S),
			   RV_DBTR_BIT(MC6, S), &trig->tdata1);
		break;
	default:
		break;
	}

	perf_event_enable(trig->perf_event);
	trig->enabled = 1;
}

static void dbtr_trigger_disable(struct kvm_sbi_dbtr_trig_info *trig)
{
	unsigned long tdata1;

	if (!trig && !(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED)))
		return;

	if (trig->perf_event == NULL || !IS_TRIGGER_ENABLED(trig))
		return;

	tdata1 = trig->tdata1;

	switch (RV_DBTR_GET_TDATA1_TYPE(tdata1)) {
	case RISCV_DBTR_TRIG_MCONTROL:
		clear_bit(RV_DBTR_BIT(MC, U), &trig->tdata1);
		clear_bit(RV_DBTR_BIT(MC, S), &trig->tdata1);
		break;
	case RISCV_DBTR_TRIG_MCONTROL6:
		clear_bit(RV_DBTR_BIT(MC6, VU), &trig->tdata1);
		clear_bit(RV_DBTR_BIT(MC6, VS), &trig->tdata1);
		clear_bit(RV_DBTR_BIT(MC6, U), &trig->tdata1);
		clear_bit(RV_DBTR_BIT(MC6, S), &trig->tdata1);
		break;
	default:
		break;
	}

	perf_event_disable(trig->perf_event);
	trig->enabled = 0;
}

static void dbtr_trigger_clear(struct kvm_sbi_dbtr_trig_info *trig)
{
	struct kvm_dbtr *vdbtr = trig_to_dbtr(trig);

	if (!trig && !(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED)))
		return;

	dbtr_vcpu_destroy_perf_event(trig);

	clear_bit(RV_DBTR_BIT(TS, MAPPED), &trig->state);
	clear_bit(trig->index, vdbtr->triggers_in_use);
}

static int dbtr_trigger_supported(unsigned long type)
{
	switch (type) {
	case RISCV_DBTR_TRIG_MCONTROL:
	case RISCV_DBTR_TRIG_MCONTROL6:
		return 1;
	default:
		break;
	}

	return 0;
}

static int dbtr_trigger_valid(unsigned long type, unsigned long tdata)
{
	switch (type) {
	case RISCV_DBTR_TRIG_MCONTROL:
		if (!(tdata & RV_DBTR_BIT_MASK(MC, ACTION)) &&
		    !(tdata & RV_DBTR_BIT_MASK(MC, DMODE)) &&
		    !(tdata & RV_DBTR_BIT_MASK(MC, M)))
			return 1;
		break;
	case RISCV_DBTR_TRIG_MCONTROL6:
		if (!(tdata & RV_DBTR_BIT_MASK(MC6, ACTION)) &&
		    !(tdata & RV_DBTR_BIT_MASK(MC6, DMODE)) &&
		    !(tdata & RV_DBTR_BIT_MASK(MC6, M)))
			return 1;
		break;
	default:
		break;
	}

	return 0;
}

int kvm_riscv_vcpu_dbtr_num_trigs(struct kvm_vcpu *vcpu, unsigned long data,
				  unsigned long *outval)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	unsigned long type = RV_DBTR_GET_TDATA1_TYPE(data);
	int ret;

	if (!vdbtr->init_done)
		return SBI_ERR_NOT_SUPPORTED;

	if (!type) {
		*outval = vdbtr->num_hw_triggers;
		ret = SBI_SUCCESS;
		goto done;
	}

	/* TODO: filter here we have information of different triggers */
	if (type == vdbtr->hw_trigger_type) {
		*outval = vdbtr->num_hw_triggers;
		ret = SBI_SUCCESS;
		goto done;
	}

	ret = SBI_ERR_NOT_SUPPORTED;

 done:
	return ret;
}

int kvm_riscv_vcpu_dbtr_setup_shmem(struct kvm_vcpu *vcpu, unsigned long gpa_lo,
				    unsigned long gpa_hi)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	bool writable;
	unsigned long hva;
	unsigned long shmem;

	if (gpa_hi == SBI_DBTR_SHMEM_INVALID_ADDR &&
	    gpa_lo == SBI_DBTR_SHMEM_INVALID_ADDR) {
		pr_err("%s: guest clearing dbtr shared memory\n", __func__);
		vdbtr->sbi_shmem = SBI_DBTR_SHMEM_INVALID_ADDR;
		return 0;
	}

	if (gpa_lo & (SZ_64 - 1)) {
		pr_err("%s: guest shared mem not aligned\n", __func__);
		return SBI_ERR_INVALID_PARAM;
	}

	shmem = gpa_lo;

	if (gpa_hi != 0) {
#ifdef CONFIG_32BIT
		pr_err("%s: invalid hi addr in 32-bit\n", __func__);
		return SBI_ERR_INVALID_ADDRESS;
#else
		shmem |= ((gpa_t)gpa_hi << 32);
#endif
	}

	hva = kvm_vcpu_gfn_to_hva_prot(vcpu, shmem >> PAGE_SHIFT, &writable);

	if (kvm_is_error_hva(hva) || !writable) {
		pr_err("%s: access denied\n", __func__);
		return SBI_ERR_DENIED;
	}

	vdbtr->sbi_shmem = shmem;

	return 0;
}

int kvm_riscv_vcpu_dbtr_trig_read(struct kvm_vcpu *vcpu, unsigned long base,
				  unsigned long count)
{
	struct kvm_sbi_dbtr_data_msg *xmit;
	struct kvm_sbi_dbtr_trig_info *trig;
	struct kvm_sbi_dbtr_shmem_entry *pentry, entry;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	void *shmem_base;
	int tidx = base;
	unsigned long gfn;
	int rc;

	if (base > RISCV_KVM_MAX_DBTR_TRIGGERS ||
	    ((base + count) >= RISCV_KVM_MAX_DBTR_TRIGGERS))
		return SBI_ERR_INVALID_PARAM;

	if (kvm_riscv_vcpu_dbtr_shmem_disabled(vcpu))
		return SBI_ERR_NO_SHMEM;

	gfn = vdbtr->sbi_shmem >> PAGE_SHIFT;
	shmem_base = (void *)vdbtr->sbi_shmem;

	for_each_trig_entry(shmem_base, count, typeof(*pentry), pentry) {
		rc = kvm_vcpu_read_guest(vcpu, (gpa_t)pentry, &entry,
					 sizeof(entry));
		if (rc)
			return SBI_ERR_FAILURE;

		xmit = &entry.data;

		trig = &vdbtr->triggers[tidx];

		if (!(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED)))
			pr_warn("%s: Read on unmapped trigger %d\n",
				__func__, tidx);

		xmit->tstate = cpu_to_lle(trig->state);
                xmit->tdata1 = cpu_to_lle(trig->tdata1);
                xmit->tdata2 = cpu_to_lle(trig->tdata2);
                xmit->tdata3 = cpu_to_lle(trig->tdata3);

		rc = kvm_vcpu_write_guest(vcpu, (gpa_t)pentry, &entry,
					  sizeof(entry));
		if (rc) {
			pr_err("Failed to write trigger config to guest\n");
			return SBI_ERR_FAILURE;
		}
	}

	kvm_vcpu_mark_page_dirty(vcpu, gfn);
	return 0;
}

int kvm_riscv_vcpu_dbtr_trig_install(struct kvm_vcpu *vcpu, unsigned long count)
{
	struct kvm_sbi_dbtr_shmem_entry *pentry, entry;
	struct kvm_sbi_dbtr_data_msg *recv;
	struct kvm_sbi_dbtr_id_msg *xmit;
	unsigned long ctrl;
	struct kvm_sbi_dbtr_trig_info *trig;
	void *shmem_base;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	int rc;
	unsigned long gfn;

	shmem_base = (void *)vdbtr->sbi_shmem;
	gfn = vdbtr->sbi_shmem >> PAGE_SHIFT;

	/* first make a sanity check on all the triggers */
	for_each_trig_entry(shmem_base, count, typeof(*pentry), pentry) {
		rc = kvm_vcpu_read_guest(vcpu, (gpa_t)pentry, &entry,
					 sizeof(entry));
		if (rc) {
			pr_err("%s: failed to read config entry (0x%lx)\n",
			       __func__, (unsigned long)pentry);
			return SBI_ERR_FAILURE;
		}

		recv = &entry.data;
		ctrl = recv->tdata1;
		if (!dbtr_trigger_supported(RV_DBTR_GET_TDATA1_TYPE(ctrl))) {
			pr_err("%s: invalid type of trigger %d\n",
			       __func__, _idx);
			return SBI_ERR_FAILURE;
		}

		if (!dbtr_trigger_valid(RV_DBTR_GET_TDATA1_TYPE(ctrl), ctrl)) {
			pr_err("%s: invalid configuration of trigger %d\n",
			       __func__, _idx);
			return SBI_ERR_FAILURE;
		}
	}

	for_each_trig_entry(shmem_base, count, typeof(*pentry), pentry) {
		rc = kvm_vcpu_read_guest(vcpu, (gpa_t)pentry, &entry,
					 sizeof(entry));
		if (rc) {
			pr_err("%s: Error reading guest entry (0x%lx)\n",
			       __func__, (unsigned long)pentry);
			return SBI_ERR_FAILURE;
		}
		trig = dbtr_alloc_trigger(vcpu);

		if (trig == NULL) {
			pr_err("%s: failed to allocate trigger\n", __func__);
			return SBI_ERR_FAILURE;
		}

		recv = &entry.data;
		xmit = &entry.id;

		dbtr_trigger_init(trig,  recv);

		/* Make and register a perf_event for this trig */
		if ((rc = dbtr_vcpu_create_perf_event(vcpu, trig)) != 0) {
			pr_err("Failed to create perf event for guest.\n");
			rc =  SBI_ERR_FAILURE;
			goto _perf_event_failed;
		}

		dbtr_trigger_enable(trig);

		xmit->idx = cpu_to_lle(trig->index);
		rc = kvm_vcpu_write_guest(vcpu, (gpa_t)pentry, &entry,
					  sizeof(entry));
		if (rc) {
			pr_err("%s: failed to write to guest\n", __func__);
			rc = SBI_ERR_FAILURE;
			goto _guest_write_failed;
		}
	}

	/* All good */
	goto _out;

 _guest_write_failed:
	dbtr_vcpu_destroy_perf_event(trig);

 _perf_event_failed:
	if (trig)
		dbtr_free_trigger(trig);
 _out:
	kvm_vcpu_mark_page_dirty(vcpu, gfn);
	return 0;
}

int kvm_riscv_vcpu_dbtr_trig_update(struct kvm_vcpu *vcpu, unsigned long base,
				    unsigned long mask)
{
	struct kvm_sbi_dbtr_data_msg *recv;
	struct kvm_sbi_dbtr_trig_info *trig;
	struct kvm_sbi_dbtr_shmem_entry entry;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	void *shmem_base;
	unsigned long idx = base, uidx = 0;
	int ret;
	unsigned long trig_mask = mask << base;

	if (base > RISCV_KVM_MAX_DBTR_TRIGGERS)
		return SBI_ERR_INVALID_PARAM;

	if (kvm_riscv_vcpu_dbtr_shmem_disabled(vcpu))
		return SBI_ERR_NO_SHMEM;

	shmem_base = (void *)vdbtr->sbi_shmem;

	for_each_set_bit_from(idx, &trig_mask, dbtr_total_trigs(vdbtr)) {
		trig = &vdbtr->triggers[idx];

		if (!(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED))) {
			pr_warn("%s: Update on unmapped trigger %ld\n",
				__func__, idx);
			return SBI_ERR_FAILURE;
		}

		/* disable perf_event of trigger for update */
		dbtr_trigger_disable(trig);

		recv = &idx_to_shmem_entry(shmem_base, uidx)->data;

		ret = kvm_vcpu_read_guest(vcpu, (gpa_t)recv, &entry,
					  sizeof(entry));
		if (ret)
			return SBI_ERR_FAILURE;

		trig->tdata2 = cpu_to_lle(entry.data.tdata2);

		/* re-enable perf_event */
		dbtr_trigger_enable(trig);

		uidx++; /* next entry in shared mem */
	}

	return 0;
}

int kvm_riscv_vcpu_dbtr_trig_uninstall(struct kvm_vcpu *vcpu,
				       unsigned long base,
				       unsigned long mask)
{
	unsigned long trig_mask = mask << base;
	unsigned long idx = base;
	struct kvm_sbi_dbtr_trig_info *trig;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);

	if (base > RISCV_KVM_MAX_DBTR_TRIGGERS)
		return SBI_ERR_INVALID_PARAM;

	if (kvm_riscv_vcpu_dbtr_shmem_disabled(vcpu))
		return SBI_ERR_NO_SHMEM;

	for_each_set_bit_from(idx, &trig_mask, dbtr_total_trigs(vdbtr)) {
		trig = &vdbtr->triggers[idx];

		if (!(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED))) {
			pr_err("%s: trigger %lu not mapped (state: 0x%lx)\n",
			       __func__, idx, trig->state);
			return SBI_ERR_INVALID_PARAM;
		}

		dbtr_trigger_clear(trig);
	}

	return 0;
}

int kvm_riscv_vcpu_dbtr_trig_enable(struct kvm_vcpu *vcpu, unsigned long base,
				    unsigned long mask)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	struct kvm_sbi_dbtr_trig_info *trig;
	unsigned long idx = base;
	unsigned long trig_mask = mask << base;

	if (base > RISCV_KVM_MAX_DBTR_TRIGGERS)
		return SBI_ERR_INVALID_PARAM;

	for_each_set_bit_from(idx, &trig_mask, dbtr_total_trigs(vdbtr)) {
		trig = &vdbtr->triggers[idx];

		if (!(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED))) {
			pr_warn("%s: Update on unmapped trigger %ld\n",
				__func__, idx);
			return SBI_ERR_FAILURE;
		}

		if (IS_TRIGGER_ENABLED(trig))
			continue;

		/* enable perf_event of trigger for update */
		dbtr_trigger_enable(trig);
	}

	return 0;
}

int kvm_riscv_vcpu_dbtr_trig_disable(struct kvm_vcpu *vcpu, unsigned long base,
				     unsigned long mask)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	struct kvm_sbi_dbtr_trig_info *trig;
	unsigned long idx = base;
	unsigned long trig_mask = mask << base;

	if (base > RISCV_KVM_MAX_DBTR_TRIGGERS)
		return SBI_ERR_INVALID_PARAM;

	for_each_set_bit_from(idx, &trig_mask, dbtr_total_trigs(vdbtr)) {
		trig = &vdbtr->triggers[idx];

		if (!(trig->state & RV_DBTR_BIT_MASK(TS, MAPPED))) {
			pr_warn("%s: Update on unmapped trigger %ld\n",
				__func__, idx);
			return SBI_ERR_FAILURE;
		}

		if (!IS_TRIGGER_ENABLED(trig))
			continue;

		/* enable perf_event of trigger for update */
		dbtr_trigger_disable(trig);
	}

	return 0;
}

void kvm_riscv_vcpu_dbtr_init(struct kvm_vcpu *vcpu)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	unsigned long num_triggers;
	unsigned long trigger_type;
	int i;

	vdbtr->init_done = 0;

	if (sbi_probe_extension(SBI_EXT_DBTR) <= 0) {
		pr_info("%s: SBI debug trigger extension is not supported\n",
			__func__);
		return;
	}

	if (riscv_hw_get_num_triggers(&num_triggers, &trigger_type) < 0) {
		pr_info("%s: Hardware triggers haven't been initialized\n",
			__func__);
		return;
	}

	vdbtr->num_hw_triggers = num_triggers;
	vdbtr->hw_trigger_type = trigger_type;

	bitmap_zero(vdbtr->triggers_in_use, RISCV_KVM_MAX_DBTR_TRIGGERS);

	for (i = 0; i < RISCV_KVM_MAX_DBTR_TRIGGERS; i++)
		vdbtr->triggers[i].index = i;

	vdbtr->init_done = 1;
}
