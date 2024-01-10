// SPDX-License-Identifier: GPL-2.0-only

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/kdebug.h>
#include <linux/bitops.h>
#include <linux/cpu.h>

#include <asm/sbi.h>

/* bps/wps currently set on each debug trigger for each cpu */
static DEFINE_PER_CPU(struct perf_event *, bp_per_reg[HBP_NUM_MAX]);
static DEFINE_PER_CPU(unsigned long, msg_lock_flags);
static DEFINE_PER_CPU(raw_spinlock_t, msg_lock);

static struct sbi_dbtr_shmem_entry __percpu *sbi_dbtr_shmem;

/* number of debug triggers on this cpu . */
static int dbtr_total_num __ro_after_init;
static int dbtr_type __ro_after_init;
static int dbtr_init __ro_after_init;

#if __riscv_xlen == 64
#define MEM_HI(_m)	(((u64)_m) >> 32)
#define MEM_LO(_m)	(((u64)_m) & 0xFFFFFFFFUL)
#elif __riscv_xlen == 32
#define MEM_HI(_m)	((((u64)_m) >> 32) & 0x3)
#define MEM_LO(_m)	(((u64)_m) & 0xFFFFFFFFUL)
#else
#error "Unknown __riscv_xlen"
#endif

static void arch_smp_setup_sbi_shmem(void *ctxt)
{
	struct sbi_dbtr_shmem_entry *dbtr_shmem = (struct sbi_dbtr_shmem_entry *)ctxt;
	unsigned long shmem_pa;
	struct sbiret ret;
	int cpu;

	cpu = get_cpu();

	shmem_pa = __pa(dbtr_shmem);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_SETUP_SHMEM,
			MEM_LO(shmem_pa), MEM_HI(shmem_pa), 0, 0, 0, 0);

	if (ret.error) {
		switch(ret.error) {
		case SBI_ERR_DENIED:
			pr_err("%s: Access denied for shared memory at %lx\n",
			       __func__, shmem_pa);
			break;

		case SBI_ERR_INVALID_PARAM:
		case SBI_ERR_INVALID_ADDRESS:
			pr_err("%s: Invalid address parameter (%lu)\n",
			       __func__, ret.error);
			break;
				
		case SBI_ERR_ALREADY_AVAILABLE:
			pr_err("%s: Shared memory is already set\n",
			       __func__);
			break;
				
		default:
			pr_err("%s: Unknown error %lu\n", __func__, ret.error);
			break;
		}
	}

	put_cpu();

	pr_debug("CPU %d: HW Breakpoint shared memory registered.\n", cpu);

	return;
}

static void arch_hw_setup_sbi_shmem(void)
{
	unsigned int cpu = 0;
	struct sbi_dbtr_shmem_entry *dbtr_shmem;

	for_each_online_cpu(cpu) {
		dbtr_shmem = per_cpu_ptr(sbi_dbtr_shmem, cpu);
		if (smp_call_function_single(cpu, arch_smp_setup_sbi_shmem,
					     (void *)dbtr_shmem, true) != 0)
			pr_warn("HW Breakpoint: CPU %d shared memory setup failed\n", cpu);
	}
}

void arch_hw_breakpoint_init_sbi(void)
{
	unsigned long tdata1;
	struct sbiret ret;

	if (sbi_probe_extension(SBI_EXT_DBTR) <= 0) {
		pr_info("%s: SBI_EXT_DBTR is not supported\n", __func__);
		dbtr_total_num = 0;
		goto done;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			0, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to detect triggers\n", __func__);
		dbtr_total_num = 0;
		goto done;
	}

	tdata1 = 0;
	RV_DBTR_SET_TDATA1_TYPE(tdata1, RISCV_DBTR_TRIG_MCONTROL6);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to detect mcontrol6 triggers\n", __func__);
	} else if (!ret.value) {
		pr_warn("%s: type 6 triggers not available\n", __func__);
	} else {
		dbtr_total_num = ret.value;
		dbtr_type = RISCV_DBTR_TRIG_MCONTROL6;
		pr_warn("%s: mcontrol6 trigger available.\n", __func__);
		goto done;
	}

	/* fallback to type 2 triggers if type 6 is not available */

	tdata1 = 0;
	RV_DBTR_SET_TDATA1_TYPE(tdata1, RISCV_DBTR_TRIG_MCONTROL);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS,
			tdata1, 0, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to detect mcontrol triggers\n", __func__);
	} else if (!ret.value) {
		pr_warn("%s: type 2 triggers not available\n", __func__);
	} else {
		dbtr_total_num = ret.value;
		dbtr_type = RISCV_DBTR_TRIG_MCONTROL;
		goto done;
	}

done:
	dbtr_init = 1;
}

int riscv_hw_get_num_triggers(unsigned long *num_triggers,
			      unsigned long *type)
{
	if (!dbtr_init)
		return -1;

	*num_triggers = dbtr_total_num;
	*type = dbtr_type;

	return 0;
}
EXPORT_SYMBOL_GPL(riscv_hw_get_num_triggers);

int hw_breakpoint_slots(int type)
{
	/*
	 * We can be called early, so don't rely on
	 * static variables being initialised.
	 */

	if (!dbtr_init)
		arch_hw_breakpoint_init_sbi();

	return dbtr_total_num;
}

int arch_check_bp_in_kernelspace(struct arch_hw_breakpoint *hw)
{
	unsigned int len;
	unsigned long va;

	va = hw->address;
	len = hw->len;

	return (va >= TASK_SIZE) && ((va + len - 1) >= TASK_SIZE);
}

int arch_build_type2_trigger(const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw)
{
	/* type */
	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		hw->type = RISCV_DBTR_BREAKPOINT;
		RV_DBTR_SET_MC_EXEC(hw->trig_data1);
		break;
	case HW_BREAKPOINT_R:
		hw->type = RISCV_DBTR_WATCHPOINT;
		RV_DBTR_SET_MC_LOAD(hw->trig_data1);
		break;
	case HW_BREAKPOINT_W:
		hw->type = RISCV_DBTR_WATCHPOINT;
		RV_DBTR_SET_MC_STORE(hw->trig_data1);
		break;
	case HW_BREAKPOINT_RW:
		hw->type = RISCV_DBTR_WATCHPOINT;
		RV_DBTR_SET_MC_LOAD(hw->trig_data1);
		RV_DBTR_SET_MC_STORE(hw->trig_data1);
		break;
	default:
		return -EINVAL;
	}

	/* length */
	switch (attr->bp_len) {
	case HW_BREAKPOINT_LEN_1:
		hw->len = 1;
		RV_DBTR_SET_MC_SIZELO(hw->trig_data1, 1);
		break;
	case HW_BREAKPOINT_LEN_2:
		hw->len = 2;
		RV_DBTR_SET_MC_SIZELO(hw->trig_data1, 2);
		break;
	case HW_BREAKPOINT_LEN_4:
		hw->len = 4;
		RV_DBTR_SET_MC_SIZELO(hw->trig_data1, 3);
		break;
#if __riscv_xlen >= 64
	case HW_BREAKPOINT_LEN_8:
		hw->len = 8;
		RV_DBTR_SET_MC_SIZELO(hw->trig_data1, 1);
		RV_DBTR_SET_MC_SIZEHI(hw->trig_data1, 1);
		break;
#endif
	default:
		return -EINVAL;
	}

	RV_DBTR_SET_MC_TYPE(hw->trig_data1, RISCV_DBTR_TRIG_MCONTROL);

	CLEAR_DBTR_BIT(hw->trig_data1, MC, DMODE);
	CLEAR_DBTR_BIT(hw->trig_data1, MC, TIMING);
	CLEAR_DBTR_BIT(hw->trig_data1, MC, SELECT);
	CLEAR_DBTR_BIT(hw->trig_data1, MC, ACTION);
	CLEAR_DBTR_BIT(hw->trig_data1, MC, CHAIN);
	CLEAR_DBTR_BIT(hw->trig_data1, MC, MATCH);
	CLEAR_DBTR_BIT(hw->trig_data1, MC, M);

	SET_DBTR_BIT(hw->trig_data1, MC, S);
	SET_DBTR_BIT(hw->trig_data1, MC, U);

	return 0;
}

int arch_build_type6_trigger(const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw)
{
	/* type */
	switch (attr->bp_type) {
	case HW_BREAKPOINT_X:
		hw->type = RISCV_DBTR_BREAKPOINT;
		RV_DBTR_SET_MC6_EXEC(hw->trig_data1);
		break;
	case HW_BREAKPOINT_R:
		hw->type = RISCV_DBTR_WATCHPOINT;
		RV_DBTR_SET_MC6_LOAD(hw->trig_data1);
		break;
	case HW_BREAKPOINT_W:
		hw->type = RISCV_DBTR_WATCHPOINT;
		RV_DBTR_SET_MC6_STORE(hw->trig_data1);
		break;
	case HW_BREAKPOINT_RW:
		hw->type = RISCV_DBTR_WATCHPOINT;
		RV_DBTR_SET_MC6_STORE(hw->trig_data1);
		RV_DBTR_SET_MC6_LOAD(hw->trig_data1);
		break;
	default:
		return -EINVAL;
	}

	/* length */
	switch (attr->bp_len) {
	case HW_BREAKPOINT_LEN_1:
		hw->len = 1;
		RV_DBTR_SET_MC6_SIZE(hw->trig_data1, 1);
		break;
	case HW_BREAKPOINT_LEN_2:
		hw->len = 2;
		RV_DBTR_SET_MC6_SIZE(hw->trig_data1, 2);
		break;
	case HW_BREAKPOINT_LEN_4:
		hw->len = 4;
		RV_DBTR_SET_MC6_SIZE(hw->trig_data1, 3);
		break;
	case HW_BREAKPOINT_LEN_8:
		hw->len = 8;
		RV_DBTR_SET_MC6_SIZE(hw->trig_data1, 5);
		break;
	default:
		return -EINVAL;
	}

	RV_DBTR_SET_MC6_TYPE(hw->trig_data1, RISCV_DBTR_TRIG_MCONTROL6);

	CLEAR_DBTR_BIT(hw->trig_data1, MC6, DMODE);
	CLEAR_DBTR_BIT(hw->trig_data1, MC6, TIMING);
	CLEAR_DBTR_BIT(hw->trig_data1, MC6, SELECT);
	CLEAR_DBTR_BIT(hw->trig_data1, MC6, ACTION);
	CLEAR_DBTR_BIT(hw->trig_data1, MC6, CHAIN);
	CLEAR_DBTR_BIT(hw->trig_data1, MC6, MATCH);
	CLEAR_DBTR_BIT(hw->trig_data1, MC6, M);

	if (attr->config3 & RISCV_DBTR_CONFIG3_GUEST_EVENTS) {
		CLEAR_DBTR_BIT(hw->trig_data1, MC6, U);
		SET_DBTR_BIT(hw->trig_data1, MC6, S);
		SET_DBTR_BIT(hw->trig_data1, MC6, VU);
		SET_DBTR_BIT(hw->trig_data1, MC6, VS);

		if (attr->exclude_host || attr->exclude_hv)
			CLEAR_DBTR_BIT(hw->trig_data1, MC6, S);

		if (attr->exclude_kernel)
			CLEAR_DBTR_BIT(hw->trig_data1, MC6, VS);

		if (attr->exclude_user)
			CLEAR_DBTR_BIT(hw->trig_data1, MC6, VU);
	} else {
		if (attr->exclude_kernel)
			CLEAR_DBTR_BIT(hw->trig_data1, MC6, S);
		else
			SET_DBTR_BIT(hw->trig_data1, MC6, S);

		if (attr->exclude_user)
			CLEAR_DBTR_BIT(hw->trig_data1, MC6, U);
		else
			SET_DBTR_BIT(hw->trig_data1, MC6, U);

		CLEAR_DBTR_BIT(hw->trig_data1, MC6, VS);
		CLEAR_DBTR_BIT(hw->trig_data1, MC6, VU);
	}

	return 0;
}

int hw_breakpoint_arch_parse(struct perf_event *bp,
			     const struct perf_event_attr *attr,
			     struct arch_hw_breakpoint *hw)
{
	int ret;

	/* address */
	hw->address = attr->bp_addr;
	hw->trig_data2 = attr->bp_addr;
	hw->trig_data3 = 0x0;

	switch (dbtr_type) {
	case RISCV_DBTR_TRIG_MCONTROL:
		ret = arch_build_type2_trigger(attr, hw);
		break;
	case RISCV_DBTR_TRIG_MCONTROL6:
		ret = arch_build_type6_trigger(attr, hw);
		break;
	default:
		pr_warn("unsupported trigger type\n");
		ret = -EOPNOTSUPP;
		break;
	}

	return ret;
}

/*
 * Handle debug exception notifications.
 */
static int hw_breakpoint_handler(struct die_args *args)
{
	int ret = NOTIFY_DONE;
	struct arch_hw_breakpoint *info;
	struct perf_event *bp;
	int i;

	for (i = 0; i < dbtr_total_num; ++i) {
		bp = this_cpu_read(bp_per_reg[i]);
		if (!bp)
			continue;

		info = counter_arch_bp(bp);
		switch (info->type) {
		case RISCV_DBTR_BREAKPOINT:
			if (info->address == args->regs->epc) {
				pr_warn("%s: breakpoint fired: pc[0x%lx]\n",
					 __func__, args->regs->epc);
				perf_bp_event(bp, args->regs);
				ret = NOTIFY_STOP;
			}

			break;
		case RISCV_DBTR_WATCHPOINT:
			if (info->address == csr_read(CSR_STVAL)) {
				pr_warn("%s: watchpoint fired: addr[0x%lx]\n",
					 __func__, info->address);
				perf_bp_event(bp, args->regs);
				ret = NOTIFY_STOP;
			}

			break;
		default:
			pr_warn("%s: unexpected breakpoint type: %u\n",
				__func__, info->type);
			break;
		}
	}

	return ret;
}

int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
				    unsigned long val, void *data)
{
	if (val != DIE_DEBUG)
		return NOTIFY_DONE;

	return hw_breakpoint_handler(data);
}

/* atomic: counter->ctx->lock is held */
int arch_install_hw_breakpoint(struct perf_event *bp)
{
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
	struct sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);
	struct sbi_dbtr_data_msg *xmit;
	struct sbi_dbtr_id_msg *recv;
	struct perf_event **slot;
	unsigned long idx;
	struct sbiret ret;
	int err = 0;

	raw_spin_lock_irqsave(this_cpu_ptr(&msg_lock),
			  *this_cpu_ptr(&msg_lock_flags));

	xmit = &shmem->data;
	recv = &shmem->id;
	xmit->tdata1 = cpu_to_lle(info->trig_data1);
	xmit->tdata2 = cpu_to_lle(info->trig_data2);
	xmit->tdata3 = cpu_to_lle(info->trig_data3);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_INSTALL,
			1, 0, 0, 0, 0, 0);

	if (ret.error) {
		pr_warn("%s: failed to install trigger\n", __func__);
		err = -EIO;
		goto done;
	}

	idx = lle_to_cpu(recv->idx);

	if (idx >= dbtr_total_num) {
		pr_warn("%s: invalid trigger index %lu\n", __func__, idx);
		err = -EINVAL;
		goto done;
	}

	slot = this_cpu_ptr(&bp_per_reg[idx]);
	if (*slot) {
		pr_warn("%s: slot %lu is in use\n", __func__, idx);
		err = -EBUSY;
		goto done;
	}

	*slot = bp;

done:
	raw_spin_unlock_irqrestore(this_cpu_ptr(&msg_lock),
			       *this_cpu_ptr(&msg_lock_flags));
	return err;
}

/* atomic: counter->ctx->lock is held */
void arch_uninstall_hw_breakpoint(struct perf_event *bp)
{
	struct sbiret ret;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);

		if (*slot == bp) {
			*slot = NULL;
			break;
		}
	}

	if (i == dbtr_total_num) {
		pr_warn("%s: unknown breakpoint\n", __func__);
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_UNINSTALL,
			i, 1, 0, 0, 0, 0);
	if (ret.error)
		pr_warn("%s: failed to uninstall trigger %d\n", __func__, i);
}

void arch_enable_hw_breakpoint(struct perf_event *bp)
{
	struct sbiret ret;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);

		if (*slot == bp)
			break;
	}

	if (i == dbtr_total_num) {
		pr_err("%s: unknown breakpoint\n", __func__);
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_ENABLE,
			i, 1, 0, 0, 0, 0);
	if (ret.error) {
		pr_err("%s: failed to install trigger %d\n", __func__, i);
		return;
	}
}
EXPORT_SYMBOL_GPL(arch_enable_hw_breakpoint);

void arch_update_hw_breakpoint(struct perf_event *bp)
{
	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
	struct sbi_dbtr_shmem_entry *shmem = this_cpu_ptr(sbi_dbtr_shmem);
	struct sbi_dbtr_data_msg *xmit;
	struct perf_event **slot;
	struct sbiret ret;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		slot = this_cpu_ptr(&bp_per_reg[i]);

		if (*slot == bp)
			break;
	}

	if (i == dbtr_total_num) {
		pr_warn("%s: unknown breakpoint\n", __func__);
		return;
	}

	raw_spin_lock_irqsave(this_cpu_ptr(&msg_lock),
			  *this_cpu_ptr(&msg_lock_flags));

	xmit = &shmem->data;
	xmit->tdata1 = cpu_to_lle(info->trig_data1);
	xmit->tdata2 = cpu_to_lle(info->trig_data2);
	xmit->tdata3 = cpu_to_lle(info->trig_data3);

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_UPDATE,
			i, 1, 0, 0, 0, 0);
	if (ret.error)
		pr_warn("%s: failed to update trigger %d\n", __func__, i);

	raw_spin_unlock_irqrestore(this_cpu_ptr(&msg_lock),
			       *this_cpu_ptr(&msg_lock_flags));
}
EXPORT_SYMBOL_GPL(arch_update_hw_breakpoint);

void arch_disable_hw_breakpoint(struct perf_event *bp)
{
	struct sbiret ret;
	int i;

	for (i = 0; i < dbtr_total_num; i++) {
		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);

		if (*slot == bp)
			break;
	}

	if (i == dbtr_total_num) {
		pr_warn("%s: unknown breakpoint\n", __func__);
		return;
	}

	ret = sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_DISABLE,
			i, 1, 0, 0, 0, 0);
	if (ret.error) {
		pr_warn("%s: failed to uninstall trigger %d\n", __func__, i);
		return;
	}
}
EXPORT_SYMBOL_GPL(arch_disable_hw_breakpoint);

void hw_breakpoint_pmu_read(struct perf_event *bp)
{
}

/*
 * Set ptrace breakpoint pointers to zero for this task.
 * This is required in order to prevent child processes from unregistering
 * breakpoints held by their parent.
 */
void clear_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	memset(tsk->thread.ptrace_bps, 0, sizeof(tsk->thread.ptrace_bps));
}

/*
 * Unregister breakpoints from this task and reset the pointers in
 * the thread_struct.
 */
void flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
	int i;
	struct thread_struct *t = &tsk->thread;

	for (i = 0; i < dbtr_total_num; i++) {
		unregister_hw_breakpoint(t->ptrace_bps[i]);
		t->ptrace_bps[i] = NULL;
	}
}

static int __init arch_hw_breakpoint_init(void)
{
	unsigned int cpu;
	int rc = 0;

	for_each_possible_cpu(cpu)
		raw_spin_lock_init(&per_cpu(msg_lock, cpu));

	if (!dbtr_init)
		arch_hw_breakpoint_init_sbi();

	if (dbtr_total_num)
		pr_info("%s: total number of type %d triggers: %u\n",
			__func__, dbtr_type, dbtr_total_num);
	else {
		pr_info("%s: no hardware triggers available\n", __func__);
		goto out;
	}

	sbi_dbtr_shmem = __alloc_percpu(sizeof(*sbi_dbtr_shmem) * dbtr_total_num, PAGE_SIZE);
	if (!sbi_dbtr_shmem) {
		pr_warn("failed to allocate SBI shared memory\n");
		sbi_dbtr_shmem = NULL;
		return -ENOMEM;
	}

 out:
	return rc;
}
arch_initcall(arch_hw_breakpoint_init);

static int __init arch_hw_setup_dbtr_shmem(void)
{
	if (sbi_dbtr_shmem)
		arch_hw_setup_sbi_shmem();

	return 0;
}
late_initcall(arch_hw_setup_dbtr_shmem);
