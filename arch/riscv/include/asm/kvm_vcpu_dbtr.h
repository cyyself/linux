/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 Ventana Micro Systems, Inc.
 *
 * Authors:
 *     Himanshu Chauhan <hchauhan@ventanamicro.com>
 */

#ifndef __KVM_VCPU_DBTR_H
#define __KVM_VCPU_DBTR_H

#ifdef CONFIG_HAVE_VIRT_HW_BREAKPOINT
#include <asm/hw_breakpoint.h>

#define RISCV_KVM_MAX_DBTR_TRIGGERS	16

#if __riscv_xlen == 64
#define SBI_DBTR_SHMEM_INVALID_ADDR	0xFFFFFFFFFFFFFFFFUL
#elif __riscv_xlen == 32
#define SBI_DBTR_SHMEM_INVALID_ADDR	0xFFFFFFFFUL
#error "Unexpected __riscv_xlen"
#endif

#define vcpu_to_dbtr(_vcpu) (&(_vcpu)->arch.dbtr_context)
#define dbtr_to_vcpu(_dbtr)  (container_of((dbtr), struct kvm_vcpu,	\
					   arch.dbtr_context))

#define RISCV_KVM_DBTR_MAPPED_BIT	0
#define RISCV_KVM_DBTR_U_BIT		1
#define RISCV_KVM_DBTR_S_BIT		2
#define RISCV_KVM_DBTR_VU_BIT		3
#define RISCV_KVM_DBTR_VS_BIT		4

#define RISCV_KVM_DBTR_MAPPED_BIT_MASK	(1UL << RISCV_KVM_DBTR_MAPPED_BIT)
#define RISCV_KVM_DBTR_U_BIT_MASK	(1UL << RISCV_KVM_DBTR_U_BIT)
#define RISCV_KVM_DBTR_S_BIT_MASK	(1UL << RISCV_KVM_DBTR_S_BIT)
#define RISCV_KVM_DBTR_VU_BIT_MASK	(1UL << RISCV_KVM_DBTR_VU_BIT)
#define RISCV_KVM_DBTR_VS_BIT_MASK	(1UL << RISCV_KVM_DBTR_VS_BIT)

#define IS_TRIGGER_MAPPED(_trigger)	(_trigger->state & \
					 RISCV_KVM_DBTR_MAPPED_BIT_MASK)
#define IS_TRIGGER_ENABLED(_trigger)	(_trigger->enabled)

typedef unsigned long kvm_dbtr_state_t;

struct kvm_sbi_dbtr_trig_info {
	unsigned long index;
	unsigned long type_mask;
	kvm_dbtr_state_t state;
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
	unsigned long bp_addr; /** trigger hit address */
	unsigned long bp_type; /** type of trigger R/W/X (not perf type) */
	unsigned long bp_len; /** in case of R/W trigger the length of it */
	struct perf_event *perf_event; /** perf_event associated to this trig */
	unsigned long enabled;
};

struct kvm_sbi_dbtr_data_msg {
	unsigned long tstate;
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
};

struct kvm_sbi_dbtr_id_msg {
	unsigned long idx;
};

struct kvm_sbi_dbtr_shmem_entry {
	struct kvm_sbi_dbtr_data_msg data;
	struct kvm_sbi_dbtr_id_msg id;
};

struct kvm_dbtr {
	struct kvm_sbi_dbtr_trig_info triggers[RISCV_KVM_MAX_DBTR_TRIGGERS];
	unsigned long num_hw_triggers;
	unsigned long hw_trigger_type;
	unsigned long sbi_shmem;
	int init_done;
	DECLARE_BITMAP(triggers_in_use, RISCV_KVM_MAX_DBTR_TRIGGERS);
};

#define trig_to_dbtr(_trig)		((struct kvm_dbtr *)(_trig - \
							     ((sizeof(typeof(*_trig))) \
							      * _trig->index)))
#define dbtr_total_trigs(_vdbtr)	(_vdbtr->num_hw_triggers)
#define dbtr_trig_type(_vdbtr)		(_vdbtr->hw_trigger_type)

#define idx_to_shmem_entry(_shmem, _i)					\
	(((struct kvm_sbi_dbtr_shmem_entry *)_shmem) + _i)

#define for_each_trig_entry_from(_base, _start, _max, _etype, _entry)	\
	for (int _idx = _start; _entry = ((_etype *)_base + _idx),	\
		     _idx < _max;					\
	     _idx++, _entry = ((_etype *)_base + _idx))

#define for_each_trig_entry(_base, _max, _etype, _entry)		\
	for_each_trig_entry_from(_base, 0, _max, _etype, _entry)

void kvm_riscv_vcpu_dbtr_init(struct kvm_vcpu *vcpu);
int kvm_riscv_vcpu_dbtr_num_trigs(struct kvm_vcpu *vcpu, unsigned long data,
				  unsigned long *outval);
int kvm_riscv_vcpu_dbtr_setup_shmem(struct kvm_vcpu *vcpu, unsigned long gpa_lo,
				    unsigned long gpa_hi);
int kvm_riscv_vcpu_dbtr_trig_read(struct kvm_vcpu *vcpu, unsigned long base,
				  unsigned long count);
int kvm_riscv_vcpu_dbtr_trig_install(struct kvm_vcpu *vcpu, unsigned long count);
int kvm_riscv_vcpu_dbtr_trig_update(struct kvm_vcpu *vcpu, unsigned long base,
				    unsigned long mask);
int kvm_riscv_vcpu_dbtr_trig_uninstall(struct kvm_vcpu *vcpu, unsigned long base,
				       unsigned long mask);
int kvm_riscv_vcpu_dbtr_trig_enable(struct kvm_vcpu *vcpu, unsigned long base,
				    unsigned long mask);
int kvm_riscv_vcpu_dbtr_trig_disable(struct kvm_vcpu *vcpu, unsigned long base,
				     unsigned long mask);
#else
struct kvm_dbtr {
};
static inline void kvm_riscv_vcpu_dbtr_init(struct kvm_vcpu *vcpu) { }
#endif /* CONFIG_HAVE_VIRT_HW_BREAKPOINT */
#endif /* __KVM_VCPU_DBTR_H */
