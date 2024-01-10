// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Ventana Microsystems, Inc.
 *
 * Authors:
 *     Himanshu Chauhan <hchauhan@ventanamicro.com>
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/kvm_host.h>
#include <asm/csr.h>
#include <asm/sbi.h>
#include <asm/kvm_vcpu_sbi.h>
#include <asm/kvm_vcpu_dbtr.h>

static int kvm_sbi_ext_dbtr_handler(struct kvm_vcpu *vcpu, struct kvm_run *run,
				    struct kvm_vcpu_sbi_return *rv)
{
	struct kvm_cpu_context *cp = &vcpu->arch.guest_context;
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);
	unsigned long funcid = cp->a6;
	unsigned long outv;
	int ret;

	if (!vdbtr->init_done) {
		rv->err_val = SBI_ERR_NOT_SUPPORTED;
		return 0;
	}

	switch(funcid) {
	case SBI_EXT_DBTR_NUM_TRIGGERS:
		ret = kvm_riscv_vcpu_dbtr_num_trigs(vcpu, cp->a0, &outv);
		if (ret == 0) {
			rv->out_val = outv;
			rv->err_val = SBI_SUCCESS;
		}
		break;

	case SBI_EXT_DBTR_SETUP_SHMEM:
		ret = kvm_riscv_vcpu_dbtr_setup_shmem(vcpu, cp->a0, cp->a1);
		break;

	case SBI_EXT_DBTR_TRIGGER_READ:
		ret = kvm_riscv_vcpu_dbtr_trig_read(vcpu, cp->a0, cp->a1);
		break;

	case SBI_EXT_DBTR_TRIGGER_INSTALL:
		ret = kvm_riscv_vcpu_dbtr_trig_install(vcpu, cp->a0);
		break;

	case SBI_EXT_DBTR_TRIGGER_UPDATE:
		ret = kvm_riscv_vcpu_dbtr_trig_update(vcpu, cp->a0, cp->a1);
		break;

	case SBI_EXT_DBTR_TRIGGER_UNINSTALL:
		ret = kvm_riscv_vcpu_dbtr_trig_uninstall(vcpu, cp->a0, cp->a1);
		break;

	case SBI_EXT_DBTR_TRIGGER_ENABLE:
		ret = kvm_riscv_vcpu_dbtr_trig_enable(vcpu, cp->a0, cp->a1);
		break;

	case SBI_EXT_DBTR_TRIGGER_DISABLE:
		ret = kvm_riscv_vcpu_dbtr_trig_disable(vcpu, cp->a0, cp->a1);
		break;

	default:
		rv->err_val = SBI_ERR_NOT_SUPPORTED;
		break;
	}

	return 0;
}

static unsigned long kvm_sbi_ext_dbtr_probe(struct kvm_vcpu *vcpu)
{
	struct kvm_dbtr *vdbtr = vcpu_to_dbtr(vcpu);

	return vdbtr->init_done;
}

const struct kvm_vcpu_sbi_extension vcpu_sbi_ext_dbtr = {
	.extid_start = SBI_EXT_DBTR,
	.extid_end = SBI_EXT_DBTR,
	.handler = kvm_sbi_ext_dbtr_handler,
	.probe = kvm_sbi_ext_dbtr_probe,
};
