#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <asm/apple_cpufeature.h>

MODULE_AUTHOR("Yangyu Chen <cyy@cyyself.name>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TSO Enabler for Apple M1");

int m1tso_user = 0;
int m1tso_kernel = 0;

static ssize_t m1tso_status_load(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t m1tso_status_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t cnt);

static struct kobj_attribute m1tso_kernel_query = __ATTR(kernel, 0664, m1tso_status_load, m1tso_status_store);
static struct kobj_attribute m1tso_user_query   = __ATTR(user  , 0664, m1tso_status_load, m1tso_status_store);

void m1tso_update_actlr(int is_kernel)
{
    unsigned long actlr = read_sysreg(actlr_el1);
    if (is_kernel) {
        if (m1tso_kernel)
            actlr |= ACTLR_APPLE_TSO;
        else
            actlr &= ~ACTLR_APPLE_TSO;
    }
    else {
        if (m1tso_user)
            actlr |= ACTLR_APPLE_TSO;
        else
            actlr &= ~ACTLR_APPLE_TSO;
    }
    write_sysreg(actlr, actlr_el1);
}

static ssize_t m1tso_status_load(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    if (strcmp(attr->attr.name, "kernel") == 0) {
        return sprintf(buf, "%d\n", m1tso_kernel);
    }
    else if (strcmp(attr->attr.name, "user") == 0) {
        return sprintf(buf, "%d\n", m1tso_user);
    }
    return -EINVAL;
}

static ssize_t m1tso_status_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t cnt) {
    int val;
    if (sscanf(buf, "%d", &val) != 1) {
        return -EINVAL;
    }
    if (strcmp(attr->attr.name, "kernel") == 0) {
        m1tso_kernel = val ? 1 : 0;
        return cnt;
    }
    else if (strcmp(attr->attr.name, "user") == 0) {
        m1tso_user = val ? 1 : 0;
        return cnt;
    }
    return -EINVAL;
}

static struct attribute *m1tso_attrs[] = {
    &m1tso_kernel_query.attr,
    &m1tso_user_query.attr,
    NULL,
};

static struct attribute_group m1tso_attr_group = {
    .attrs = m1tso_attrs,
};

struct kobject *m1tso_kobj;

static int __init m1tso_init(void) {
    int ret = 0;
    m1tso_kobj = kobject_create_and_add("m1tso", kernel_kobj);
    if (!(m1tso_kobj)) ret = -ENOMEM;
    ret = sysfs_create_group(m1tso_kobj, &m1tso_attr_group);
    if (ret) kobject_put(m1tso_kobj);
    return ret;
}

static void __exit m1tso_exit(void) {
    sysfs_remove_group(m1tso_kobj, &m1tso_attr_group);
    kobject_put(m1tso_kobj);
}

module_init(m1tso_init);
module_exit(m1tso_exit);
