// SPDX-License-Identifier: GPL-2.0-only
/*
 * uImage.FIT virtual block device driver.
 *
 * Copyright (C) 2022 Daniel Golle
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Derived from drivers/block/brd.c which is in parts derived from
 * drivers/block/rd.c, and drivers/block/loop.c, copyright of their respective
 * owners.
 *
 * uImage.FIT headers extracted from U-Boot mkimage sources
 *  (C) Copyright 2008 Semihalf
 *  (C) Copyright 2000-2005
 *  Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/ctype.h>
#include <linux/hdreg.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_fdt.h>
#include <linux/pagemap.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/libfdt.h>
#include <linux/mtd/mtd.h>
#include <linux/root_dev.h>

#define FIT_IMAGES_PATH		"/images"
#define FIT_CONFS_PATH		"/configurations"

/* hash/signature/key node */
#define FIT_HASH_NODENAME	"hash"
#define FIT_ALGO_PROP		"algo"
#define FIT_VALUE_PROP		"value"
#define FIT_IGNORE_PROP		"uboot-ignore"
#define FIT_SIG_NODENAME	"signature"
#define FIT_KEY_REQUIRED	"required"
#define FIT_KEY_HINT		"key-name-hint"

/* cipher node */
#define FIT_CIPHER_NODENAME	"cipher"
#define FIT_ALGO_PROP		"algo"

/* image node */
#define FIT_DATA_PROP		"data"
#define FIT_DATA_POSITION_PROP	"data-position"
#define FIT_DATA_OFFSET_PROP	"data-offset"
#define FIT_DATA_SIZE_PROP	"data-size"
#define FIT_TIMESTAMP_PROP	"timestamp"
#define FIT_DESC_PROP		"description"
#define FIT_ARCH_PROP		"arch"
#define FIT_TYPE_PROP		"type"
#define FIT_OS_PROP		"os"
#define FIT_COMP_PROP		"compression"
#define FIT_ENTRY_PROP		"entry"
#define FIT_LOAD_PROP		"load"

/* configuration node */
#define FIT_KERNEL_PROP		"kernel"
#define FIT_FILESYSTEM_PROP	"filesystem"
#define FIT_RAMDISK_PROP	"ramdisk"
#define FIT_FDT_PROP		"fdt"
#define FIT_LOADABLE_PROP	"loadables"
#define FIT_DEFAULT_PROP	"default"
#define FIT_SETUP_PROP		"setup"
#define FIT_FPGA_PROP		"fpga"
#define FIT_FIRMWARE_PROP	"firmware"
#define FIT_STANDALONE_PROP	"standalone"

#define MIN_FREE_SECT		16
#define MAX_FIT_LOADABLES	16

static const char *ubootver;
static struct of_phandle_args rootdisk;
static LIST_HEAD(fitblk_devices);
static DEFINE_MUTEX(devices_mutex);

struct fitblk {
	struct block_device	*lower_bdev;
	sector_t		start_sect;
	struct gendisk		*disk;
	struct list_head	list;
};

static int fitblk_open(struct block_device *bdev, fmode_t mode)
{
	struct fitblk *fitblk = bdev->bd_disk->private_data;

	if (fitblk->lower_bdev->bd_disk->fops->open)
		return fitblk->lower_bdev->bd_disk->fops->open(fitblk->lower_bdev, mode);
	else
		return 0;
}

static void fitblk_release(struct gendisk *disk, fmode_t mode)
{
	struct fitblk *fitblk = disk->private_data;

	if (fitblk->lower_bdev->bd_disk->fops->release)
		fitblk->lower_bdev->bd_disk->fops->release(fitblk->lower_bdev->bd_disk, mode);
}

static void fitblk_submit_bio(struct bio *orig_bio)
{
	struct bio *bio = orig_bio;
	struct fitblk *fitblk = bio->bi_bdev->bd_disk->private_data;

	/* mangle bio and re-submit */
	while (bio) {
		bio->bi_iter.bi_sector += fitblk->start_sect;
		bio->bi_bdev = fitblk->lower_bdev;
		bio = bio->bi_next;
	}
	submit_bio(orig_bio);
}

static const struct block_device_operations fitblk_fops = {
	.owner		= THIS_MODULE,
	.open		= fitblk_open,
	.release	= fitblk_release,
	.submit_bio	= fitblk_submit_bio,
};

static void remove_all_subimages(struct device *dev)
{
	struct list_head *n, *tmp;
	struct fitblk *fitblk;

	pr_err("FIT: removing affected devices\n");

	mutex_lock(&devices_mutex);
	list_for_each_safe(n, tmp, &fitblk_devices) {
		fitblk = list_entry(n, struct fitblk, list);
		if (&fitblk->lower_bdev->bd_device != dev)
			continue;

		del_gendisk(fitblk->disk);
		blkdev_put(fitblk->lower_bdev, FMODE_READ);
		kfree(fitblk);
	}
	mutex_unlock(&devices_mutex);
}

static int fitblk_notify(struct notifier_block *nb, unsigned long action,
			 void *data)
{
	struct device *dev = data;

	pr_err("FIT: got notification\n");

	switch (action) {
	case BUS_NOTIFY_DEL_DEVICE:
		remove_all_subimages(dev);
		break;
	}
	return 0;
};

static struct notifier_block fitblk_nb = {
	.notifier_call = fitblk_notify,
};


static int add_fit_subimage_device(struct block_device *lower_bdev, unsigned int slot,
				   sector_t start_sect, sector_t nr_sect,
				   bool readonly)
{
	struct fitblk *fitblk;
	struct gendisk *disk;
	int err;

	mutex_lock(&devices_mutex);

	fitblk = kzalloc(sizeof(struct fitblk), GFP_KERNEL);
	if (!fitblk) {
		err = -ENOMEM;
		goto out_unlock;
	}

	fitblk->lower_bdev = lower_bdev;
	fitblk->start_sect = start_sect;

	disk = blk_alloc_disk(NUMA_NO_NODE);
	if (!disk) {
		err = -ENOMEM;
		goto out_free_fitblk;
	}

	fitblk->disk = disk;
	disk->first_minor = 0;
	disk->flags = lower_bdev->bd_disk->flags | GENHD_FL_NO_PART;
	disk->fops = &fitblk_fops;
	disk->private_data = fitblk;
	if (readonly) {
		set_disk_ro(disk, 1);
		snprintf(disk->disk_name, sizeof(disk->disk_name), "fit%u", slot);
	} else {
		strcpy(disk->disk_name, "fitrw");
	}

	set_capacity(disk, nr_sect);

	disk->queue->queue_flags = lower_bdev->bd_disk->queue->queue_flags;
	memcpy(&disk->queue->limits, &lower_bdev->bd_disk->queue->limits,
	       sizeof(struct queue_limits));

	err = device_add_disk(&lower_bdev->bd_device, disk, NULL);
	if (err)
		goto out_cleanup_disk;

	if (!ROOT_DEV)
		ROOT_DEV = disk->part0->bd_dev;

	list_add_tail(&fitblk->list, &fitblk_devices);

	mutex_unlock(&devices_mutex);

	return 0;

out_cleanup_disk:
	put_disk(disk);
out_free_fitblk:
	kfree(fitblk);
out_unlock:
	mutex_unlock(&devices_mutex);
	return err;
}

static int parse_fit_on_dev(struct device *dev)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct block_device *bdev = blkdev_get_by_dev(dev_to_bdev(dev)->bd_dev, FMODE_READ, NULL);
	struct address_space *mapping = bdev->bd_inode->i_mapping;
	struct folio *folio;
	void *fit;
	u64 dsize, dsectors, imgmaxsect = 0;
	u32 size, image_pos, image_len;
	const __be32 *image_offset_be, *image_len_be, *image_pos_be;
	int ret = 0, node, images, config;
	const char *image_name, *image_type, *image_description,
		*config_default, *config_description, *config_loadables;
	u32 image_name_len, image_type_len, image_description_len,
		bootconf_len, config_default_len, config_description_len,
		config_loadables_len;
	sector_t start_sect, nr_sects;
	struct device_node *np = NULL;
	const char *bootconf;
	const char *loadable;
	bool found;
	int loadables_rem_len, loadable_len;
	u16 loadcnt;
	unsigned int slot = 0;

	/* map first page */
	folio = read_mapping_folio(mapping, 0, NULL);
	if (IS_ERR(folio)) {
		ret = -PTR_ERR(folio);
		goto out_blkdev;
	}

	fit = folio_address(folio) + offset_in_folio(folio, 0);

	/* uImage.FIT is based on flattened device tree structure */
	if (fdt_check_header(fit)) {
		ret = -EINVAL;
		goto out_folio;
	}

	/* acquire disk size */
	dsectors = bdev_nr_sectors(bdev);
	dsize = dsectors << SECTOR_SHIFT;

	/* silently skip non-external-data legacy uImage.FIT */
	size = fdt_totalsize(fit);
	if (size > PAGE_SIZE) {
		ret = -EOPNOTSUPP;
		goto out_folio;
	}

	/* abort if FIT structure is larger than disk or partition size */
	if (size >= dsize) {
		ret = -EFBIG;
		goto out_folio;
	}

	/* set boot config node name U-Boot may have added to the device tree */
	np = of_find_node_by_path("/chosen");
	if (np)
		bootconf = of_get_property(np, "u-boot,bootconf", &bootconf_len);
	else
		bootconf = NULL;

	/* find configuration path in uImage.FIT */
	config = fdt_path_offset(fit, FIT_CONFS_PATH);
	if (config < 0) {
		pr_err("FIT: Cannot find %s node: %d\n",
			FIT_CONFS_PATH, config);
		ret = -ENOENT;
		goto out_folio;
	}

	/* get default configuration node name */
	config_default =
		fdt_getprop(fit, config, FIT_DEFAULT_PROP, &config_default_len);

	/* make sure we got either default or selected boot config node name */
	if (!config_default && !bootconf) {
		pr_err("FIT: Cannot find default configuration\n");
		ret = -ENOENT;
		goto out_folio;
	}

	/* find selected boot config node, fallback on default config node */
	node = fdt_subnode_offset(fit, config, bootconf ?: config_default);
	if (node < 0) {
		pr_err("FIT: Cannot find %s node: %d\n",
			bootconf ?: config_default, node);
		ret = -ENOENT;
		goto out_folio;
	}

	pr_info("FIT: Detected U-Boot %s\n", ubootver);

	/* get selected configuration data */
	config_description =
		fdt_getprop(fit, node, FIT_DESC_PROP, &config_description_len);
	config_loadables = fdt_getprop(fit, node, FIT_LOADABLE_PROP,
				       &config_loadables_len);

	pr_info("FIT: %s configuration: \"%.*s\"%s%.*s%s\n",
		bootconf ? "Selected" : "Default",
		bootconf ? bootconf_len : config_default_len,
		bootconf ?: config_default,
		config_description ? " (" : "",
		config_description ? config_description_len : 0,
		config_description ?: "",
		config_description ? ")" : "");

	if (!config_loadables || !config_loadables_len) {
		pr_err("FIT: No loadables configured in \"%s\"\n",
			bootconf ?: config_default);
		ret = -ENOENT;
		goto out_folio;
	}

	/* get images path in uImage.FIT */
	images = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (images < 0) {
		pr_err("FIT: Cannot find %s node: %d\n", FIT_IMAGES_PATH, images);
		ret = -EINVAL;
		goto out_folio;
	}

	/* register for notifications, so device removal can be tracked */
	if (disk_to_dev(disk)->bus) {
		pr_err("FIT: registering notified on bus %s\n",
			disk_to_dev(disk)->bus->name);
		ret = bus_register_notifier(disk_to_dev(disk)->bus, &fitblk_nb);
		if (ret)
			goto out_folio;
	}

	/* iterate over images in uImage.FIT */
	fdt_for_each_subnode(node, fit, images) {
		image_name = fdt_get_name(fit, node, &image_name_len);
		image_type = fdt_getprop(fit, node, FIT_TYPE_PROP, &image_type_len);
		image_offset_be = fdt_getprop(fit, node, FIT_DATA_OFFSET_PROP, NULL);
		image_pos_be = fdt_getprop(fit, node, FIT_DATA_POSITION_PROP, NULL);
		image_len_be = fdt_getprop(fit, node, FIT_DATA_SIZE_PROP, NULL);

		if (!image_name || !image_type || !image_len_be ||
		    !image_name_len || !image_type_len)
			continue;

		image_len = be32_to_cpu(*image_len_be);
		if (!image_len)
			continue;

		if (image_offset_be)
			image_pos = be32_to_cpu(*image_offset_be) + size;
		else if (image_pos_be)
			image_pos = be32_to_cpu(*image_pos_be);
		else
			continue;

		image_description = fdt_getprop(fit, node, FIT_DESC_PROP,
						&image_description_len);

		pr_info("FIT: %16s sub-image 0x%08x..0x%08x \"%.*s\"%s%.*s%s\n",
			image_type, image_pos, image_pos + image_len - 1,
			image_name_len, image_name, image_description ? " (" : "",
			image_description ? image_description_len : 0,
			image_description ?: "", image_description ? ") " : "");

		/* only 'filesystem' images should be mapped as partitions */
		if (strncmp(image_type, FIT_FILESYSTEM_PROP, image_type_len))
			continue;

		/* check if sub-image is part of configured loadables */
		found = false;
		loadable = config_loadables;
		loadables_rem_len = config_loadables_len;
		for (loadcnt = 0; loadables_rem_len > 1 &&
				  loadcnt < MAX_FIT_LOADABLES; ++loadcnt) {
			loadable_len =
				strnlen(loadable, loadables_rem_len - 1) + 1;
			loadables_rem_len -= loadable_len;
			if (!strncmp(image_name, loadable, loadable_len)) {
				found = true;
				break;
			}
			loadable += loadable_len;
		}
		if (!found)
			continue;

		if (image_pos % (1 << PAGE_SHIFT)) {
			dev_err(dev, "FIT: image %.*s start not aligned to page boundaries, skipping\n",
				image_name_len, image_name);
			continue;
		}

		if (image_len % (1 << PAGE_SHIFT)) {
			dev_err(dev, "FIT: sub-image %.*s end not aligned to page boundaries, skipping\n",
				image_name_len, image_name);
			continue;
		}

		start_sect = image_pos >> SECTOR_SHIFT;
		nr_sects = image_len >> SECTOR_SHIFT;
		imgmaxsect = max_t(sector_t, imgmaxsect, start_sect + nr_sects);

		if (start_sect + nr_sects > dsectors) {
			dev_err(dev, "FIT: sub-image %.*s disk access beyond EOD\n",
				image_name_len, image_name);
			continue;
		}

		add_fit_subimage_device(bdev, slot++, start_sect, nr_sects, true);
	}

	if (slot)
		dev_info(dev, "mapped %u uImage.FIT filesystem sub-image%s as /dev/fit%s%u%s\n",
			 slot, (slot > 1)?"s":"", (slot > 1)?"[0...":"", slot - 1,
			 (slot > 1)?"]":"");

	/* in case uImage.FIT is stored in a partition, map the remaining space */
	if (!bdev->bd_read_only && bdev_is_partition(bdev) &&
	    (imgmaxsect + MIN_FREE_SECT) < dsectors) {
		add_fit_subimage_device(bdev, slot++, imgmaxsect,
					dsectors - imgmaxsect, false);
		dev_info(dev, "mapped remaing space as /dev/fitrw\n");
	}

out_folio:
	folio_put(folio);
out_blkdev:
	if (ret)
		blkdev_put(bdev, FMODE_READ);

	return ret;
}

static int fitblk_match_block(struct device *_dev, const void *data)
{
	struct device *dev = _dev;
	struct of_phandle_args *rootdisk = (struct of_phandle_args *)data;
	struct block_device *bdev = dev_to_bdev(dev);
	struct device_node *np;
	int ret = 0;
	u8 partno = (rootdisk->args[0] == -1)?0:rootdisk->args[0];

	if (bdev->bd_partno != partno)
		return 0;

	while (dev) {
		np = dev_of_node(dev);
		if (rootdisk->np == np) {
			ret = 1;
			break;
		}
		dev = dev->parent;
	}

	if (!ret)
		return ret;

	return ret;
}

static int fitblk_match_mtd(struct device *_dev, const void *data)
{
	struct device *dev = _dev;
	struct of_phandle_args *rootdisk = (struct of_phandle_args *)data;
	struct device_node *np;
	char *tmp;
	unsigned long vol_id;
	int ret = 0;

	while (dev) {
		np = dev_of_node(dev);
		if (rootdisk->np == np) {
			ret = 1;
			break;
		}
		dev = dev->parent;
	}

	if (!ret)
		return 0;

	/*
	 * arg == (-1) for mtdblock on MTD device
	 * arg == (n)  for ubiblock on UBI volume n on MTD device
	 */
	tmp = strchr(dev_name(_dev), '_');
	if (!tmp || (rootdisk->args[0] == -1))
		return (!tmp != !(rootdisk->args[0] == -1));

	++tmp;
	if (kstrtoul(tmp, 10, &vol_id) < 0)
		return 0;

	if (rootdisk->args[0] == vol_id)
		return 1;

	return 0;
}

static int fitblk_probe(struct platform_device *pdev)
{
	struct device *dev;
	struct mtd_info *mtddev;

	mtddev = of_get_mtd_device_by_node(rootdisk.np);
	if (!IS_ERR(mtddev)) {
		put_mtd_device(mtddev);
		dev = class_find_device(&block_class, NULL, &rootdisk, fitblk_match_mtd);
	} else {
		dev = class_find_device(&block_class, NULL, &rootdisk, fitblk_match_block);
	}

	if (!dev)
		return -EPROBE_DEFER;

	return parse_fit_on_dev(dev);
}

static struct platform_driver fitblk_driver = {
	.probe		= fitblk_probe,
	.driver		= {
		.name   = "fitblk",
		.owner   = THIS_MODULE,
	},
};

static int __init fitblk_init(void)
{
	/* detect U-Boot firmware */
	ubootver = of_get_property(of_chosen, "u-boot,version", NULL);
	if (!ubootver)
		return 0;

	/* parse 'rootdisk' property phandle and 1 argument */
	if (of_parse_phandle_with_fixed_args(of_chosen, "rootdisk",
					     1, 0, &rootdisk))
		return 0;

	platform_device_register_simple("fitblk", -1, NULL, 0);
	return platform_driver_register(&fitblk_driver);
}
module_init(fitblk_init);

MODULE_AUTHOR("Daniel Golle");
MODULE_DESCRIPTION("uImage.FIT virtual block driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:fitblk");
