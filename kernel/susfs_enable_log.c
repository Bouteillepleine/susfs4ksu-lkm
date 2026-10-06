// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/cred.h>	/* current_uid(), control-node gate */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_expose_proc */

static bool log_enabled = true;

module_param_named(enable_log, log_enabled, bool, 0444);

bool susfs_log_enabled(void)
{
	return READ_ONCE(log_enabled);
}

static int log_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", log_enabled ? 1 : 0);
	return 0;
}

static int log_proc_open(struct inode *inode, struct file *file)
{

	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, log_proc_show, NULL);
}

static ssize_t log_proc_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *off)
{
	char c;

	if (current_uid().val != 0)
		return -ENOENT;

	if (copy_from_user(&c, buf, 1))
		return -EFAULT;

	if (c != '0' && c != '1')
		return -EINVAL;

	if (c == '1') {
		WRITE_ONCE(log_enabled, true);
		SUSFS_LOGI("susfs: enable logging to kernel\n");
	} else {
		WRITE_ONCE(log_enabled, false);

		pr_info("susfs: disable logging to kernel\n");
	}
	return len;
}

static const struct proc_ops log_proc_ops = {
	.proc_open = log_proc_open,
	.proc_read = seq_read,
	.proc_write = log_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *log_proc_entry;

int susfs_enable_log_init(void)
{

	if (susfs_control_node_allowed()) {
		log_proc_entry = proc_create("susfs_enable_log", 0777, NULL,
					     &log_proc_ops);
		if (!log_proc_entry)
			pr_warn("proc_create(susfs_enable_log) failed\n");
		else
			SUSFS_LOGI("susfs_enable_log: armed (proc: /proc/susfs_enable_log)\n");
	} else {
		SUSFS_LOGI("susfs_enable_log: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}
	return 0;
}

void susfs_enable_log_exit(void)
{
	if (log_proc_entry) {
		proc_remove(log_proc_entry);
		log_proc_entry = NULL;
	}
	log_enabled = true;	/* back to the load-time default */
}

/* supercall: CMD_SUSFS_ENABLE_LOG */
void susfs_enable_log_supercall(void __user **arg)
{
    struct st_susfs_log info = {0};

    if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
        info.err = -EFAULT;
        goto out;
    }
    if (info.enabled) {
        WRITE_ONCE(log_enabled, true);
        SUSFS_LOGI("susfs: enable logging to kernel (supercall)\n");
    } else {
        WRITE_ONCE(log_enabled, false);
        pr_info("susfs: disable logging to kernel (supercall)\n");
    }
    info.err = 0;
out:
    /* upstream writes back only ->err for input-type commands */
    if (copy_to_user(&((struct st_susfs_log __user *)*arg)->err,
                     &info.err, sizeof(info.err)))
        pr_warn("enable_log supercall copy_to_user failed\n");
}
