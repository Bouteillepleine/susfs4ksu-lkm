// SPDX-License-Identifier: GPL-2.0
/*
 * sus_dirent.c - filter the listing BEFORE it reaches the caller's buffer.
 *
 * The post-hoc filter in sus_path.c lets the kernel fill the user buffer and rewrites it
 * afterwards.  Two public detectors read that design directly:
 *
 *   - the all-hidden chunk has no honest answer, so the rewrite fabricates one record with
 *     d_ino = 0 and an empty name (a real filesystem never emits d_ino 0).  Ask for a 64-byte
 *     buffer and every chunk holds one record, so the placeholder is handed over on its own.
 *   - the rewrite is a copy_to_user()/clear_user() over a buffer the caller still owns.  A
 *     second thread flipping it PROT_NONE and back faults the scrub, and the "filtering would
 *     be worse than not filtering" fallback then returns the chunk UNFILTERED, with the
 *     kernel's own bytes still in it.
 *
 * Neither is a bug in that code: both follow from rewriting memory the caller can touch.  So
 * this layer does not rewrite anything.  It calls iterate_dir() with its own filldir, which
 * simply does not emit a hidden name - the bytes are never written, so there is nothing to
 * scrub, nothing to fault, and no chunk that needs a placeholder.  An all-hidden stretch just
 * continues to the next entry inside the same call, which is what the kernel itself does.
 *
 * iterate_dir() is EXPORT_SYMBOL and takes i_rwsem, f_pos, fsnotify and the LSM check with it,
 * so what is reimplemented here is only filldir64()'s record layout (fs/readdir.c).
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <asm/unistd.h>		/* __NR_getdents64 */
#include <asm/ptrace.h>		/* struct pt_regs */

#include "susfs.h"
#include "susfs_fp_hook.h"
#include "susfs_log.h"
#include "symbol_resolver.h"

/* 6.1 turned filldir_t's "keep going" from 0 into true. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define SD_RET		bool
#define SD_GO		true
#define SD_STOP		false
#else
#define SD_RET		int
#define SD_GO		0
#define SD_STOP		-EINVAL
#endif

struct sd_dirent64 {
	u64		d_ino;
	s64		d_off;
	unsigned short	d_reclen;
	unsigned char	d_type;
	char		d_name[];
};

struct sd_buf {
	struct dir_context		ctx;
	struct sd_dirent64 __user	*current_dir;
	int				prev_reclen;
	int				count;
	int				error;
};

static int (*sd_iterate_dir)(struct file *, struct dir_context *);
static struct file *(*sd_fget)(unsigned int);

static bool sd_armed;
static bool prefilter = true;
module_param(prefilter, bool, 0644);

static atomic_t n_sd_calls = ATOMIC_INIT(0);
static atomic_t n_sd_hidden = ATOMIC_INIT(0);
static atomic_t n_sd_fallback = ATOMIC_INIT(0);

static susfs_syscall_fn_t sd_orig_getdents64;

/* fs/readdir.c's verify_dirent_name(), which is static there. */
static bool sd_name_ok(const char *name, int len)
{
	return len > 0 && !memchr(name, '/', len);
}

static SD_RET sd_filldir(struct dir_context *ctx, const char *name, int namlen,
			 loff_t offset, u64 ino, unsigned int d_type)
{
	struct sd_buf *buf = container_of(ctx, struct sd_buf, ctx);
	struct sd_dirent64 __user *dirent, *prev;
	int reclen = ALIGN(offsetof(struct sd_dirent64, d_name) + namlen + 1, sizeof(u64));
	int prev_reclen;

	/* The whole point: a hidden name is never written, so there is nothing to take back. */
	if (sus_path_dirent_hidden(ino, name)) {
		atomic_inc(&n_sd_hidden);
		return SD_GO;
	}

	if (!sd_name_ok(name, namlen)) {
		buf->error = -EIO;
		return SD_STOP;
	}
	buf->error = -EINVAL;
	if (reclen > buf->count)
		return SD_STOP;
	prev_reclen = buf->prev_reclen;
	if (prev_reclen && signal_pending(current))
		return SD_STOP;

	dirent = buf->current_dir;
	prev = (void __user *)dirent - prev_reclen;

	/* Same order as filldir64(): the previous record learns this entry's position.  With
	 * prev_reclen 0 that write lands on this record and is overwritten by the next entry,
	 * or by the tail fixup in the wrapper. */
	if (put_user(offset, &prev->d_off) ||
	    put_user(ino, &dirent->d_ino) ||
	    put_user((unsigned short)reclen, &dirent->d_reclen) ||
	    put_user((unsigned char)d_type, &dirent->d_type) ||
	    copy_to_user(dirent->d_name, name, namlen) ||
	    put_user((char)0, &dirent->d_name[namlen])) {
		buf->error = -EFAULT;
		return SD_STOP;
	}

	buf->error = 0;
	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	buf->count -= reclen;
	return SD_GO;
}

/* fs/readdir.c's SYSCALL_DEFINE3(getdents64), with sd_filldir in place of filldir64. */
static __nocfi long sd_getdents64(const struct pt_regs *regs)
{
	susfs_syscall_fn_t orig = READ_ONCE(sd_orig_getdents64);
	unsigned int fd = (unsigned int)regs->regs[0];
	unsigned int count = (unsigned int)regs->regs[2];
	struct sd_buf buf = {};
	struct file *f;
	long error;

	if (!orig)
		return -ENOSYS;
	/* Anything unresolved, or the switch off, and the original answers: the post-hoc filter
	 * in sus_path.c is still armed behind it, so hiding never silently stops. */
	if (!READ_ONCE(prefilter) || !sd_armed || !sd_iterate_dir || !sd_fget) {
		atomic_inc(&n_sd_fallback);
		return orig(regs);
	}

	atomic_inc(&n_sd_calls);
	buf.ctx.actor = sd_filldir;
	buf.ctx.pos = 0;
	buf.current_dir = (struct sd_dirent64 __user *)regs->regs[1];
	buf.count = (int)count;

	f = sd_fget(fd);
	if (!f)
		return -EBADF;

	error = sd_iterate_dir(f, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct sd_dirent64 __user *last =
			(void __user *)buf.current_dir - buf.prev_reclen;

		if (put_user((s64)buf.ctx.pos, &last->d_off))
			error = -EFAULT;
		else
			error = (long)count - buf.count;
	}
	fput(f);
	return error;
}

static struct susfs_fp_hook sd_hook = {
	.nr		= __NR_getdents64,
	.nr_compat	= 0,
	.name		= "dirent/getdents64",
	.sym		= "__arm64_sys_getdents64",
	.wrapper	= sd_getdents64,
	.orig_slot	= &sd_orig_getdents64,
};

int susfs_sus_dirent_init(void)
{
	int err;

	sd_iterate_dir = (void *)find_kernel_symbol_exact("iterate_dir");
	sd_fget = (void *)find_kernel_symbol_exact("fget");
	if (!sd_iterate_dir || !sd_fget) {
		pr_warn("sus_dirent: iterate_dir=%px fget=%px - staying off, the post-hoc filter keeps hiding\n",
			(void *)sd_iterate_dir, (void *)sd_fget);
		return 0;
	}

	sd_armed = true;
	err = susfs_fp_install(&sd_hook);
	if (err) {
		sd_armed = false;
		pr_warn("sus_dirent: table entry %d not installed (%d) - the post-hoc filter keeps hiding\n",
			__NR_getdents64, err);
		return 0;
	}

	SUSFS_LOGI("sus_dirent: armed on nr %d, iterate_dir=%px fget=%px\n",
		   __NR_getdents64, (void *)sd_iterate_dir, (void *)sd_fget);
	return 0;
}

void susfs_sus_dirent_exit(void)
{
	if (sd_armed) {
		susfs_fp_remove(&sd_hook);
		sd_armed = false;
	}
	SUSFS_LOGI("sus_dirent: calls=%d hidden=%d fallback=%d\n",
		   atomic_read(&n_sd_calls), atomic_read(&n_sd_hidden),
		   atomic_read(&n_sd_fallback));
}
