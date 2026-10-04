// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_kstat.c - spoof kstat fields (SUSFS SUS_KSTAT feature), LKM port.
 *
 * Interface mirrors the original SUSFS userspace commands, one command per write to
 * /proc/susfs_kstat:
 *   add_sus_kstat <path> - store the CURRENT stat of <path> as the spoof target
 *       (ino/dev/times/blocks/blksize), flags = KSTAT_AUTO_SPOOF; use it BEFORE the path is
 *       bind-mounted/overlayed, then call update_sus_kstat.
 *   add_sus_kstat_statically <path> <ino> <dev> <nlink> <size> <atime> <atime_nsec> <mtime>
 *       <mtime_nsec> <ctime> <ctime_nsec> <blocks> <blksize> - set each field explicitly;
 *       "default" keeps the current value and does NOT spoof that field, and only non-default
 *       fields get their KSTAT_SPOOF_* flag set.
 *   update_sus_kstat <path> / update_sus_kstat_full_clone <path> - re-resolve <path> (after it was
 *       bind-mounted/overlayed) and update target_ino/target_dev only, spoofed values staying as
 *       previously added; the _full_clone form also raises KSTAT_SPOOF_NLINK|KSTAT_SPOOF_SIZE.
 *   del <path> - remove one rule by its target pathname;   clear - remove all rules.
 *
 * Hook strategy: ONE hook, the global sys_exit tracepoint (kstat_sys_exit()).  LTO on this GKI
 * inlines the whole stat chain (vfs_fstatat -> vfs_statx -> vfs_getattr -> cp_new_stat, and
 * vfs_fstat/do_statx -> cp_new_stat/cp_statx the same way), so no VFS-layer probe is ever hit:
 * measured on the 5.15 device, 120 000 app-uid newfstatat calls moved a vfs_getattr kretprobe's
 * counter by +15, i.e. noise - that kretprobe is deleted, not disabled.  What IS reliable is the
 * return of the syscall-table entry points, where the user buffer is fully written and
 * syscall_get_arguments() still returns the original args from the live pt_regs.  So the
 * tracepoint whitelists the syscall numbers that fill a user stat buffer and rewrites the buffer
 * through copy_to_user:
 *
 *   native 79 __NR_newfstatat -> struct stat, user buffer args[2]
 *   native 80 __NR_fstat      -> struct stat, user buffer args[1] (the fd-based one)
 *   native 291 __NR_statx     -> struct statx, buffer args[4], caller's mask args[3]
 *   AArch32 327 fstatat64 / 197 fstat64 -> struct stat64
 *   AArch32 106/107/108 stat/lstat/fstat -> struct compat_stat (not reachable from this kernel's
 *           unistd32 table, kept listed so the two layouts are not confused - see below)
 *
 * The SAME tracepoint and the same handler carry sus_path's dirent (getdents) rewrite - see
 * sus_path_dirent_filter() under the stat branch below.  One register_trace_sys_exit() call in the
 * module, one handler, one dispatch: the syscall number is fetched once and tested against the
 * whitelist, and only a whitelisted number pays for anything after that.  Field offsets are arm64
 * asm-generic struct stat / struct statx, derived with offsetof() (this file) and static_assert'ed
 * rather than hard-coded.
 */
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/stat.h>
#include <linux/compat.h>
#include <linux/tracepoint.h>
#include <trace/events/syscalls.h>
#include <asm/syscall.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/kdev_t.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/version.h>	/* LINUX_VERSION_CODE: the inode ctime accessor */
#include "susfs_abi.h"
#include "susfs_log.h"
#include "susfs.h"	/* susfs_expose_proc, sus_path_dirent_filter() */

/* KSTAT_SPOOF_* bits live in susfs_abi.h (upstream declares them in susfs.h next to struct
 * st_susfs_sus_kstat).  KSTAT_AUTO_SPOOF* below are /proc-interface masks, not supercall ABI. */
#define KSTAT_AUTO_SPOOF (KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV | \
	KSTAT_SPOOF_ATIME_TV_SEC | KSTAT_SPOOF_ATIME_TV_NSEC | \
	KSTAT_SPOOF_MTIME_TV_SEC | KSTAT_SPOOF_MTIME_TV_NSEC | \
	KSTAT_SPOOF_CTIME_TV_SEC | KSTAT_SPOOF_CTIME_TV_NSEC | \
	KSTAT_SPOOF_BLKSIZE | KSTAT_SPOOF_BLOCKS)
#define KSTAT_AUTO_SPOOF_FULL_CLONE (KSTAT_AUTO_SPOOF | \
	KSTAT_SPOOF_NLINK | KSTAT_SPOOF_SIZE)

#define SUS_KSTAT_MAX 32
/* Upstream's target_pathname is char[256]: a shorter buffer truncates a legal long path into a wrong rule. */
#define KSTAT_PATH_MAX 256

struct sus_kstat_entry {
	char target_pathname[KSTAT_PATH_MAX];
	unsigned long target_ino;
	/* dev stored ENCODED (new_encode_dev) so it matches the user statbuf st_dev field 1:1 on the tracepoint hot path. */
	dev_t target_dev;
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_tv_sec;
	unsigned long spoofed_atime_tv_nsec;
	long spoofed_mtime_tv_sec;
	unsigned long spoofed_mtime_tv_nsec;
	long spoofed_ctime_tv_sec;
	unsigned long spoofed_ctime_tv_nsec;
	long long spoofed_blocks;
	long spoofed_blksize;
	unsigned int flags;
};

static struct sus_kstat_entry kstat_entries[SUS_KSTAT_MAX];
static int nkstat;
static DEFINE_MUTEX(kstat_lock);

/* Table locking, in two tiers.  kstat_lock (mutex) serialises WRITERS and the /proc read, because
 * writers resolve paths and that sleeps.  kstat_table_lock (spinlock) guards the table for the
 * READERS - the sys_exit tracepoint and the show_map_vma kretprobe, hot paths where kstat_lock
 * cannot be taken; a reader holds it only long enough to copy the matching entry out and must never
 * copy_to_user under it.  Rule: resolve first (sleeping, outside), then swap (non-sleeping, inside) -
 * publishing a slot before it is filled is a bug (an empty slot used to be visible as soon as nkstat
 * was bumped, before kern_path() had even run). */
static DEFINE_SPINLOCK(kstat_table_lock);

/* The part of an entry a reader needs, copied out under kstat_table_lock. */
struct sus_kstat_snapshot {
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_tv_sec;
	unsigned long spoofed_atime_tv_nsec;
	long spoofed_mtime_tv_sec;
	unsigned long spoofed_mtime_tv_nsec;
	long spoofed_ctime_tv_sec;
	unsigned long spoofed_ctime_tv_nsec;
	long long spoofed_blocks;
	long spoofed_blksize;
	unsigned int flags;
};

static void kstat_snapshot(const struct sus_kstat_entry *e,
			   struct sus_kstat_snapshot *s)
{
	s->spoofed_ino = e->spoofed_ino;
	s->spoofed_dev = e->spoofed_dev;
	s->spoofed_nlink = e->spoofed_nlink;
	s->spoofed_size = e->spoofed_size;
	s->spoofed_atime_tv_sec = e->spoofed_atime_tv_sec;
	s->spoofed_atime_tv_nsec = e->spoofed_atime_tv_nsec;
	s->spoofed_mtime_tv_sec = e->spoofed_mtime_tv_sec;
	s->spoofed_mtime_tv_nsec = e->spoofed_mtime_tv_nsec;
	s->spoofed_ctime_tv_sec = e->spoofed_ctime_tv_sec;
	s->spoofed_ctime_tv_nsec = e->spoofed_ctime_tv_nsec;
	s->spoofed_blocks = e->spoofed_blocks;
	s->spoofed_blksize = e->spoofed_blksize;
	s->flags = e->flags;
}

/* arm64 asm-generic struct stat offsets (native 64-bit) */
#define ST_DEV_OFF          0
#define ST_INO_OFF          8
#define ST_NLINK_OFF        20
#define ST_SIZE_OFF         48
#define ST_BLKSIZE_OFF      56
#define ST_BLOCKS_OFF       64
#define ST_ATIME_OFF        72
#define ST_ATIME_NSEC_OFF   80
#define ST_MTIME_OFF        88
#define ST_MTIME_NSEC_OFF   96
#define ST_CTIME_OFF        104
#define ST_CTIME_NSEC_OFF   112

/* The numbers above are a uapi contract, checked at build time instead of trusted: arm64 uses the
 * generic layout (__ARCH_WANT_NEW_STAT), and a DDK header change that moved a member would
 * otherwise corrupt the caller's stat buffer instead of failing this build. */
static_assert(offsetof(struct stat, st_dev) == ST_DEV_OFF, "stat.st_dev");
static_assert(offsetof(struct stat, st_ino) == ST_INO_OFF, "stat.st_ino");
static_assert(offsetof(struct stat, st_nlink) == ST_NLINK_OFF, "stat.st_nlink");
static_assert(offsetof(struct stat, st_size) == ST_SIZE_OFF, "stat.st_size");
static_assert(offsetof(struct stat, st_blksize) == ST_BLKSIZE_OFF, "stat.st_blksize");
static_assert(offsetof(struct stat, st_blocks) == ST_BLOCKS_OFF, "stat.st_blocks");
static_assert(offsetof(struct stat, st_atime) == ST_ATIME_OFF, "stat.st_atime");
static_assert(offsetof(struct stat, st_mtime) == ST_MTIME_OFF, "stat.st_mtime");
static_assert(offsetof(struct stat, st_ctime) == ST_CTIME_OFF, "stat.st_ctime");

/* ---- the read gate ----
 *
 * Upstream gates every sus_kstat read on susfs_is_current_proc_umounted_app(), exactly
 * (TIF_PROC_UMOUNTED && current_uid().val >= 10000).  KernelSU's setuid_hook sets that flag only
 * when SUSFS integration is compiled into the kernel, and this device's kernel has none (zero susfs
 * symbols in kallsyms) - so uid >= 10000 is the available proxy, the same one sus_path uses.
 * Without it the spoofing is visible to root too, wider than upstream.  Writers (supercall, /proc)
 * are configuration and stay ungated. */
static bool susfs_kstat_gate_ok(void)
{
	return current_uid().val >= 10000;
}

/* ---- table access ----
 * The *_table_* helpers are the ONLY places that modify kstat_entries or nkstat, each under
 * kstat_table_lock; their callers hold kstat_lock, making the index they pass stable. */

/* Cheapest possible gate for the READ paths: with nothing registered no lookup can match, which on
 * the sys_exit tracepoint saves the two copy_from_user() reads the spoofers do before matching, and
 * on the show_map_vma kprobe (still armed after a `clear`) saves an uncontended spinlock per VMA.
 * READ_ONCE is enough: nkstat is published only AFTER the entry it counts has been written, under
 * kstat_table_lock (kstat_table_append stores the entry, then bumps the count), so a stale non-zero
 * value only means work we used to do and a stale zero can cost at most the single read racing the
 * very first add; the authoritative test is the locked lookup.
 * sus_path uses the same idiom (READ_ONCE(sus_path_count)). */
static bool susfs_kstat_table_empty(void)
{
	return READ_ONCE(nkstat) == 0;
}

/* Hot-path lookup: match (ino, dev) and copy the entry out atomically w.r.t. the writers. */
static bool susfs_kstat_lookup(unsigned long ino, dev_t dev,
			       struct sus_kstat_snapshot *out)
{
	unsigned long flags;
	bool found = false;
	int i;

	spin_lock_irqsave(&kstat_table_lock, flags);
	for (i = 0; i < nkstat; i++) {
		if (kstat_entries[i].target_ino == ino &&
		    kstat_entries[i].target_dev == dev) {
			kstat_snapshot(&kstat_entries[i], out);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
	return found;
}

/* Writer-side lookup by path: safe without the spinlock, since every caller holds kstat_lock. */
static struct sus_kstat_entry *susfs_kstat_find_by_path(const char *path)
{
	int i;

	for (i = 0; i < nkstat; i++)
		if (!strcmp(kstat_entries[i].target_pathname, path))
			return &kstat_entries[i];
	return NULL;
}

/* Append a fully-prepared entry; -ENOSPC when the table is full. */
static int kstat_table_append(const struct sus_kstat_entry *src)
{
	unsigned long flags;
	int idx = -1;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (nkstat < SUS_KSTAT_MAX) {
		idx = nkstat;
		kstat_entries[idx] = *src;
		nkstat = idx + 1;
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
	return idx;
}

/* Replace a live entry wholesale: the reader sees old or new, never a mix of the two. */
static void kstat_table_put(int idx, const struct sus_kstat_entry *src)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (idx >= 0 && idx < nkstat)
		kstat_entries[idx] = *src;
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

/* Re-target an entry, and optionally raise its flags. */
static void kstat_table_retarget(int idx, unsigned long ino, dev_t dev,
				 unsigned int add_flags)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (idx >= 0 && idx < nkstat) {
		kstat_entries[idx].target_ino = ino;
		kstat_entries[idx].target_dev = dev;
		kstat_entries[idx].flags |= add_flags;
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

/* Remove by index: move the last entry into the hole, under the lock so a reader never sees that move half-done. */
static void kstat_table_del(int idx)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	if (idx >= 0 && idx < nkstat) {
		nkstat--;
		if (idx != nkstat)
			kstat_entries[idx] = kstat_entries[nkstat];
	}
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

static void kstat_table_clear(void)
{
	unsigned long flags;

	spin_lock_irqsave(&kstat_table_lock, flags);
	nkstat = 0;
	spin_unlock_irqrestore(&kstat_table_lock, flags);
}

/* ---- /proc/<pid>/maps coverage ----
 *
 * Upstream's susfs_sus_kstat_spoof_show_map_vma() rewrites dev/ino inside show_map_vma(), where
 * both are still locals, i.e. unreachable from an LKM - and re-printing the line would mean
 * reproducing the kernel's column padding (seq_setwidth()/seq_pad() are not exported, m->pad_until
 * is private state), while a line padded differently from its neighbours is itself a tell.  So the
 * already-formatted line is edited at the return of the function that printed it: the "maj:min ino"
 * run is located by rendering the REAL values the way fs/proc/task_mmu.c does (seq_put_hex_ll for
 * major/minor - lowercase, minimum width 2 - and seq_put_decimal_ull for the ino) and replaced by
 * the spoofed ones.  An earlier version DROPPED the whole line: that closed the stat-vs-maps
 * contradiction but changed the line count (a mapping listed for every process except this one is
 * its own signal) and left smaps unfiltered anyway, its header coming from another call site.
 *
 * The spoofed dev is stored as userspace sees st_dev (new_encode_dev), so it is decoded with
 * new_decode_dev(), the kernel's own inverse, before being printed in the maj:min column; upstream
 * substitutes target_dev into the RAW dev local instead, printing "0:fe4b" for a file whose stat()
 * says 254:75.  Armed on the first rule that spoofs ino or dev. */

/* Same buffer edit as the maps name/numbers rewrite in susfs_open_redirect.c: replace the first
 * occurrence of old[] with new[], growing only when the buffer has room. */
static bool kstat_buf_replace(struct seq_file *m, const char *old, size_t old_len,
			      const char *new, size_t new_len)
{
	char *buf = m->buf;
	size_t count = m->count, i, pos = 0;

	if (!old_len || !new_len || old_len > count)
		return false;
	for (i = 0; i + old_len <= count; i++) {
		if (!memcmp(buf + i, old, old_len)) {
			pos = i;
			break;
		}
	}
	if (i + old_len > count)
		return false;
	if (new_len > old_len && count + (new_len - old_len) >= m->size)
		return false;
	if (new_len != old_len)
		memmove(buf + pos + new_len, buf + pos + old_len, count - (pos + old_len));
	memcpy(buf + pos, new, new_len);
	m->count = count - old_len + new_len;
	return true;
}

struct kstat_map_args {
	struct seq_file *m;
	struct vm_area_struct *vma;
};

static atomic_t n_kstat_map_hits = ATOMIC_INIT(0);
static atomic_t n_kstat_map_rewrites = ATOMIC_INIT(0);

static int kstat_map_vma_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kstat_map_args *a = (struct kstat_map_args *)ri->data;

	a->m = (struct seq_file *)regs->regs[0];
	a->vma = (struct vm_area_struct *)regs->regs[1];
	return 0;
}

static int kstat_map_vma_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	const struct kstat_map_args *a = (const struct kstat_map_args *)ri->data;
	struct seq_file *m = a->m;
	struct vm_area_struct *vma = a->vma;
	struct sus_kstat_snapshot snap;
	struct inode *inode;
	char old[48], new[48];
	unsigned int major, minor;
	int old_len, new_len;

	if (susfs_kstat_table_empty())
		return 0;
	if (!susfs_ptr_plausible(m) || !susfs_ptr_plausible(vma) ||
	    !m->buf || !m->count || !vma->vm_file)
		return 0;
	inode = file_inode(vma->vm_file);
	if (!inode)
		return 0;
	if (!susfs_kstat_gate_ok())
		return 0;
	if (!susfs_kstat_lookup(inode->i_ino,
				new_encode_dev(inode->i_sb->s_dev), &snap))
		return 0;
	if (!(snap.flags & (KSTAT_SPOOF_INO | KSTAT_SPOOF_DEV)))
		return 0;

	atomic_inc(&n_kstat_map_hits);

	/* What the kernel just printed is MAJOR()/MINOR() of the RAW s_dev. */
	old_len = scnprintf(old, sizeof(old), "%02x:%02x %lu",
			    (unsigned int)MAJOR(inode->i_sb->s_dev),
			    (unsigned int)MINOR(inode->i_sb->s_dev),
			    (unsigned long)inode->i_ino);

	if (snap.flags & KSTAT_SPOOF_DEV) {
		unsigned int enc = (unsigned int)snap.spoofed_dev;

		/* new_decode_dev(): the inverse of what cp_new_stat() encoded, so a file whose stat() says 254:75 prints "fe:4b" here too. */
		major = (enc & 0xfff00u) >> 8;
		minor = (enc & 0xffu) | ((enc >> 12) & 0xfff00u);
	} else {
		major = (unsigned int)MAJOR(inode->i_sb->s_dev);
		minor = (unsigned int)MINOR(inode->i_sb->s_dev);
	}
	new_len = scnprintf(new, sizeof(new), "%02x:%02x %lu", major, minor,
			    (snap.flags & KSTAT_SPOOF_INO)
				    ? snap.spoofed_ino
				    : (unsigned long)inode->i_ino);

	/* Keep the column width, space-padding the run: a SHORTER run would pull the name left by the
	 * difference and a line whose name does not line up with its neighbours is visible on its own.
	 * A LONGER run does shift it - the rare case (a spoofed ino with more digits than the real one). */
	while (new_len < old_len && new_len < (int)sizeof(new) - 1)
		new[new_len++] = ' ';

	if (old_len > 0 && new_len > 0 &&
	    kstat_buf_replace(m, old, (size_t)old_len, new, (size_t)new_len))
		atomic_inc(&n_kstat_map_rewrites);
	return 0;
}

static struct kretprobe krp_kstat_map_vma = {
	.kp.symbol_name = "show_map_vma",
	.entry_handler = kstat_map_vma_entry,
	.handler = kstat_map_vma_ret,
	.data_size = sizeof(struct kstat_map_args),
	.maxactive = 16,
};

static bool kstat_maps_registered;

/* Registering sleeps, so this runs from the rule-management paths (kstat_lock held, process context). */
static void kstat_maps_arm(void)
{
	int rc;

	if (kstat_maps_registered)
		return;
	rc = register_kretprobe(&krp_kstat_map_vma);
	if (rc)
		pr_warn("susfs_kstat: register_kretprobe(show_map_vma) failed %d - maps keeps printing the real dev:ino\n",
			rc);
	else {
		kstat_maps_registered = true;
		SUSFS_LOGI("susfs_kstat: maps hook armed (kretprobe show_map_vma)\n");
	}
}

static void kstat_maps_disarm(void)
{
	if (!kstat_maps_registered)
		return;
	unregister_kretprobe(&krp_kstat_map_vma);
	kstat_maps_registered = false;
}

/* ---- per-syscall observability ----
 *
 * Every whitelisted number gets its own line of counters, and every early-out is counted with the
 * reason it happened.  "The rule is registered" and "the rule was reached" are different claims -
 * a false "the feature is broken" report was already produced once by reading a counter that could
 * not fire - so the numbers below are what turns "it did not work" into one of: not this number,
 * the buffer was NULL, no rule, gate (not an app), the lookup did not match, or a uaccess fault.
 *
 * The increments sit INSIDE the per-number handlers, i.e. after the whitelist test: an ordinary
 * syscall (getpid, read, ...) never reaches them - it pays the (now unconditional) number compare
 * and nothing else.  atomic_t on purpose: several CPUs run the tracepoint at once, and the cost is
 * a per-cpu add on a line only this layer writes. */
struct kstat_call_counters {
	atomic_t calls;		/* this number returned 0: it reached the statbuf code */
	atomic_t ret_err;	/* this number returned -errno */
	atomic_t no_buf;	/* statbuf argument was NULL */
	atomic_t rewrite;	/* the buffer really changed */
	atomic_t miss_empty;	/* no rule registered at all */
	atomic_t miss_gate;	/* gate: uid < 10000 (not an app) */
	atomic_t miss_lookup;	/* the (ino,dev) key matched no rule */
	atomic_t match_noflag;	/* matched, but this buffer has no field we impersonate */
	atomic_t uaccess;	/* copy_from_user/copy_to_user failed */
};

#define KSTAT_COUNTERS(nm)						\
	static struct kstat_call_counters cnt_##nm = {			\
		.calls = ATOMIC_INIT(0), .ret_err = ATOMIC_INIT(0),	\
		.no_buf = ATOMIC_INIT(0), .rewrite = ATOMIC_INIT(0),	\
		.miss_empty = ATOMIC_INIT(0), .miss_gate = ATOMIC_INIT(0),\
		.miss_lookup = ATOMIC_INIT(0), .match_noflag = ATOMIC_INIT(0),\
		.uaccess = ATOMIC_INIT(0),				\
	}

/* One instance per whitelisted number.  nfstatat = native newfstatat(79), nfstat = native
 * fstat(80), statx = native statx(291); the AArch32 five are fstatat64(327), stat64(195),
 * lstat64(196) and fstat64(197) plus the struct compat_stat family that is NOT wired yet - see the
 * note above STAT64_ST_*: those three numbers get a counter line of their own from the moment they
 * are handled, and until then they are reported by "unlisted-nr" if they are ever issued. */
KSTAT_COUNTERS(nfstatat);
KSTAT_COUNTERS(nfstat);
KSTAT_COUNTERS(statx);
KSTAT_COUNTERS(fstatat64);
KSTAT_COUNTERS(stat64);
KSTAT_COUNTERS(lstat64);
KSTAT_COUNTERS(fstat64);
/* A stat-family syscall the whitelist does NOT carry: counted, with the last few numbers kept, so
 * "a stat call was made and nothing happened" is answerable.  The number list cannot be derived
 * from our own header (asm/unistd.h is unreachable here), which is why it is worth reporting what
 * actually arrived rather than trusting the table.
 *
 * What "looks like one of ours" means, given that the syscall number is all this handler has:
 * the AArch32 numbers and the native ones are in two different ranges, and the three whitelisted
 * native numbers span a small window, so the test below is deliberately narrow - 106..600, the
 * band that holds __NR_fstat/__NR_newfstatat/__NR_statx and every AArch32 number.  It costs one
 * compare on the stat-family calls that are NOT whitelisted and nothing at all on ordinary
 * syscalls (the compare sits after the whitelist switch, not before it). */
#define KSTAT_NR_SCAN_LO	106
#define KSTAT_NR_SCAN_HI	600
#define KSTAT_UNLISTED_SEEN	8

static atomic_t n_kstat_unlisted = ATOMIC_INIT(0);
static atomic_t kstat_unlisted_next = ATOMIC_INIT(0);
static long kstat_unlisted_seen[KSTAT_UNLISTED_SEEN];

static void kstat_note_unlisted(long nr)
{
	int slot;

	atomic_inc(&n_kstat_unlisted);
	slot = atomic_inc_return(&kstat_unlisted_next) - 1;
	kstat_unlisted_seen[slot % KSTAT_UNLISTED_SEEN] = nr;
}

/* The whitelist table itself (kstat_nr_table) is defined further down, after the syscall-number
 * constants it is built from: __NR_* come from the uapi headers, but the AArch32 numbers are
 * spelled out in this file next to the struct stat64 layout they belong to, so the table has to
 * come after them or it would reference names that do not exist yet.  Its /proc report and this
 * file's dispatcher both read it, which is what keeps the two from drifting apart. */

/* Rewrite the requested fields of the native user statbuf.  Returns true when the buffer was
 * really changed, so the caller can count "matched" from "rewrote". */
static bool susfs_kstat_spoof_statbuf(struct kstat_call_state *st, unsigned long statbuf)
{
	/* Snapshot, not a pointer into the table: a concurrent writer must not be able to retarget the
	 * entry between the match and the copy_to_user below, which must not run under a spinlock. */
	struct sus_kstat_snapshot snap;
	const struct sus_kstat_snapshot *e = &snap;
	unsigned long ino = 0, dev = 0;
	unsigned long v;
	unsigned int v32;
	long long v64;
	long sl;
	bool rewrote = false;

	if (susfs_kstat_table_empty()) {
		atomic_inc(&st->cnt->miss_empty);
		return false;
	}
	if (!susfs_kstat_gate_ok()) {
		atomic_inc(&st->cnt->miss_gate);
		return false;
	}

	if (copy_from_user(&ino, (void __user *)(statbuf + ST_INO_OFF), sizeof(ino))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}
	if (copy_from_user(&dev, (void __user *)(statbuf + ST_DEV_OFF), sizeof(dev))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}

	if (!susfs_kstat_lookup(ino, dev, &snap)) {
		atomic_inc(&st->cnt->miss_lookup);
		return false;
	}

	if (e->flags & KSTAT_SPOOF_INO) {
		v = e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + ST_INO_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_DEV) {
		v = e->spoofed_dev;
		if (copy_to_user((void __user *)(statbuf + ST_DEV_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_NLINK) {
		v32 = e->spoofed_nlink;
		if (copy_to_user((void __user *)(statbuf + ST_NLINK_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_SIZE) {
		v64 = e->spoofed_size;
		if (copy_to_user((void __user *)(statbuf + ST_SIZE_OFF), &v64, sizeof(v64))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_BLKSIZE) {
		v32 = (unsigned int)e->spoofed_blksize;
		if (copy_to_user((void __user *)(statbuf + ST_BLKSIZE_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_BLOCKS) {
		v64 = e->spoofed_blocks;
		if (copy_to_user((void __user *)(statbuf + ST_BLOCKS_OFF), &v64, sizeof(v64))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC) {
		sl = e->spoofed_atime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + ST_ATIME_OFF), &sl, sizeof(sl))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC) {
		v = e->spoofed_atime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + ST_ATIME_NSEC_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC) {
		sl = e->spoofed_mtime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + ST_MTIME_OFF), &sl, sizeof(sl))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC) {
		v = e->spoofed_mtime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + ST_MTIME_NSEC_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC) {
		sl = e->spoofed_ctime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + ST_CTIME_OFF), &sl, sizeof(sl))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC) {
		v = e->spoofed_ctime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + ST_CTIME_NSEC_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}

	if (!rewrote)
		atomic_inc(&st->cnt->match_noflag);
	else
		atomic_inc(&st->cnt->rewrite);
	return rewrote;
}

/* AArch32 (compat) statbuf layouts.  There are TWO, and which one a syscall fills is decided by
 * its NUMBER, not by the caller being 32-bit:
 *   __NR_stat64 195, __NR_lstat64 196, __NR_fstat64 197, __NR_fstatat64 327 -> struct stat64
 *       (arch/arm64/include/asm/stat.h), filled by cp_new_stat64() via SYSCALL_DEFINE2(stat64)/
 *       (lstat64)/(fstat64) and SYSCALL_DEFINE4(fstatat64) (fs/stat.c, __ARCH_WANT_COMPAT_STAT64);
 *       this struct is NOT struct compat_stat.  All four are handled below (the first three keep
 *       statbuf in args[1], fstatat64 in args[2]).
 *   __NR_stat 106, __NR_lstat 107, __NR_fstat 108 -> struct compat_stat
 *       (arch/arm64/include/asm/compat.h) via cp_compat_stat().  They ARE mapped in this tree's
 *       arch/arm64/include/asm/unistd32.h (checked: 106 -> compat_sys_newstat, 107 -> newlstat,
 *       108 -> newfstat).  They are listed so nobody concludes "compat = compat_stat" and wires the
 *       wrong offsets - which is what this code used to do: st_ino was read at +4, the HIGH half of
 *       st_dev in stat64 and always 0, so the lookup could never match (a match would have written
 *       into st_dev/st_rdev).  Wiring them needs their own offset table (st_dev+0, st_ino+4,
 *       st_nlink+10, st_size+20, st_blksize+24, st_blocks+28, atime+32/36, mtime+40/44,
 *       ctime+48/52), which is a third layout rather than a copy of the one below - deliberately
 *       left as its own change.  Until then a 32-bit caller using stat()/lstat()/fstat() (the
 *       numbers 106/107/108) is answered with the real numbers, and the per-number counter block
 *       says so: those three appear as "unlisted-nr" hits if they are ever issued, the same way the
 *       deleted vfs_getattr fallback reported a path it could not cover.
 *
 * ALIGNMENT (these numbers were established twice): compat_u64/compat_s64 are
 * __attribute__((aligned(4))) only when CONFIG_COMPAT_FOR_U64_ALIGNMENT is set
 * (include/asm-generic/compat.h), and only the 32-bit arm architecture selects it - so on this
 * arm64 kernel the plain `typedef s64 compat_s64;` applies, u64 members keep natural 8-byte
 * alignment, and st_size is at +48 (not +44), st_ino at +96 (not +88).  A 4-byte-aligned read is
 * not a silent near-miss - measured on device with tools/susfs_compat_stat, a 6-byte file reported
 * size=25769803776 = 6 << 32 (low half from padding, high half from the value).  The offsets below
 * are what that client and the kernel agree on. */
#define STAT64_ST_DEV_OFF       0	/* compat_u64 */
#define STAT64_ST_BROKEN_INO_OFF 12	/* compat_ulong_t __st_ino (one of the two ino fields) */
#define STAT64_ST_NLINK_OFF     20	/* compat_uint_t */
#define STAT64_ST_SIZE_OFF      48	/* compat_s64 */
#define STAT64_ST_BLKSIZE_OFF   56	/* compat_ulong_t */
#define STAT64_ST_BLOCKS_OFF    64	/* compat_u64 */
#define STAT64_ST_ATIME_OFF     72
#define STAT64_ST_ATIME_NSEC_OFF 76
#define STAT64_ST_MTIME_OFF     80
#define STAT64_ST_MTIME_NSEC_OFF 84
#define STAT64_ST_CTIME_OFF     88
#define STAT64_ST_CTIME_NSEC_OFF 92
#define STAT64_ST_INO_OFF       96	/* compat_u64 st_ino (also written; the KEY is read from +12) */
#define STAT64_ST_SIZE          104

/* ARM EABI syscall numbers that fill struct stat64 (arch/arm64/include/asm/unistd32.h; the
 * statbuf argument position is from fs/stat.c's COMPAT_SYSCALL_DEFINE2/4). */
#define COMPAT_FSTATAT64_NR	327	/* fstatat64(dfd, path, statbuf, flag) */
#define COMPAT_STAT64_NR	195	/* stat64(path, statbuf) */
#define COMPAT_LSTAT64_NR	196	/* lstat64(path, statbuf) */
#define COMPAT_FSTAT64_NR	197	/* fstat64(fd, statbuf) */

/* The listing (getdents) numbers sus_path's rewrite answers for.  Spelled out rather than taken
 * from asm/unistd.h, which is unreachable in this build: native getdents64 is 61
 * (include/uapi/asm-generic/unistd.h), and the AArch32 table (arch/arm64/include/asm/unistd32.h)
 * maps 217 to the SAME native body while 141 is its own compat body.  Kept here next to the
 * dispatcher that tests them, in the file that owns the tracepoint. */
#define KSTAT_NR_GETDENTS64	61
#define COMPAT_GETDENTS64_NR	217
#define COMPAT_GETDENTS_NR	141

/* ---- the whitelist as data ----
 *
 * Defined here, after the numbers above: it is built from the same constants the dispatcher
 * compares against, so a number cannot be handled by one and missing from the other, and /proc's
 * report reads this one list. */
struct kstat_nr_entry {
	long nr;
	const char *name;
	struct kstat_call_counters *cnt;
};

static struct kstat_nr_entry kstat_nr_table[] = {
	{ __NR_newfstatat, "newfstatat", &cnt_nfstatat },
	{ __NR_fstat,      "fstat",      &cnt_nfstat },
	{ __NR_statx,      "statx",      &cnt_statx },
	{ COMPAT_FSTATAT64_NR, "fstatat64/compat", &cnt_fstatat64 },
	{ COMPAT_STAT64_NR,    "stat64/compat",    &cnt_stat64 },
	{ COMPAT_LSTAT64_NR,   "lstat64/compat",   &cnt_lstat64 },
	{ COMPAT_FSTAT64_NR,   "fstat64/compat",   &cnt_fstat64 },
};

/* The dispatch state for one call.  Passed by pointer into the helpers so a call site never
 * repeats the counter bookkeeping, and typed counters cannot be wired to the wrong line.
 * `compat` is the one thing a helper cannot work out from its counter set: on a 32-bit task the
 * user buffer is a zero-extended u32 and has to go through compat_ptr() first. */
struct kstat_call_state {
	struct kstat_call_counters *cnt;
	bool compat;
};

/* compat (32-bit) statbuf: struct stat64 (see above) - the layout both handled syscalls use. */
static bool susfs_kstat_spoof_compat_statbuf(struct kstat_call_state *st, unsigned long statbuf)
{
	struct sus_kstat_snapshot snap;
	const struct sus_kstat_snapshot *e = &snap;
	unsigned long long v64;
	unsigned int ino = 0, dev = 0;
	unsigned int v32;
	int v;
	bool rewrote = false;

	if (susfs_kstat_table_empty()) {
		atomic_inc(&st->cnt->miss_empty);
		return false;
	}
	if (!susfs_kstat_gate_ok()) {
		atomic_inc(&st->cnt->miss_gate);
		return false;
	}

	/* Key lookup on what the kernel ACTUALLY filled: __st_ino at +12.  stat64 carries the
	 * STAT64_HAS_BROKEN_ST_INO marker (arch/arm64/include/asm/stat.h), so cp_new_stat64() writes
	 * __st_ino and leaves st_ino (+96) alone - reading the key from +96 would compare against
	 * whatever the caller's buffer held and never match.  Both fields are written when spoofing, so
	 * a libc that synthesises st_ino from __st_ino and one that reads st_ino directly both see the
	 * spoofed value. */
	if (copy_from_user(&ino, (void __user *)(statbuf + STAT64_ST_BROKEN_INO_OFF), sizeof(ino))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}
	if (copy_from_user(&dev, (void __user *)(statbuf + STAT64_ST_DEV_OFF), sizeof(dev))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}
	if (!susfs_kstat_lookup(ino, dev, &snap)) {
		atomic_inc(&st->cnt->miss_lookup);
		return false;
	}

	if (e->flags & KSTAT_SPOOF_INO) {
		v32 = (unsigned int)e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_BROKEN_INO_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		v64 = (unsigned long long)e->spoofed_ino;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_INO_OFF), &v64, sizeof(v64))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_DEV) {
		v64 = (unsigned long long)e->spoofed_dev;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_DEV_OFF), &v64, sizeof(v64))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_NLINK) {
		v32 = (unsigned int)e->spoofed_nlink;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_NLINK_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_SIZE) {
		v64 = (unsigned long long)e->spoofed_size;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_SIZE_OFF), &v64, sizeof(v64))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_BLKSIZE) {
		v32 = (unsigned int)e->spoofed_blksize;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_BLKSIZE_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_BLOCKS) {
		v64 = (unsigned long long)e->spoofed_blocks;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_BLOCKS_OFF), &v64, sizeof(v64))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC) {
		v = (int)e->spoofed_atime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_ATIME_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_atime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_ATIME_NSEC_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC) {
		v = (int)e->spoofed_mtime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_MTIME_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_mtime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_MTIME_NSEC_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC) {
		v = (int)e->spoofed_ctime_tv_sec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_CTIME_OFF), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC) {
		v32 = (unsigned int)e->spoofed_ctime_tv_nsec;
		if (copy_to_user((void __user *)(statbuf + STAT64_ST_CTIME_NSEC_OFF), &v32, sizeof(v32))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}

	if (!rewrote)
		atomic_inc(&st->cnt->match_noflag);
	else
		atomic_inc(&st->cnt->rewrite);
	return rewrote;
}

/* ---- statx(2): a different struct, and a MASK contract ----
 *
 * struct statx (include/uapi/linux/stat.h) is not struct stat and not struct stat64: the offsets
 * come from offsetof() rather than being spelled out, because a wrong offset here corrupts the
 * caller's buffer instead of failing - and the static_asserts below make such a change a build
 * failure.  Note stx_mnt_id sits BEFORE stx_dio_mem_align, so the fields this module impersonates
 * are all in the first 0x40 bytes.
 *
 * THE MASK IS PART OF THE ANSWER, not decoration: cp_statx() (fs/stat.c) records in the buffer's
 * stx_mask what the kernel actually put there, and the caller's mask says what it asked for.  So
 * this rewriter (a) computes the mask it acts under as the caller's request mask OR the buffer's
 * stx_mask - the effective mask - and (b) writes a field only when that mask carries it, so a
 * spoofed stx_ino is never accompanied by a mask bit that says stx_ino carries nothing.  It never
 * LOWERS a mask bit; it does not need to raise one either, which is worth being precise about:
 * vfs_getattr_nosec() unconditionally sets stat->result_mask |= STATX_BASIC_STATS (fs/stat.c:100)
 * on this kernel, so the buffer's mask already carries every field this module impersonates.
 *
 * Two fields are the exception, and the code says so where it writes them:
 *   stx_blksize - filled by cp_statx() from stat->blksize, but covered by no mask bit on a kernel
 *                 this old (STATX_BLKSIZE arrived later than the stx_mask contract), so gating it
 *                 on a bit would mean never spoofing it;
 *   stx_dev_major/minor - also always filled (cp_statx() copies MAJOR/MINOR(stat->dev) with no
 *                 mask participation, unlike struct stat where st_dev has a field of its own), and
 *                 so they are gated on the rule's DEV flag plus the effective mask naming the
 *                 basic pair, not on a bit that does not exist.
 * The mask bits below are the UAPI ones: the kernel's internal KSTAT_* mask (include/linux/stat.h)
 * is translated by cp_statx() before it reaches the user buffer, and on this kernel STATX_INO ==
 * KSTAT_ATTR_INO etc. numerically - using the UAPI names keeps that a property of the header, not
 * of this file.
 *
 * What the caller can see: a statx() whose mask lists a field the buffer does not carry is the
 * documented failure mode, and that is exactly what a detector would look for.  A field the caller
 * did not request is left with the REAL value the kernel wrote (the kernel wrote it because it
 * always does), not with a spoofed one - so "no mask, real value" stays consistent.
 *
 * The four STATX_F_* names below are just names for the UAPI bits that gate each field, so a write
 * site reads as "this field, under its own bit" without the bit's spelling repeated. */
#define STATX_F_INO		STATX_INO
#define STATX_F_NLINK		STATX_NLINK
#define STATX_F_SIZE		STATX_SIZE
#define STATX_F_BLOCKS		STATX_BLOCKS

struct susfs_statx_offs {
	unsigned short dev, ino, nlink, size, blksize, blocks;
	unsigned short atime_sec, atime_nsec, mtime_sec, mtime_nsec,
		       ctime_sec, ctime_nsec, mask;
};

static const struct susfs_statx_offs kstat_statx_offs = {
	.dev = offsetof(struct statx, stx_dev_major),
	.ino = offsetof(struct statx, stx_ino),
	.nlink = offsetof(struct statx, stx_nlink),
	.size = offsetof(struct statx, stx_size),
	.blksize = offsetof(struct statx, stx_blksize),
	.blocks = offsetof(struct statx, stx_blocks),
	.atime_sec = offsetof(struct statx, stx_atime),
	.atime_nsec = offsetof(struct statx, stx_atime) + offsetof(struct timespec64, tv_nsec),
	.mtime_sec = offsetof(struct statx, stx_mtime),
	.mtime_nsec = offsetof(struct statx, stx_mtime) + offsetof(struct timespec64, tv_nsec),
	.ctime_sec = offsetof(struct statx, stx_ctime),
	.ctime_nsec = offsetof(struct statx, stx_ctime) + offsetof(struct timespec64, tv_nsec),
	.mask = offsetof(struct statx, stx_mask),
};

/* A wrong offset here is the whole failure mode: an assert per field, not one for the struct.
 * The numbers were confirmed against the real layout twice - once by these asserts in CI, and once
 * by a host-side copy of the same structs (dist/statx_offs.c, not part of the build), because a
 * wrong offset CORRUPTS the caller's buffer instead of failing anything. */
static_assert(offsetof(struct statx, stx_mask) == 0x00, "statx.stx_mask");
static_assert(offsetof(struct statx, stx_blksize) == 0x04, "statx.stx_blksize");
static_assert(offsetof(struct statx, stx_attributes) == 0x08, "statx.stx_attributes");
static_assert(offsetof(struct statx, stx_nlink) == 0x10, "statx.stx_nlink");
static_assert(offsetof(struct statx, stx_ino) == 0x20, "statx.stx_ino");
static_assert(offsetof(struct statx, stx_size) == 0x28, "statx.stx_size");
static_assert(offsetof(struct statx, stx_blocks) == 0x30, "statx.stx_blocks");
static_assert(offsetof(struct statx, stx_atime) == 0x40, "statx.stx_atime");
static_assert(offsetof(struct statx, stx_btime) == 0x50, "statx.stx_btime");
static_assert(offsetof(struct statx, stx_ctime) == 0x60, "statx.stx_ctime");
static_assert(offsetof(struct statx, stx_mtime) == 0x70, "statx.stx_mtime");
/* stx_dev_major/stx_dev_minor hold MAJOR()/MINOR() of the real dev_t, while the rule stores the
 * userspace new_encode_dev() value the stat buffer shows - so both halves are derived from that
 * encoding (see the write site).  Note they sit at 0x88, before stx_mnt_id, NOT after it: the
 * struct's tail is a sparse area, and an earlier revision of this table had them 8 bytes late. */
static_assert(offsetof(struct statx, stx_dev_major) == 0x88, "statx.stx_dev_major");
static_assert(offsetof(struct statx, stx_dev_minor) == 0x8c, "statx.stx_dev_minor");
static_assert(offsetof(struct statx, stx_mnt_id) == 0x90, "statx.stx_mnt_id");
static_assert(sizeof(struct statx) == 256, "statx size");
static_assert(sizeof(((struct statx *)0)->stx_ino) == 8, "statx stx_ino is u64");
static_assert(sizeof(((struct statx *)0)->stx_size) == 8, "statx stx_size is u64");

/* Read a field of the buffer, write the spoofed value back only when the mask carries the field. */
#define STATX_FIELD_U64(off, val, mbit)						\
	do {									\
		if (eff & (mbit)) {						\
			u64 __v = (u64)(val);					\
										\
			if (copy_to_user((void __user *)(sbuf + (off)), &__v,	\
					 sizeof(__v))) {			\
				atomic_inc(&st->cnt->uaccess);			\
				return false;					\
			}							\
			rewrote = true;						\
		}								\
	} while (0)

#define STATX_FIELD_S32(off, val, mbit)						\
	do {									\
		if (eff & (mbit)) {						\
			s32 __v = (s32)(val);					\
			u32 __u = (u32)__v;					\
										\
			if (copy_to_user((void __user *)(sbuf + (off)), &__u,	\
					 sizeof(__u))) {			\
				atomic_inc(&st->cnt->uaccess);			\
				return false;					\
			}							\
			rewrote = true;						\
		}								\
	} while (0)

#define STATX_FIELD_U32(off, val, mbit)						\
	do {									\
		if (eff & (mbit)) {						\
			u32 __v = (u32)(val);					\
										\
			if (copy_to_user((void __user *)(sbuf + (off)), &__v,	\
					 sizeof(__v))) {			\
				atomic_inc(&st->cnt->uaccess);			\
				return false;					\
			}							\
			rewrote = true;						\
		}								\
	} while (0)

/* returns true when the buffer was really changed */
static bool susfs_kstat_spoof_statx(struct kstat_call_state *st, unsigned long sbuf,
				    u32 req_mask)
{
	const struct susfs_statx_offs *o = &kstat_statx_offs;
	struct sus_kstat_snapshot snap;
	const struct sus_kstat_snapshot *e = &snap;
	unsigned long ino = 0;
	unsigned int dev = 0;
	u32 buf_mask = 0, eff;
	bool rewrote = false;

	if (susfs_kstat_table_empty()) {
		atomic_inc(&st->cnt->miss_empty);
		return false;
	}
	if (!susfs_kstat_gate_ok()) {
		atomic_inc(&st->cnt->miss_gate);
		return false;
	}

	/* The lookup key, taken from what cp_statx() wrote: stx_ino is u64 and stx_dev_major/minor are
	 * two halves of the encoded dev_t the rule stores. */
	if (copy_from_user(&ino, (void __user *)(sbuf + o->ino), sizeof(ino))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}
	if (copy_from_user(&dev, (void __user *)(sbuf + o->dev), sizeof(dev))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}
	if (copy_from_user(&buf_mask, (void __user *)(sbuf + o->mask), sizeof(buf_mask))) {
		atomic_inc(&st->cnt->uaccess);
		return false;
	}

	if (!susfs_kstat_lookup(ino, dev, &snap)) {
		atomic_inc(&st->cnt->miss_lookup);
		return false;
	}

	eff = req_mask | buf_mask;

	if (e->flags & KSTAT_SPOOF_INO)
		STATX_FIELD_U64(o->ino, e->spoofed_ino, STATX_F_INO);
	if (e->flags & KSTAT_SPOOF_NLINK)
		STATX_FIELD_U32(o->nlink, e->spoofed_nlink, STATX_F_NLINK);
	if (e->flags & KSTAT_SPOOF_SIZE)
		STATX_FIELD_U64(o->size, e->spoofed_size, STATX_F_SIZE);
	if (e->flags & KSTAT_SPOOF_BLOCKS)
		STATX_FIELD_U64(o->blocks, e->spoofed_blocks, STATX_F_BLOCKS);
	/* Unconditional by design - see the mask note above the offset table: no mask bit covers
	 * stx_blksize on this kernel, while cp_statx() always fills it. */
	if (e->flags & KSTAT_SPOOF_BLKSIZE) {
		s32 v = (s32)e->spoofed_blksize;

		if (copy_to_user((void __user *)(sbuf + o->blksize), &v, sizeof(v))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}
	if (e->flags & KSTAT_SPOOF_ATIME_TV_SEC)
		STATX_FIELD_S32(o->atime_sec, e->spoofed_atime_tv_sec, STATX_ATIME);
	if (e->flags & KSTAT_SPOOF_ATIME_TV_NSEC)
		STATX_FIELD_U32(o->atime_nsec, e->spoofed_atime_tv_nsec, STATX_ATIME);
	if (e->flags & KSTAT_SPOOF_MTIME_TV_SEC)
		STATX_FIELD_S32(o->mtime_sec, e->spoofed_mtime_tv_sec, STATX_MTIME);
	if (e->flags & KSTAT_SPOOF_MTIME_TV_NSEC)
		STATX_FIELD_U32(o->mtime_nsec, e->spoofed_mtime_tv_nsec, STATX_MTIME);
	if (e->flags & KSTAT_SPOOF_CTIME_TV_SEC)
		STATX_FIELD_S32(o->ctime_sec, e->spoofed_ctime_tv_sec, STATX_CTIME);
	if (e->flags & KSTAT_SPOOF_CTIME_TV_NSEC)
		STATX_FIELD_U32(o->ctime_nsec, e->spoofed_ctime_tv_nsec, STATX_CTIME);
	/* The device pair: stx_dev_major/minor are always written by cp_statx() and have no mask bit,
	 * so the condition is "the rule spoofs dev" AND "this call fills the basic set at all" - the
	 * second half is what keeps a caller that asked for nothing in particular from getting a
	 * spoofed dev out of a buffer it does not otherwise trust. */
	if ((e->flags & KSTAT_SPOOF_DEV) && (eff & STATX_BASIC_STATS)) {
		unsigned int enc = (unsigned int)e->spoofed_dev;
		/* e->spoofed_dev is new_encode_dev() (what struct stat shows); split it back into the
		 * major/minor pair this struct carries. */
		u16 maj = (u16)((enc & 0xfff00u) >> 8);
		u16 min = (u16)MINOR(new_decode_dev(enc));

		if (copy_to_user((void __user *)(sbuf + o->dev), &maj, sizeof(maj))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		if (copy_to_user((void __user *)(sbuf + o->dev + 4), &min, sizeof(min))) {
			atomic_inc(&st->cnt->uaccess);
			return false;
		}
		rewrote = true;
	}

	/* Nothing to raise: vfs_getattr_nosec() sets STATX_BASIC_STATS on this kernel, so the buffer's
	 * mask already names every field written above - and the two fields that are written without a
	 * mask bit (stx_blksize, stx_dev) have no bit to raise.  Re-writing the mask is therefore
	 * deliberately NOT done: a mask write is one more chance to corrupt the caller's buffer for no
	 * gain.  The consequence, stated plainly because it is the sort of thing a reviewer should
	 * check: this rewriter can only ever produce a buffer whose mask is the kernel's own. */
	if (!rewrote) {
		atomic_inc(&st->cnt->match_noflag);
		return false;
	}

	atomic_inc(&st->cnt->rewrite);
	return true;
}

/* ---- the ONE sys_exit tracepoint in this module ----
 *
 * It carries three things, behind a single register_trace_sys_exit(): the stat family's buffer
 * rewrite, sus_path's dirent (getdents) listing rewrite, and the per-number counters that say
 * which of the two ran on a given syscall.
 *
 * Cost and ordering.  @ret and @nr are read first, and then the number is compared against a
 * whitelist of compile-time constants (__NR_* and the AArch32 table), so the compiler emits
 * immediates and an ordinary syscall (getpid, read, ...) pays those compares and nothing else:
 * syscall_get_arguments() - six register copies - lives inside each matched branch, which is why
 * every branch reads the arguments for itself rather than sharing one call.
 *
 * Why a whitelist and not "is this a stat-ish call": there is no cheap way to ask the kernel
 * whether a number fills a stat buffer, and a range test would have to grow with every new ABI.
 * The whitelist is therefore a switch on compile-time constants and nothing else.  A number that
 * misses it is not counted - an atomic_inc on every syscall in the system is exactly the cost this
 * design avoids - with ONE narrow exception: a number inside the stat family's own range (and the
 * native getdents64) is recorded by kstat_note_unlisted(), because that is the shape of the
 * mistake this counter block exists to catch: a stat call that reached a return we did not
 * recognise and therefore did nothing for.  The compare sits after the whitelist switch, so an
 * ordinary syscall never reaches it.
 *
 * The statbuf argument is NOT the same one for every syscall, so the NULL check lives inside each
 * branch: fstat64(fd, statbuf) and fstat(fd, statbuf) keep it in args[1], and checking args[2]
 * first once made every 32-bit fstat64() return early.
 *
 * Context: a tracepoint, so it cannot sleep.  kstat's own buffer work is per-call stack state
 * plus copy_to_user (measured working from this very tracepoint); sus_path's dirent rewrite takes
 * its own spinlock around its shared scratch buffer and must not be called with one held. */
static void kstat_sys_exit(void *data, struct pt_regs *regs, long ret)
{
	unsigned long args[6];
	struct kstat_call_counters *c;
	struct kstat_call_state st;
	long nr = syscall_get_nr(current, regs);

	/* ---- sus_path's dirent (getdents) rewrite ----
	 *
	 * The listing filter used to be two kretprobes on the getdents wrappers in sus_path.c.  It
	 * rides this tracepoint now: one extra compare per syscall here against a brk trap per
	 * listing there, and no maxactive to silently drop a return under concurrency (see the block
	 * above sus_path_dirent_filter(), which owns the rewrite and its counters).  The numbers are
	 * the ones the probes watched: native getdents64 (61), AArch32 getdents64 (217 - the SAME
	 * native body) and AArch32 getdents (141, its own compat record layout). */
	if (nr == KSTAT_NR_GETDENTS64 || nr == COMPAT_GETDENTS64_NR ||
	    nr == COMPAT_GETDENTS_NR) {
		long rc;

		syscall_get_arguments(current, regs, args);
		/* getdents64(fd, buf, count) and getdents(fd, buf, count): the buffer is argument 1
		 * in all three cases.  compat_ptr() for a 32-bit task - its pointer is a
		 * zero-extended u32, and that holds for the shared native getdents64 body too. */
		rc = sus_path_dirent_filter(nr,
					    is_compat_task()
						    ? (unsigned long)compat_ptr((u32)args[1])
						    : args[1],
					    ret);
		if (rc != ret)
			syscall_set_return_value(current, regs, 0, rc);
		return;
	}

	/* ---- stat family: number -> counters -> argument positions ---- */
	switch (nr) {
	case __NR_newfstatat:
		c = &cnt_nfstatat;
		break;
	case __NR_fstat:
		/* fstat(fd, statbuf): the buffer is args[1], not args[2]. */
		c = &cnt_nfstat;
		break;
	case __NR_statx:
		c = &cnt_statx;
		break;
	case COMPAT_FSTATAT64_NR:
		c = &cnt_fstatat64;
		break;
	case COMPAT_STAT64_NR:
		c = &cnt_stat64;
		break;
	case COMPAT_LSTAT64_NR:
		c = &cnt_lstat64;
		break;
	case COMPAT_FSTAT64_NR:
		c = &cnt_fstat64;
		break;
	default:
		/* Not a whitelisted number.  Nothing is counted for an ordinary syscall (that is the
		 * whole point of the whitelist), but a number in the stat family's range is worth
		 * knowing about: it means a syscall that fills a user stat buffer reached a return we
		 * did not recognise - a wrong number in the table, or an ABI this build has not met. */
		if ((nr >= KSTAT_NR_SCAN_LO && nr <= KSTAT_NR_SCAN_HI) ||
		    nr == KSTAT_NR_GETDENTS64)
			kstat_note_unlisted(nr);
		return;
	}

	/* Whitelisted: from here on only this number's counters move. */
	if (ret != 0) {
		atomic_inc(&c->ret_err);
		return;
	}
	atomic_inc(&c->calls);

	/* The helpers take the counter set, not a bare pointer to one of its counters, so a call site
	 * cannot wire a line to the wrong struct. */
	st.cnt = c;
	st.compat = (nr == COMPAT_FSTATAT64_NR || nr == COMPAT_STAT64_NR ||
		     nr == COMPAT_LSTAT64_NR || nr == COMPAT_FSTAT64_NR);

	switch (nr) {
	case __NR_newfstatat:
		syscall_get_arguments(current, regs, args);
		if (!args[2]) {
			atomic_inc(&c->no_buf);
			return;
		}
		susfs_kstat_spoof_statbuf(&st, args[2]);
		return;
	case __NR_fstat:
		syscall_get_arguments(current, regs, args);
		if (!args[1]) {
			atomic_inc(&c->no_buf);
			return;
		}
		susfs_kstat_spoof_statbuf(&st, args[1]);
		return;
	case __NR_statx:
		/* statx(dfd, pathname, flags, mask, statxbuf): the caller's mask is args[3] and the
		 * buffer args[4], and the mask decides which fields may be written - see
		 * susfs_kstat_spoof_statx().
		 *
		 * A 32-bit caller can issue this number too (arm64's compat #293 is NOT what reaches
		 * here - the AArch32 table maps its statx to the native sys_statx), so the buffer
		 * pointer is converted the same way as everywhere else on this path. */
		syscall_get_arguments(current, regs, args);
		if (!args[4]) {
			atomic_inc(&c->no_buf);
			return;
		}
		susfs_kstat_spoof_statx(&st,
			st.compat ? (unsigned long)compat_ptr((u32)args[4]) : args[4],
			(u32)args[3]);
		return;
	case COMPAT_FSTATAT64_NR:
		/* An AArch32-only number, and the only path that CAN deliver it is a 32-bit task's
		 * syscall, so compat_ptr() is unconditional here: a compat pointer is a zero-extended
		 * u32 and must not be used as an address. */
		syscall_get_arguments(current, regs, args);
		if (!args[2]) {
			atomic_inc(&c->no_buf);
			return;
		}
		susfs_kstat_spoof_compat_statbuf(&st, (unsigned long)compat_ptr((u32)args[2]));
		return;
	case COMPAT_STAT64_NR:
	case COMPAT_LSTAT64_NR:
	case COMPAT_FSTAT64_NR:
		/* stat64/lstat64/fstat64: all three keep statbuf in args[1] and all three fill the same
		 * struct stat64 this helper expects.  AArch32-only numbers, so compat_ptr() is
		 * unconditional: a compat pointer is a zero-extended u32 and must not be used as an
		 * address. */
		syscall_get_arguments(current, regs, args);
		if (!args[1]) {
			atomic_inc(&c->no_buf);
			return;
		}
		susfs_kstat_spoof_compat_statbuf(&st, (unsigned long)compat_ptr((u32)args[1]));
		return;
	}
}

/* NO vfs_getattr kretprobe here any more, and neither is the function that used to rewrite the
 * KERNEL struct kstat for it.  Both removals are measured, not aesthetic: the whole stat chain is
 * inlined by LTO on this GKI, so the probe was hit by 15 of 120 000 app-uid newfstatat calls
 * (noise, and its gattr_spoofs counter read 0 for every one of them) while costing a brk trap per
 * call that did reach it.  fstat() and statx() are whitelisted in the tracepoint above now, so the
 * fallback had no job left: the maps rewrite below edits the already-formatted line from the same
 * snapshot and never needed the kernel-kstat rewriter.
 * The "/proc/susfs_kstat" line that printed that probe's two counters is gone with it; in its place
 * are the per-syscall-number counters of the tracepoint, which cannot stay at 0 for a syscall that
 * is really being issued (see kstat_proc_show()). */

/* ---- path resolution + rule management (original SUSFS semantics) ---- */

/* resolve <path> to its CURRENT (ino, encoded dev).  Sleeps - never call it with kstat_table_lock held. */
static int susfs_kstat_resolve(const char *path, unsigned long *ino, dev_t *dev)
{
	struct path p;
	struct inode *inode;
	int err;

	err = kern_path(path, 0, &p);
	if (err)
		return err;
	inode = d_backing_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		return -ENOENT;
	}
	*ino = inode->i_ino;
	*dev = new_encode_dev(inode->i_sb->s_dev);
	path_put(&p);
	return 0;
}

/* resolve <path> and fill the spoofed_* fields with its CURRENT stat (the generic_fillattr
 * mapping).  Fills a DETACHED entry only: callers build here, then commit through one of the
 * kstat_table_* helpers, so nothing half-built is ever visible to a reader. */
static int susfs_kstat_fill_from_path(struct sus_kstat_entry *e, const char *path)
{
	struct path p;
	struct inode *inode;
	int err;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	/* 6.6 renamed the inode field to __i_ctime and marked it private ("use inode_*_ctime
	 * accessors!"), so reading it stopped compiling: "no member named 'i_ctime' in 'struct inode'".
	 * inode_get_ctime() returns the very same struct timespec64 by value; i_atime/i_mtime were NOT
	 * renamed in 6.6, so those two keep being read directly. */
	struct timespec64 ctime;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	/* Same story for atime/mtime, one move later: v6.11 replaced the `struct timespec64
	 * i_atime/i_mtime` fields of struct inode with the split `time64_t i_atime_sec/i_mtime_sec` +
	 * `u32 i_atime_nsec/i_mtime_nsec` (in the trees built here: android16-6.12
	 * include/linux/fs.h:669-674; android15-6.6 still has the old `struct timespec64 i_atime` at
	 * :664), so those two stopped compiling the same way.  inode_get_atime()/inode_get_mtime()
	 * reassemble the very same struct timespec64 by value (fs.h:1616-1622, :1651-1657), which is
	 * what the < 6.12 branch below reads directly.  The gate is on 6.12 rather than on 6.11
	 * because 6.11 is not a GKI kernel: the trees this module is built for are 6.6 (old fields)
	 * and 6.12/6.18 (accessors), and an untested 6.7-6.11 kernel is not something this claims. */
	struct timespec64 atime, mtime;
#endif

	err = kern_path(path, 0, &p);
	if (err)
		return err;
	inode = d_backing_inode(p.dentry);
	if (!inode) {
		path_put(&p);
		return -ENOENT;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	ctime = inode_get_ctime(inode);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	atime = inode_get_atime(inode);
	mtime = inode_get_mtime(inode);
#endif

	e->target_ino = inode->i_ino;
	e->target_dev = new_encode_dev(inode->i_sb->s_dev);
	e->spoofed_ino = inode->i_ino;
	e->spoofed_dev = new_encode_dev(inode->i_sb->s_dev);
	e->spoofed_nlink = inode->i_nlink;
	e->spoofed_size = inode->i_size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	e->spoofed_atime_tv_sec = atime.tv_sec;
	e->spoofed_atime_tv_nsec = atime.tv_nsec;
	e->spoofed_mtime_tv_sec = mtime.tv_sec;
	e->spoofed_mtime_tv_nsec = mtime.tv_nsec;
#else
	e->spoofed_atime_tv_sec = inode->i_atime.tv_sec;
	e->spoofed_atime_tv_nsec = inode->i_atime.tv_nsec;
	e->spoofed_mtime_tv_sec = inode->i_mtime.tv_sec;
	e->spoofed_mtime_tv_nsec = inode->i_mtime.tv_nsec;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	e->spoofed_ctime_tv_sec = ctime.tv_sec;
	e->spoofed_ctime_tv_nsec = ctime.tv_nsec;
#else
	e->spoofed_ctime_tv_sec = inode->i_ctime.tv_sec;
	e->spoofed_ctime_tv_nsec = inode->i_ctime.tv_nsec;
#endif
	e->spoofed_blocks = inode->i_blocks;
	e->spoofed_blksize = 1 << inode->i_blkbits;

	path_put(&p);
	return 0;
}

/* re-resolve only target_ino/target_dev; spoofed values stay untouched.  Resolve first (sleeping),
 * then re-target under the lock: a reader sees the old pair or the new pair, never ino-of-B with
 * dev-of-A. */
static int susfs_kstat_update(const char *path, bool full_clone)
{
	struct sus_kstat_entry *e;
	unsigned long ino;
	dev_t dev;
	int err;

	e = susfs_kstat_find_by_path(path);
	if (!e)
		return -ENOENT;
	err = susfs_kstat_resolve(path, &ino, &dev);
	if (err)
		return err;
	kstat_table_retarget((int)(e - kstat_entries), ino, dev,
			     full_clone ? KSTAT_AUTO_SPOOF_FULL_CLONE
					: KSTAT_AUTO_SPOOF);
	return 0;
}

/* add/update a rule from its pathname; kstat_lock held */
static int susfs_kstat_add(const char *path)
{
	struct sus_kstat_entry tmp;
	struct sus_kstat_entry *e;
	int err, idx;

	if (strlen(path) >= KSTAT_PATH_MAX)
		return -ENAMETOOLONG;

	e = susfs_kstat_find_by_path(path);

	memset(&tmp, 0, sizeof(tmp));
	err = susfs_kstat_fill_from_path(&tmp, path);
	if (err)
		return err;
	strscpy(tmp.target_pathname, path, KSTAT_PATH_MAX);
	tmp.flags = KSTAT_AUTO_SPOOF;

	if (e) {
		kstat_table_put((int)(e - kstat_entries), &tmp);
		return 0;
	}
	idx = kstat_table_append(&tmp);
	return idx < 0 ? -ENOSPC : 0;
}

static void susfs_kstat_del(const char *path)
{
	struct sus_kstat_entry *e = susfs_kstat_find_by_path(path);

	if (!e)
		return;
	kstat_table_del((int)(e - kstat_entries));
}

/* parse "default" -> *is_default=true, else parse signed 64-bit int */
static int parse_override(const char *tok, bool *is_default, long long *val)
{
	if (!strcmp(tok, "default")) {
		*is_default = true;
		return 0;
	}
	*is_default = false;
	return kstrtoll(tok, 10, val);
}

/* add_sus_kstat_statically: 12 fields follow the path, each a number or "default". */
static int susfs_kstat_add_statically(char **argv, int argc)
{
	struct sus_kstat_entry tmp;
	struct sus_kstat_entry *e;
	long long val;
	bool dflt;
	int err, i, idx;
	/* field index -> flag and setter, ordered as the CLI:
	 * ino dev nlink size atime atime_nsec mtime mtime_nsec
	 * ctime ctime_nsec blocks blksize */
	static const unsigned int f_flags[12] = {
		KSTAT_SPOOF_INO, KSTAT_SPOOF_DEV, KSTAT_SPOOF_NLINK,
		KSTAT_SPOOF_SIZE, KSTAT_SPOOF_ATIME_TV_SEC,
		KSTAT_SPOOF_ATIME_TV_NSEC, KSTAT_SPOOF_MTIME_TV_SEC,
		KSTAT_SPOOF_MTIME_TV_NSEC, KSTAT_SPOOF_CTIME_TV_SEC,
		KSTAT_SPOOF_CTIME_TV_NSEC, KSTAT_SPOOF_BLOCKS,
		KSTAT_SPOOF_BLKSIZE,
	};
	const char *path = argv[1];

	if (strlen(path) >= KSTAT_PATH_MAX)
		return -ENAMETOOLONG;

	e = susfs_kstat_find_by_path(path);

	memset(&tmp, 0, sizeof(tmp));
	/* start from the CURRENT stat; non-default fields override it */
	err = susfs_kstat_fill_from_path(&tmp, path);
	if (err)
		return err;
	strscpy(tmp.target_pathname, path, KSTAT_PATH_MAX);
	tmp.flags = 0;

	for (i = 0; i < 12; i++) {
		err = parse_override(argv[2 + i], &dflt, &val);
		if (err)
			return err;
		if (dflt)
			continue;
		tmp.flags |= f_flags[i];
		switch (i) {
		case 0: tmp.spoofed_ino = (unsigned long)val; break;
		case 1: tmp.spoofed_dev = (unsigned long)val; break;
		case 2: tmp.spoofed_nlink = (unsigned int)val; break;
		case 3: tmp.spoofed_size = val; break;
		case 4: tmp.spoofed_atime_tv_sec = (long)val; break;
		case 5: tmp.spoofed_atime_tv_nsec = (unsigned long)val; break;
		case 6: tmp.spoofed_mtime_tv_sec = (long)val; break;
		case 7: tmp.spoofed_mtime_tv_nsec = (unsigned long)val; break;
		case 8: tmp.spoofed_ctime_tv_sec = (long)val; break;
		case 9: tmp.spoofed_ctime_tv_nsec = (unsigned long)val; break;
		case 10: tmp.spoofed_blocks = val; break;
		case 11: tmp.spoofed_blksize = (long)val; break;
		}
	}

	if (e) {
		kstat_table_put((int)(e - kstat_entries), &tmp);
		return 0;
	}
	idx = kstat_table_append(&tmp);
	return idx < 0 ? -ENOSPC : 0;
}

/* statically-add from the supercall ABI struct (is_statically=1): copy the caller's 12 spoofed
 * fields + flags verbatim; resolve target ino/dev here. */
static int susfs_kstat_add_statically_abi(struct st_susfs_sus_kstat *info)
{
	struct sus_kstat_entry tmp;
	struct sus_kstat_entry *e;
	int err, idx;

	e = susfs_kstat_find_by_path(info->target_pathname);

	memset(&tmp, 0, sizeof(tmp));
	err = susfs_kstat_fill_from_path(&tmp, info->target_pathname);
	if (err)
		return err;
	strscpy(tmp.target_pathname, info->target_pathname, KSTAT_PATH_MAX);

	tmp.spoofed_ino = info->spoofed_ino;
	tmp.spoofed_dev = info->spoofed_dev;
	tmp.spoofed_nlink = info->spoofed_nlink;
	tmp.spoofed_size = info->spoofed_size;
	tmp.spoofed_atime_tv_sec = info->spoofed_atime_tv_sec;
	tmp.spoofed_atime_tv_nsec = info->spoofed_atime_tv_nsec;
	tmp.spoofed_mtime_tv_sec = info->spoofed_mtime_tv_sec;
	tmp.spoofed_mtime_tv_nsec = info->spoofed_mtime_tv_nsec;
	tmp.spoofed_ctime_tv_sec = info->spoofed_ctime_tv_sec;
	tmp.spoofed_ctime_tv_nsec = info->spoofed_ctime_tv_nsec;
	tmp.spoofed_blocks = info->spoofed_blocks;
	tmp.spoofed_blksize = info->spoofed_blksize;
	tmp.flags = info->flags;

	if (e) {
		kstat_table_put((int)(e - kstat_entries), &tmp);
		return 0;
	}
	idx = kstat_table_append(&tmp);
	return idx < 0 ? -ENOSPC : 0;
}

/* supercall: CMD_SUSFS_ADD_SUS_KSTAT / UPDATE / STATICALLY */
void susfs_kstat_supercall(unsigned int cmd, void __user **arg)
{
	struct st_susfs_sus_kstat info = {0};
	int err = -EINVAL;

	if (copy_from_user(&info, (void __user *)*arg, sizeof(info))) {
		info.err = -EFAULT;
		goto out;
	}

	/* All three commands key on target_pathname, and a caller may fill all 256 bytes of that field -
	 * reject an unterminated one before any strlen() or kern_path() can walk off our stack copy. */
	if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {
		info.err = -ENAMETOOLONG;
		goto out;
	}

	mutex_lock(&kstat_lock);
	switch (cmd) {
	case CMD_SUSFS_ADD_SUS_KSTAT:
		err = susfs_kstat_add(info.target_pathname);
		break;
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		err = susfs_kstat_add_statically_abi(&info);
		break;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		err = susfs_kstat_update(info.target_pathname, false);
		break;
	}
	mutex_unlock(&kstat_lock);
	info.err = err;
	/* Armed outside the lock and only after a rule actually landed: a hook that can never fire is worse than no hook. */
	if (!err)
		kstat_maps_arm();
out:
	/* Upstream (fs/susfs.c susfs_add_sus_kstat) writes back ONLY the err field for this
	 * input-type command, never the whole struct: copying the full struct back would overrun a
	 * caller whose own struct is smaller/differently laid out (the prebuilt ksu_susfs tool) and
	 * corrupt its stack - match upstream exactly. */
	if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*arg)->err,
			 &info.err, sizeof(info.err)))
		pr_warn("kstat supercall copy_to_user failed\n");
}

/* ---- /proc/susfs_kstat: runtime rule management ---- */
static int kstat_proc_show(struct seq_file *m, void *v);
static int kstat_proc_open(struct inode *inode, struct file *file);
static ssize_t kstat_proc_write(struct file *file, const char __user *buf,
                                size_t len, loff_t *off);

static const struct proc_ops kstat_proc_ops = {
	.proc_open = kstat_proc_open,
	.proc_read = seq_read,
	.proc_write = kstat_proc_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *kstat_proc_entry;

static bool kstat_tp_registered;

int susfs_kstat_init(void)
{
	int rc;

	/* The ONE tracepoint of this module, armed UNCONDITIONALLY, and that is not cosmetic: the
	 * supercall interface (CMD_SUSFS_ADD_SUS_KSTAT) can install rules with no /proc node at all,
	 * so skipping registration when expose_proc=0 silently turned the whole feature into a no-op -
	 * rules accepted, never applied.  expose_proc decides whether the node exists, nothing else.
	 * This registration carries both features that need a syscall return: kstat's stat rewrite and
	 * sus_path's dirent rewrite, which is why the registration is not conditional on either
	 * feature's own rules. */
	rc = register_trace_sys_exit(kstat_sys_exit, NULL);
	if (rc)
		pr_warn("register_trace_sys_exit failed %d\n", rc);
	else
		kstat_tp_registered = true;

	/* 0777 is deliberate, not an oversight.  inode_permission() runs the DAC check BEFORE
	 * security_inode_permission(), so a node the app cannot open hands it EACCES - "this exists,
	 * you may not read it" - instead of the ENOENT sus_path is supposed to produce.  0777 lets DAC
	 * pass and leaves the answer to sus_path's LSM layer, which then becomes the ONLY thing
	 * between an app and a world-writable control node - so without that layer the node is not
	 * created at all, see susfs_control_node_allowed(). */
	if (susfs_control_node_allowed()) {
		kstat_proc_entry = proc_create("susfs_kstat", 0777, NULL,
					       &kstat_proc_ops);
		if (!kstat_proc_entry)
			pr_warn("proc_create(susfs_kstat) failed\n");
	} else {
		SUSFS_LOGI("susfs_kstat: /proc node not created (expose_proc=%d lsm=%d)\n",
			(int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	/* Says which mechanism carries what: this line alone answers "is the listing filter armed",
	 * now that no probe of its own exists to report. */
	SUSFS_LOGI("kstat armed: %d rules (sys_exit tp=%d proc=%d); stat rewrite + sus_path dirent rewrite ride that one tracepoint\n",
		nkstat, kstat_tp_registered, kstat_proc_entry != NULL);
	return 0;
}

void susfs_kstat_exit(void)
{
	kstat_maps_disarm();
	/* Order matters on unload: this tracepoint calls into sus_path (sus_path_dirent_filter()),
	 * and sus_path_exit() frees that layer's scratch buffer.  The layer table in susfs_main.c
	 * tears down in the reverse of its arming order, so kstat's exit runs AFTER sus_path's -
	 * the tracepoint is therefore removed only once nothing needs it.  tracepoint_synchronize_
	 * unregister() waits out any handler already running, so no call can be in flight past it. */
	if (kstat_tp_registered) {
		unregister_trace_sys_exit(kstat_sys_exit, NULL);
		tracepoint_synchronize_unregister();
		kstat_tp_registered = false;
	}
	if (kstat_proc_entry) {
		proc_remove(kstat_proc_entry);
		kstat_proc_entry = NULL;
	}
	kstat_table_clear();
}

static int kstat_proc_show(struct seq_file *m, void *v)
{
	int i;

	mutex_lock(&kstat_lock);
	if (nkstat == 0) {
		seq_puts(m, "(empty)\n");
	} else {
		for (i = 0; i < nkstat; i++) {
			struct sus_kstat_entry *e = &kstat_entries[i];

			seq_printf(m,
				"%s ino=%lu dev=%lu flags=0x%x"
				" [ino=%lu dev=%lu nlink=%u size=%lld"
				" atime=%ld.%lu mtime=%ld.%lu ctime=%ld.%lu"
				" blocks=%lld blksize=%ld]\n",
				e->target_pathname, e->target_ino,
				(unsigned long)e->target_dev, e->flags,
				e->spoofed_ino, e->spoofed_dev, e->spoofed_nlink,
				e->spoofed_size,
				e->spoofed_atime_tv_sec, e->spoofed_atime_tv_nsec,
				e->spoofed_mtime_tv_sec, e->spoofed_mtime_tv_nsec,
				e->spoofed_ctime_tv_sec, e->spoofed_ctime_tv_nsec,
				e->spoofed_blocks, e->spoofed_blksize);
		}
	}
	mutex_unlock(&kstat_lock);
	/* "armed" is not "fired": the maps hook has to be readable the same way the other feature
	 * hooks are, or a rewrite that never happens looks identical to one that works. */
	seq_printf(m, "maps: armed=%d hits=%d rewrites=%d\n",
		   kstat_maps_registered, atomic_read(&n_kstat_map_hits),
		   atomic_read(&n_kstat_map_rewrites));

	/* ---- the tracepoint's per-number counters ----
	 *
	 * One line per whitelisted syscall number.  `ok` is the number of calls that reached the
	 * rewriter (i.e. returned 0), and the reasons a call did not rewrite anything: `err` (the call
	 * returned -errno), `nobuf` (a NULL statbuf argument), `empty` (no rule registered - the
	 * expected value for an idle module), `gate` (uid < 10000, so not an app), `lookup` (no rule
	 * matched the (ino, dev) the kernel just wrote), `noflag` (a rule MATCHED but its flags have
	 * nothing to say about this buffer - e.g. add_sus_kstat, which does not spoof size/nlink, so
	 * `rw` stays 0 while `lookup` does not move), `uacc` (a uaccess fault) and `rw` (the number of
	 * calls that really changed the buffer).  A number that stays at zero through a run that
	 * issues that syscall means the number the process used is not the one this module
	 * whitelisted - which is exactly the class of mistake this block exists to catch, and which
	 * the kernel symbol table alone cannot rule out. */
	{
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(kstat_nr_table); i++) {
			struct kstat_call_counters *c = kstat_nr_table[i].cnt;

			/* Atomic reads, no lock: the printout is a snapshot, and a torn value would
			 * only mean a number read a few calls ago. */
			seq_printf(m,
				   "stat nr %-16s (%ld): ok=%d rw=%d | err=%d nobuf=%d empty=%d gate=%d lookup=%d noflag=%d uacc=%d\n",
				   kstat_nr_table[i].name, kstat_nr_table[i].nr,
				   atomic_read(&c->calls), atomic_read(&c->rewrite),
				   atomic_read(&c->ret_err), atomic_read(&c->no_buf),
				   atomic_read(&c->miss_empty), atomic_read(&c->miss_gate),
				   atomic_read(&c->miss_lookup), atomic_read(&c->match_noflag),
				   atomic_read(&c->uaccess));
		}
		seq_printf(m, "stat unlisted-nr hits=%d (stat-range numbers the dispatcher did not know: last %d seen: %ld %ld %ld %ld %ld %ld %ld %ld)\n",
			   atomic_read(&n_kstat_unlisted), (int)KSTAT_UNLISTED_SEEN,
			   kstat_unlisted_seen[0], kstat_unlisted_seen[1],
			   kstat_unlisted_seen[2], kstat_unlisted_seen[3],
			   kstat_unlisted_seen[4], kstat_unlisted_seen[5],
			   kstat_unlisted_seen[6], kstat_unlisted_seen[7]);
	}

	/* sus_path's dirent layer prints its own counters: they belong to that file, and the number
	 * comparisons live here - the two views are next to each other so "which layer ran" is one
	 * read, not two files. */
	{
		char line[512];
		int n = sus_path_dirent_stat_line(line, sizeof(line));

		if (n > 0)
			seq_write(m, line, min_t(int, n, (int)sizeof(line) - 1));
	}
	return 0;
}

static int kstat_proc_open(struct inode *inode, struct file *file)
{
	/* root-only, like kstat_proc_open() above - 0777 is deliberate (see susfs_kstat_init()) */
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, kstat_proc_show, NULL);
}

static int split_ws(char *buf, char **argv, int max)
{
	int argc = 0;
	char *p = buf;

	while (argc < max) {
		while (*p == ' ' || *p == '\t' || *p == '\n')
			p++;
		if (*p == '\0')
			break;
		argv[argc++] = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
		if (*p)
			*p++ = '\0';
	}
	return argc;
}

static ssize_t kstat_proc_write(struct file *file, const char __user *buf,
                                size_t len, loff_t *off)
{
	char cmd[768];
	char *argv[16];
	int argc, err;

	/* Same gate as kstat_proc_open(): open() alone is not enough - an fd opened by root and
	 * handed on would keep working, which is why the sibling files check both. */
	if (current_uid().val != 0)
		return -ENOENT;

	if (len >= sizeof(cmd))
		len = sizeof(cmd) - 1;
	if (copy_from_user(cmd, buf, len))
		return -EFAULT;
	cmd[len] = 0;

	argc = split_ws(cmd, argv, 16);
	if (argc == 0)
		return len;

	mutex_lock(&kstat_lock);
	err = -EINVAL;

	if (!strcmp(argv[0], "add_sus_kstat") && argc == 2)
		err = susfs_kstat_add(argv[1]);
	else if (!strcmp(argv[0], "add_sus_kstat_statically") && argc == 14)
		err = susfs_kstat_add_statically(argv, argc);
	else if (!strcmp(argv[0], "update_sus_kstat") && argc == 2)
		err = susfs_kstat_update(argv[1], false);
	else if (!strcmp(argv[0], "update_sus_kstat_full_clone") && argc == 2)
		err = susfs_kstat_update(argv[1], true);
	else if (!strcmp(argv[0], "del") && argc == 2) {
		susfs_kstat_del(argv[1]);
		err = 0;
	} else if (!strcmp(argv[0], "clear")) {
		kstat_table_clear();
		err = 0;
	}

	mutex_unlock(&kstat_lock);

	if (!err)
		kstat_maps_arm();

	if (err) {
		pr_warn("kstat proc write '%s' -> err %d\n", argv[0], err);
		/* Reported to the writer: a command that did not take effect must not look like a
		 * successful full write.  Success still returns len, so callers that expect a complete
		 * write keep working. */
		return err;
	}
	return len;
}
