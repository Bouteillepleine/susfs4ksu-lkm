/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_H
#define __SUSFS_H

#include <linux/string.h>
#include <linux/err.h>	/* IS_ERR */
#include <linux/mm.h>	/* PAGE_SIZE */
#include <linux/version.h>	/* LINUX_VERSION_CODE for the pre-5.10 shims below */

/* ---- pre-5.10 portability shims (legacy branch; see LEGACY_PORTING.md) ----
 *
 * This branch exists so that somebody with a pre-5.10 non-GKI kernel (4.14/4.19/5.4) can
 * port this module themselves.  Nothing below 5.10 is built or tested here - there is no
 * DDK image and no device for it, and no binary is provided - so the shims are kept to
 * what can be named from the upstream sources at the release that changed it, and the
 * rest of what such a port needs is the porter's own verification problem, listed area by
 * area in LEGACY_PORTING.md.
 *
 * Everything here sits inside one explicit < 5.10 gate, so on every kernel this module is
 * built and tested against (5.10 and up) the token stream is unchanged: the macros do not
 * exist there and every gate below is false.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
/* struct proc_ops does not exist before 5.6: proc_create() takes a file_operations
 * (v5.5 include/linux/proc_fs.h:49) and proc_ops appears in v5.6 (:15) with the changed
 * prototype (:64).  Only the fields this module uses are mapped. */
# if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#  define proc_ops	file_operations
#  define proc_read	read
#  define proc_write	write
#  define proc_open	open
#  define proc_release	release
#  define proc_lseek	llseek
# endif
/* The nofault accessors are probe_kernel_read()/probe_kernel_write() before 5.8
 * (include/linux/uaccess.h, same call shape; this module only ever calls them directly). */
# if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#  define copy_from_kernel_nofault(dst, src, size)	probe_kernel_read(dst, src, size)
#  define copy_to_kernel_nofault(dst, src, size)	probe_kernel_write(dst, src, size)
# endif
/* Symbol namespaces (and with them MODULE_IMPORT_NS) arrived in 5.4
 * (v5.4 include/linux/module.h:276); before that the import cannot exist. */
# if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
#  define MODULE_IMPORT_NS(ns)
# endif
/* __nocfi comes with CFI_CLANG, which is an ACK 5.10 addition (its
 * include/linux/compiler_types.h:240 is the definition this module relies on; upstream at
 * that tag has none).  Without CFI there is nothing to disable, so defining it away is
 * correct - but it also means the prototype rules that exist FOR CFI (see sus_path.c's
 * static_asserts) stop being enforced at runtime, which LEGACY_PORTING.md states. */
# ifndef __nocfi
#  define __nocfi
# endif
#endif /* < 5.10 */

/* A kernel pointer taken out of a kprobe register, checked before dereference: single_open()'s fake inode is (void *)1
 * and a kretprobe hands that sentinel over as "the argument" - the sus_map vma probe panicked on exactly that (fault
 * address 0xa1) until this test existed.  Every kernel object lives above the first page, so "< PAGE_SIZE" covers a
 * sentinel and a garbage register too, and IS_ERR() covers error pointers; user pointers must NOT go through it. */
static inline bool susfs_ptr_plausible(const void *p)
{
	return (unsigned long)p >= PAGE_SIZE && !IS_ERR(p);
}

/* Bind a fixed-size ABI pathname field to a C string safely: char[N] pathname fields a caller need not NUL-terminate, and
 * strlen()/strcmp()/kern_path() on one walks off the end of the struct, which lives on OUR kernel stack.  Every consumer of
 * an ABI pathname goes through this first. */
static inline bool susfs_abi_path_ok(const char *field, size_t size)
{
	return strnlen(field, size) < size;
}

/* Add a path to sus_path's hidden set from kernel code (no supercall needed); returns 0 or negative errno. */
int sus_path_add_hidden(const char *path);

/* Same, for one of this module's own control nodes: flagged so the gate hides it from EVERY non-root caller, not merely
 * from apps (uid>=10000) - otherwise a probe running as system (1000) or shell (2000) reads the node name out of /proc. */
int sus_path_add_self_hidden(const char *path);

/* Undo sus_path_add_self_hidden(): drops the rule for @path and restores whatever it changed (the relaxed mode, the inode
 * reference); returns the number of rules removed, so 0 means "was not registered".  Process context only (iput). */
int sus_path_del_path(const char *path);

/* The module's own name: the /sys/module directory and the modinfo name are both the module file name, and the self-hide
 * rules and the /proc/modules filter have to agree with it. */
#define SUSFS_LKM_MODULE_NAME "susfs_guard_lkm"
#define SUSFS_LKM_SYSFS_DIR   "/sys/module/" SUSFS_LKM_MODULE_NAME

/* hide_modules (susfs_hide_syms.c): filters module NAMES out of /proc/modules (plus /sys/module and /proc/kallsyms for
 * non-root callers).  Node and same-named parameter are root-only; the node answers ENOENT through sus_path's hidden set. */
#define SUSFS_HIDE_MODULES_NODE "/proc/susfs_hide_modules"
bool susfs_hide_modules_active(void);

/* The sus_mount control node: decides WHICH mounts count as ours (the on/off switch stays the hide_sus_mnts_for_non_su_procs supercall); root-only, ENOENT for everyone else through sus_path. */
#define SUSFS_HIDE_MOUNTS_NODE "/proc/susfs_hide_mounts"
bool susfs_hide_modules_node_ready(void);

/* sus_path's own control node: `cat` is the rule listing (the hide_list parameter view), writing takes add/del/clear.  An
 * operator who cannot see the rule table cannot tell "registered" from "hiding"; root-only, everyone else gets ENOENT. */
#define SUSFS_PATH_NODE "/proc/susfs_path"

/* Whether the /proc/susfs_* control nodes are created at all.  Defaults to TRUE; they are created only when the LSM layer
 * that hides them is installed, so nobody ends up with an unprotected control node, and expose_proc=0 removes them. */
extern bool susfs_expose_proc;

/* feature init/exit (each feature is its own translation unit) */
int susfs_uname_init(void);
void susfs_uname_exit(void);

int susfs_kstat_init(void);
void susfs_kstat_exit(void);

int susfs_sus_map_init(void);
void susfs_sus_map_exit(void);

int sus_path_init(void);
void sus_path_exit(void);

int susfs_sus_mount_init(void);
void susfs_sus_mount_exit(void);

int susfs_spoof_cmdline_init(void);
void susfs_spoof_cmdline_exit(void);

int susfs_open_redirect_init(void);
void susfs_open_redirect_exit(void);

int susfs_enable_log_init(void);
void susfs_enable_log_exit(void);
bool susfs_log_enabled(void);

int susfs_avc_spoof_init(void);
void susfs_avc_spoof_exit(void);

int susfs_supercall_init(void);
void susfs_supercall_exit(void);

/* feature supercall handlers (upstream signature: void xxx(void __user **arg)) */
void susfs_uname_supercall(void __user **arg);
void susfs_enable_log_supercall(void __user **arg);
void susfs_avc_spoof_supercall(void __user **arg);
void susfs_spoof_cmdline_supercall(void __user **arg);
void susfs_sus_map_supercall(void __user **arg);
void sus_path_supercall(unsigned int cmd, void __user **arg);
void susfs_kstat_supercall(unsigned int cmd, void __user **arg);
void susfs_open_redirect_supercall(void __user **arg);
void susfs_sus_mount_supercall(void __user **arg);

int susfs_hide_syms_init(void);
void susfs_hide_syms_exit(void);

/* Actual install state: enabled_features must not advertise a feature whose registration failed - hide_syms used to fail
 * silently and still be reported as active, the kind of inconsistency a detector looks for. */
bool susfs_hide_syms_active(void);
bool sus_path_lsm_active(void);

/* Whether a 0777 /proc/susfs_* control node may be created.  Two independent conditions, neither optional: susfs_expose_proc
 * (the operator opted in) and sus_path_lsm_active() (with 0777 DAC passes every caller, so only the LSM layer can still
 * answer ENOENT for an app).  This gates node CREATION ONLY, never hook registration: an earlier revision returned early from
 * the feature inits on !susfs_expose_proc, which silently disabled sus_kstat's tracepoint and kretprobe. */
static inline bool susfs_control_node_allowed(void)
{
	return susfs_expose_proc && sus_path_lsm_active();
}

/* open_redirect, reverse direction, for callers that only have an inode NUMBER: fdinfo prints "ino:\t<i>" with no device, so
 * this is a lookup by ino alone and returns false when the number is ambiguous (two rules, same redirected ino) or the caller is
 * not one the reverse disguise applies to.  On success *out_ino is the target inode to show, *out_mnt_id the target mount id. */
bool susfs_open_redirect_spoof_ids(unsigned long ino, unsigned long *out_ino, unsigned long *out_mnt_id);

#endif
