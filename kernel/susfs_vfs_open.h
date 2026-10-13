/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * susfs_vfs_open.h - the vendored O_PATH open: its control entry points only.
 *
 * The decision this layer acts on belongs to sus_path and is declared there
 * (susfs.h).  What lives here is only the interface kernel/susfs_opath.c uses: the
 * syscall entry (site + the caller's registers in, the answer out) plus its own
 * init/exit/dump, so the two O_PATH layers can be composed the same way every other
 * layer of this module is (susfs_main.c's layer table).
 */

#ifndef __SUSFS_VFS_OPEN_H
#define __SUSFS_VFS_OPEN_H

#include <linux/types.h>

struct pt_regs;

/* Which sys_call_table entry the call came from.  The two sites differ only in how
 * the flags are read: openat(56) has them in a register, openat2(437) in the
 * caller's struct open_how, which has to be copied in before the O_PATH question
 * can be answered at all. */
#define SUSFS_VFS_SITE_OPENAT	0
#define SUSFS_VFS_SITE_OPENAT2	1

/* True when the vendored walk is armed and may answer an O_PATH call.  The wrappers
 * test this on every O_PATH call: false means "run the original entry and post-check
 * it", which is the behaviour on every kernel line other than 5.15 and on a 5.15
 * device whose required symbols could not be resolved. */
bool susfs_vfs_open_ready(void);

/* Answer the syscall when it carries O_PATH and this layer is armed.  *ret is then
 * the syscall's answer and the return value is true; false means the caller must run
 * the original entry (and its post-check) instead.  Never called for a call without
 * O_PATH - the wrapper decides that from the flags register itself, so the non-O_PATH
 * path does not enter this file at all. */
bool susfs_vfs_open_syscall(int site, const struct pt_regs *regs, long *ret);

int susfs_vfs_open_init(void);
void susfs_vfs_open_exit(void);

/* The same assembly report the layer prints at load time, for susfs_opath.c's
 * opath_dump and for a bring-up that has already loaded the module. */
void susfs_vfs_open_dump(void);

#define SUSFS_VFS_OPEN_NODE "/proc/susfs_vfs_open"

#endif /* __SUSFS_VFS_OPEN_H */
