/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_KSU_UMOUNT_GATE_H
#define __SUSFS_KSU_UMOUNT_GATE_H

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/types.h>

/* KernelSU's own answer to "would I umount modules for this uid" (issue #34).  It is not exported
 * (device: `t ksu_uid_should_umount [kernelsu]`, and kernelsu.ko has no `__ksymtab`), so the loader
 * fills it from kallsyms like this module's other unexported imports.
 *
 * On a Magisk device the symbol does not exist at all.  The loader decides that - not this module -
 * and either resolves it or pins it to 0 and passes `is_magisk=1` (see kernel/ksu_umount_gate.c and
 * tools/susfs_insmod.c); a loader that does neither leaves the name SHN_UNDEF and the kernel
 * refuses the load with "Unknown symbol", which is the wanted behaviour. */
extern bool ksu_uid_should_umount(uid_t uid);

/* Set once by ksu_umount_gate.c's init from the loader's parameter: false = ask KernelSU, true =
 * answer the pre-#34 way without ever calling the symbol above. */
extern bool susfs_ksu_umount_gate_off;

#define SUSFS_PER_USER_RANGE		100000
#define SUSFS_FIRST_ISOLATED_UID	99000
#define SUSFS_LAST_ISOLATED_UID		99999

/* Upstream's susfs_is_current_proc_umounted_app(): app uid AND KernelSU would umount for it.  The
 * uid half is upstream's literal 10000; the flag half is the predicate that flag is set from, so a
 * su-granted app, the manager and a profile with "umount modules" off are not hidden from. */
static inline bool susfs_is_current_proc_umounted_app(void)
{
	uid_t uid = current_uid().val;
	uid_t appid;

	if (uid < 10000)
		return false;
	if (READ_ONCE(susfs_ksu_umount_gate_off))
		return true;	/* no KernelSU to ask: hide from app uids, as this module did before #34 */

	/* Isolated processes are hidden from unconditionally, as the SUSFS KernelSU patch marks
	 * them (10_enable_susfs_for_ksu.patch).  Asking KernelSU instead would answer the GLOBAL
	 * default for them - an isolated uid carries no app profile - so a device with
	 * default_non_root_profile.umount_modules off would stop hiding from them, and an isolated
	 * process can be neither the manager nor an allow_su app. */
	appid = uid % SUSFS_PER_USER_RANGE;
	if (appid >= SUSFS_FIRST_ISOLATED_UID && appid <= SUSFS_LAST_ISOLATED_UID)
		return true;

	return ksu_uid_should_umount(uid);
}

int susfs_ksu_umount_gate_init(void);

#endif /* __SUSFS_KSU_UMOUNT_GATE_H */
