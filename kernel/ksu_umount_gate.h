/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_KSU_UMOUNT_GATE_H
#define __SUSFS_KSU_UMOUNT_GATE_H

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/types.h>

/* Set once, by ksu_umount_gate.c's init, from whether KernelSU's symbol was found: false = the gates
 * ask KernelSU, true = answer the pre-#34 way (uid >= 10000) without calling anything.  Read by the
 * gates, never recomputed, and never a loader parameter: the only thing that matters is one fact
 * about the device, and it is established where the module can still see the whole picture. */
extern bool susfs_ksu_umount_gate_off;

/* Defined in ksu_umount_gate.c: the one indirect call, through the address resolved at load. */
bool susfs_ksu_umount_ask(uid_t uid);

/* Upstream's susfs_is_current_proc_umounted_app(): app uid AND KernelSU would umount for it.  The
 * uid half is upstream's literal 10000; the flag half is the predicate that flag is set from, so a
 * su-granted app, the manager and a profile with "umount modules" off are not hidden from. */
#define SUSFS_PER_USER_RANGE		100000
#define SUSFS_FIRST_ISOLATED_UID	99000
#define SUSFS_LAST_ISOLATED_UID		99999

static inline bool susfs_is_current_proc_umounted_app(void)
{
	uid_t uid = current_uid().val;
	uid_t appid;

	if (uid < 10000)
		return false;
	if (READ_ONCE(susfs_ksu_umount_gate_off))
		return true;	/* nothing resolved to ask: hide from app uids, as this module did before #34 */

	/* Isolated processes are hidden from unconditionally, as the SUSFS KernelSU patch marks
	 * them (10_enable_susfs_for_ksu.patch).  Asking KernelSU instead would answer the GLOBAL
	 * default for them - an isolated uid carries no app profile - so a device with
	 * default_non_root_profile.umount_modules off would stop hiding from them, and an isolated
	 * process can be neither the manager nor an allow_su app. */
	appid = uid % SUSFS_PER_USER_RANGE;
	if (appid >= SUSFS_FIRST_ISOLATED_UID && appid <= SUSFS_LAST_ISOLATED_UID)
		return true;

	return susfs_ksu_umount_ask(uid);
}

int susfs_ksu_umount_gate_init(void);

#endif /* __SUSFS_KSU_UMOUNT_GATE_H */
