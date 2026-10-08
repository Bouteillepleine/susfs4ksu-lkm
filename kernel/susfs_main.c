// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>	/* LINUX_VERSION_CODE: the MODULE_IMPORT_NS spelling below */

#include <linux/cred.h>		/* current_uid(), for the hide gate below */
#include "symbol_resolver.h"
#include "susfs_log.h"
#include "lsm_hook.h"
#include "susfs.h"

/* SUSFS_LKM_VERSION lives in susfs.h: imports_guard.c reports it when it refuses a load, and that
 * happens before this file's banner runs. */

bool susfs_expose_proc = true;
module_param_named(expose_proc, susfs_expose_proc, bool, 0600);

/* ---- the hide gate ---------------------------------------------------------
 * Upstream SUSFS hides from susfs_is_current_proc_umounted_app(), which is
 * (test_thread_flag(TIF_PROC_UMOUNTED) && uid >= 10000): only the apps KernelSU has
 * already umounted modules for.  An LKM cannot read that thread flag, so every feature
 * here used "uid >= 10000" alone - which hides from EVERY app, the KernelSU manager
 * included.  Measured on device: under that proxy, hiding /data/adb makes the manager's
 * own module list unreadable, so the one rule that has any effect is the one you cannot
 * use.
 *
 * KernelSU answers the same question itself.  ksu_uid_should_umount() is the function
 * its UID_SHOULD_UMOUNT ioctl wraps, and it folds in all of it: the manager excluded,
 * allow_su apps excluded, the per-app umount_modules flag, and the global default.
 * That is what TIF_PROC_UMOUNTED records, so following it makes this gate faithful to
 * upstream instead of an approximation of it.
 *
 * It is resolved from kallsyms, which finds it only when KernelSU is built into the
 * kernel - the resolver answers from vmlinux and refuses module-owned symbols on the
 * kernels where it can tell the difference.  A KernelSU-as-LKM (or no KernelSU) setup
 * therefore falls back to the old uid test and behaves exactly as before.  The fallback
 * is logged, because "also hides from the manager" is not a difference anyone should
 * have to discover from behaviour. */
#define SUSFS_PER_USER_RANGE		100000
#define SUSFS_FIRST_APPLICATION_UID	10000
#define SUSFS_FIRST_ISOLATED_UID	99000
#define SUSFS_LAST_ISOLATED_UID		99999

static bool (*ksu_uid_should_umount_fn)(uid_t uid);

/* __nocfi: called through a runtime-resolved pointer, which kCFI checks at the call
 * site - the same rule every other resolved call in this module follows. */
static __nocfi bool susfs_ksu_should_umount(uid_t uid)
{
	return ksu_uid_should_umount_fn(uid);
}

bool susfs_uid_is_hidden_target(void)
{
	uid_t uid = current_uid().val;
	uid_t appid;

	/* Keep upstream's floor.  It is not redundant with the DenyList: asked about uid 0
	 * or a service uid, ksu_uid_should_umount() finds no app profile and answers the
	 * GLOBAL DEFAULT - normally true - so handing it root would start hiding /data/adb
	 * from ksud and the module scripts themselves. */
	if (uid < SUSFS_FIRST_APPLICATION_UID)
		return false;

	if (unlikely(!ksu_uid_should_umount_fn))
		return true;			/* the old proxy, unchanged */

	/* ksu_handle_umount() umounts isolated processes whatever their profile says. */
	appid = uid % SUSFS_PER_USER_RANGE;
	if (appid >= SUSFS_FIRST_ISOLATED_UID && appid <= SUSFS_LAST_ISOLATED_UID)
		return true;

	return susfs_ksu_should_umount(uid);
}

static void susfs_init_hide_gate(void)
{
	ksu_uid_should_umount_fn = (void *)find_kernel_symbol_exact("ksu_uid_should_umount");
	if (ksu_uid_should_umount_fn)
		SUSFS_LOGI("hide gate: following KernelSU's DenyList (ksu_uid_should_umount at %px) - the manager and allow_su apps are NOT hidden from\n",
			   ksu_uid_should_umount_fn);
	else
		pr_warn("hide gate: ksu_uid_should_umount is not resolvable (KernelSU built as a module, or absent) - falling back to uid >= 10000, which hides from EVERY app including the manager\n");
}

static const char *const susfs_self_hide_paths[] = {
    "/proc/susfs_kstat",
    "/proc/susfs_open_redirect",
    "/proc/susfs_enable_log",
    "/proc/susfs_avc_spoof",
    SUSFS_HIDE_MODULES_NODE,
    SUSFS_HIDE_MOUNTS_NODE,

    SUSFS_PATH_NODE,

};

static void susfs_self_hide_nodes(void)
{
    int i;

    if (!susfs_expose_proc)
        return;

    for (i = 0; i < ARRAY_SIZE(susfs_self_hide_paths); i++) {
        int rc = sus_path_add_self_hidden(susfs_self_hide_paths[i]);

        if (rc)
            pr_warn("self-hide %s failed %d\n",
                    susfs_self_hide_paths[i], rc);
    }
}

static int layer_lsm_hook_init(void)
{
    ksu_lsm_hook_init();
    return 0;
}

/* Not const: the `armed` flags live here (the pointers must outlive __init too). */
static struct {
    const char *name;
    int (*init)(void);
    void (*exit)(void);
    bool fatal;
    bool armed;			/* exit is run for every layer that was attempted */
} susfs_layers[] = {
    { "lsm_hook",	layer_lsm_hook_init,		ksu_lsm_hook_exit,	false, false },
    { "sus_path",	sus_path_init,			sus_path_exit,		true,  false },
    { "uname",		susfs_uname_init,		susfs_uname_exit,	false, false },
    { "kstat",		susfs_kstat_init,		susfs_kstat_exit,	false, false },
    { "sus_map",	susfs_sus_map_init,		susfs_sus_map_exit,	false, false },
    { "sus_mount",	susfs_sus_mount_init,		susfs_sus_mount_exit,	false, false },
    { "cmdline",	susfs_spoof_cmdline_init,	susfs_spoof_cmdline_exit, false, false },
    { "open_redirect",	susfs_open_redirect_init,	susfs_open_redirect_exit, false, false },
    { "enable_log",	susfs_enable_log_init,		susfs_enable_log_exit,	false, false },
    { "avc_spoof",	susfs_avc_spoof_init,		susfs_avc_spoof_exit,	false, false },
    { "supercall",	susfs_supercall_init,		susfs_supercall_exit,	true,  false },
    { "hide_syms",	susfs_hide_syms_init,		susfs_hide_syms_exit,	false, false },
};

static int fail_layer;
module_param_named(fail_layer, fail_layer, int, 0644);

static void susfs_layers_down(int upto)
{
    int i;

    for (i = upto; i >= 0; i--) {
        if (!susfs_layers[i].armed)
            continue;
        susfs_layers[i].armed = false;
        if (susfs_layers[i].exit)
            susfs_layers[i].exit();
    }
}

static int __init susfs_init(void)
{
    int i;

    /* First, before any layer runs and while nothing is armed: an import that was not filled in
     * is an address this module would jump to on its first call through it.  See
     * imports_guard.c - a loader that continues after an unresolved name leaves it zero, which
     * the kernel accepts without a word. */
    if (susfs_imports_guard())
        return -EINVAL;

    SUSFS_LOGI("init v%s\n", SUSFS_LKM_VERSION);
    ksu_init_symbol_resolver();
    susfs_init_hide_gate();

    /* Now that kallsyms lookups work, check the addresses themselves: see imports_guard.c. */
    if (susfs_imports_crosscheck())
        return -EINVAL;

    for (i = 0; i < (int)ARRAY_SIZE(susfs_layers); i++) {
        int ret;

        /* Marked before the call: a layer that half-ran still has to be taken down. */
        susfs_layers[i].armed = true;

        if (fail_layer == i + 1) {
            pr_warn("fail_layer=%d - forcing %s's init to fail (diagnostic)\n",
                    fail_layer, susfs_layers[i].name);
            ret = -EIO;
        } else {
            ret = susfs_layers[i].init ? susfs_layers[i].init() : 0;
        }

        if (!ret)
            continue;

        if (susfs_layers[i].fatal) {
            pr_err("%s init failed %d, refusing to load\n",
                   susfs_layers[i].name, ret);
            /* The kernel is about to free this module; a hook left behind points into it. */
            susfs_layers_down(i);
            return ret;
        }
        pr_warn("%s init failed %d - that feature stays off\n",
                susfs_layers[i].name, ret);
    }

    susfs_self_hide_nodes();

    pr_info("loaded. This module is filtered out of /proc/modules for every caller including root, so `lsmod | grep susfs` stays empty - check /sys/module/%s instead (a second insmod fails with -EEXIST while it is loaded).\n",
            SUSFS_LKM_MODULE_NAME);

    return 0;
}

static void __exit susfs_exit(void)
{
    susfs_layers_down((int)ARRAY_SIZE(susfs_layers) - 1);
    SUSFS_LOGI("susfs_guard_lkm: exit\n");
}

module_init(susfs_init);
module_exit(susfs_exit);
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
MODULE_DESCRIPTION("SUSFS guard LKM (susfs_guard_lkm) v2.3.0-gki");
