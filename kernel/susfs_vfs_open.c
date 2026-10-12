// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_vfs_open.c - the O_PATH open answered by our own copy of the VFS walk.
 *
 * WHY THIS FILE EXISTS AT ALL (and why it is not a hook)
 * -----------------------------------------------------
 * The device kernel is built with CONFIG_LTO_CLANG_FULL.  In such a kernel the
 * helpers of fs/namei.c are inlined into their callers and the address kallsyms
 * holds for them belongs to a leftover copy nobody executes: measured on this very
 * device with kprobes, do_sys_open / getname_flags / do_filp_open / do_dentry_open
 * never fire, while vfs_open still has a live body (123/123 hits).  So there is no
 * instruction on the user's path that could be rewritten, and no probe that could
 * observe it: whatever has to be added to this syscall has to be added to code we
 * compile ourselves.  (The matching disaster is on record too: rewriting the
 * .cfi_jt stub that sys_call_table actually holds is an unrecoverable
 * "Oops - FPAC", which is why nothing in this project patches kernel text.)
 *
 * So: this file carries a copy of every function on the O_PATH open path, taken from
 * the 5.15.180 tree this device is built from, compiled into this module.  The
 * sys_call_table entry for openat(56)/openat2(437) points at a wrapper in
 * kernel/susfs_opath.c, which hands every O_PATH call to this file and tail-calls the
 * original entry for every call that is not O_PATH.  The regression surface for an
 * ordinary open is therefore zero: it does not enter this file at all.
 *
 * WHY THE HIDDEN ANSWER HAS TO COME OUT OF THE LOOKUP
 * --------------------------------------------------
 * The layer this replaces (susfs_opath.c) lets the kernel open the file and then
 * takes the descriptor away.  That is correct, and it is observable: a hidden path
 * answered -ENOENT 760..1430 ns FASTER than a path that does not exist, because the
 * hidden file's dentry is a dcache hit while a name that is not there pays a real,
 * failing filesystem lookup.  Three families were 100% separable by timing alone.
 * The only way to remove that is to make the hidden component fail the way a missing
 * component fails - inside the walk, in the lookup, before anything has been
 * committed to nd->path.  That is what walk_component() below does: lookup_fast()
 * refuses the hit, and the name actually handed to the filesystem is a DERIVED one
 * that is not there.
 *
 * WHY THE FAKE NAME IS DERIVED AND NOT A CONSTANT
 * ----------------------------------------------
 * Upstream SUSFS re-looks the component up under the fixed name "..5.u.S".  A fixed
 * name is one an adversary can pre-create in the directory they want to probe: the
 * lookup then SUCCEEDS and the cost drops back to a hit, restoring exactly the side
 * channel this mechanism exists to remove.  The name used here is derived from a
 * boot-time random salt that never leaves the module, and it is a fixed 16
 * characters long, so the hash and the filesystem lookup cost the same on every call.
 * See susfs_vfs_fake_name().
 *
 * WHY THE POST-CHECK LAYER STAYS
 * -----------------------------
 * The two layers answer different questions and are deliberately kept together:
 *   - this file decides from the inode it RESOLVED, before any descriptor exists.
 *     That is what makes the failure a real lookup failure and the timing right.  It
 *     covers openat/openat2 only, and only while this layer is armed (a kernel line
 *     other than 5.15, or a required name this device cannot supply, turns it off and
 *     says so).
 *   - susfs_opath.c decides from the inode the KERNEL actually handed out, so it has
 *     no TOCTOU window at all and it covers every entry that reaches the table - the
 *     AArch32 open/openat entries, an entry this layer never sees, a future one.
 * Neither is redundant: this one buys the timing semantics, that one keeps the last
 * word on the descriptor that exists.
 *
 * LOAD-TIME ASSEMBLY, AND WHAT "INLINED" MEANS HERE
 * ------------------------------------------------
 * Every function below is a POINT in an assembly table, and the load
 * (susfs_vfs_open_init()) records for each one which implementation finally runs:
 *
 *   SUSFS_VFS_KIND_OURS           the copy in this file.  Fixed for the points that
 *                                 carry (or must carry) the hidden decision: the
 *                                 kernel's copy of those cannot be changed, so binding
 *                                 to it would silently disable the layer.
 *   SUSFS_VFS_KIND_PREFER_KERNEL  the kernel's own compiled entity when kallsyms has
 *                                 the name, the copy in this file otherwise.
 *                                 Preferring the kernel's entity is not a performance
 *                                 choice: on a vendor-modified kernel the logic that
 *                                 runs is then the logic the vendor compiled, and the
 *                                 struct nameidata contract is the vendor's own.
 *   SUSFS_VFS_KIND_OURS_INLINED   the point has no body of its own on this path: an
 *                                 ancestor copy contains it.  That is DERIVED at load
 *                                 time by scanning the ancestor for a `bl` to it, not
 *                                 assumed - see the edge scan.  A point that is inlined
 *                                 must never be called a second time as well, or the
 *                                 walk does its work twice (two lookups, two refusals,
 *                                 or the hidden verdict applied inside a body that has
 *                                 already applied it).
 *
 * The points that MUST be ours, one line each - the report asks for the reason per
 * point, and this list is the reason:
 *
 *   lookup_fast          carries the refusal: the RCU hit has to become an in-place ref-walk miss and
 *                            the ref-walk hit has to be dropped, or the hidden component
 *                            keeps its dcache-hit cost
 *   lookup_slow          the entry the derived name is looked up through (susfs_vfs_fake_lookup()
 *                            calls it), and the twin of __lookup_slow
 *   __lookup_slow        the slow half of the same decision - keeping only one of the pair would let
 *                            a call site we do not control reach the other
 *   walk_component       turns "that hit was hidden" into the derived-name lookup, and is the last
 *                            point before the component is committed to nd->path
 *   step_into            commits the component (nd->path = path); in-chain neighbour of
 *                            walk_component(), so it has to be the copy that runs
 *   handle_mounts        step_into()'s first act; it is where the derived name's NEGATIVE dentry
 *                            becomes -ENOENT through traverse_mounts()
 *   path_lookupat        drives link_path_walk()/lookup_last(): the kernel's copy would call the
 *                            kernel's inlined walk_component() and the patch would never run
 *   link_path_walk       same reason one level up - the caller of walk_component() for every
 *                            non-final component
 *   lookup_last          the caller of walk_component() for the FINAL component, i.e. exactly the
 *                            component an O_PATH open is about
 *   do_o_path            produces the O_PATH answer itself (dentry_open() -> FMODE_PATH|FMODE_OPENED)
 *                            and is where the unexported audit_inode() had to be left out
 *   path_openat          owns the RCU/reval retry contract with do_filp_open(), is static in the
 *                            kernel (no entity to bind to), and the kernel's inlined copy
 *                            would bypass do_o_path()
 *   do_filp_open         calls path_openat() three times (RCU, ref-walk, REVAL); the kernel's
 *                            out-of-line copy calls ITS OWN inlined path_openat()
 *   do_sys_openat2       static in the kernel; it owns the fd lifecycle for this path
 *                            (get_unused_fd_flags -> fsnotify_open -> fd_install)
 *   set_nameidata        must not be split from __set_nameidata - see there
 *   __set_nameidata      initialises the private tail appended to struct nameidata; if the kernel's
 *                            copy ran, every patched lookup would read stack garbage
 *   restore_nameidata    the destructor of the struct __set_nameidata() built (it frees nd->stack
 *                            when it was reallocated); keeping one half only is how a layout
 *                            bug hides
 *
 * The rule that produced that list: a patched point forces every caller between it
 * and the entry to be ours as well, because the kernel's copy of a caller contains
 * the kernel's INLINED copy of the callee - the patch would simply not run.  The
 * load-time edge scan asserts exactly that, on the artifact, and refuses to arm when
 * an edge shows the forbidden shape (parent bound to the kernel, child needed by us).
 *
 * The frame self-check runs at the entry of these points, and only on this path:
 *
 *   lookup_fast
 *   lookup_slow
 *   __lookup_slow
 *   walk_component
 *   step_into
 *   handle_mounts
 *   path_lookupat
 *   link_path_walk
 *   do_o_path
 *
 * WHAT IS SHARED WITH THE KERNEL AND CANNOT BE CHECKED HERE
 * --------------------------------------------------------
 * struct nameidata below is a verbatim copy of fs/namei.c:565-587, and it is NOT ours
 * alone: after __set_nameidata() points current->nameidata at it, the KERNEL reads
 * and writes it through the KERNEL's layout - nd_jump_link() (fs/namei.c:989) is
 * reachable from an O_PATH open with LOOKUP_FOLLOW, from a procfs magic link's
 * ->get_link, and it reads nd->flags, nd->path, nd->inode and nd->state while the
 * struct lives on THIS MODULE'S stack.  A layout mismatch is not an error return, it
 * is silent corruption, and no compiler on the build host can see it: the struct is
 * file-local in fs/namei.c and is not in the DDK headers at all.
 *
 * Everything of ours therefore lives OUTSIDE that struct: the walk's private state is
 * in struct susfs_vfs_nd, whose first member is the struct itself, so the address
 * handed to current->nameidata is the kernel's layout and the kernel never sees our
 * bytes.  The three layout numbers of the device (sizeof 224, offsetof(state) 60,
 * offsetof(internal) 96) are static_assert'd in the build and re-checked at load time
 * against the same three module parameters, which stay 0 ("not checked") until an
 * operator fills them in from the device's BTF.  The device gate caught a real defect
 * once - an appended private field made our copy 240 bytes - which is why the private
 * state is a wrapper now.
 *
 * 5.10 AND 6.x ARE NOT SUPPORTED, ON PURPOSE
 * -----------------------------------------
 * 5.10 is not a smaller version of this file, it is a different one: struct nameidata
 * has no `state` field (the jumped/root-preset state lives in `flags`),
 * set_nameidata() takes no root and does not initialise depth/path, the try_to_unlazy
 * pair is spelled unlazy_walk/unlazy_child, and may_lookup() has no mnt_userns
 * argument.  6.1+ differs again: mnt_idmap instead of user_namespace, dir_vfsuid,
 * next_seq, and six functions that lost their out-parameter forms.  Copying a 5.15
 * body onto one of those kernels would not fail to compile - it would write the wrong
 * bytes into current->nameidata, which every namei path in the kernel then reads
 * through the kernel's own layout.  So on every other kernel line this file compiles
 * to an empty layer that says so once and leaves the existing O_PATH post-check layer
 * as the whole answer, which is also what keeps the eight CI variants building.
 *
 * PROVENANCE, AND WHY THIS FILE IS HAND-MAINTAINED FROM HERE ON
 * ------------------------------------------------------------
 * The copied bodies came out of one specific tree -
 * C:\Users\ASUS\dsh\workspace\android_kernel_oneplus_sm8550, i.e. the 5.15.180
 * source this device's kernel was built from - and they were taken function by
 * function from fs/namei.c (the walk: hash machinery at :2002-2211, the nameidata
 * block at :564-591, then :593-2474 up to path_lookupat()) and from fs/open.c
 * (build_open_how :1080-1094, build_open_flags :1096-1213, do_sys_openat2
 * :1293-1320).  The closure itself - which functions are on the O_PATH path, and
 * therefore what had to be taken - was worked out in a separate static analysis,
 * %TEMP%\\opath-vendor\\SCOPE.md; that file (not this comment) is the place to look
 * for the argument about why each one is in the set, and it is also where the
 * "variants A/B" question is answered.
 *
 * They were extracted and rewritten by a throwaway script (see
 * susfs4ksu-lkm-notes/tools/opath_vendor/ - archived, NOT in this repository, and
 * NOT to be re-run against this file any more).  That is the part worth stating
 * plainly: an earlier round did re-run it, and doing so silently reverted four
 * hand-made fixes that had already been committed (a forward declaration, one
 * variable spelled two ways, __nocfi on the init function, and __cond_resched
 * being optional on this device).  A file whose content is regenerated from
 * outside the repository will keep losing hand edits, and every other source file
 * in kernel/ is hand-written anyway - so:
 *
 *   ** EDIT THIS FILE DIRECTLY.  Do not regenerate it. **
 *
 * The two things the generator did that are easy to get wrong by hand, and that a
 * reviewer should check on any future edit: (1) every copied body is `__nocfi`
 * (an instrumented indirect call into the kernel is a panic here, not an error
 * return - the CI's tools/cfi_sites.py asserts this on the artifact), and (2) no
 * copied body may call another one by name unless it is one of the points this
 * file owns - everything else goes through the vfs table, which is filled at load
 * time.
 *
 * Which bodies are NOT verbatim copies, and why (both are stated in full at the
 * definitions themselves): path_openat() keeps only the O_PATH branch, and
 * do_o_path() produces its file through dentry_open() instead of
 * alloc_empty_file()+vfs_open(), because alloc_empty_file() has no entity in this
 * device's kallsyms.  Everything else is byte-identical to the tree above, except
 * for four deliberate insertions (the layout gate and the private wrapper, the
 * refusal in lookup_fast(), the derived-name dispatch in walk_component(), and the
 * removal of touch_atime()/atime_needs_update() from pick_link() - each of them
 * carries its own comment) and for the audit_inode() call sites, which are gone
 * because this kernel has no such symbol.
 *
 * LF only, English comments, and every comment in here says WHY rather than what.
 */

#include <linux/version.h>
#include <linux/types.h>
#include <linux/module.h>

#include "susfs_log.h"
#include "susfs_vfs_open.h"

/* 5.15 is the device's line; everything else gets the empty layer at the bottom of
 * this file - see "5.10 AND 6.x ARE NOT SUPPORTED". */
#define SUSFS_VFS_OPEN_SUPPORTED					\
	(LINUX_VERSION_CODE >= KERNEL_VERSION(5,15,0) &&		\
	 LINUX_VERSION_CODE < KERNEL_VERSION(5,16,0))

#if SUSFS_VFS_OPEN_SUPPORTED

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include <linux/delayed_call.h>
#include <linux/stringhash.h>
#include <linux/string.h>
#include <linux/kallsyms.h>
#include <linux/seqlock.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/thread_info.h>
#include <linux/slab.h>
#include <linux/overflow.h>
#include <linux/minmax.h>
#include <linux/build_bug.h>
#include <linux/atomic.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/wait.h>
#include <linux/seq_file.h>
#include <asm/word-at-a-time.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>

#include "mount.h"		/* fs/mount.h: struct mount, real_mount(), __lookup_mnt() */
#include "symbol_resolver.h"
#include "susfs.h"		/* sus_path_inode_hidden_public(), susfs_control_node_allowed() */

/*
 * =====================================================================
 * 1. struct open_flags - copied from fs/internal.h:123-129 and fs/open.c:1077-1078
 * =====================================================================
 *
 * Not from a header on purpose: fs/internal.h is a kernel-private header and the DDK
 * header set does not carry it.  Five int-sized fields, unchanged in every kernel
 * this file is about; the asserts pin the layout, and they are also the reason the
 * kernel's own build_open_flags() may safely be bound to at load time (it writes into
 * an object of OUR type).
 */
#define WILL_CREATE(flags)	(flags & (O_CREAT | __O_TMPFILE))
#define O_PATH_FLAGS		(O_DIRECTORY | O_NOFOLLOW | O_PATH | O_CLOEXEC)

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

static_assert(sizeof(struct open_flags) == 20);
static_assert(offsetof(struct open_flags, mode) == 4);
static_assert(offsetof(struct open_flags, acc_mode) == 8);
static_assert(offsetof(struct open_flags, intent) == 12);
static_assert(offsetof(struct open_flags, lookup_flags) == 16);

/*
 * =====================================================================
 * 2. The leaf dependencies - every kernel function this file calls
 * =====================================================================
 *
 * POLICY: not one kernel function is called by name.  Each is resolved at load time
 * with find_kernel_symbol_exact() and called through a pointer, because:
 *
 *   - the loaders (tools/susfs_insmod.c, ksud) rewrite every SHN_UNDEF entry of the
 *     image to SHN_ABS with an address from /proc/kallsyms, and the CI's loader gate
 *     then demands that each of those names exist in the tree's System.map.  A name
 *     that is not exported, or that LTO folded away, becomes a module that does not
 *     LOAD - far worse than this one layer staying off, which is what a missing name
 *     causes here.
 *   - a resolved pointer is also the only shape in which this can be upgraded to the
 *     "copy the kernel's machine code into module memory" variant: the same slot then
 *     holds the address of that copy.
 *
 * CFI: every call through one of these pointers sits inside a __nocfi function (all of
 * the copied bodies are __nocfi).  That is not a style choice - an instrumented
 * indirect call into the kernel panics with "CFI failure" on this platform, and the CI
 * asserts on the artifact that no such call site exists outside its allow-list
 * (tools/cfi_sites.py).
 */
static struct dentry * (*susfs_k___d_lookup)(const struct dentry *, const struct qstr *);
static struct dentry * (*susfs_k___d_lookup_rcu)(const struct dentry *, const struct qstr *, unsigned *);
static void           (*susfs_k___d_lookup_done)(struct dentry *);
static unsigned long  (*susfs_k___fdget_raw)(unsigned int);
static int            (*susfs_k___fsnotify_parent)(struct dentry *, __u32, const void *, int);
static void *         (*susfs_k___kmalloc)(size_t, gfp_t);
static int            (*susfs_k___legitimize_mnt)(struct vfsmount *, unsigned);
static struct mount * (*susfs_k___lookup_mnt)(struct vfsmount *, struct dentry *);
static void           (*susfs_k_audit_log_path_denied)(int, const char *);
static struct dentry * (*susfs_k_d_alloc)(struct dentry *, const struct qstr *);
static struct dentry * (*susfs_k_d_alloc_parallel)(struct dentry *, const struct qstr *, wait_queue_head_t *);
static int            (*susfs_k_d_invalidate)(struct dentry *);
static struct file *  (*susfs_k_dentry_open)(const struct path *, int, const struct cred *);
static struct dentry * (*susfs_k_dget_parent)(struct dentry *);
static void           (*susfs_k_dput)(struct dentry *);
static void           (*susfs_k_fd_install)(unsigned int, struct file *);
static int            (*susfs_k_finish_automount)(struct vfsmount *, struct path *);
static void           (*susfs_k_fput)(struct file *);
static int            (*susfs_k_fsnotify)(__u32, const void *, int, struct inode *);
static void           (*susfs_k_get_random_bytes)(void *, int);
static int            (*susfs_k_get_unused_fd_flags)(unsigned int);
static struct filename * (*susfs_k_getname)(const char __user *);
static int            (*susfs_k_inode_permission)(struct user_namespace *, struct inode *, int);
static bool           (*susfs_k_is_subdir)(const struct dentry *, const struct dentry *);
static void           (*susfs_k_kfree)(const void *);
static bool           (*susfs_k_legitimize_mnt)(struct vfsmount *, unsigned);
static struct vfsmount * (*susfs_k_lookup_mnt)(const struct path *);
static void *         (*susfs_k_memcpy)(void *, const void *, size_t);
static struct vfsmount * (*susfs_k_mntget)(struct vfsmount *);
static void           (*susfs_k_mntput)(struct vfsmount *);
static void           (*susfs_k_path_get)(const struct path *);
static bool           (*susfs_k_path_is_under)(const struct path *, const struct path *);
static void           (*susfs_k_path_put)(const struct path *);
static void           (*susfs_k_put_unused_fd)(unsigned int);
static void           (*susfs_k_putname)(struct filename *);
static int            (*susfs_k_security_inode_follow_link)(struct dentry *, struct inode *, bool);
static seqlock_t      *susfs_k_mount_lock;
static seqlock_t      *susfs_k_rename_lock;
static int            *susfs_k_sysctl_protected_symlinks;
static int            (*susfs_k___cond_resched)(void);

struct susfs_vfs_leaf {
	const char	*name;
	void		**slot;
};

/* NOT const: the load-time resolution writes the addresses here. */
static struct susfs_vfs_leaf susfs_vfs_leaves[] = {
	{ "__d_lookup", (void **)&susfs_k___d_lookup },
	{ "__d_lookup_rcu", (void **)&susfs_k___d_lookup_rcu },
	{ "__d_lookup_done", (void **)&susfs_k___d_lookup_done },
	{ "__fdget_raw", (void **)&susfs_k___fdget_raw },
	{ "__fsnotify_parent", (void **)&susfs_k___fsnotify_parent },
	{ "__kmalloc", (void **)&susfs_k___kmalloc },
	{ "__legitimize_mnt", (void **)&susfs_k___legitimize_mnt },
	{ "__lookup_mnt", (void **)&susfs_k___lookup_mnt },
	{ "audit_log_path_denied", (void **)&susfs_k_audit_log_path_denied },
	{ "d_alloc", (void **)&susfs_k_d_alloc },
	{ "d_alloc_parallel", (void **)&susfs_k_d_alloc_parallel },
	{ "d_invalidate", (void **)&susfs_k_d_invalidate },
	{ "dentry_open", (void **)&susfs_k_dentry_open },
	{ "dget_parent", (void **)&susfs_k_dget_parent },
	{ "dput", (void **)&susfs_k_dput },
	{ "fd_install", (void **)&susfs_k_fd_install },
	{ "finish_automount", (void **)&susfs_k_finish_automount },
	{ "fput", (void **)&susfs_k_fput },
	{ "fsnotify", (void **)&susfs_k_fsnotify },
	{ "get_random_bytes", (void **)&susfs_k_get_random_bytes },
	{ "get_unused_fd_flags", (void **)&susfs_k_get_unused_fd_flags },
	{ "getname", (void **)&susfs_k_getname },
	{ "inode_permission", (void **)&susfs_k_inode_permission },
	{ "is_subdir", (void **)&susfs_k_is_subdir },
	{ "kfree", (void **)&susfs_k_kfree },
	{ "legitimize_mnt", (void **)&susfs_k_legitimize_mnt },
	{ "lookup_mnt", (void **)&susfs_k_lookup_mnt },
	{ "memcpy", (void **)&susfs_k_memcpy },
	{ "mntget", (void **)&susfs_k_mntget },
	{ "mntput", (void **)&susfs_k_mntput },
	{ "path_get", (void **)&susfs_k_path_get },
	{ "path_is_under", (void **)&susfs_k_path_is_under },
	{ "path_put", (void **)&susfs_k_path_put },
	{ "put_unused_fd", (void **)&susfs_k_put_unused_fd },
	{ "putname", (void **)&susfs_k_putname },
	{ "security_inode_follow_link", (void **)&susfs_k_security_inode_follow_link },
};

/*
 * The name mappings the copied bodies are written in terms of.  Defined HERE, i.e.
 * after every #include: a macro must never be in force while a header declares the
 * function it is named after.  The four memory/RNG primitives have no macro - they are
 * called through the pointers by the small helpers below instead, so that the kernel's
 * own fortify-style `memcpy` macro (where a tree has one) cannot collide with this.
 */
#define __d_lookup(...)	susfs_k___d_lookup(__VA_ARGS__)
#define __d_lookup_rcu(...)	susfs_k___d_lookup_rcu(__VA_ARGS__)
#define __d_lookup_done(...)	susfs_k___d_lookup_done(__VA_ARGS__)
#define __fsnotify_parent(...)	susfs_k___fsnotify_parent(__VA_ARGS__)
#define __legitimize_mnt(...)	susfs_k___legitimize_mnt(__VA_ARGS__)
#define __lookup_mnt(...)	susfs_k___lookup_mnt(__VA_ARGS__)
#define audit_log_path_denied(...)	susfs_k_audit_log_path_denied(__VA_ARGS__)
#define d_alloc(...)		susfs_k_d_alloc(__VA_ARGS__)
#define d_alloc_parallel(...)	susfs_k_d_alloc_parallel(__VA_ARGS__)
#define d_invalidate(...)	susfs_k_d_invalidate(__VA_ARGS__)
#define dentry_open(...)	susfs_k_dentry_open(__VA_ARGS__)
#define dget_parent(...)	susfs_k_dget_parent(__VA_ARGS__)
#define dput(...)	susfs_k_dput(__VA_ARGS__)
#define fd_install(...)	susfs_k_fd_install(__VA_ARGS__)
#define finish_automount(...)	susfs_k_finish_automount(__VA_ARGS__)
#define fput(...)	susfs_k_fput(__VA_ARGS__)
#define fsnotify(...)	susfs_k_fsnotify(__VA_ARGS__)
#define get_unused_fd_flags(...)	susfs_k_get_unused_fd_flags(__VA_ARGS__)
#define getname(...)	susfs_k_getname(__VA_ARGS__)
#define inode_permission(...)	susfs_k_inode_permission(__VA_ARGS__)
#define is_subdir(...)	susfs_k_is_subdir(__VA_ARGS__)
#define kfree(...)	susfs_k_kfree(__VA_ARGS__)
#define legitimize_mnt(...)	susfs_k_legitimize_mnt(__VA_ARGS__)
#define lookup_mnt(...)	susfs_k_lookup_mnt(__VA_ARGS__)
#define mntget(...)	susfs_k_mntget(__VA_ARGS__)
#define mntput(...)	susfs_k_mntput(__VA_ARGS__)
#define path_get(...)	susfs_k_path_get(__VA_ARGS__)
#define path_is_under(...)	susfs_k_path_is_under(__VA_ARGS__)
#define path_put(...)	susfs_k_path_put(__VA_ARGS__)
#define put_unused_fd(...)	susfs_k_put_unused_fd(__VA_ARGS__)
#define putname(...)	susfs_k_putname(__VA_ARGS__)
#define security_inode_follow_link(...)	susfs_k_security_inode_follow_link(__VA_ARGS__)
#define mount_lock	(*susfs_k_mount_lock)
#define rename_lock	(*susfs_k_rename_lock)
#define sysctl_protected_symlinks	(*susfs_k_sysctl_protected_symlinks)

/* Prototypes for every point, so the table above can name their addresses. */
static __nocfi void __set_nameidata(struct nameidata *p, int dfd, struct filename *name);
static __nocfi void set_nameidata(struct nameidata *p, int dfd, struct filename *name, const struct path *root);
static __nocfi void restore_nameidata(void);
static __nocfi bool nd_alloc_stack(struct nameidata *nd);
static __nocfi bool path_connected(struct vfsmount *mnt, struct dentry *dentry);
static __nocfi void drop_links(struct nameidata *nd);
static __nocfi void terminate_walk(struct nameidata *nd);
static __nocfi bool __legitimize_path(struct path *path, unsigned seq, unsigned mseq);
static __nocfi bool legitimize_path(struct nameidata *nd, struct path *path, unsigned seq);
static __nocfi bool legitimize_links(struct nameidata *nd);
static __nocfi bool legitimize_root(struct nameidata *nd);
static __nocfi bool try_to_unlazy(struct nameidata *nd);
static __nocfi bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry, unsigned seq);
static __nocfi int d_revalidate(struct dentry *dentry, unsigned int flags);
static __nocfi int complete_walk(struct nameidata *nd);
static __nocfi int set_root(struct nameidata *nd);
static __nocfi int nd_jump_root(struct nameidata *nd);
static __nocfi void put_link(struct nameidata *nd);
static __nocfi int may_follow_link(struct nameidata *nd, const struct inode *inode);
static __nocfi bool choose_mountpoint_rcu(struct mount *m, const struct path *root, struct path *path, unsigned *seqp);
static __nocfi bool choose_mountpoint(struct mount *m, const struct path *root, struct path *path);
static __nocfi int follow_automount(struct path *path, int *count, unsigned lookup_flags);
static __nocfi int __traverse_mounts(struct path *path, unsigned flags, bool *jumped, int *count, unsigned lookup_flags);
static __nocfi int traverse_mounts(struct path *path, bool *jumped, int *count, unsigned lookup_flags);
static __nocfi bool __follow_mount_rcu(struct nameidata *nd, struct path *path, struct inode **inode, unsigned *seqp);
static __nocfi int handle_mounts(struct nameidata *nd, struct dentry *dentry, struct path *path, struct inode **inode, unsigned int *seqp);
static __nocfi struct dentry *lookup_fast(struct nameidata *nd, struct inode **inode, unsigned *seqp);
static __nocfi struct dentry *__lookup_slow(const struct qstr *name, struct dentry *dir, unsigned int flags);
static __nocfi struct dentry *lookup_slow(const struct qstr *name, struct dentry *dir, unsigned int flags);
static __nocfi int may_lookup(struct user_namespace *mnt_userns, struct nameidata *nd);
static __nocfi int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq);
static __nocfi const char *pick_link(struct nameidata *nd, struct path *link, struct inode *inode, unsigned seq, int flags);
static __nocfi const char *step_into(struct nameidata *nd, int flags, struct dentry *dentry, struct inode *inode, unsigned seq);
static __nocfi struct dentry *follow_dotdot_rcu(struct nameidata *nd, struct inode **inodep, unsigned *seqp);
static __nocfi struct dentry *follow_dotdot(struct nameidata *nd, struct inode **inodep, unsigned *seqp);
static __nocfi const char *handle_dots(struct nameidata *nd, int type);
static __nocfi const char *walk_component(struct nameidata *nd, int flags);
static __nocfi int link_path_walk(const char *name, struct nameidata *nd);
static __nocfi const char *path_init(struct nameidata *nd, unsigned flags);
static __nocfi const char *lookup_last(struct nameidata *nd);
static __nocfi int handle_lookup_down(struct nameidata *nd);
static __nocfi int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path);
static __nocfi struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
static __nocfi struct file *path_openat(struct nameidata *nd, const struct open_flags *op, unsigned flags);
static __nocfi int do_o_path(struct nameidata *nd, unsigned flags, const struct open_flags *op, struct file **out);
static __nocfi struct open_how build_open_how(int flags, umode_t mode);
static __nocfi int build_open_flags(const struct open_how *how, struct open_flags *op);
static __nocfi long do_sys_openat2(int dfd, const char __user *filename, struct open_how *how);
static __nocfi unsigned int susfs_vfs_full_name_hash(const void *salt, const char *name,
						     unsigned int len);
static __nocfi u64 susfs_vfs_hashlen_string(const void *salt, const char *name);
static __nocfi u64 susfs_vfs_hash_name(const void *salt, const char *name);
static __nocfi unsigned int susfs_vfs_fold_hash(unsigned long x, unsigned long y);


/*
 * Forward declaration only: susfs_vfs_copy_open_how() is defined with the entry code
 * further down, while the openat2 branch above it is its first caller - and
 * -Werror,-Wimplicit-function-declaration turns that into a hard error rather than a
 * warning.
 */
static int susfs_vfs_copy_open_how(const void __user *u, size_t usize, struct open_how *out);

/*
 * =====================================================================
 * 3. Parameters and counters
 * =====================================================================
 *
 * Everything that has to be tuned against a device measurement is a runtime-writable
 * parameter, because the measurement (susfs_bench -p 7, the paired
 * hidden-vs-nonexistent difference) can only be taken on the device, and because the
 * right setting depends on how the benchmark's "does not exist" side is looked up.
 */
int vopen_enable = 1;
module_param_named(vopen_enable, vopen_enable, int, 0644);

/* Verdict tracing, declared here with the other parameters: writing N to vopen_dbg logs the
 * next N decisions with their input, filtered to vopen_dbg_name when that is non-empty (it
 * has to be filtered - every process's O_PATH opens pass through this layer, so an unfiltered
 * window drains before the benchmark starts, which is how the first trace came back without
 * the benchmark's own component in it). */
int vopen_dbg;
module_param_named(vopen_dbg, vopen_dbg, int, 0644);

static char vopen_dbg_name[64];
module_param_string(vopen_dbg_name, vopen_dbg_name, sizeof(vopen_dbg_name), 0644);

/* 0 = refuse the hidden component immediately (no extra lookup at all), 1 = always the
 * same derived name for a directory (its negative dentry stays cached, so only the
 * first call pays a real lookup), 2 = a fresh derived name per call (every call pays a
 * real failing lookup).  Which of 1 and 2 is right is decided by what the benchmark's
 * B side costs: if B is a name that has been looked up before, its negative dentry is
 * cached and only mode 1 matches it; if B is looked up cold, only mode 2 does.  Mode 2
 * is the default because it can never come out CHEAPER than a name that is not there,
 * and being cheaper is the side channel.
 *
 * MODE 3 (SUSFS_VFS_FAKE_DISCARD) is the structurally different one: no derived name, no
 * "cache hit that has to be refused", no second lookup.  The same name is looked up for real
 * - the filesystem does exactly the search a name that is not there makes it do - the
 * success is thrown away, and a NEGATIVE dentry for that name is left in the dcache.  The
 * result is that the hidden path and a name that is not there take the same route in BOTH
 * states: one real lookup and -ENOENT when the answer is cold, a negative dcache hit with
 * this layer not consulted when it is warm.  (Cold-then-warm itself is not a channel - every
 * path does it, via the VFS's retention of a hashed negative dentry, fs/dcache.c:642-667 -
 * which is exactly why leaving the negative is required: a shape that drops it, like
 * upstream's, stays cold forever and can be told apart by anyone repeating the same probe.)
 * Its residuals, all measurable, are at susfs_vfs_discard_hidden(): a filesystem whose HIT
 * is much more expensive than its miss (f2fs_iget can read a block for the inode), the
 * -EBUSY case of d_invalidate(), and vopen_neg=0 as the deliberate control that reproduces
 * the always-cold shape. */
int vopen_fake = 2;
module_param_named(vopen_fake, vopen_fake, int, 0644);

/* Mode 3 only, and ON by default because it IS the mode's semantics: leave a NEGATIVE
 * dentry for the real name in the dcache, exactly the way a name that is not there leaves
 * one.  That is what makes the second and later lookups of the hidden path take the
 * identical route to the second and later lookups of a name that is not there - a negative
 * dcache hit, -ENOENT from d_flags_negative(), with this layer not consulted at all (the
 * verdict sees a NULL inode and answers false without doing anything).
 *
 * Turn it OFF only as a CONTROL: with 0 the hidden path answers -ENOENT and leaves nothing,
 * i.e. it stays cold on every call - which is the shape upstream SUSFS produces by dropping
 * the dentry (its "hit + re-look-up with a fixed name" leaves no negative either).  Running
 * -p 7 once with 1 and once with 0 is how that difference is demonstrated: with 0 the hidden
 * path never warms up while a name that is not there does, which is a state difference an
 * observer that repeats its probe would see. */
bool vopen_neg = true;
module_param_named(vopen_neg, vopen_neg, bool, 0644);

/* Measured on the device, and the measurement has a direction: turning this on made the
 * hidden path 6.8us SLOWER than a path that does not exist (diff -6775/-7240), because
 * dropping the hidden dentry costs TWO real lookups - the next lookup of the real name is
 * cold again, and the derived name is looked up after it.  So it is not a parity knob; it
 * is for the case where the hidden dentry must not stay in the dcache at all (a detector
 * that watches dcache-cached state), and it stays off. */
bool vopen_drop;
module_param_named(vopen_drop, vopen_drop, bool, 0644);

bool vopen_drop_fake;
module_param_named(vopen_drop_fake, vopen_drop_fake, bool, 0644);


/* Countdown as well: writing N logs the next N verdict decisions, with their input
 * (dentry name, inode, dev, uid) and their answer, and then stops.  This exists because
 * the device reports a case that cannot happen if the verdict is asked the question the
 * code thinks it asks: the post-check layer - the same predicate, in the same task, on
 * the inode this layer's walk handed out - answers HIDDEN for /proc/susfs_kstat while
 * this layer's own verdict answers "not hidden" for every one of 8640 walks (hidden=0,
 * fa_* whatever, old layer deny +8000).  Two calls that cannot differ must not be
 * guessed about, so from here on the verdict prints its input.  The parameter itself is
 * declared up with the others. */

/*
 * Name filter for the tracing below: with this set, only a component whose dentry name
 * matches it is logged.  Without it the log is useless on a phone - every process's
 * O_PATH opens pass through this layer, and a 200-line window drains long before the
 * benchmark starts, which is exactly how the first trace came back with the benchmark's
 * own component missing.
 */

/*
 * True when this component should be traced (and consumes one from the vopen_dbg
 * countdown).  An empty filter means "everything"; a set one means "only this name", so
 * the countdown cannot be spent on other processes' paths.
 */
static bool susfs_vfs_dbg_on(const char *name, unsigned int len)
{
	unsigned int want = 0, i;

	if (READ_ONCE(vopen_dbg) <= 0)
		return false;

	while (want < sizeof(vopen_dbg_name) && vopen_dbg_name[want])
		want++;
	/* `echo name > param` may leave the newline in the buffer depending on the kernel's
	 * sysfs write path, and a filter that silently never matches would look exactly like
	 * "the component was never judged". */
	while (want && (vopen_dbg_name[want - 1] == '\n' || vopen_dbg_name[want - 1] == '\r'))
		want--;
	if (want) {
		if (want != len)
			return false;
		for (i = 0; i < len; i++)
			if (vopen_dbg_name[i] != name[i])
				return false;
	}

	WRITE_ONCE(vopen_dbg, vopen_dbg - 1);
	return true;
}


/* Not a switch: writing N logs the next N frames and then stops by itself, so a
 * benchmark run cannot turn the self-check into a dmesg flood whose own cost would then
 * be part of the measurement.  Write it again for another batch. */
int vopen_frame;
module_param_named(vopen_frame, vopen_frame, int, 0644);

/* The layout gate: 0 = do not check.  Fill these three from the device's BTF
 * (bpftool/pahole on the device's vmlinux, or the BTF the kernel publishes) before
 * trusting this layer; a non-zero value that disagrees makes the layer refuse to arm. */
unsigned long vopen_nd_size;
module_param_named(vopen_nd_size, vopen_nd_size, ulong, 0644);

unsigned long vopen_nd_internal;
module_param_named(vopen_nd_internal, vopen_nd_internal, ulong, 0644);

unsigned long vopen_nd_state;
module_param_named(vopen_nd_state, vopen_nd_state, ulong, 0644);

static atomic_t n_vopen_seen = ATOMIC_INIT(0);		/* O_PATH calls handed here */
static atomic_t n_vopen_opath = ATOMIC_INIT(0);		/* of those, the ones we answered */
static atomic_t n_vopen_hidden = ATOMIC_INIT(0);	/* components refused as hidden */
static atomic_t n_vopen_faked = ATOMIC_INIT(0);		/* derived-name lookups paid */
static atomic_t n_vopen_cold = ATOMIC_INIT(0);		/* of those, after a real lookup */
static atomic_t n_vopen_dropped = ATOMIC_INIT(0);	/* dentries dropped (vopen_drop) */
static atomic_t n_vopen_collide = ATOMIC_INIT(0);	/* derived name existed (must not) */
static atomic_t n_vopen_err = ATOMIC_INIT(0);
/* Written once at load time, so plain ints: which leaves were absent, and which were
 * present in kallsyms with no callable address (a device difference - see the
 * resolver). */
static unsigned int n_vopen_leaf_missing;
static unsigned int n_vopen_leaf_zero;

/*
 * ---- diagnostics that exist because the first device run could not be read ----------
 *
 * The first measurement on the device left three questions open, and all three are
 * answerable only by counting the right events:
 *
 *   - `faked` stayed 0 while the refuse path was clearly not costing what it should.
 *     The counter sat AFTER `if (IS_ERR(d)) return d;` in susfs_vfs_fake_lookup(), and
 *     that is a place the common outcome on THIS device never reaches: procfs answers a
 *     lookup of a name that does not exist with ERR_PTR(-ENOENT) (fs/proc/generic.c:261,
 *     fs/proc/base.c:2335) rather than handing back a negative dentry, and
 *     __lookup_slow() propagates that error verbatim (fs/namei.c:1663-1668).  So the
 *     counter could not distinguish "the refusal never ran" from "the refusal ran and
 *     the filesystem said ENOENT the way it always does".  The attempt and its outcome
 *     are now counted separately.
 *   - whether the verdict is even CONSULTED for the last component, and what it
 *     answered.  n_vopen_hidden counts the refuse branch of walk_component() (a
 *     different event), so on its own it cannot say which of the two broke.
 *   - which of the seven resolution paths each component took.  That is what turns
 *     "A is 1us cheaper than B" into "A did these steps and not those".
 */
static atomic_t n_vopen_fake_try = ATOMIC_INIT(0);	/* derived-name lookup attempted */
static atomic_t n_vopen_fake_neg = ATOMIC_INIT(0);	/* ... came back as a negative dentry */
static atomic_t n_vopen_fake_enoent = ATOMIC_INIT(0);	/* ... fs answered -ENOENT (procfs) */
static atomic_t n_vopen_fake_other = ATOMIC_INIT(0);	/* ... some other error */

/* Mode 3: how often the result of a REAL-name lookup was judged hidden and thrown away,
 * how often the filesystem refused to let its dentry go (-EBUSY from d_invalidate() - the
 * positive dentry then stays cached and the next call is a dcache hit, so the timing
 * advantage of a cache hit can come back for that entry), and how often a negative dentry
 * was left behind on purpose (vopen_neg). */
static atomic_t n_vopen_discarded = ATOMIC_INIT(0);
static atomic_t n_vopen_inval_fail = ATOMIC_INIT(0);
static atomic_t n_vopen_neg_left = ATOMIC_INIT(0);
/* Discards where the FILESYSTEM did not run: the dcache already held an answer, so this
 * call was cheaper than a cold lookup of a name that is not there.  Non-zero means the
 * positive dentry survived (d_invalidate() said -EBUSY, or the caller never went through
 * the slow path) - the counter to look at first when the -p 7 distribution is bimodal. */
static atomic_t n_vopen_discard_cached = ATOMIC_INIT(0);

/* The verdict counted at its own site: `calls` proves the check is reached for a
 * component, `true` proves the inode matched.  Compared with n_vopen_hidden (the refuse
 * branch) this says whether the verdict and the refusal are wired to each other. */
static atomic_t n_vopen_verdict_calls = ATOMIC_INIT(0);
static atomic_t n_vopen_verdict_true = ATOMIC_INIT(0);

/* Where each component was resolved. */
static atomic_t n_vopen_fa_rcu_hit = ATOMIC_INIT(0);
static atomic_t n_vopen_fa_rcu_miss = ATOMIC_INIT(0);
static atomic_t n_vopen_fa_ref_hit = ATOMIC_INIT(0);
static atomic_t n_vopen_fa_ref_miss = ATOMIC_INIT(0);
static atomic_t n_vopen_wc_hot = ATOMIC_INIT(0);	/* refuse branch taken */
static atomic_t n_vopen_wc_plain = ATOMIC_INIT(0);	/* ordinary slow lookup */
static atomic_t n_vopen_wc_cold = ATOMIC_INIT(0);	/* verdict true after a slow lookup */
static atomic_t n_vopen_wc_commit = ATOMIC_INIT(0);	/* verdict true at the commit point */

/*
 * ENTRY counters: one per copied function, incremented unconditionally at its first
 * statement, before any branch.  These are the only counters that answer "was OUR
 * implementation the one that ran" - the branch counters above cannot, because a branch
 * that is never taken and a function that is never called look the same from them, and
 * the assembly table cannot either: a point labelled "no bl to the child in the parent"
 * may be inlined there, may be called through the vfs table (an indirect call the scan
 * does not recognise), or may not be called by that parent at all.  A counter at the
 * callee's own body counts all three cases correctly - inlining keeps the body's code.
 *
 * Measured need: on the device the verdict ran 3177 times and never judged the trailing
 * component of /proc/susfs_kstat, while the table called every point on that path ours.
 */
static atomic_t n_vopen_enter_link_path_walk = ATOMIC_INIT(0);
static atomic_t n_vopen_enter_lookup_last = ATOMIC_INIT(0);
static atomic_t n_vopen_enter_walk_component = ATOMIC_INIT(0);
static atomic_t n_vopen_enter_step_into = ATOMIC_INIT(0);
static atomic_t n_vopen_enter_handle_mounts = ATOMIC_INIT(0);
static atomic_t n_vopen_enter_lookup_fast = ATOMIC_INIT(0);
static atomic_t n_vopen_enter_lookup_slow = ATOMIC_INIT(0);

/*
 * =====================================================================
 * 4. The assembly table
 * =====================================================================
 *
 * A function pointer per point was chosen over the other load-time binding shape - a
 * stub in our own text whose `movz/movk` immediate is backfilled with
 * ksu_patch_text() - for three reasons, and the last one decides it:
 *
 *   - module text is already read-only by the time init_module() runs
 *     (complete_formation() -> module_enable_ro() happens before the module's init is
 *     called), so a stub's immediate cannot just be written; it needs ksu_patch_text(),
 *     stop_machine() and an icache flush for data that is exactly a pointer.
 *   - a `br x16` stub is a BTI hazard: arm64 kernels are built with
 *     -mbranch-protection=pac-ret+leaf+bti and a kernel function's landing pad is
 *     `bti c`, which accepts a call and NOT a jump.  The BTI-safe stub would be
 *     stp/mov x19/blr x16/mov x30/ldp/ret - a call plus a return, strictly more work
 *     than the indirect call below for the same effect.
 *   - the pointer table already IS the abstraction the next variant needs: "which
 *     implementation runs for this point" is one field per point, and pointing that
 *     field at a body copied into module memory instead of at the kernel symbol is a
 *     change of one assignment.  Nothing about the choice is baked at compile time
 *     except for the points that MUST be ours, where it is not a choice.
 */
struct susfs_vfs_binding;
struct susfs_vfs_edge;

#define SUSFS_VFS_KIND_OURS		0	/* this file's copy, by necessity */
#define SUSFS_VFS_KIND_PREFER_KERNEL	1	/* kernel entity if kallsyms has it */
#define SUSFS_VFS_KIND_OURS_INLINED	2	/* runs inside an ancestor's copy */

struct susfs_vfs_ops {
	void                   (*__set_nameidata)(struct nameidata *p, int dfd, struct filename *name);
	void                   (*set_nameidata)(struct nameidata *p, int dfd, struct filename *name, const struct path *root);
	void                   (*restore_nameidata)(void);
	bool                   (*nd_alloc_stack)(struct nameidata *nd);
	bool                   (*path_connected)(struct vfsmount *mnt, struct dentry *dentry);
	void                   (*drop_links)(struct nameidata *nd);
	void                   (*terminate_walk)(struct nameidata *nd);
	bool                   (*__legitimize_path)(struct path *path, unsigned seq, unsigned mseq);
	bool                   (*legitimize_path)(struct nameidata *nd, struct path *path, unsigned seq);
	bool                   (*legitimize_links)(struct nameidata *nd);
	bool                   (*legitimize_root)(struct nameidata *nd);
	bool                   (*try_to_unlazy)(struct nameidata *nd);
	bool                   (*try_to_unlazy_next)(struct nameidata *nd, struct dentry *dentry, unsigned seq);
	int                    (*d_revalidate)(struct dentry *dentry, unsigned int flags);
	int                    (*complete_walk)(struct nameidata *nd);
	int                    (*set_root)(struct nameidata *nd);
	int                    (*nd_jump_root)(struct nameidata *nd);
	void                   (*put_link)(struct nameidata *nd);
	int                    (*may_follow_link)(struct nameidata *nd, const struct inode *inode);
	bool                   (*choose_mountpoint_rcu)(struct mount *m, const struct path *root, struct path *path, unsigned *seqp);
	bool                   (*choose_mountpoint)(struct mount *m, const struct path *root, struct path *path);
	int                    (*follow_automount)(struct path *path, int *count, unsigned lookup_flags);
	int                    (*__traverse_mounts)(struct path *path, unsigned flags, bool *jumped, int *count, unsigned lookup_flags);
	int                    (*traverse_mounts)(struct path *path, bool *jumped, int *count, unsigned lookup_flags);
	bool                   (*__follow_mount_rcu)(struct nameidata *nd, struct path *path, struct inode **inode, unsigned *seqp);
	int                    (*handle_mounts)(struct nameidata *nd, struct dentry *dentry, struct path *path, struct inode **inode, unsigned int *seqp);
	struct dentry *        (*lookup_fast)(struct nameidata *nd, struct inode **inode, unsigned *seqp);
	struct dentry *        (*__lookup_slow)(const struct qstr *name, struct dentry *dir, unsigned int flags);
	struct dentry *        (*lookup_slow)(const struct qstr *name, struct dentry *dir, unsigned int flags);
	int                    (*may_lookup)(struct user_namespace *mnt_userns, struct nameidata *nd);
	int                    (*reserve_stack)(struct nameidata *nd, struct path *link, unsigned seq);
	const char *           (*pick_link)(struct nameidata *nd, struct path *link, struct inode *inode, unsigned seq, int flags);
	const char *           (*step_into)(struct nameidata *nd, int flags, struct dentry *dentry, struct inode *inode, unsigned seq);
	struct dentry *        (*follow_dotdot_rcu)(struct nameidata *nd, struct inode **inodep, unsigned *seqp);
	struct dentry *        (*follow_dotdot)(struct nameidata *nd, struct inode **inodep, unsigned *seqp);
	const char *           (*handle_dots)(struct nameidata *nd, int type);
	const char *           (*walk_component)(struct nameidata *nd, int flags);
	int                    (*link_path_walk)(const char *name, struct nameidata *nd);
	const char *           (*path_init)(struct nameidata *nd, unsigned flags);
	const char *           (*lookup_last)(struct nameidata *nd);
	int                    (*handle_lookup_down)(struct nameidata *nd);
	int                    (*path_lookupat)(struct nameidata *nd, unsigned flags, struct path *path);
	struct file *          (*do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *op);
	struct file *          (*path_openat)(struct nameidata *nd, const struct open_flags *op, unsigned flags);
	int                    (*do_o_path)(struct nameidata *nd, unsigned flags, const struct open_flags *op, struct file **out);
	struct open_how        (*build_open_how)(int flags, umode_t mode);
	int                    (*build_open_flags)(const struct open_how *how, struct open_flags *op);
	long                   (*do_sys_openat2)(int dfd, const char __user *filename, struct open_how *how);
};

static struct susfs_vfs_ops vfs;

struct susfs_vfs_binding {
	const char	*name;		/* the kallsyms name to try */
	void		**slot;		/* what the copied bodies call through */
	void		*ours;		/* this file's copy */
	void		*kernel;	/* the kallsyms answer, NULL when there is none */
	unsigned int	kind;
};

/* NOT const: the load-time assembly writes kind and kernel here. */
static struct susfs_vfs_binding susfs_vfs_bindings[] = {
	{ "__set_nameidata", (void **)&vfs.__set_nameidata, (void *)&__set_nameidata, NULL, SUSFS_VFS_KIND_OURS },
	{ "set_nameidata", (void **)&vfs.set_nameidata, (void *)&set_nameidata, NULL, SUSFS_VFS_KIND_OURS },
	{ "restore_nameidata", (void **)&vfs.restore_nameidata, (void *)&restore_nameidata, NULL, SUSFS_VFS_KIND_OURS },
	{ "nd_alloc_stack", (void **)&vfs.nd_alloc_stack, (void *)&nd_alloc_stack, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "path_connected", (void **)&vfs.path_connected, (void *)&path_connected, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "drop_links", (void **)&vfs.drop_links, (void *)&drop_links, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "terminate_walk", (void **)&vfs.terminate_walk, (void *)&terminate_walk, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "__legitimize_path", (void **)&vfs.__legitimize_path, (void *)&__legitimize_path, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "legitimize_path", (void **)&vfs.legitimize_path, (void *)&legitimize_path, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "legitimize_links", (void **)&vfs.legitimize_links, (void *)&legitimize_links, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "legitimize_root", (void **)&vfs.legitimize_root, (void *)&legitimize_root, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "try_to_unlazy", (void **)&vfs.try_to_unlazy, (void *)&try_to_unlazy, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "try_to_unlazy_next", (void **)&vfs.try_to_unlazy_next, (void *)&try_to_unlazy_next, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "d_revalidate", (void **)&vfs.d_revalidate, (void *)&d_revalidate, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "complete_walk", (void **)&vfs.complete_walk, (void *)&complete_walk, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "set_root", (void **)&vfs.set_root, (void *)&set_root, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "nd_jump_root", (void **)&vfs.nd_jump_root, (void *)&nd_jump_root, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "put_link", (void **)&vfs.put_link, (void *)&put_link, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "may_follow_link", (void **)&vfs.may_follow_link, (void *)&may_follow_link, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "choose_mountpoint_rcu", (void **)&vfs.choose_mountpoint_rcu, (void *)&choose_mountpoint_rcu, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "choose_mountpoint", (void **)&vfs.choose_mountpoint, (void *)&choose_mountpoint, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "follow_automount", (void **)&vfs.follow_automount, (void *)&follow_automount, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "__traverse_mounts", (void **)&vfs.__traverse_mounts, (void *)&__traverse_mounts, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "traverse_mounts", (void **)&vfs.traverse_mounts, (void *)&traverse_mounts, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "__follow_mount_rcu", (void **)&vfs.__follow_mount_rcu, (void *)&__follow_mount_rcu, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "handle_mounts", (void **)&vfs.handle_mounts, (void *)&handle_mounts, NULL, SUSFS_VFS_KIND_OURS },
	{ "lookup_fast", (void **)&vfs.lookup_fast, (void *)&lookup_fast, NULL, SUSFS_VFS_KIND_OURS },
	{ "__lookup_slow", (void **)&vfs.__lookup_slow, (void *)&__lookup_slow, NULL, SUSFS_VFS_KIND_OURS },
	{ "lookup_slow", (void **)&vfs.lookup_slow, (void *)&lookup_slow, NULL, SUSFS_VFS_KIND_OURS },
	{ "may_lookup", (void **)&vfs.may_lookup, (void *)&may_lookup, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "reserve_stack", (void **)&vfs.reserve_stack, (void *)&reserve_stack, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "pick_link", (void **)&vfs.pick_link, (void *)&pick_link, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "step_into", (void **)&vfs.step_into, (void *)&step_into, NULL, SUSFS_VFS_KIND_OURS },
	{ "follow_dotdot_rcu", (void **)&vfs.follow_dotdot_rcu, (void *)&follow_dotdot_rcu, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "follow_dotdot", (void **)&vfs.follow_dotdot, (void *)&follow_dotdot, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "handle_dots", (void **)&vfs.handle_dots, (void *)&handle_dots, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "walk_component", (void **)&vfs.walk_component, (void *)&walk_component, NULL, SUSFS_VFS_KIND_OURS },
	{ "link_path_walk", (void **)&vfs.link_path_walk, (void *)&link_path_walk, NULL, SUSFS_VFS_KIND_OURS },
	{ "path_init", (void **)&vfs.path_init, (void *)&path_init, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "lookup_last", (void **)&vfs.lookup_last, (void *)&lookup_last, NULL, SUSFS_VFS_KIND_OURS },
	{ "handle_lookup_down", (void **)&vfs.handle_lookup_down, (void *)&handle_lookup_down, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "path_lookupat", (void **)&vfs.path_lookupat, (void *)&path_lookupat, NULL, SUSFS_VFS_KIND_OURS },
	{ "do_filp_open", (void **)&vfs.do_filp_open, (void *)&do_filp_open, NULL, SUSFS_VFS_KIND_OURS },
	{ "path_openat", (void **)&vfs.path_openat, (void *)&path_openat, NULL, SUSFS_VFS_KIND_OURS },
	{ "do_o_path", (void **)&vfs.do_o_path, (void *)&do_o_path, NULL, SUSFS_VFS_KIND_OURS },
	{ "build_open_how", (void **)&vfs.build_open_how, (void *)&build_open_how, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "build_open_flags", (void **)&vfs.build_open_flags, (void *)&build_open_flags, NULL, SUSFS_VFS_KIND_PREFER_KERNEL },
	{ "do_sys_openat2", (void **)&vfs.do_sys_openat2, (void *)&do_sys_openat2, NULL, SUSFS_VFS_KIND_OURS },
};

static unsigned int susfs_vfs_asm_kernel;	/* points bound to a kernel entity */
static unsigned int susfs_vfs_asm_ours;		/* points running our copy */
static unsigned int susfs_vfs_asm_inlined;	/* points inlined into an ancestor */
static bool susfs_vfs_armed;

static inline bool susfs_vfs_open_enabled(void)
{
	return READ_ONCE(susfs_vfs_armed) && READ_ONCE(vopen_enable);
}

static inline const char *susfs_vfs_kind_name(unsigned int kind)
{
	switch (kind) {
	case SUSFS_VFS_KIND_OURS:		return "ours";
	case SUSFS_VFS_KIND_PREFER_KERNEL:	return "prefer-kernel";
	case SUSFS_VFS_KIND_OURS_INLINED:	return "ours-no-bl";
	}
	return "?";
}

static struct susfs_vfs_binding *susfs_vfs_find_binding(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(susfs_vfs_bindings); i++)
		if (!strcmp(susfs_vfs_bindings[i].name, name))
			return &susfs_vfs_bindings[i];
	return NULL;
}

/*
 * =====================================================================
 * 5. The edges, and the "is it inlined?" question
 * =====================================================================
 *
 * An edge is (parent, child) on the real execution path.  At load time both ends are
 * resolved to the implementation that actually runs, and the parent is searched for a
 * `bl` to the child:
 *
 *   parent is OURS, child is called      -> the child has a body of its own and is
 *                                           reached as a call: fine.
 *   parent is OURS, child is NOT called  -> the compiler inlined it: the child is
 *                                           provided by the parent's copy and must not
 *                                           be called a second time as well.  That is
 *                                           the OURS_INLINED state.
 *   parent is the KERNEL's, child is NOT called -> the kernel's parent contains the
 *                                           child's logic.  Harmless for a point nobody
 *                                           needs to change, and a REFUSAL TO ARM when
 *                                           the child is one of ours: the kernel's
 *                                           parent would run the kernel's verdict and
 *                                           the layer would be silently off where it
 *                                           claims to be on.
 *
 * The `bl` decode is done here rather than with the kernel's
 * aarch64_insn_decode_immediate(): that is an unexported lib function whose return
 * convention (raw immediate vs. sign-extended, bytes vs. instructions) has changed
 * between versions, while the 26-bit BL encoding is fixed by the architecture (ARM ARM
 * C6.2.34) and is three lines.
 */
struct susfs_vfs_edge {
	const char	*parent_name;
	const char	*child_name;
	void		*parent;	/* resolved at load time */
	void		*child;
	bool		child_called;
	unsigned int	child_kind;
	unsigned int	parent_kind;
};

/* NOT const: the load-time scan writes the resolved ends and the verdict. */
static struct susfs_vfs_edge susfs_vfs_edges[] = {
	{ "do_sys_openat2", "do_filp_open" },
	{ "do_filp_open", "path_openat" },
	{ "path_openat", "do_o_path" },
	{ "do_o_path", "path_lookupat" },
	{ "path_lookupat", "link_path_walk" },
	{ "path_lookupat", "lookup_last" },
	{ "link_path_walk", "walk_component" },
	{ "lookup_last", "walk_component" },
	{ "walk_component", "lookup_fast" },
	{ "walk_component", "lookup_slow" },
	{ "lookup_slow", "__lookup_slow" },
	{ "walk_component", "step_into" },
	{ "step_into", "handle_mounts" },
};

#define SUSFS_VFS_A64_BL_MASK	0xfc000000u
#define SUSFS_VFS_A64_BL	0x94000000u	/* BL: opcode 100101, imm26 */
#define SUSFS_VFS_A64_B	0x14000000u	/* B: same imm26, a tail call - not an inlining */
#define SUSFS_VFS_SCAN_INSNS	1024		/* 4 KiB window per parent */

static bool susfs_vfs_parent_calls_child(void *parent, void *child)
{
	const u32 *p = parent;
	unsigned long target = (unsigned long)child;
	unsigned int i;

	if (!parent || !child)
		return false;

	/* The bounded window is why this is evidence rather than proof: 4 KiB from the
	 * parent's entry covers every function in this file (the longest copied body is
	 * a few hundred bytes), and it would miss a call site further away in a much
	 * larger function.  A false "not called" is the conservative direction - it makes
	 * an edge look inlined, and an edge that is really a call but looks inlined only
	 * means the child's entry is not used from this file.  The child's BODY is never
	 * removed by that. */
	for (i = 0; i < SUSFS_VFS_SCAN_INSNS; i++) {
		u32 insn = READ_ONCE(p[i]);
		long off;

		if ((insn & SUSFS_VFS_A64_BL_MASK) != SUSFS_VFS_A64_BL &&
		    (insn & SUSFS_VFS_A64_BL_MASK) != SUSFS_VFS_A64_B)
			continue;
		off = (long)((s32)(insn << 6) >> 6);	/* sign-extended imm26 */
		if ((unsigned long)&p[i] + (unsigned long)(off << 2) == target)
			return true;
	}
	return false;
}

/*
 * =====================================================================
 * 6. The frame self-check
 * =====================================================================
 *
 * Two questions, neither answerable from the build host:
 *
 *   (a) IS OUR COPY REALLY RUNNING, IN ITS OWN FRAME?  The premise of this file is
 *       that the kernel's copy of these functions is unreachable on an LTO_FULL
 *       kernel, so "did our copy run at all" has to be observable.  The frame pointer
 *       recorded at the copy's entry sits a fixed distance below the top of the task's
 *       kernel stack, and that distance is a property of the ENTRY (a syscall entry, a
 *       KernelSU dispatch and an io_uring worker thread each leave a different one).  A
 *       body that had been inlined into its caller would report the caller's entry
 *       depth, not the point's; because the record is per point, the two are told
 *       apart by comparing the points.
 *
 *   (b) WHICH PATH CALLED US?  __builtin_return_address(0) is the caller: for an
 *       ordinary openat(2) that is __arm64_sys_openat's neighbourhood, for a
 *       KernelSU-driven call its dispatcher, for an io_uring worker a kthread.  The
 *       name is resolved with ksu_symbol_name_of() (kernel/symbol_resolver.c), the
 *       project's existing lookup, rather than by reimplementing a kallsyms walk.
 *
 * Cost: recording is a few instructions and runs only on the O_PATH path (this file is
 * never entered for any other open).  Resolving a name is expensive, so it happens only
 * while vopen_frame is non-zero - a bring-up switch, not a steady-state one.
 */
enum {
	SUSFS_VFS_FRAME_lookup_fast,
	SUSFS_VFS_FRAME_lookup_slow,
	SUSFS_VFS_FRAME___lookup_slow,
	SUSFS_VFS_FRAME_walk_component,
	SUSFS_VFS_FRAME_step_into,
	SUSFS_VFS_FRAME_handle_mounts,
	SUSFS_VFS_FRAME_path_lookupat,
	SUSFS_VFS_FRAME_link_path_walk,
	SUSFS_VFS_FRAME_do_o_path,
	SUSFS_VFS_FRAME_SLOTS_N,
};

static const char * const susfs_vfs_frame_points[] = {
	"lookup_fast", "lookup_slow", "__lookup_slow", "walk_component", "step_into", "handle_mounts", "path_lookupat", "link_path_walk", "do_o_path"
};

static_assert(ARRAY_SIZE(susfs_vfs_frame_points) == SUSFS_VFS_FRAME_SLOTS_N);

struct susfs_vfs_frame_rec {
	unsigned long	hits;
	unsigned long	lr;
	unsigned long	fp;
	unsigned long	top;
	unsigned int	depth;		/* 0 = the frame pointer is not a valid frame */
};

static struct susfs_vfs_frame_rec susfs_vfs_frames[SUSFS_VFS_FRAME_SLOTS_N];

/*
 * A macro and not a function, because the frame pointer it must read is the CALLER's:
 * __builtin_frame_address(0) inside a helper would return the helper's frame and every
 * point would report the same depth.  arm64 is compiled with frame pointers
 * (arch/arm64/Kconfig selects ARCH_WANT_FRAME_POINTERS and FRAME_POINTER), which is
 * what makes __builtin_frame_address(0) meaningful at all.
 */
#define SUSFS_VFS_FRAME(slot)							\
	do {									\
		unsigned long __fp = (unsigned long)__builtin_frame_address(0);	\
		unsigned long __top = (unsigned long)task_thread_info(current) + THREAD_SIZE; \
		unsigned long __lr = (unsigned long)__builtin_return_address(0); \
		susfs_vfs_frame_note(slot, __fp, __top, __lr);			\
	} while (0)

static __nocfi noinline void susfs_vfs_frame_note(unsigned int slot,
						  unsigned long fp,
						  unsigned long top,
						  unsigned long lr)
{
	struct susfs_vfs_frame_rec *r;

	if (slot >= SUSFS_VFS_FRAME_SLOTS_N)
		return;

	r = &susfs_vfs_frames[slot];
	r->hits++;
	r->lr = lr;
	r->fp = fp;
	r->top = top;
	/* A frame pointer outside this task's kernel stack is reported as depth 0 rather
	 * than as a plausible-looking number: on a kernel built without frame pointers,
	 * this check is the only thing that would notice. */
	r->depth = (fp && fp < top && top - fp < THREAD_SIZE) ?
		   (unsigned int)(top - fp) : 0;

	if (READ_ONCE(vopen_frame) > 0) {
		char buf[KSYM_SYMBOL_LEN];

		/* the countdown itself (see the parameter's comment) */
		WRITE_ONCE(vopen_frame, vopen_frame - 1);
		char *mod = NULL;

		if (ksu_symbol_name_of(lr, buf, &mod) && buf[0])
			SUSFS_LOGI("vfs_open frame: %-18s depth=%-6u lr=%px (%s%s%s)\n",
				   susfs_vfs_frame_points[slot], r->depth, (void *)lr,
				   mod ? mod : "", mod ? ":" : "", buf);
		else
			SUSFS_LOGI("vfs_open frame: %-18s depth=%-6u lr=%px (name unresolved)\n",
				   susfs_vfs_frame_points[slot], r->depth, (void *)lr);
	}
}

/*
 * =====================================================================
 * 7. The derived name, the verdict, and the header-inline stand-ins
 * =====================================================================
 */
static u64 susfs_vfs_salt;
static atomic64_t susfs_vfs_fake_seq = ATOMIC64_INIT(0);

#define SUSFS_VFS_FAKE_LEN	16
#define SUSFS_VFS_FAKE_FIXED	1
#define SUSFS_VFS_FAKE_ROTATING	2
/* mode 3: no derived name at all - the SAME name is looked up for real and the result is
 * then thrown away, so the answer is "this name does not resolve" (see
 * susfs_vfs_discard_hidden()). */
#define SUSFS_VFS_FAKE_DISCARD	3

static void susfs_vfs_fake_name(struct inode *parent, char *out)
{
	static const char hex[] = "0123456789abcdef";
	u64 mix;
	int i;

	mix = susfs_vfs_salt ^ ((u64)parent->i_ino * 0x9E3779B97F4A7C15ULL);
	if (READ_ONCE(vopen_fake) != SUSFS_VFS_FAKE_FIXED)
		mix ^= (u64)atomic64_inc_return(&susfs_vfs_fake_seq) * 0xBF58476D1CE4E5B9ULL;

	/* splitmix64's finaliser.  The name's whole purpose is that it cannot be
	 * guessed, and the salt it is built from is 64 random bits - but a name derived
	 * from an inode by a weak mix is the kind of thing that looks fine until someone
	 * notices the low bits track the inode number, so the full avalanche is applied
	 * and costs nothing here. */
	mix ^= mix >> 30;
	mix *= 0xBF58476D1CE4E5B9ULL;
	mix ^= mix >> 27;
	mix *= 0x94D049BB133111EBULL;
	mix ^= mix >> 31;

	for (i = 0; i < SUSFS_VFS_FAKE_LEN; i++)
		out[i] = hex[(mix >> ((SUSFS_VFS_FAKE_LEN - 1 - i) * 4)) & 0xf];
	out[SUSFS_VFS_FAKE_LEN] = '\0';
}

/*
 * The failing lookup: an ordinary slow lookup of a name that is not there, with the
 * flags the real component would have been looked up with and with LOOKUP_RCU cleared
 * (lookup_slow() takes inode_lock_shared(), so it cannot be reached from RCU mode - and
 * by construction we never are, because the RCU hit is refused through try_to_unlazy()
 * first).
 *
 * The NEGATIVE dentry is handed back to the walk on purpose: step_into() ->
 * handle_mounts() -> traverse_mounts() then turn it into -ENOENT through the ordinary
 * d_flags_negative() path, i.e. the same instructions a genuinely missing name
 * executes.  Returning -ENOENT from here would skip that tail and would show up as a
 * difference again.
 */
static __nocfi struct dentry *susfs_vfs_fake_lookup(struct dentry *dir, unsigned int flags)
{
	char name[SUSFS_VFS_FAKE_LEN + 1];
	struct qstr fake;
	struct dentry *d;

	if (!dir || !d_inode(dir))
		return ERR_PTR(-ENOENT);
	if (!READ_ONCE(vopen_fake))
		return ERR_PTR(-ENOENT);
	if (READ_ONCE(vopen_fake) == SUSFS_VFS_FAKE_DISCARD)
		/* Mode 3 uses no derived name, so reaching here means some path above did not
		 * take the discard route; answer the cheap refusal rather than invent a name
		 * (n_vopen_discarded is what says whether that ever happens). */
		return ERR_PTR(-ENOENT);

	susfs_vfs_fake_name(d_inode(dir), name);
	fake.hash_len = hashlen_create(susfs_vfs_full_name_hash(dir, name, SUSFS_VFS_FAKE_LEN),
				       SUSFS_VFS_FAKE_LEN);
	fake.name = (const unsigned char *)name;

	atomic_inc(&n_vopen_fake_try);
	d = lookup_slow(&fake, dir, flags & ~(LOOKUP_RCU | LOOKUP_PARENT));
	if (IS_ERR(d)) {
		/* Counted by outcome and not by "did it return a dentry": on procfs the
		 * answer to a name that is not there IS an error (ERR_PTR(-ENOENT),
		 * fs/proc/generic.c:261), which is why the original counter - written after
		 * this test - read 0 on a device where every derived-name lookup had in fact
		 * run. */
		if (PTR_ERR(d) == -ENOENT)
			atomic_inc(&n_vopen_fake_enoent);
		else
			atomic_inc(&n_vopen_fake_other);
		return d;
	}
	atomic_inc(&n_vopen_faked);
	atomic_inc(&n_vopen_fake_neg);

	if (unlikely(d_is_positive(d))) {
		/* The derived name exists.  Not supposed to be reachable (the name is
		 * unpredictable), and if it happens it must not become an open: answer
		 * "not there" explicitly instead of letting the walk continue with a file
		 * the caller never named. */
		atomic_inc(&n_vopen_collide);
		if (READ_ONCE(vopen_drop_fake))
			d_invalidate(d);
		dput(d);
		return ERR_PTR(-ENOENT);
	}

	if (READ_ONCE(vopen_drop_fake))
		/* Take the negative dentry back out, so the next call pays for a real
		 * lookup again.  Without this the fixed-name mode converges on a cached
		 * negative, which is CHEAPER than a cold "does not exist" - i.e. it would
		 * hand the hidden path an advantage. */
		d_invalidate(d);

	return d;
}

/*
 * The verdict.  A predicate only, and deliberately callable from RCU mode.  It is safe
 * there for a reason that is not an assumption: this exact predicate is already called
 * from sus_path's LSM hooks, and inode_permission() runs its hook chain during an RCU
 * walk (with MAY_NOT_BLOCK) - the layer's own counters show it firing in the millions
 * on this device.  Internally it is a spinlock plus reads of the rule list, so nothing
 * in it sleeps.
 *
 * It is sus_path's own published decision - sus_path_inode_hidden_public() - and not a
 * second rule engine, so this layer cannot drift from what the LSM layers answer for
 * the same inode (a second implementation is how the O_PATH answer would start
 * disagreeing with inode_getattr/inode_permission).
 */
/*
 * site (only the log uses it; it is what makes a "the verdict says no" report say WHERE
 * it said no, which is the difference between the fast path running and the slow path
 * running):
 *   0  lookup_fast(), RCU hit
 *   1  lookup_fast(), ref-walk hit
 *   2  lookup_fast(), the exit where a revalidate had to be redone after
 *      try_to_unlazy_next() - the way out the device found, which returned the dentry
 *      with no verdict at all before this fix
 *   3  walk_component(), after a slow lookup
 *   4  walk_component(), the commit point, just before step_into()
 *   5  the tail of __lookup_slow(), i.e. the verdict on what the filesystem found for the
 *      caller's own name (mode 3 only)
 */
static __nocfi bool susfs_vfs_hidden_inode(struct dentry *dentry, int site)
{
	struct inode *inode = d_backing_inode(dentry);
	bool hidden;

	if (!inode || !READ_ONCE(susfs_vfs_armed))
		return false;

	atomic_inc(&n_vopen_verdict_calls);
	hidden = sus_path_inode_hidden_public(inode);
	if (hidden)
		atomic_inc(&n_vopen_verdict_true);

	if (susfs_vfs_dbg_on((const char *)dentry->d_name.name, dentry->d_name.len)) {
		/* An input record, not a verdict record: the point is to see which inode the
		 * walk asked about (d_name/d_inode of the dentry it just resolved) next to
		 * the uid that the gate is applied to. */
		pr_info("susfs_vfs_open: verdict site=%d dentry=%.*s ino=%lu dev=%u uid=%u -> hidden=%d\n",
			site, (int)dentry->d_name.len, (const char *)dentry->d_name.name,
			inode->i_ino, inode->i_sb->s_dev, current_uid().val, (int)hidden);
	}
	return hidden;
}

/*
 * MODE 3: "the same name, really looked up, then judged not to exist".
 *
 * Called at the tail of __lookup_slow(), i.e. on the dentry that call ended up with after
 * the filesystem really searched the caller's OWN name (fs_searched says whether the
 * filesystem ran at all - it does not when the dcache already had an answer).  If that name
 * is one we hide, the answer is turned into the answer a name that is not there gets:
 *
 *   1. THE FILESYSTEM REALLY SEARCHED THE REAL NAME.  Not a derived name, not a second
 *      lookup: this is the same ->lookup() call, with the same name, doing the same work a
 *      lookup of a name that is not there makes it do.  That is the whole point of the
 *      mode, and it is why nothing here is a "re-lookup" - upstream's shape (drop the
 *      positive dentry, then look up the fixed name "..5.u.S") spends TWO lookups where a
 *      missing name spends one, which is separable by construction (measured here: the
 *      hit+derived-lookup shape ran 593ns slower than the missing-name path, and dropping
 *      the dentry first, 6.8us slower).
 *   2. THE SUCCESS IS THROWN AWAY: the inode the filesystem found does not become this
 *      walk's answer, and the dentry that carries it leaves the dcache.
 *   3. A NEGATIVE DENTRY FOR THE REAL NAME IS LEFT BEHIND (vopen_neg, default on).  This is
 *      the second watershed against upstream, and it is not about "matching a warm
 *      baseline": cold-then-warm is simply what every path does on this kernel, because the
 *      VFS retains a hashed dentry whose filesystem does not veto it (fs/dcache.c:642-667,
 *      retain_dentry() - the last reference is dropped and the dentry stays on the LRU,
 *      negative or not).  What keeping it buys is that the SECOND lookup of the hidden
 *      path takes the same route as the second lookup of a name that is not there: a
 *      negative dcache hit, -ENOENT out of d_flags_negative(), and this layer is not
 *      consulted at all (the verdict gets a NULL inode and returns false immediately).
 *      Upstream's shape leaves nothing behind, so its hidden path stays cold forever while
 *      a name that is not there warms up - a state difference, visible to anyone who
 *      repeats the same probe.  With vopen_neg=0 this mode deliberately reproduces that
 *      shape, as a control.
 *   4. ONLY THE POSITIVE ANSWER IS INVALIDATED, never a negative of ours: d_invalidate()
 *      takes this dentry out of the dcache (whether it is the one __lookup_slow allocated
 *      or the alias the filesystem returned through d_splice_alias() - both are "the
 *      positive answer" here), and it does not disturb anyone else: a holder keeps its
 *      dentry and its inode, the only visible effect being that the next lookup asks the
 *      filesystem again.  It can refuse with -EBUSY (a mountpoint, a busy directory), which
 *      is counted, because then that positive dentry stays cached and the next call is a
 *      dcache hit that does not make the filesystem search - the case that shows up as a
 *      fast mode in the -p 7 distribution.
 *   5. NO SECOND LOOKUP, NO DERIVED NAME, anywhere in this mode.  The lookup count of the
 *      hidden path is the lookup count of a name that is not there: one per cold call and
 *      zero per warm call.
 *
 * THE CONCURRENCY RULES, in the order they matter:
 *   (a) The discard happens AFTER d_lookup_done().  While the dentry is in the in-lookup
 *       state (DCACHE_PAR_LOOKUP) other lookups of the same name wait on its d_wait queue,
 *       and d_lookup_done() is what releases them with this dentry as the answer - dropping
 *       it before that call would hand a waiter a dentry that is about to be killed.
 *       __lookup_slow() already calls d_lookup_done() before this function runs.
 *   (b) Even in that order, a lookup that was already waiting on THIS dentry can come away
 *       holding it.  That is this mode's residual race: a positive dentry for a hidden name
 *       can reach that other walk for the few hundred nanoseconds until the discard lands.
 *       It cannot become a leak - the LSM layer answers the same inode with -ENOENT and the
 *       post-check takes the descriptor away - but it is a real difference from mode 2,
 *       where the dentry was never published as anything but negative (that is also why
 *       mode 3 keeps the walk's own answer negative instead of handing the positive one on).
 *   (c) That same window also means two threads looking up the SAME hidden name can each
 *       hash a negative for it: the filesystem path goes through the VFS's in-lookup
 *       protocol (d_alloc_parallel()) while this one inserts with a plain d_alloc()/d_add().
 *       Two negative dentries for one name are harmless - d_lookup() answers with the first,
 *       the duplicate is unreferenced and reclaimed through the LRU - and it only happens
 *       when two lookups of the same hidden name genuinely overlap.
 *
 * HONEST LIMIT: the cold call here costs what a filesystem HIT costs, and on a filesystem
 * whose hit is much more expensive than its miss that is more than the missing-name path
 * pays - f2fs_lookup() on a found entry calls f2fs_iget(), which can read a block for the
 * inode, while the miss path only fails a directory scan.  Nothing here can fix that (it is
 * what "the file exists" costs on that filesystem); the measurement that shows it is the
 * -p 7 p50 difference between vopen_fake=2 and vopen_fake=3 on that filesystem, and the
 * answer there is to keep mode 2.
 */
static __nocfi struct dentry *susfs_vfs_discard_hidden(struct dentry *dir,
						       const struct qstr *name,
						       struct dentry *dentry,
						       bool fs_searched)
{
	if (READ_ONCE(vopen_fake) != SUSFS_VFS_FAKE_DISCARD)
		return dentry;
	/* A negative or an errored answer is a miss already - leave it alone (this is B's
	 * own path, and it is also what the warm state of A looks like). */
	if (!dentry || IS_ERR(dentry) || d_is_negative(dentry))
		return dentry;
	if (!susfs_vfs_hidden_inode(dentry, 5))
		return dentry;

	atomic_inc(&n_vopen_discarded);
	if (!fs_searched)
		atomic_inc(&n_vopen_discard_cached);

	/* d_invalidate() may refuse; either way the dentry stops being ours here. */
	if (d_invalidate(dentry))
		atomic_inc(&n_vopen_inval_fail);
	dput(dentry);

	if (!READ_ONCE(vopen_neg))
		return ERR_PTR(-ENOENT);

	/* Leave the negative a name that is not there leaves.  d_alloc() never returns an
	 * existing dentry, so this cannot hand back the positive one we just threw away, and
	 * d_add() with a NULL inode is exactly "this name is not here" in the dcache. */
	{
		struct dentry *neg = d_alloc(dir, name);

		if (unlikely(!neg))
			return ERR_PTR(-ENOMEM);
		d_add(neg, NULL);
		atomic_inc(&n_vopen_neg_left);
		return neg;
	}
}

static __nocfi void susfs_vfs_drop_hidden(struct dentry *dentry)
{
	if (!READ_ONCE(vopen_drop))
		return;
	/* d_invalidate() may refuse (a busy dentry, a mountpoint); that is not an error
	 * here - it only means this dentry stays a cache hit, i.e. the vopen_drop=0
	 * behaviour. */
	d_invalidate(dentry);
	atomic_inc(&n_vopen_dropped);
}

/* Header inlines that would otherwise reach a non-exported symbol. */
/*
 * Is this name known to the kernel but without a callable address?  See the resolver
 * for why the .cfi_jt sibling answers this and ksu_find_symbol_all() cannot.
 */
static bool susfs_vfs_name_present_at_zero(const char *name)
{
	char cfi[128];

	if (snprintf(cfi, sizeof(cfi), "%s.cfi_jt", name) >= (int)sizeof(cfi))
		return false;
	return find_kernel_symbol_exact(cfi) != 0;
}

static __nocfi void *susfs_vfs_kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	size_t bytes;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;
	return susfs_k___kmalloc(bytes, flags);
}

static __nocfi void *susfs_vfs_memcpy(void *dst, const void *src, size_t n)
{
	return susfs_k_memcpy(dst, src, n);
}

static __nocfi void susfs_vfs_cond_resched(void)
{
	/* Optional (see OPTIONAL_LEAVES in the leaf section): without it a long path walk
	 * simply never yields the CPU. */
	if (susfs_k___cond_resched)
		susfs_k___cond_resched();
}

static inline struct fd susfs_vfs_fdget_raw(unsigned int fd)
{
	return __to_fd(susfs_k___fdget_raw(fd));
}

/* ==== copied from namei.c:2002-2211  (hash machinery (HASH_MIX/fold_hash/full_name_hash/hashlen_string/hash_name)) ==== */
#ifdef CONFIG_DCACHE_WORD_ACCESS

#include <asm/word-at-a-time.h>

#ifdef HASH_MIX

/* Architecture provides HASH_MIX and susfs_vfs_fold_hash() in <asm/hash.h> */

#elif defined(CONFIG_64BIT)
/*
 * Register pressure in the mixing function is an issue, particularly
 * on 32-bit x86, but almost any function requires one state value and
 * one temporary.  Instead, use a function designed for two state values
 * and no temporaries.
 *
 * This function cannot create a collision in only two iterations, so
 * we have two iterations to achieve avalanche.  In those two iterations,
 * we have six layers of mixing, which is enough to spread one bit's
 * influence out to 2^6 = 64 state bits.
 *
 * Rotate constants are scored by considering either 64 one-bit input
 * deltas or 64*63/2 = 2016 two-bit input deltas, and finding the
 * probability of that delta causing a change to each of the 128 output
 * bits, using a sample of random initial states.
 *
 * The Shannon entropy of the computed probabilities is then summed
 * to produce a score.  Ideally, any input change has a 50% chance of
 * toggling any given output bit.
 *
 * Mixing scores (in bits) for (12,45):
 * Input delta: 1-bit      2-bit
 * 1 round:     713.3    42542.6
 * 2 rounds:   2753.7   140389.8
 * 3 rounds:   5954.1   233458.2
 * 4 rounds:   7862.6   256672.2
 * Perfect:    8192     258048
 *            (64*128) (64*63/2 * 128)
 */
#define HASH_MIX(x, y, a)	\
	(	x ^= (a),	\
	y ^= x,	x = rol64(x,12),\
	x += y,	y = rol64(y,45),\
	y *= 9			)

/*
 * Fold two longs into one 32-bit hash value.  This must be fast, but
 * latency isn't quite as critical, as there is a fair bit of additional
 * work done before the hash value is used.
 */
static inline __nocfi unsigned int susfs_vfs_fold_hash(unsigned long x, unsigned long y)
{
	y ^= x * GOLDEN_RATIO_64;
	y *= GOLDEN_RATIO_64;
	return y >> 32;
}

#else	/* 32-bit case */

/*
 * Mixing scores (in bits) for (7,20):
 * Input delta: 1-bit      2-bit
 * 1 round:     330.3     9201.6
 * 2 rounds:   1246.4    25475.4
 * 3 rounds:   1907.1    31295.1
 * 4 rounds:   2042.3    31718.6
 * Perfect:    2048      31744
 *            (32*64)   (32*31/2 * 64)
 */
#define HASH_MIX(x, y, a)	\
	(	x ^= (a),	\
	y ^= x,	x = rol32(x, 7),\
	x += y,	y = rol32(y,20),\
	y *= 9			)

static inline __nocfi unsigned int susfs_vfs_fold_hash(unsigned long x, unsigned long y)
{
	/* Use arch-optimized multiply if one exists */
	return __hash_32(y ^ __hash_32(x));
}

#endif

/*
 * Return the hash of a string of known length.  This is carfully
 * designed to match susfs_vfs_hash_name(), which is the more critical function.
 * In particular, we must end by hashing a final word containing 0..7
 * payload bytes, to match the way that susfs_vfs_hash_name() iterates until it
 * finds the delimiter after the name.
 */
static __nocfi unsigned int susfs_vfs_full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned long a, x = 0, y = (unsigned long)salt;

	for (;;) {
		if (!len)
			goto done;
		a = load_unaligned_zeropad(name);
		if (len < sizeof(unsigned long))
			break;
		HASH_MIX(x, y, a);
		name += sizeof(unsigned long);
		len -= sizeof(unsigned long);
	}
	x ^= a & bytemask_from_count(len);
done:
	return susfs_vfs_fold_hash(x, y);
}

/* Return the "hash_len" (hash and length) of a null-terminated string */
static __nocfi u64 susfs_vfs_hashlen_string(const void *salt, const char *name)
{
	unsigned long a = 0, x = 0, y = (unsigned long)salt;
	unsigned long adata, mask, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = 0;
	goto inside;

	do {
		HASH_MIX(x, y, a);
		len += sizeof(unsigned long);
inside:
		a = load_unaligned_zeropad(name+len);
	} while (!has_zero(a, &adata, &constants));

	adata = prep_zero_mask(a, adata, &constants);
	mask = create_zero_mask(adata);
	x ^= a & zero_bytemask(mask);

	return hashlen_create(susfs_vfs_fold_hash(x, y), len + find_zero(mask));
}

/*
 * Calculate the length and hash of the path component, and
 * return the "hash_len" as the result.
 */
static inline __nocfi u64 susfs_vfs_hash_name(const void *salt, const char *name)
{
	unsigned long a = 0, b, x = 0, y = (unsigned long)salt;
	unsigned long adata, bdata, mask, len;
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;

	len = 0;
	goto inside;

	do {
		HASH_MIX(x, y, a);
		len += sizeof(unsigned long);
inside:
		a = load_unaligned_zeropad(name+len);
		b = a ^ REPEAT_BYTE('/');
	} while (!(has_zero(a, &adata, &constants) | has_zero(b, &bdata, &constants)));

	adata = prep_zero_mask(a, adata, &constants);
	bdata = prep_zero_mask(b, bdata, &constants);
	mask = create_zero_mask(adata | bdata);
	x ^= a & zero_bytemask(mask);

	return hashlen_create(susfs_vfs_fold_hash(x, y), len + find_zero(mask));
}

#else	/* !CONFIG_DCACHE_WORD_ACCESS: Slow, byte-at-a-time version */

/* Return the hash of a string of known length */
static __nocfi unsigned int susfs_vfs_full_name_hash(const void *salt, const char *name, unsigned int len)
{
	unsigned long hash = init_name_hash(salt);
	while (len--)
		hash = partial_name_hash((unsigned char)*name++, hash);
	return end_name_hash(hash);
}

/* Return the "hash_len" (hash and length) of a null-terminated string */
static __nocfi u64 susfs_vfs_hashlen_string(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	while (c) {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	}
	return hashlen_create(end_name_hash(hash), len);
}

/*
 * We know there's a real path component here of at least
 * one character.
 */
static inline __nocfi u64 susfs_vfs_hash_name(const void *salt, const char *name)
{
	unsigned long hash = init_name_hash(salt);
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	do {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	} while (c && c != '/');
	return hashlen_create(end_name_hash(hash), len);
}

#endif

/* ==== copied from namei.c:564-591  (EMBEDDED_LEVELS + struct nameidata + ND_* defines) ==== */
#define EMBEDDED_LEVELS 2
struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags, state;
	unsigned	seq, m_seq, r_seq;
	int		last_type;
	unsigned	depth;
	int		total_link_count;
	struct saved {
		struct path link;
		struct delayed_call done;
		const char *name;
		unsigned seq;
	} *stack, internal[EMBEDDED_LEVELS];
	struct filename	*name;
	struct nameidata *saved;
	unsigned	root_seq;
	int		dfd;
	kuid_t		dir_uid;
	umode_t		dir_mode;
} __randomize_layout;

/*
 * ---- the layout gate, and why nothing of ours is inside this struct ----
 *
 * This struct is SHARED with the kernel: __set_nameidata() points current->nameidata
 * at it, and the kernel's own code then reads it through the KERNEL's layout -
 * nd_jump_link() (fs/namei.c:989) is the one an O_PATH open can reach, from a procfs
 * magic link's ->get_link while LOOKUP_FOLLOW is set, and it reads nd->flags,
 * nd->path, nd->inode and nd->state while the struct lives on THIS MODULE'S stack.
 *
 * The three asserts below are therefore the three numbers the DEVICE reports for
 * this struct (5.15.180, read from BTF: sizeof = 224, offsetof(state) = 60,
 * offsetof(internal) = 96).  A mismatch has to break the BUILD rather than the
 * phone, and the gate caught a real defect once: an earlier version of this file
 * appended a private field here, which made our copy 240 bytes against the device's
 * 224 while every other check still passed.  Nothing of ours goes inside this struct
 * any more - the walk's private state lives in struct susfs_vfs_nd below, whose
 * FIRST member is this struct, so the pointer the kernel follows starts at the
 * kernel's idea of the layout and ends exactly where the kernel's struct ends.
 *
 * What these asserts cannot do is speak for the device: they pin the layout this
 * file was derived from, and the vopen_nd_* parameters re-check the same three
 * numbers at load time against whatever that device's BTF says.
 */
static_assert(sizeof(struct nameidata) == 224);
static_assert(offsetof(struct nameidata, state) == 60);
static_assert(offsetof(struct nameidata, internal) == 96);
static_assert(EMBEDDED_LEVELS == 2);
static_assert(sizeof(((struct nameidata *)0)->internal) ==
	      EMBEDDED_LEVELS * sizeof(struct saved));
static_assert(offsetof(struct nameidata, state) ==
	      offsetof(struct nameidata, flags) + sizeof(unsigned int));
static_assert(offsetof(struct nameidata, internal) +
	      sizeof(((struct nameidata *)0)->internal) == offsetof(struct nameidata, name));

/*
 * The wrapper this walk's private state lives in.  `nd` MUST stay the first member:
 * that is what makes &w.nd both the address the kernel follows through
 * current->nameidata and the address every copied body in this file already expects,
 * i.e. what makes this a pure container rather than a second struct.
 */
struct susfs_vfs_nd {
	struct nameidata nd;
	u64 hidden_last;	/* this component's hit was refused as hidden */
};

static_assert(offsetof(struct susfs_vfs_nd, nd) == 0);

/*
 * container_of(), and reached through a FUNCTION and not through a macro - which is a
 * lesson this file paid for in CI.  The wrapper is only ever entered from this file's
 * own walks: every one of them starts in do_filp_open() below, which is the only place
 * set_nameidata() is called, and the private field is only touched by points bound to
 * our own copies (lookup_fast, walk_component, __set_nameidata), so no kernel copy of
 * a function can be holding one of these pointers instead.
 *
 * It was `#define SUSFS_VFS_ND(nd) container_of((nd), struct susfs_vfs_nd, nd)` first,
 * and that is subtly wrong: a function-like macro substitutes its argument into EVERY
 * occurrence of the parameter, including the one that has to stay the MEMBER NAME.  So
 * the definition happened to be right only for call sites whose expression was spelled
 * `nd`; SUSFS_VFS_ND(p) - the __set_nameidata() call site, where the variable is called
 * p - expanded into container_of((p), struct susfs_vfs_nd, p), i.e. into a search for a
 * member named `p`.  container_of() checks precisely that with __same_type()
 * (include/linux/kernel.h:497), so the build failed with
 *
 *     error: no member named 'p' in 'struct susfs_vfs_nd'
 *
 * A static inline function cannot have that failure mode: its parameter is an ordinary
 * local name and the member name stays a literal.  This is called on the hot path
 * (lookup_fast, walk_component), and it costs nothing there because the compiler inlines
 * it - the whole body is an address adjustment plus the same __same_type() check, which
 * is compile-time.
 */
static inline struct susfs_vfs_nd *susfs_vfs_nd_of(struct nameidata *nd)
{
	return container_of(nd, struct susfs_vfs_nd, nd);
}

#define ND_ROOT_PRESET 1
#define ND_ROOT_GRABBED 2
#define ND_JUMPED 4

/* ==== copied from namei.c:593-616  (__set_nameidata + set_nameidata) ==== */
static __nocfi void __set_nameidata(struct nameidata *p, int dfd, struct filename *name)
{
	struct nameidata *old = current->nameidata;

	/* The private state is ours alone, so only we may initialise it - and it must be
	 * initialised on EVERY walk: the wrapper is an uninitialised stack object in
	 * do_filp_open(), and hidden_last is read by walk_component() on the first
	 * component of that walk. */
	susfs_vfs_nd_of(p)->hidden_last = 0;

	p->stack = p->internal;
	p->depth = 0;
	p->dfd = dfd;
	p->name = name;
	p->path.mnt = NULL;
	p->path.dentry = NULL;
	p->total_link_count = old ? old->total_link_count : 0;
	p->saved = old;
	current->nameidata = p;
}

static inline __nocfi void set_nameidata(struct nameidata *p, int dfd, struct filename *name,
			  const struct path *root)
{
	__set_nameidata(p, dfd, name);
	p->state = 0;
	if (unlikely(root)) {
		p->state = ND_ROOT_PRESET;
		p->root = *root;
	}
}

/* ==== copied from namei.c:618-640  (restore_nameidata + nd_alloc_stack) ==== */
static __nocfi void restore_nameidata(void)
{
	struct nameidata *now = current->nameidata, *old = now->saved;

	current->nameidata = old;
	if (old)
		old->total_link_count = now->total_link_count;
	if (now->stack != now->internal)
		kfree(now->stack);
}

static __nocfi bool nd_alloc_stack(struct nameidata *nd)
{
	struct saved *p;

	p= susfs_vfs_kmalloc_array(MAXSYMLINKS, sizeof(struct saved),
			 nd->flags & LOOKUP_RCU ? GFP_ATOMIC : GFP_KERNEL);
	if (unlikely(!p))
		return false;
	susfs_vfs_memcpy(p, nd->internal, sizeof(nd->internal));
	nd->stack = p;
	return true;
}

/* ==== copied from namei.c:642-667  (path_connected + drop_links) ==== */
/**
 * path_connected - Verify that a dentry is below mnt.mnt_root
 *
 * Rename can sometimes move a file or directory outside of a bind
 * mount, path_connected allows those cases to be detected.
 */
static __nocfi bool path_connected(struct vfsmount *mnt, struct dentry *dentry)
{
	struct super_block *sb = mnt->mnt_sb;

	/* Bind mounts can have disconnected paths */
	if (mnt->mnt_root == sb->s_root)
		return true;

	return is_subdir(dentry, mnt->mnt_root);
}

static __nocfi void drop_links(struct nameidata *nd)
{
	int i = nd->depth;
	while (i--) {
		struct saved *last = nd->stack + i;
		do_delayed_call(&last->done);
		clear_delayed_call(&last->done);
	}
}

/* ==== copied from namei.c:669-711  (terminate_walk + __legitimize_path + legitimize_path) ==== */
static __nocfi void terminate_walk(struct nameidata *nd)
{
	vfs.drop_links(nd);
	if (!(nd->flags & LOOKUP_RCU)) {
		int i;
		path_put(&nd->path);
		for (i = 0; i < nd->depth; i++)
			path_put(&nd->stack[i].link);
		if (nd->state & ND_ROOT_GRABBED) {
			path_put(&nd->root);
			nd->state &= ~ND_ROOT_GRABBED;
		}
	} else {
		nd->flags &= ~LOOKUP_RCU;
		rcu_read_unlock();
	}
	nd->depth = 0;
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;
}

/* path_put is needed afterwards regardless of success or failure */
static __nocfi bool __legitimize_path(struct path *path, unsigned seq, unsigned mseq)
{
	int res = __legitimize_mnt(path->mnt, mseq);
	if (unlikely(res)) {
		if (res > 0)
			path->mnt = NULL;
		path->dentry = NULL;
		return false;
	}
	if (unlikely(!lockref_get_not_dead(&path->dentry->d_lockref))) {
		path->dentry = NULL;
		return false;
	}
	return !read_seqcount_retry(&path->dentry->d_seq, seq);
}

static inline __nocfi bool legitimize_path(struct nameidata *nd,
			    struct path *path, unsigned seq)
{
	return vfs.__legitimize_path(path, seq, nd->m_seq);
}

/* ==== copied from namei.c:713-746  (legitimize_links + legitimize_root) ==== */
static __nocfi bool legitimize_links(struct nameidata *nd)
{
	int i;
	if (unlikely(nd->flags & LOOKUP_CACHED)) {
		vfs.drop_links(nd);
		nd->depth = 0;
		return false;
	}
	for (i = 0; i < nd->depth; i++) {
		struct saved *last = nd->stack + i;
		if (unlikely(!vfs.legitimize_path(nd, &last->link, last->seq))) {
			vfs.drop_links(nd);
			nd->depth = i + 1;
			return false;
		}
	}
	return true;
}

static __nocfi bool legitimize_root(struct nameidata *nd)
{
	/*
	 * For scoped-lookups (where nd->root has been zeroed), we need to
	 * restart the whole lookup from scratch -- because set_root() is wrong
	 * for these lookups (nd->dfd is the root, not the filesystem root).
	 */
	if (!nd->root.mnt && (nd->flags & LOOKUP_IS_SCOPED))
		return false;
	/* Nothing to do if nd->root is zero or is managed by the VFS user. */
	if (!nd->root.mnt || (nd->state & ND_ROOT_PRESET))
		return true;
	nd->state |= ND_ROOT_GRABBED;
	return vfs.legitimize_path(nd, &nd->root, nd->root_seq);
}

/* ==== copied from namei.c:759-793  (try_to_unlazy) ==== */
/**
 * try_to_unlazy - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * Returns: true on success, false on failure
 *
 * try_to_unlazy attempts to legitimize the current nd->path and nd->root
 * for ref-walk mode.
 * Must be called from rcu-walk context.
 * Nothing should touch nameidata between try_to_unlazy() failure and
 * terminate_walk().
 */
static __nocfi bool try_to_unlazy(struct nameidata *nd)
{
	struct dentry *parent = nd->path.dentry;

	BUG_ON(!(nd->flags & LOOKUP_RCU));

	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!vfs.legitimize_links(nd)))
		goto out1;
	if (unlikely(!vfs.legitimize_path(nd, &nd->path, nd->seq)))
		goto out;
	if (unlikely(!vfs.legitimize_root(nd)))
		goto out;
	rcu_read_unlock();
	BUG_ON(nd->inode != parent->d_inode);
	return true;

out1:
	nd->path.mnt = NULL;
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
	return false;
}

/* ==== copied from namei.c:795-851  (try_to_unlazy_next) ==== */
/**
 * try_to_unlazy_next - try to switch to ref-walk mode.
 * @nd: nameidata pathwalk data
 * @dentry: next dentry to step into
 * @seq: seq number to check @dentry against
 * Returns: true on success, false on failure
 *
 * Similar to to try_to_unlazy(), but here we have the next dentry already
 * picked by rcu-walk and want to legitimize that in addition to the current
 * nd->path and nd->root for ref-walk mode.  Must be called from rcu-walk context.
 * Nothing should touch nameidata between try_to_unlazy_next() failure and
 * terminate_walk().
 */
static __nocfi bool try_to_unlazy_next(struct nameidata *nd, struct dentry *dentry, unsigned seq)
{
	BUG_ON(!(nd->flags & LOOKUP_RCU));

	nd->flags &= ~LOOKUP_RCU;
	if (unlikely(!vfs.legitimize_links(nd)))
		goto out2;
	if (unlikely(!legitimize_mnt(nd->path.mnt, nd->m_seq)))
		goto out2;
	if (unlikely(!lockref_get_not_dead(&nd->path.dentry->d_lockref)))
		goto out1;

	/*
	 * We need to move both the parent and the dentry from the RCU domain
	 * to be properly refcounted. And the sequence number in the dentry
	 * validates *both* dentry counters, since we checked the sequence
	 * number of the parent after we got the child sequence number. So we
	 * know the parent must still be valid if the child sequence number is
	 */
	if (unlikely(!lockref_get_not_dead(&dentry->d_lockref)))
		goto out;
	if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
		goto out_dput;
	/*
	 * Sequence counts matched. Now make sure that the root is
	 * still valid and get it if required.
	 */
	if (unlikely(!vfs.legitimize_root(nd)))
		goto out_dput;
	rcu_read_unlock();
	return true;

out2:
	nd->path.mnt = NULL;
out1:
	nd->path.dentry = NULL;
out:
	rcu_read_unlock();
	return false;
out_dput:
	rcu_read_unlock();
	dput(dentry);
	return false;
}

/* ==== copied from namei.c:853-859  (d_revalidate) ==== */
static inline __nocfi int d_revalidate(struct dentry *dentry, unsigned int flags)
{
	if (unlikely(dentry->d_flags & DCACHE_OP_REVALIDATE))
		return dentry->d_op->d_revalidate(dentry, flags);
	else
		return 1;
}

/* ==== copied from namei.c:861-924  (complete_walk) ==== */
/**
 * complete_walk - successful completion of path walk
 * @nd:  pointer nameidata
 *
 * If we had been in RCU mode, drop out of it and legitimize nd->path.
 * Revalidate the final result, unless we'd already done that during
 * the path walk or the filesystem doesn't ask for it.  Return 0 on
 * success, -error on failure.  In case of failure caller does not
 * need to drop nd->path.
 */
static __nocfi int complete_walk(struct nameidata *nd)
{
	struct dentry *dentry = nd->path.dentry;
	int status;

	if (nd->flags & LOOKUP_RCU) {
		/*
		 * We don't want to zero nd->root for scoped-lookups or
		 * externally-managed nd->root.
		 */
		if (!(nd->state & ND_ROOT_PRESET))
			if (!(nd->flags & LOOKUP_IS_SCOPED))
				nd->root.mnt = NULL;
		nd->flags &= ~LOOKUP_CACHED;
		if (!vfs.try_to_unlazy(nd))
			return -ECHILD;
	}

	if (unlikely(nd->flags & LOOKUP_IS_SCOPED)) {
		/*
		 * While the guarantee of LOOKUP_IS_SCOPED is (roughly) "don't
		 * ever step outside the root during lookup" and should already
		 * be guaranteed by the rest of namei, we want to avoid a namei
		 * BUG resulting in userspace being given a path that was not
		 * scoped within the root at some point during the lookup.
		 *
		 * So, do a final sanity-check to make sure that in the
		 * worst-case scenario (a complete bypass of LOOKUP_IS_SCOPED)
		 * we won't silently return an fd completely outside of the
		 * requested root to userspace.
		 *
		 * Userspace could move the path outside the root after this
		 * check, but as discussed elsewhere this is not a concern (the
		 * resolved file was inside the root at some point).
		 */
		if (!path_is_under(&nd->path, &nd->root))
			return -EXDEV;
	}

	if (likely(!(nd->state & ND_JUMPED)))
		return 0;

	if (likely(!(dentry->d_flags & DCACHE_OP_WEAK_REVALIDATE)))
		return 0;

	status = dentry->d_op->d_weak_revalidate(dentry, nd->flags);
	if (status > 0)
		return 0;

	if (!status)
		status = -ESTALE;

	return status;
}

/* ==== copied from namei.c:926-951  (set_root) ==== */
static __nocfi int set_root(struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;

	/*
	 * Jumping to the real root in a scoped-lookup is a BUG in namei, but we
	 * still have to ensure it doesn't happen because it will cause a breakout
	 * from the dirfd.
	 */
	if (WARN_ON(nd->flags & LOOKUP_IS_SCOPED))
		return -ENOTRECOVERABLE;

	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;

		do {
			seq = read_seqcount_begin(&fs->seq);
			nd->root = fs->root;
			nd->root_seq = __read_seqcount_begin(&nd->root.dentry->d_seq);
		} while (read_seqcount_retry(&fs->seq, seq));
	} else {
		get_fs_root(fs, &nd->root);
		nd->state |= ND_ROOT_GRABBED;
	}
	return 0;
}

/* ==== copied from namei.c:953-983  (nd_jump_root) ==== */
static __nocfi int nd_jump_root(struct nameidata *nd)
{
	if (unlikely(nd->flags & LOOKUP_BENEATH))
		return -EXDEV;
	if (unlikely(nd->flags & LOOKUP_NO_XDEV)) {
		/* Absolute path arguments to vfs.path_init() are allowed. */
		if (nd->path.mnt != NULL && nd->path.mnt != nd->root.mnt)
			return -EXDEV;
	}
	if (!nd->root.mnt) {
		int error = vfs.set_root(nd);
		if (error)
			return error;
	}
	if (nd->flags & LOOKUP_RCU) {
		struct dentry *d;
		nd->path = nd->root;
		d = nd->path.dentry;
		nd->inode = d->d_inode;
		nd->seq = nd->root_seq;
		if (unlikely(read_seqcount_retry(&d->d_seq, nd->seq)))
			return -ECHILD;
	} else {
		path_put(&nd->path);
		nd->path = nd->root;
		path_get(&nd->path);
		nd->inode = nd->path.dentry->d_inode;
	}
	nd->state |= ND_JUMPED;
	return 0;
}

/* ==== copied from namei.c:1017-1023  (put_link) ==== */
static inline __nocfi void put_link(struct nameidata *nd)
{
	struct saved *last = nd->stack + --nd->depth;
	do_delayed_call(&last->done);
	if (!(nd->flags & LOOKUP_RCU))
		path_put(&last->link);
}

/* ==== copied from namei.c:1030-1073  (may_follow_link) ==== */
/**
 * may_follow_link - Check symlink following for unsafe situations
 * @nd: nameidata pathwalk data
 *
 * In the case of the sysctl_protected_symlinks sysctl being enabled,
 * CAP_DAC_OVERRIDE needs to be specifically ignored if the symlink is
 * in a sticky world-writable directory. This is to protect privileged
 * processes from failing races against path names that may change out
 * from under them by way of other users creating malicious symlinks.
 * It will permit symlinks to be followed only when outside a sticky
 * world-writable directory, or when the uid of the symlink and follower
 * match, or when the directory owner matches the symlink's owner.
 *
 * Returns 0 if following the symlink is allowed, -ve on error.
 */
static inline __nocfi int may_follow_link(struct nameidata *nd, const struct inode *inode)
{
	struct user_namespace *mnt_userns;
	kuid_t i_uid;

	if (!sysctl_protected_symlinks)
		return 0;

	mnt_userns = mnt_user_ns(nd->path.mnt);
	i_uid = i_uid_into_mnt(mnt_userns, inode);
	/* Allowed if owner and follower match. */
	if (uid_eq(current_cred()->fsuid, i_uid))
		return 0;

	/* Allowed if parent directory not sticky and world-writable. */
	if ((nd->dir_mode & (S_ISVTX|S_IWOTH)) != (S_ISVTX|S_IWOTH))
		return 0;

	/* Allowed if parent directory and link owner match. */
	if (uid_valid(nd->dir_uid) && uid_eq(nd->dir_uid, i_uid))
		return 0;

	if (nd->flags & LOOKUP_RCU)
		return -ECHILD;

	/*
	 * audit_inode() was here (fs/namei.c:1070).  This vendor kernel kept no
	 * out-of-line copy of it - it is a static inline over __audit_inode() and the
	 * device's kallsyms has neither name - and no audit record is wanted on this
	 * path, so the call is dropped rather than resolved.  It is only reached when
	 * sysctl_protected_symlinks is on (default 0) and it only writes a record: the
	 * decision itself (-EACCES) is unchanged.
	 */
	audit_log_path_denied(AUDIT_ANOM_LINK, "follow_link");
	return -EACCES;
}

/* ==== copied from namei.c:1240-1283  (choose_mountpoint_rcu + choose_mountpoint) ==== */
static __nocfi bool choose_mountpoint_rcu(struct mount *m, const struct path *root,
				  struct path *path, unsigned *seqp)
{
	while (mnt_has_parent(m)) {
		struct dentry *mountpoint = m->mnt_mountpoint;

		m = m->mnt_parent;
		if (unlikely(root->dentry == mountpoint &&
			     root->mnt == &m->mnt))
			break;
		if (mountpoint != m->mnt.mnt_root) {
			path->mnt = &m->mnt;
			path->dentry = mountpoint;
			*seqp = read_seqcount_begin(&mountpoint->d_seq);
			return true;
		}
	}
	return false;
}

static __nocfi bool choose_mountpoint(struct mount *m, const struct path *root,
			      struct path *path)
{
	bool found;

	rcu_read_lock();
	while (1) {
		unsigned seq, mseq = read_seqbegin(&mount_lock);

		found = vfs.choose_mountpoint_rcu(m, root, path, &seq);
		if (unlikely(!found)) {
			if (!read_seqretry(&mount_lock, mseq))
				break;
		} else {
			if (likely(vfs.__legitimize_path(path, seq, mseq)))
				break;
			rcu_read_unlock();
			path_put(path);
			rcu_read_lock();
		}
	}
	rcu_read_unlock();
	return found;
}

/* ==== copied from namei.c:1285-1388  (follow_automount + __traverse_mounts + traverse_mounts) ==== */
/*
 * Perform an automount
 * - return -EISDIR to tell follow_managed() to stop and return the path we
 *   were called with.
 */
static __nocfi int follow_automount(struct path *path, int *count, unsigned lookup_flags)
{
	struct dentry *dentry = path->dentry;

	/* We don't want to mount if someone's just doing a stat -
	 * unless they're stat'ing a directory and appended a '/' to
	 * the name.
	 *
	 * We do, however, want to mount if someone wants to open or
	 * create a file of any type under the mountpoint, wants to
	 * traverse through the mountpoint or wants to open the
	 * mounted directory.  Also, autofs may mark negative dentries
	 * as being automount points.  These will need the attentions
	 * of the daemon to instantiate them before they can be used.
	 */
	if (!(lookup_flags & (LOOKUP_PARENT | LOOKUP_DIRECTORY |
			   LOOKUP_OPEN | LOOKUP_CREATE | LOOKUP_AUTOMOUNT)) &&
	    dentry->d_inode)
		return -EISDIR;

	if (count && (*count)++ >= MAXSYMLINKS)
		return -ELOOP;

	return finish_automount(dentry->d_op->d_automount(path), path);
}

/*
 * mount traversal - out-of-line part.  One note on ->d_flags accesses -
 * dentries are pinned but not locked here, so negative dentry can go
 * positive right under us.  Use of smp_load_acquire() provides a barrier
 * sufficient for ->d_inode and ->d_flags consistency.
 */
static __nocfi int __traverse_mounts(struct path *path, unsigned flags, bool *jumped,
			     int *count, unsigned lookup_flags)
{
	struct vfsmount *mnt = path->mnt;
	bool need_mntput = false;
	int ret = 0;

	while (flags & DCACHE_MANAGED_DENTRY) {
		/* Allow the filesystem to manage the transit without i_mutex
		 * being held. */
		if (flags & DCACHE_MANAGE_TRANSIT) {
			ret = path->dentry->d_op->d_manage(path, false);
			flags = smp_load_acquire(&path->dentry->d_flags);
			if (ret < 0)
				break;
		}

		if (flags & DCACHE_MOUNTED) {	// something's mounted on it..
			struct vfsmount *mounted = lookup_mnt(path);
			if (mounted) {		// ... in our namespace
				dput(path->dentry);
				if (need_mntput)
					mntput(path->mnt);
				path->mnt = mounted;
				path->dentry = dget(mounted->mnt_root);
				// here we know it's positive
				flags = path->dentry->d_flags;
				need_mntput = true;
				continue;
			}
		}

		if (!(flags & DCACHE_NEED_AUTOMOUNT))
			break;

		// uncovered automount point
		ret = vfs.follow_automount(path, count, lookup_flags);
		flags = smp_load_acquire(&path->dentry->d_flags);
		if (ret < 0)
			break;
	}

	if (ret == -EISDIR)
		ret = 0;
	// possible if you race with several mount --move
	if (need_mntput && path->mnt == mnt)
		mntput(path->mnt);
	if (!ret && unlikely(d_flags_negative(flags)))
		ret = -ENOENT;
	*jumped = need_mntput;
	return ret;
}

static inline __nocfi int traverse_mounts(struct path *path, bool *jumped,
				  int *count, unsigned lookup_flags)
{
	unsigned flags = smp_load_acquire(&path->dentry->d_flags);

	/* fastpath */
	if (likely(!(flags & DCACHE_MANAGED_DENTRY))) {
		*jumped = false;
		if (unlikely(d_flags_negative(flags)))
			return -ENOENT;
		return 0;
	}
	return vfs.__traverse_mounts(path, flags, jumped, count, lookup_flags);
}

/* ==== copied from namei.c:1423-1514  (__follow_mount_rcu + handle_mounts) ==== */
/*
 * Try to skip to top of mountpoint pile in rcuwalk mode.  Fail if
 * we meet a managed dentry that would need blocking.
 */
static __nocfi bool __follow_mount_rcu(struct nameidata *nd, struct path *path,
			       struct inode **inode, unsigned *seqp)
{
	struct dentry *dentry = path->dentry;
	unsigned int flags = dentry->d_flags;

	if (likely(!(flags & DCACHE_MANAGED_DENTRY)))
		return true;

	if (unlikely(nd->flags & LOOKUP_NO_XDEV))
		return false;

	for (;;) {
		/*
		 * Don't forget we might have a non-mountpoint managed dentry
		 * that wants to block transit.
		 */
		if (unlikely(flags & DCACHE_MANAGE_TRANSIT)) {
			int res = dentry->d_op->d_manage(path, true);
			if (res)
				return res == -EISDIR;
			flags = dentry->d_flags;
		}

		if (flags & DCACHE_MOUNTED) {
			struct mount *mounted = __lookup_mnt(path->mnt, dentry);
			if (mounted) {
				path->mnt = &mounted->mnt;
				dentry = path->dentry = mounted->mnt.mnt_root;
				nd->state |= ND_JUMPED;
				*seqp = read_seqcount_begin(&dentry->d_seq);
				*inode = dentry->d_inode;
				/*
				 * We don't need to re-check ->d_seq after this
				 * ->d_inode read - there will be an RCU delay
				 * between mount hash removal and ->mnt_root
				 * becoming unpinned.
				 */
				flags = dentry->d_flags;
				if (read_seqretry(&mount_lock, nd->m_seq))
					return false;
				continue;
			}
			if (read_seqretry(&mount_lock, nd->m_seq))
				return false;
		}
		return !(flags & DCACHE_NEED_AUTOMOUNT);
	}
}

static inline __nocfi int handle_mounts(struct nameidata *nd, struct dentry *dentry,
			  struct path *path, struct inode **inode,
			  unsigned int *seqp)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_handle_mounts);
	atomic_inc(&n_vopen_enter_handle_mounts);
	bool jumped;
	int ret;

	path->mnt = nd->path.mnt;
	path->dentry = dentry;
	if (nd->flags & LOOKUP_RCU) {
		unsigned int seq = *seqp;
		if (unlikely(!*inode))
			return -ENOENT;
		if (likely(vfs.__follow_mount_rcu(nd, path, inode, seqp)))
			return 0;
		if (!vfs.try_to_unlazy_next(nd, dentry, seq))
			return -ECHILD;
		// *path might've been clobbered by vfs.__follow_mount_rcu()
		path->mnt = nd->path.mnt;
		path->dentry = dentry;
	}
	ret = vfs.traverse_mounts(path, &jumped, &nd->total_link_count, nd->flags);
	if (jumped) {
		if (unlikely(nd->flags & LOOKUP_NO_XDEV))
			ret = -EXDEV;
		else
			nd->state |= ND_JUMPED;
	}
	if (unlikely(ret)) {
		dput(path->dentry);
		if (path->mnt != nd->path.mnt)
			mntput(path->mnt);
	} else {
		*inode = d_backing_inode(path->dentry);
		*seqp = 0; /* out of RCU mode, so the value doesn't matter */
	}
	return ret;
}

/* ==== copied from namei.c:1572-1633  (lookup_fast) ==== */
static __nocfi struct dentry *lookup_fast(struct nameidata *nd,
				  struct inode **inode,
			          unsigned *seqp)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_lookup_fast);
	atomic_inc(&n_vopen_enter_lookup_fast);
	struct dentry *dentry, *parent = nd->path.dentry;
	int status = 1;

	/*
	 * Rename seqlock is not required here because in the off chance
	 * of a false negative due to a concurrent rename, the caller is
	 * going to fall back to non-racy lookup.
	 */
	if (nd->flags & LOOKUP_RCU) {
		unsigned seq;
		dentry = __d_lookup_rcu(parent, &nd->last, &seq);
		if (unlikely(!dentry)) {
			atomic_inc(&n_vopen_fa_rcu_miss);
			if (!vfs.try_to_unlazy(nd))
				return ERR_PTR(-ECHILD);
			return NULL;
		}
		atomic_inc(&n_vopen_fa_rcu_hit);
		if (susfs_vfs_dbg_on(nd->last.name, nd->last.len))
			pr_info("susfs_vfs_open: lookup_fast rcu hit last=%.*s dentry=%.*s ino=%lu\n",
				(int)nd->last.len, (const char *)nd->last.name,
				(int)dentry->d_name.len, (const char *)dentry->d_name.name,
				(unsigned long)(d_backing_inode(dentry) ?
						d_backing_inode(dentry)->i_ino : 0));

		/*
		 * This sequence count validates that the inode matches
		 * the dentry name information from lookup.
		 */
		*inode = d_backing_inode(dentry);
		if (unlikely(read_seqcount_retry(&dentry->d_seq, seq)))
			return ERR_PTR(-ECHILD);

		/*
		 * This sequence count validates that the parent had no
		 * changes while we did the lookup of the dentry above.
		 *
		 * The memory barrier in read_seqcount_begin of child is
		 *  enough, we can use __read_seqcount_retry here.
		 */
		if (unlikely(__read_seqcount_retry(&parent->d_seq, nd->seq)))
			return ERR_PTR(-ECHILD);

		*seqp = seq;
		/*
		 * A HIDDEN COMPONENT - AND THE ANSWER IS NOT PRODUCED HERE, AND IT IS ASKED
		 * BEFORE d_revalidate().
		 *
		 * This is the RCU fast path, and it is where the post-check layer's timing
		 * side channel came from: the hidden file's dentry is a plain dcache hit, so
		 * the caller paid a cache-hit lookup and was refused afterwards, while a path
		 * that is not there pays a real, failing filesystem lookup.  Nothing may
		 * sleep here (the slow lookup takes inode_lock_shared) and no reference to
		 * the child may be taken while LOOKUP_RCU is set, so the hit is refused in
		 * place, with exactly the two steps a dcache miss takes: drop out of RCU,
		 * report "not in the dcache".  walk_component() then runs the slow lookup -
		 * of the DERIVED name, so what actually runs is the failing lookup a name
		 * that is not there would run.
		 *
		 * THE ORDER IS THE POINT, and this device paid for it twice over.  The check
		 * used to sit inside `if (likely(status > 0))`, i.e. BEHIND the filesystem's
		 * d_revalidate() - and a procfs misc node's dentry answers -ECHILD to
		 * d_revalidate() while LOOKUP_RCU is set (fs/proc/generic.c:220,
		 * proc_misc_d_revalidate()).  That sent the walk through
		 * try_to_unlazy_next() plus a second d_revalidate() and out of the
		 * fall-through at the end of this function: the verdict was never asked and
		 * the hidden file was opened (measured: wc_hot=4 with lookup_slow=0 and no
		 * verdict line at all).  No filesystem callback may be able to hide the
		 * verdict - and asking first is CHEAPER as well, because that -ECHILD detour
		 * is exactly the extra work a dcache hit was paying over a miss (measured:
		 * the hidden path ran 593ns slower than the nonexistent one, and the detour
		 * is the bulk of that).
		 */
		if (unlikely(susfs_vfs_hidden_inode(dentry, 0))) {
			if (!vfs.try_to_unlazy(nd))
				return ERR_PTR(-ECHILD);
			susfs_vfs_nd_of(nd)->hidden_last = 1;
			return NULL;
		}
		status = vfs.d_revalidate(dentry, nd->flags);
		if (likely(status > 0))
			return dentry;
		if (!vfs.try_to_unlazy_next(nd, dentry, seq))
			return ERR_PTR(-ECHILD);
		if (status == -ECHILD)
			/* we'd been told to redo it in non-rcu mode */
			status = vfs.d_revalidate(dentry, nd->flags);
		/*
		 * A BACKSTOP, NOT THE MAIN PATH.  This is the exit the first device run went
		 * through: a hit whose revalidate had to be redone in ref-walk returns the
		 * dentry from the fall-through at the end of this function, which used to
		 * bypass the verdict entirely (measured: the trailing component of
		 * /proc/susfs_kstat reached step_into() with lookup_slow=0 and no verdict call
		 * at all).  The verdict is now asked BEFORE d_revalidate() above, so a hidden
		 * dentry no longer reaches here; this stays as the backstop for what the
		 * detour can still change - a dentry that was negative at the first look and
		 * positive now, or a rule registered in between.
		 * A reference IS held here (try_to_unlazy_next() took one on the child), so
		 * the refusal drops it exactly like the ref-walk site above does.
		 */
		if (likely(status > 0) && unlikely(susfs_vfs_hidden_inode(dentry, 2))) {
			susfs_vfs_drop_hidden(dentry);
			dput(dentry);
			susfs_vfs_nd_of(nd)->hidden_last = 1;
			return NULL;
		}
	} else {
		dentry = __d_lookup(parent, &nd->last);
		if (unlikely(!dentry)) {
			atomic_inc(&n_vopen_fa_ref_miss);
			return NULL;
		}
		atomic_inc(&n_vopen_fa_ref_hit);
		if (susfs_vfs_dbg_on(nd->last.name, nd->last.len))
			pr_info("susfs_vfs_open: lookup_fast ref hit last=%.*s dentry=%.*s ino=%lu\n",
				(int)nd->last.len, (const char *)nd->last.name,
				(int)dentry->d_name.len, (const char *)dentry->d_name.name,
				(unsigned long)(d_backing_inode(dentry) ?
						d_backing_inode(dentry)->i_ino : 0));
		/* The ref-walk half of the refusal above, and asked before d_revalidate()
		 * for the same reason: the answer must not depend on what a filesystem
		 * callback says about this dentry (that dependency is what let a procfs misc
		 * node's -ECHILD hide the verdict in the RCU branch).  A reference IS held
		 * here, so the dentry can also be taken out of the dcache when the tuning
		 * asks for it (vopen_drop) - which makes the NEXT lookup of this path a real
		 * one too, at the price of one failing lookup per call instead of a cache
		 * hit.  That is why it is not the default. */
		if (unlikely(susfs_vfs_hidden_inode(dentry, 1))) {
			susfs_vfs_drop_hidden(dentry);
			dput(dentry);
			susfs_vfs_nd_of(nd)->hidden_last = 1;
			return NULL;
		}
		status = vfs.d_revalidate(dentry, nd->flags);
	}
	if (unlikely(status <= 0)) {
		if (!status)
			d_invalidate(dentry);
		dput(dentry);
		return ERR_PTR(status);
	}
	return dentry;
}

/* ==== copied from namei.c:1635-1683  (__lookup_slow + lookup_slow) ==== */
/* Fast lookup failed, do it the slow way */
static __nocfi struct dentry *__lookup_slow(const struct qstr *name,
				    struct dentry *dir,
				    unsigned int flags)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME___lookup_slow);
	struct dentry *dentry, *old;
	struct inode *inode = dir->d_inode;
	/* mode 3 only: did the filesystem really search this name on this call?  The
	 * d_revalidate branch below means the dcache already had an answer, and then the
	 * filesystem did not run - which is a cheaper call than a cold one, so mode 3 counts
	 * it (n_vopen_discard_cached) instead of pretending the two are the same. */
	bool fs_searched = false;
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(wq);

	/* Don't go there if it's already dead */
	if (unlikely(IS_DEADDIR(inode)))
		return ERR_PTR(-ENOENT);
again:
	dentry = d_alloc_parallel(dir, name, &wq);
	if (IS_ERR(dentry))
		return dentry;
	if (unlikely(!d_in_lookup(dentry))) {
		int error = vfs.d_revalidate(dentry, flags);
		if (unlikely(error <= 0)) {
			if (!error) {
				d_invalidate(dentry);
				dput(dentry);
				goto again;
			}
			dput(dentry);
			dentry = ERR_PTR(error);
		}
	} else {
		old = inode->i_op->lookup(inode, dentry, flags);
		fs_searched = true;
		d_lookup_done(dentry);
		if (unlikely(old)) {
			dput(dentry);
			dentry = old;
		}
	}
	/* MODE 3: the filesystem has really searched the caller's own name (either through
	 * the ->lookup() above, or through the revalidate of a dentry the dcache already had),
	 * and d_lookup_done() has released anyone waiting on it - so this is the point where
	 * a hidden name is turned into the answer a name that is not there gets. */
	return susfs_vfs_discard_hidden(dir, name, dentry, fs_searched);
}

static __nocfi struct dentry *lookup_slow(const struct qstr *name,
				  struct dentry *dir,
				  unsigned int flags)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_lookup_slow);
	atomic_inc(&n_vopen_enter_lookup_slow);
	struct inode *inode = dir->d_inode;
	struct dentry *res;
	inode_lock_shared(inode);
	res = __lookup_slow(name, dir, flags);
	inode_unlock_shared(inode);
	return res;
}

/* ==== copied from namei.c:1685-1720  (may_lookup + reserve_stack) ==== */
static inline __nocfi int may_lookup(struct user_namespace *mnt_userns,
			     struct nameidata *nd)
{
	if (nd->flags & LOOKUP_RCU) {
		int err = inode_permission(mnt_userns, nd->inode, MAY_EXEC|MAY_NOT_BLOCK);
		if (err != -ECHILD || !vfs.try_to_unlazy(nd))
			return err;
	}
	return inode_permission(mnt_userns, nd->inode, MAY_EXEC);
}

static __nocfi int reserve_stack(struct nameidata *nd, struct path *link, unsigned seq)
{
	if (unlikely(nd->total_link_count++ >= MAXSYMLINKS))
		return -ELOOP;

	if (likely(nd->depth != EMBEDDED_LEVELS))
		return 0;
	if (likely(nd->stack != nd->internal))
		return 0;
	if (likely(vfs.nd_alloc_stack(nd)))
		return 0;

	if (nd->flags & LOOKUP_RCU) {
		// we need to grab link before we do unlazy.  And we can't skip
		// unlazy even if we fail to grab the link - cleanup needs it
		bool grabbed_link = vfs.legitimize_path(nd, link, seq);

		if (!vfs.try_to_unlazy(nd) != 0 || !grabbed_link)
			return -ECHILD;

		if (vfs.nd_alloc_stack(nd))
			return 0;
	}
	return -ENOMEM;
}

/* ==== copied from namei.c:1722-1794  (WALK_* enum + pick_link) ==== */
enum {WALK_TRAILING = 1, WALK_MORE = 2, WALK_NOFOLLOW = 4};

static __nocfi const char *pick_link(struct nameidata *nd, struct path *link,
		     struct inode *inode, unsigned seq, int flags)
{
	struct saved *last;
	const char *res;
	int error = vfs.reserve_stack(nd, link, seq);

	if (unlikely(error)) {
		if (!(nd->flags & LOOKUP_RCU))
			path_put(link);
		return ERR_PTR(error);
	}
	last = nd->stack + nd->depth++;
	last->link = *link;
	clear_delayed_call(&last->done);
	last->seq = seq;

	if (flags & WALK_TRAILING) {
		error = vfs.may_follow_link(nd, inode);
		if (unlikely(error))
			return ERR_PTR(error);
	}

	if (unlikely(nd->flags & LOOKUP_NO_SYMLINKS) ||
			unlikely(link->mnt->mnt_flags & MNT_NOSYMFOLLOW))
		return ERR_PTR(-ELOOP);

	if (!(nd->flags & LOOKUP_RCU)) {
		/*
		 * touch_atime() and atime_needs_update() were here (fs/namei.c:1751-1758)
		 * and are REMOVED, not resolved.  This device's kallsyms carries
		 * touch_atime with address 0 (plus a touch_atime.cfi_jt stub), so there is
		 * no callable entity to bind to - and an O_PATH open does not update atime
		 * in the first place: do_dentry_open() returns early for an O_PATH file
		 * and do_o_path() never calls it.  What is given up is the atime update of
		 * a SYMLINK traversed on the way (an atime side effect on the link inode,
		 * on mounts that are noatime on this device); what is gained is that no
		 * branch of this walk can call a NULL pointer.  The RCU-to-ref-walk
		 * transition this branch forced existed only to make touch_atime() safe, so
		 * the walk now simply stays in RCU mode here.
		 */
		susfs_vfs_cond_resched();
	}

	error = security_inode_follow_link(link->dentry, inode,
					   nd->flags & LOOKUP_RCU);
	if (unlikely(error))
		return ERR_PTR(error);

	res = READ_ONCE(inode->i_link);
	if (!res) {
		const char * (*get)(struct dentry *, struct inode *,
				struct delayed_call *);
		get = inode->i_op->get_link;
		if (nd->flags & LOOKUP_RCU) {
			res = get(NULL, inode, &last->done);
			if (res == ERR_PTR(-ECHILD) && vfs.try_to_unlazy(nd))
				res = get(link->dentry, inode, &last->done);
		} else {
			res = get(link->dentry, inode, &last->done);
		}
		if (!res)
			goto all_done;
		if (IS_ERR(res))
			return res;
	}
	if (*res == '/') {
		error = vfs.nd_jump_root(nd);
		if (unlikely(error))
			return ERR_PTR(error);
		while (unlikely(*++res == '/'))
			;
	}
	if (*res)
		return res;
all_done: // pure jump
	vfs.put_link(nd);
	return NULL;
}

/* ==== copied from namei.c:1796-1833  (step_into) ==== */
/*
 * Do we need to follow links? We _really_ want to be able
 * to do this check without having to look at inode->i_op,
 * so we keep a cache of "no, this doesn't need follow_link"
 * for the common case.
 */
static __nocfi const char *step_into(struct nameidata *nd, int flags,
		     struct dentry *dentry, struct inode *inode, unsigned seq)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_step_into);
	atomic_inc(&n_vopen_enter_step_into);
	struct path path;
	int err = handle_mounts(nd, dentry, &path, &inode, &seq);

	if (err < 0)
		return ERR_PTR(err);
	if (likely(!d_is_symlink(path.dentry)) ||
	   ((flags & WALK_TRAILING) && !(nd->flags & LOOKUP_FOLLOW)) ||
	   (flags & WALK_NOFOLLOW)) {
		/* not a symlink or should not follow */
		if (!(nd->flags & LOOKUP_RCU)) {
			dput(nd->path.dentry);
			if (nd->path.mnt != path.mnt)
				mntput(nd->path.mnt);
		}
		nd->path = path;
		nd->inode = inode;
		nd->seq = seq;
		return NULL;
	}
	if (nd->flags & LOOKUP_RCU) {
		/* make sure that d_is_symlink above matches inode */
		if (read_seqcount_retry(&path.dentry->d_seq, seq))
			return ERR_PTR(-ECHILD);
	} else {
		if (path.mnt == nd->path.mnt)
			mntget(path.mnt);
	}
	return vfs.pick_link(nd, &path, inode, seq, flags);
}

/* ==== copied from namei.c:1835-1955  (follow_dotdot_rcu + follow_dotdot + handle_dots) ==== */
static __nocfi struct dentry *follow_dotdot_rcu(struct nameidata *nd,
					struct inode **inodep,
					unsigned *seqp)
{
	struct dentry *parent, *old;

	if (path_equal(&nd->path, &nd->root))
		goto in_root;
	if (unlikely(nd->path.dentry == nd->path.mnt->mnt_root)) {
		struct path path;
		unsigned seq;
		if (!vfs.choose_mountpoint_rcu(real_mount(nd->path.mnt),
					   &nd->root, &path, &seq))
			goto in_root;
		if (unlikely(nd->flags & LOOKUP_NO_XDEV))
			return ERR_PTR(-ECHILD);
		nd->path = path;
		nd->inode = path.dentry->d_inode;
		nd->seq = seq;
		if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
			return ERR_PTR(-ECHILD);
		/* we know that mountpoint was pinned */
	}
	old = nd->path.dentry;
	parent = old->d_parent;
	*inodep = parent->d_inode;
	*seqp = read_seqcount_begin(&parent->d_seq);
	if (unlikely(read_seqcount_retry(&old->d_seq, nd->seq)))
		return ERR_PTR(-ECHILD);
	if (unlikely(!vfs.path_connected(nd->path.mnt, parent)))
		return ERR_PTR(-ECHILD);
	return parent;
in_root:
	if (unlikely(read_seqretry(&mount_lock, nd->m_seq)))
		return ERR_PTR(-ECHILD);
	if (unlikely(nd->flags & LOOKUP_BENEATH))
		return ERR_PTR(-ECHILD);
	return NULL;
}

static __nocfi struct dentry *follow_dotdot(struct nameidata *nd,
				 struct inode **inodep,
				 unsigned *seqp)
{
	struct dentry *parent;

	if (path_equal(&nd->path, &nd->root))
		goto in_root;
	if (unlikely(nd->path.dentry == nd->path.mnt->mnt_root)) {
		struct path path;

		if (!vfs.choose_mountpoint(real_mount(nd->path.mnt),
				       &nd->root, &path))
			goto in_root;
		path_put(&nd->path);
		nd->path = path;
		nd->inode = path.dentry->d_inode;
		if (unlikely(nd->flags & LOOKUP_NO_XDEV))
			return ERR_PTR(-EXDEV);
	}
	/* rare case of legitimate dget_parent()... */
	parent = dget_parent(nd->path.dentry);
	if (unlikely(!vfs.path_connected(nd->path.mnt, parent))) {
		dput(parent);
		return ERR_PTR(-ENOENT);
	}
	*seqp = 0;
	*inodep = parent->d_inode;
	return parent;

in_root:
	if (unlikely(nd->flags & LOOKUP_BENEATH))
		return ERR_PTR(-EXDEV);
	dget(nd->path.dentry);
	return NULL;
}

static __nocfi const char *handle_dots(struct nameidata *nd, int type)
{
	if (type == LAST_DOTDOT) {
		const char *error = NULL;
		struct dentry *parent;
		struct inode *inode;
		unsigned seq;

		if (!nd->root.mnt) {
			error = ERR_PTR(vfs.set_root(nd));
			if (error)
				return error;
		}
		if (nd->flags & LOOKUP_RCU)
			parent = vfs.follow_dotdot_rcu(nd, &inode, &seq);
		else
			parent = vfs.follow_dotdot(nd, &inode, &seq);
		if (IS_ERR(parent))
			return ERR_CAST(parent);
		if (unlikely(!parent))
			error = step_into(nd, WALK_NOFOLLOW,
					 nd->path.dentry, nd->inode, nd->seq);
		else
			error = step_into(nd, WALK_NOFOLLOW,
					 parent, inode, seq);
		if (unlikely(error))
			return error;

		if (unlikely(nd->flags & LOOKUP_IS_SCOPED)) {
			/*
			 * If there was a racing rename or mount along our
			 * path, then we can't be sure that ".." hasn't jumped
			 * above nd->root (and so userspace should retry or use
			 * some fallback).
			 */
			smp_rmb();
			if (unlikely(__read_seqcount_retry(&mount_lock.seqcount, nd->m_seq)))
				return ERR_PTR(-EAGAIN);
			if (unlikely(__read_seqcount_retry(&rename_lock.seqcount, nd->r_seq)))
				return ERR_PTR(-EAGAIN);
		}
	}
	return NULL;
}

/* ==== copied from namei.c:1957-1983  (walk_component) ==== */
static __nocfi const char *walk_component(struct nameidata *nd, int flags)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_walk_component);
	atomic_inc(&n_vopen_enter_walk_component);
	if (susfs_vfs_dbg_on(nd->last.name, nd->last.len))
		pr_info("susfs_vfs_open: walk_component name=%.*s type=%d flags=%#x\n",
			(int)nd->last.len, (const char *)nd->last.name, nd->last_type, flags);
	struct dentry *dentry;
	struct inode *inode;
	unsigned seq;
	/*
	 * "." and ".." are special - ".." especially so because it has
	 * to be able to know about the current root directory and
	 * parent relationships.
	 */
	if (unlikely(nd->last_type != LAST_NORM)) {
		if (!(flags & WALK_MORE) && nd->depth)
			vfs.put_link(nd);
		return vfs.handle_dots(nd, nd->last_type);
	}
	dentry = lookup_fast(nd, &inode, &seq);
	if (IS_ERR(dentry))
		return ERR_CAST(dentry);
	if (unlikely(!dentry)) {
		if (unlikely(susfs_vfs_nd_of(nd)->hidden_last)) {
			/*
			 * lookup_fast() refused a hit because the component is hidden.  Do
			 * NOT look the real name up now: that lookup would SUCCEED (the file
			 * does exist - it is only this caller that must not see it) and would
			 * cost a dcache hit again, which is the side channel.  The derived
			 * name is looked up instead, so this component fails with the cost
			 * structure of a component that is not there.
			 */
			susfs_vfs_nd_of(nd)->hidden_last = 0;
			atomic_inc(&n_vopen_wc_hot);
			atomic_inc(&n_vopen_hidden);
			if (READ_ONCE(vopen_fake) == SUSFS_VFS_FAKE_DISCARD) {
				/* MODE 3: pay for a lookup of the SAME name and let the tail of
				 * __lookup_slow() throw its result away - no derived name, and the
				 * filesystem does the search a missing name would make it do. */
				dentry = lookup_slow(&nd->last, nd->path.dentry,
						     nd->flags & ~(LOOKUP_RCU | LOOKUP_PARENT));
			} else {
				dentry = susfs_vfs_fake_lookup(nd->path.dentry, nd->flags);
			}
		} else {
			dentry = lookup_slow(&nd->last, nd->path.dentry, nd->flags);
			atomic_inc(&n_vopen_wc_plain);
			if (!IS_ERR(dentry) &&
			    unlikely(susfs_vfs_hidden_inode(dentry, 3))) {
				/*
				 * Cold path: the dentry was not in the dcache, so the real
				 * lookup had to run before the inode was known.  Drop what it
				 * produced and pay one failing lookup, so this call costs what
				 * a name that is not there costs instead of what a lookup that
				 * succeeded and was thrown away costs.
				 */
				atomic_inc(&n_vopen_wc_cold);
				atomic_inc(&n_vopen_cold);
				susfs_vfs_drop_hidden(dentry);
				dput(dentry);
				dentry = susfs_vfs_fake_lookup(nd->path.dentry, nd->flags);
			}
		}
		if (IS_ERR(dentry))
			return ERR_CAST(dentry);
	}
	if (!(flags & WALK_MORE) && nd->depth)
		vfs.put_link(nd);

	/*
	 * THE COMMIT-POINT CHECK.  By the time the walk gets here the component IS
	 * resolved and is about to become nd->path - and this is the one place no branch
	 * of lookup_fast() can bypass, which is why it exists: the fast-path checks above
	 * cover the two ways a hit is normally taken, and the device showed a third way
	 * (a revalidate redone after try_to_unlazy_next()) that returned a hidden dentry
	 * without ever asking.  The refusal here is the same one, with the same cost
	 * structure: the resolved dentry is given back, and the name actually handed to
	 * the filesystem is the derived one, so this component fails the way a component
	 * that is not there fails.
	 *
	 * No double work: when lookup_fast() DID refuse, it left hidden_last set and
	 * walk_component()'s branch above handles it, so this dentry is never the hidden
	 * one (it is the derived one, which is not hidden).
	 */
	if (unlikely(susfs_vfs_hidden_inode(dentry, 4))) {
		atomic_inc(&n_vopen_wc_commit);
		atomic_inc(&n_vopen_hidden);
		if (nd->flags & LOOKUP_RCU) {
			/* No reference to the child is held in RCU mode, and the derived-name
			 * lookup sleeps, so take the same two steps a dcache miss takes: drop
			 * to ref-walk and let it be resolved again - except that here it will be
			 * this function's slow path, which is where the derived name is used. */
			if (!vfs.try_to_unlazy(nd))
				return ERR_PTR(-ECHILD);
		} else {
			/* A reference IS held: give it back, and drop it from the cache when
			 * the tuning asks for it. */
			susfs_vfs_drop_hidden(dentry);
			dput(dentry);
		}
		if (READ_ONCE(vopen_fake) == SUSFS_VFS_FAKE_DISCARD)
			dentry = lookup_slow(&nd->last, nd->path.dentry,
					     nd->flags & ~(LOOKUP_RCU | LOOKUP_PARENT));
		else
			dentry = susfs_vfs_fake_lookup(nd->path.dentry, nd->flags);
		if (IS_ERR(dentry))
			return ERR_CAST(dentry);
		inode = NULL;	/* handle_mounts() derives it again, in ref-walk */
		seq = 0;
	}
	return step_into(nd, flags, dentry, inode, seq);
}

/* ==== copied from namei.c:2213-2321  (link_path_walk) ==== */
/*
 * Name resolution.
 * This is the basic name resolution function, turning a pathname into
 * the final dentry. We expect 'base' to be positive and a directory.
 *
 * Returns 0 and nd will have valid dentry and mnt on success.
 * Returns error and drops reference to input namei data on failure.
 */
static __nocfi int link_path_walk(const char *name, struct nameidata *nd)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_link_path_walk);
	atomic_inc(&n_vopen_enter_link_path_walk);
	int depth = 0; // depth <= nd->depth
	int err;

	nd->last_type = LAST_ROOT;
	nd->flags |= LOOKUP_PARENT;
	if (IS_ERR(name))
		return PTR_ERR(name);
	while (*name=='/')
		name++;
	if (!*name) {
		nd->dir_mode = 0; // short-circuit the 'hardening' idiocy
		return 0;
	}

	/* At this point we know we have a real path component. */
	for(;;) {
		struct user_namespace *mnt_userns;
		const char *link;
		u64 hash_len;
		int type;

		mnt_userns = mnt_user_ns(nd->path.mnt);
		err = vfs.may_lookup(mnt_userns, nd);
		if (err)
			return err;

		hash_len = susfs_vfs_hash_name(nd->path.dentry, name);

		type = LAST_NORM;
		if (name[0] == '.') switch (hashlen_len(hash_len)) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->state |= ND_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			struct dentry *parent = nd->path.dentry;
			nd->state &= ~ND_JUMPED;
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				struct qstr this = { { .hash_len = hash_len }, .name = name };
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					return err;
				hash_len = this.hash_len;
				name = this.name;
			}
		}

		nd->last.hash_len = hash_len;
		nd->last.name = name;
		nd->last_type = type;

		name += hashlen_len(hash_len);
		if (!*name)
			goto OK;
		/*
		 * If it wasn't NUL, we know it was '/'. Skip that
		 * slash, and continue until no more slashes.
		 */
		do {
			name++;
		} while (unlikely(*name == '/'));
		if (unlikely(!*name)) {
OK:
			/* pathname or trailing symlink, done */
			if (!depth) {
				nd->dir_uid = i_uid_into_mnt(mnt_userns, nd->inode);
				nd->dir_mode = nd->inode->i_mode;
				nd->flags &= ~LOOKUP_PARENT;
				return 0;
			}
			/* last component of nested symlink */
			name = nd->stack[--depth].name;
			link = walk_component(nd, 0);
		} else {
			/* not the last component */
			link = walk_component(nd, WALK_MORE);
		}
		if (unlikely(link)) {
			if (IS_ERR(link))
				return PTR_ERR(link);
			/* a symlink to follow */
			nd->stack[depth++].name = name;
			name = link;
			continue;
		}
		if (unlikely(!d_can_lookup(nd->path.dentry))) {
			if (nd->flags & LOOKUP_RCU) {
				if (!vfs.try_to_unlazy(nd))
					return -ECHILD;
			}
			return -ENOTDIR;
		}
	}
}

/* ==== copied from namei.c:2323-2424  (path_init) ==== */
/* must be paired with vfs.terminate_walk() */
static __nocfi const char *path_init(struct nameidata *nd, unsigned flags)
{
	int error;
	const char *s = nd->name->name;

	/* LOOKUP_CACHED requires RCU, ask caller to retry */
	if ((flags & (LOOKUP_RCU | LOOKUP_CACHED)) == LOOKUP_CACHED)
		return ERR_PTR(-EAGAIN);

	if (!*s)
		flags &= ~LOOKUP_RCU;
	if (flags & LOOKUP_RCU)
		rcu_read_lock();

	nd->flags = flags;
	nd->state |= ND_JUMPED;

	nd->m_seq = __read_seqcount_begin(&mount_lock.seqcount);
	nd->r_seq = __read_seqcount_begin(&rename_lock.seqcount);
	smp_rmb();

	if (nd->state & ND_ROOT_PRESET) {
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*s && unlikely(!d_can_lookup(root)))
			return ERR_PTR(-ENOTDIR);
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->root_seq = nd->seq;
		} else {
			path_get(&nd->path);
		}
		return s;
	}

	nd->root.mnt = NULL;

	/* Absolute pathname -- fetch the root (LOOKUP_IN_ROOT uses nd->dfd). */
	if (*s == '/' && !(flags & LOOKUP_IN_ROOT)) {
		error = vfs.nd_jump_root(nd);
		if (unlikely(error))
			return ERR_PTR(error);
		return s;
	}

	/* Relative pathname -- get the starting-point it is relative to. */
	if (nd->dfd == AT_FDCWD) {
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = current->fs;
			unsigned seq;

			do {
				seq = read_seqcount_begin(&fs->seq);
				nd->path = fs->pwd;
				nd->inode = nd->path.dentry->d_inode;
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			get_fs_pwd(current->fs, &nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
	} else {
		/* Caller must check execute permissions on the starting path component */
		struct fd f = susfs_vfs_fdget_raw(nd->dfd);
		struct dentry *dentry;

		if (!f.file)
			return ERR_PTR(-EBADF);

		dentry = f.file->f_path.dentry;

		if (*s && unlikely(!d_can_lookup(dentry))) {
			fdput(f);
			return ERR_PTR(-ENOTDIR);
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			nd->inode = nd->path.dentry->d_inode;
			nd->seq = read_seqcount_begin(&nd->path.dentry->d_seq);
		} else {
			path_get(&nd->path);
			nd->inode = nd->path.dentry->d_inode;
		}
		fdput(f);
	}

	/* For scoped-lookups we need to set the root to the dirfd as well. */
	if (flags & LOOKUP_IS_SCOPED) {
		nd->root = nd->path;
		if (flags & LOOKUP_RCU) {
			nd->root_seq = nd->seq;
		} else {
			path_get(&nd->root);
			nd->state |= ND_ROOT_GRABBED;
		}
	}
	return s;
}

/* ==== copied from namei.c:2426-2474  (lookup_last + handle_lookup_down + path_lookupat) ==== */
static __nocfi const char *lookup_last(struct nameidata *nd)
{
	atomic_inc(&n_vopen_enter_lookup_last);
	if (susfs_vfs_dbg_on(nd->last.name, nd->last.len))
		pr_info("susfs_vfs_open: lookup_last name=%.*s type=%d\n",
			(int)nd->last.len, (const char *)nd->last.name, nd->last_type);
	if (nd->last_type == LAST_NORM && nd->last.name[nd->last.len])
		nd->flags |= LOOKUP_FOLLOW | LOOKUP_DIRECTORY;

	return walk_component(nd, WALK_TRAILING);
}

static __nocfi int handle_lookup_down(struct nameidata *nd)
{
	if (!(nd->flags & LOOKUP_RCU))
		dget(nd->path.dentry);
	return PTR_ERR(step_into(nd, WALK_NOFOLLOW,
			nd->path.dentry, nd->inode, nd->seq));
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
static __nocfi int path_lookupat(struct nameidata *nd, unsigned flags, struct path *path)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_path_lookupat);
	const char *s = vfs.path_init(nd, flags);
	int err;

	if (unlikely(flags & LOOKUP_DOWN) && !IS_ERR(s)) {
		err = vfs.handle_lookup_down(nd);
		if (unlikely(err < 0))
			s = ERR_PTR(err);
	}

	while (!(err = link_path_walk(s, nd)) &&
	       (s = lookup_last(nd)) != NULL)
		;
	if (!err && unlikely(nd->flags & LOOKUP_MOUNTPOINT)) {
		err = vfs.handle_lookup_down(nd);
		nd->state &= ~ND_JUMPED; // no d_weak_revalidate(), please...
	}
	if (!err)
		err = vfs.complete_walk(nd);

	if (!err && nd->flags & LOOKUP_DIRECTORY)
		if (!d_can_lookup(nd->path.dentry))
			err = -ENOTDIR;
	if (!err) {
		*path = nd->path;
		nd->path.mnt = NULL;
		nd->path.dentry = NULL;
	}
	vfs.terminate_walk(nd);
	return err;
}

/*
 * =====================================================================
 * path_openat() and do_o_path(), reduced to the O_PATH branch
 * =====================================================================
 *
 * These are the only copied bodies that are re-expressed instead of copied
 * byte-for-byte, and both changes are forced by what this device's kernel has:
 *
 *   path_openat() keeps ONLY the `file->f_flags & O_PATH` branch.  The other two
 *   cannot be here at all: the `else` branch needs open_last_lookups() ->
 *   lookup_open() -> atomic_open()/do_open() and the __O_TMPFILE branch needs
 *   do_tmpfile(), none of which is in this closure - and an O_PATH open never
 *   reaches them, since build_open_flags() rejects O_PATH|__O_TMPFILE with -EINVAL
 *   (O_PATH_FLAGS has no __O_TMPFILE) and the O_PATH test is the one that is taken.
 *
 *   do_o_path() produced its file with alloc_empty_file() + vfs_open().  That pair is
 *   not usable by name on this device: alloc_empty_file() is not in the kallsyms the
 *   device reports, while dentry_open() is - and dentry_open() IS that pair
 *   (fs/open.c:1036-1056: alloc_empty_file(flags, cred), then vfs_open(path, f)).
 *   The single call therefore reproduces both steps exactly, and it checks nothing
 *   extra: for an O_PATH file it lands in the same do_dentry_open() early return that
 *   sets f_mode = FMODE_PATH | FMODE_OPENED (fs/open.c:801-805), which is the
 *   contract this layer has to keep.
 *
 * audit_inode() is gone from do_o_path() for the same reason as in
 * may_follow_link(): this kernel kept no out-of-line copy of the static inline, and
 * no audit record is wanted on this path.
 */
static __nocfi int do_o_path(struct nameidata *nd, unsigned flags,
			     const struct open_flags *op, struct file **out)
{
	SUSFS_VFS_FRAME(SUSFS_VFS_FRAME_do_o_path);
	struct path path;
	struct file *file;
	int error;

	*out = NULL;

	error = path_lookupat(nd, flags, &path);
	if (!error) {
		file = dentry_open(&path, op->open_flag, current_cred());
		path_put(&path);
		if (IS_ERR(file))
			return PTR_ERR(file);
		*out = file;
	}
	return error;
}

static __nocfi struct file *path_openat(struct nameidata *nd,
					const struct open_flags *op, unsigned flags)
{
	struct file *file = NULL;
	int error;

	/*
	 * By the time this returns, the hidden decision has already been taken inside
	 * the lookup: path_lookupat() -> link_path_walk()/lookup_last() ->
	 * walk_component() -> lookup_fast() refuse a hidden component and make the walk
	 * fail there.  A file that exists at this point is one the caller may see.
	 */
	error = do_o_path(nd, flags, op, &file);
	if (likely(!error)) {
		if (likely(file->f_mode & FMODE_OPENED))
			return file;
		WARN_ON(1);
		error = -EINVAL;
	}
	if (!IS_ERR_OR_NULL(file))
		fput(file);
	/* -EOPENSTALE is not mapped here: it exists for do_open()'s atomic_open() path
	 * (fs/namei.c:3564), which an O_PATH open never enters.  -ESTALE from
	 * complete_walk()'s d_weak_revalidate() propagates unchanged, and do_filp_open()
	 * retries exactly as it does for the kernel's own path_openat(). */
	return ERR_PTR(error);
}


/* ==== copied from namei.c:3761-3776  (do_filp_open) ==== */
static __nocfi struct file *do_filp_open(int dfd, struct filename *pathname,
		const struct open_flags *op)
{
	struct susfs_vfs_nd w;
	int flags = op->lookup_flags;
	struct file *filp;

	/*
	 * The walk's private state lives in this wrapper and NOT in struct nameidata:
	 * current->nameidata is a pointer the KERNEL follows with its own layout (see
	 * the layout gate at struct nameidata), so our struct nameidata has to be
	 * byte-for-byte the kernel's.  &w.nd is what the kernel sees, and it is the
	 * wrapper's first member (asserted there).
	 */
	set_nameidata(&w.nd, dfd, pathname, NULL);
	filp = path_openat(&w.nd, op, flags | LOOKUP_RCU);
	if (unlikely(filp == ERR_PTR(-ECHILD)))
		filp = path_openat(&w.nd, op, flags);
	if (unlikely(filp == ERR_PTR(-ESTALE)))
		filp = path_openat(&w.nd, op, flags | LOOKUP_REVAL);
	restore_nameidata();
	return filp;
}

/* ==== copied from open.c:1080-1213  (build_open_how + build_open_flags) ==== */
static inline __nocfi struct open_how build_open_how(int flags, umode_t mode)
{
	struct open_how how = {
		.flags = flags & VALID_OPEN_FLAGS,
		.mode = mode & S_IALLUGO,
	};

	/* O_PATH beats everything else. */
	if (how.flags & O_PATH)
		how.flags &= O_PATH_FLAGS;
	/* Modes should only be set for create-like flags. */
	if (!WILL_CREATE(how.flags))
		how.mode = 0;
	return how;
}

static inline __nocfi int build_open_flags(const struct open_how *how, struct open_flags *op)
{
	u64 flags = how->flags;
	u64 strip = FMODE_NONOTIFY | O_CLOEXEC;
	int lookup_flags = 0;
	int acc_mode = ACC_MODE(flags);

	BUILD_BUG_ON_MSG(upper_32_bits(VALID_OPEN_FLAGS),
			 "struct open_flags doesn't yet handle flags > 32 bits");

	/*
	 * Strip flags that either shouldn't be set by userspace like
	 * FMODE_NONOTIFY or that aren't relevant in determining struct
	 * open_flags like O_CLOEXEC.
	 */
	flags &= ~strip;

	/*
	 * Older syscalls implicitly clear all of the invalid flags or argument
	 * values before calling build_open_flags(), but openat2(2) checks all
	 * of its arguments.
	 */
	if (flags & ~VALID_OPEN_FLAGS)
		return -EINVAL;
	if (how->resolve & ~VALID_RESOLVE_FLAGS)
		return -EINVAL;

	/* Scoping flags are mutually exclusive. */
	if ((how->resolve & RESOLVE_BENEATH) && (how->resolve & RESOLVE_IN_ROOT))
		return -EINVAL;

	/* Deal with the mode. */
	if (WILL_CREATE(flags)) {
		if (how->mode & ~S_IALLUGO)
			return -EINVAL;
		op->mode = how->mode | S_IFREG;
	} else {
		if (how->mode != 0)
			return -EINVAL;
		op->mode = 0;
	}

	/*
	 * In order to ensure programs get explicit errors when trying to use
	 * O_TMPFILE on old kernels, O_TMPFILE is implemented such that it
	 * looks like (O_DIRECTORY|O_RDWR & ~O_CREAT) to old kernels. But we
	 * have to require userspace to explicitly set it.
	 */
	if (flags & __O_TMPFILE) {
		if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
			return -EINVAL;
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	}
	if (flags & O_PATH) {
		/* O_PATH only permits certain other flags to be set. */
		if (flags & ~O_PATH_FLAGS)
			return -EINVAL;
		acc_mode = 0;
	}

	/*
	 * O_SYNC is implemented as __O_SYNC|O_DSYNC.  As many places only
	 * check for O_DSYNC if the need any syncing at all we enforce it's
	 * always set instead of having to deal with possibly weird behaviour
	 * for malicious applications setting only __O_SYNC.
	 */
	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	op->open_flag = flags;

	/* O_TRUNC implies we need access checks for write permissions */
	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	/* Allow the LSM permission hook to distinguish append
	   access from general write access. */
	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL) {
			op->intent |= LOOKUP_EXCL;
			flags |= O_NOFOLLOW;
		}
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;

	if (how->resolve & RESOLVE_NO_XDEV)
		lookup_flags |= LOOKUP_NO_XDEV;
	if (how->resolve & RESOLVE_NO_MAGICLINKS)
		lookup_flags |= LOOKUP_NO_MAGICLINKS;
	if (how->resolve & RESOLVE_NO_SYMLINKS)
		lookup_flags |= LOOKUP_NO_SYMLINKS;
	if (how->resolve & RESOLVE_BENEATH)
		lookup_flags |= LOOKUP_BENEATH;
	if (how->resolve & RESOLVE_IN_ROOT)
		lookup_flags |= LOOKUP_IN_ROOT;
	if (how->resolve & RESOLVE_CACHED) {
		/* Don't bother even trying for create/truncate/tmpfile open */
		if (flags & (O_TRUNC | O_CREAT | __O_TMPFILE))
			return -EAGAIN;
		lookup_flags |= LOOKUP_CACHED;
	}

	op->lookup_flags = lookup_flags;
	return 0;
}

/* ==== copied from open.c:1293-1320  (do_sys_openat2) ==== */
static __nocfi long do_sys_openat2(int dfd, const char __user *filename,
			   struct open_how *how)
{
	struct open_flags op;
	int fd = vfs.build_open_flags(how, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(how->flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
		}
	}
	putname(tmp);
	return fd;
}
/*
 * =====================================================================
 * 8. The syscall entry the wrapper in susfs_opath.c calls
 * =====================================================================
 *
 * Only reached for a call whose raw flags carry O_PATH: the wrapper reads the flags
 * register itself and tail-calls the original entry otherwise, so the non-O_PATH path
 * does not enter this file at all and its behaviour is untouched.
 */
static __nocfi noinline bool susfs_vfs_do_opath(int site, const struct pt_regs *regs, long *ret)
{
	struct open_how how;
	int dfd;
	const char __user *filename;

	atomic_inc(&n_vopen_seen);

	switch (site) {
	case SUSFS_VFS_SITE_OPENAT:
		dfd = (int)regs->regs[0];
		filename = (const char __user *)regs->regs[1];
		how = build_open_how((int)regs->regs[2], (umode_t)regs->regs[3]);
		break;
	case SUSFS_VFS_SITE_OPENAT2:
		/* The AArch32 slot of openat2 is read exactly like this one: it is a
		 * different element of compat_sys_call_table but holds the NATIVE
		 * __arm64_sys_openat2 (arch/arm64/include/asm/unistd32.h:884-885 ->
		 * arch/arm64/kernel/sys32.c:130), so its registers are shaped like these.
		 * The compat open(5)/openat(322) entries are NOT handled here: they are
		 * COMPAT_SYSCALL_DEFINE with a different argument layout, and they keep the
		 * post-check layer. */
		dfd = (int)regs->regs[0];
		filename = (const char __user *)regs->regs[1];
		if (susfs_vfs_copy_open_how((const void __user *)regs->regs[2],
					    (size_t)regs->regs[3], &how))
			/* Let the kernel answer its own -EINVAL/-E2BIG/-EFAULT: a failed
			 * copy means the question "is this O_PATH?" was never answered, and
			 * the original entry answers the syscall identically. */
			return false;
		break;
	default:
		return false;
	}

	if (!(how.flags & O_PATH))
		return false;		/* not ours: the caller tail-calls the original entry */

	/*
	 * O_LARGEFILE is NOT added here, on purpose: __arm64_sys_openat() ORs it in
	 * before build_open_how() and build_open_how() then strips it for O_PATH
	 * (O_PATH_FLAGS has no O_LARGEFILE), and the openat2 wrapper explicitly does not
	 * add it when O_PATH is set (fs/open.c:1362-1364).  Both paths are reproduced
	 * exactly by not touching the flag.
	 */
	atomic_inc(&n_vopen_opath);
	*ret = do_sys_openat2(dfd, filename, &how);
	return true;
}

/*
 * The part of __arm64_sys_openat2() that reads the user's struct open_how
 * (fs/open.c:1344-1367), including the copy_struct_from_user() contract it is built
 * on: a size below the first published version is -EINVAL, a size above PAGE_SIZE is
 * -E2BIG, and any byte of a FUTURE (larger) struct beyond the bytes this kernel knows
 * must be zero or the answer is -E2BIG.  Re-expressed rather than called because
 * copy_struct_from_user() is a header inline that reaches check_zeroed_user() - not
 * exported, and the order of its checks is observable.
 */
static int susfs_vfs_copy_open_how(const void __user *u, size_t usize, struct open_how *out)
{
	size_t ksize = sizeof(*out);
	unsigned char pad[64];
	size_t off;

	if (unlikely(usize < OPEN_HOW_SIZE_VER0))
		return -EINVAL;
	if (unlikely(usize > PAGE_SIZE))
		return -E2BIG;

	memset(out, 0, ksize);
	if (copy_from_user(out, u, min(usize, ksize)))
		return -EFAULT;

	for (off = ksize; off < usize; ) {
		size_t n = min(usize - off, sizeof(pad));
		size_t i;

		if (copy_from_user(pad, (const char __user *)u + off, n))
			return -EFAULT;
		for (i = 0; i < n; i++)
			if (pad[i])
				return -E2BIG;
		off += n;
	}
	return 0;
}

bool susfs_vfs_open_ready(void)
{
	return susfs_vfs_open_enabled();
}

bool susfs_vfs_open_syscall(int site, const struct pt_regs *regs, long *ret)
{
	if (!susfs_vfs_open_ready())
		return false;
	return susfs_vfs_do_opath(site, regs, ret);
}

/*
 * =====================================================================
 * 9. /proc/susfs_vfs_open - the assembly report
 * =====================================================================
 */
static int vopen_proc_show(struct seq_file *m, void *v);
static int vopen_proc_open(struct inode *inode, struct file *file);

static const struct proc_ops vopen_proc_ops = {
	.proc_open = vopen_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static struct proc_dir_entry *vopen_proc_entry;

void susfs_vfs_open_dump(void)
{
	unsigned int i, k = 0, o = 0, in = 0;

	for (i = 0; i < ARRAY_SIZE(susfs_vfs_bindings); i++) {
		struct susfs_vfs_binding *b = &susfs_vfs_bindings[i];
		unsigned long cur = (unsigned long)READ_ONCE(*b->slot);

		switch (b->kind) {
		case SUSFS_VFS_KIND_OURS:		o++; break;
		case SUSFS_VFS_KIND_OURS_INLINED:	in++; break;
		default:
			if (b->kernel && cur == (unsigned long)b->kernel)
				k++;
			break;
		}
		pr_info("susfs_vfs_open: point %-18s %-13s kernel=%px ours=%px -> %px\n",
			b->name, susfs_vfs_kind_name(b->kind), b->kernel,
			b->ours, (void *)cur);
	}
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_leaves); i++) {
		struct susfs_vfs_leaf *l = &susfs_vfs_leaves[i];

		if (!READ_ONCE(*l->slot))
			pr_warn("susfs_vfs_open: leaf %-28s NOT RESOLVED\n", l->name);
	}
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_edges); i++) {
		struct susfs_vfs_edge *e = &susfs_vfs_edges[i];

		pr_info("susfs_vfs_open: edge %s -> %s: parent=%s child=%s\n",
			e->parent_name, e->child_name,
			susfs_vfs_kind_name(e->parent_kind),
			e->child_called ? "called (bl/b to the child)" :
			(e->child_kind == SUSFS_VFS_KIND_OURS_INLINED ?
			 "no bl/b seen - inlined, or called through the table, or not called by this parent"
			 : "not called"));
	}
	pr_info("susfs_vfs_open: enter link_path_walk=%d lookup_last=%d walk_component=%d step_into=%d handle_mounts=%d lookup_fast=%d lookup_slow=%d\n",
		atomic_read(&n_vopen_enter_link_path_walk), atomic_read(&n_vopen_enter_lookup_last),
		atomic_read(&n_vopen_enter_walk_component), atomic_read(&n_vopen_enter_step_into),
		atomic_read(&n_vopen_enter_handle_mounts), atomic_read(&n_vopen_enter_lookup_fast),
		atomic_read(&n_vopen_enter_lookup_slow));
	pr_info("susfs_vfs_open: resolve rcu_hit=%d rcu_miss=%d ref_hit=%d ref_miss=%d wc_hot=%d wc_plain=%d wc_cold=%d wc_commit=%d\n",
		atomic_read(&n_vopen_fa_rcu_hit), atomic_read(&n_vopen_fa_rcu_miss),
		atomic_read(&n_vopen_fa_ref_hit), atomic_read(&n_vopen_fa_ref_miss),
		atomic_read(&n_vopen_wc_hot), atomic_read(&n_vopen_wc_plain),
		atomic_read(&n_vopen_wc_cold), atomic_read(&n_vopen_wc_commit));
	pr_info("susfs_vfs_open: mode3 discarded=%d cached=%d inval_fail=%d neg_left=%d\n",
		atomic_read(&n_vopen_discarded), atomic_read(&n_vopen_discard_cached),
		atomic_read(&n_vopen_inval_fail), atomic_read(&n_vopen_neg_left));
	pr_info("susfs_vfs_open: verdict calls=%d true=%d | derived name try=%d neg=%d enoent=%d other=%d\n",
		atomic_read(&n_vopen_verdict_calls), atomic_read(&n_vopen_verdict_true),
		atomic_read(&n_vopen_fake_try), atomic_read(&n_vopen_fake_neg),
		atomic_read(&n_vopen_fake_enoent), atomic_read(&n_vopen_fake_other));
	pr_info("susfs_vfs_open: assembly %u kernel / %u ours / %u inlined (of %u points), leaves %u (absent %u, present-at-0 %u), armed=%d\n",
		k, o, in, (unsigned int)ARRAY_SIZE(susfs_vfs_bindings),
		(unsigned int)ARRAY_SIZE(susfs_vfs_leaves), n_vopen_leaf_missing,
		n_vopen_leaf_zero, (int)READ_ONCE(susfs_vfs_armed));
}

static int vopen_proc_show(struct seq_file *m, void *v)
{
	unsigned int i;

	seq_puts(m, "point              kind          avail implementation\n");
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_bindings); i++) {
		struct susfs_vfs_binding *b = &susfs_vfs_bindings[i];
		unsigned long cur = (unsigned long)READ_ONCE(*b->slot);

		seq_printf(m, "%-18s %-13s %-5s %s%s\n", b->name,
			   susfs_vfs_kind_name(b->kind), b->kernel ? "yes" : "no",
			   cur == (unsigned long)b->ours ? "ours" : "kernel",
			   b->kind == SUSFS_VFS_KIND_OURS ? " (required)" : "");
	}

	seq_printf(m, "\nleaf                            resolved   (absent %u, present-at-0 %u)\n",
		   n_vopen_leaf_missing, n_vopen_leaf_zero);
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_leaves); i++) {
		struct susfs_vfs_leaf *l = &susfs_vfs_leaves[i];

		seq_printf(m, "%-30s %px\n", l->name, (void *)READ_ONCE(*l->slot));
	}

	seq_puts(m, "\nedge                     parent        child\n");
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_edges); i++) {
		struct susfs_vfs_edge *e = &susfs_vfs_edges[i];

		seq_printf(m, "%-24s %-13s %s\n", e->parent_name,
			   susfs_vfs_kind_name(e->parent_kind),
			   (!e->parent || !e->child) ? "unresolved" :
			   (susfs_vfs_parent_calls_child(e->parent, e->child) ?
			    "call to child seen" : "no call seen"));
	}

	seq_puts(m, "\nframe self-check (depth = kernel stack top - frame pointer; 0 = not a frame)\n");
	for (i = 0; i < SUSFS_VFS_FRAME_SLOTS_N; i++) {
		struct susfs_vfs_frame_rec *r = &susfs_vfs_frames[i];

		seq_printf(m, "%-18s calls=%-10lu depth=%-7u lr=%px fp=%px\n",
			   susfs_vfs_frame_points[i], r->hits, r->depth,
			   (void *)r->lr, (void *)r->fp);
	}

	seq_printf(m, "\narmed=%d enable=%d fake=%d drop=%d drop_fake=%d 	frame=%d dbg=%d dbg_name=%s salt=%d\n",
		   (int)READ_ONCE(susfs_vfs_armed), vopen_enable, vopen_fake,
		   (int)vopen_drop, (int)vopen_drop_fake, vopen_frame, vopen_dbg,
		   vopen_dbg_name[0] ? vopen_dbg_name : "-", (int)(susfs_vfs_salt != 0));
	seq_printf(m, "enter: link_path_walk=%d lookup_last=%d walk_component=%d step_into=%d handle_mounts=%d lookup_fast=%d lookup_slow=%d\n",
		   atomic_read(&n_vopen_enter_link_path_walk), atomic_read(&n_vopen_enter_lookup_last),
		   atomic_read(&n_vopen_enter_walk_component), atomic_read(&n_vopen_enter_step_into),
		   atomic_read(&n_vopen_enter_handle_mounts), atomic_read(&n_vopen_enter_lookup_fast),
		   atomic_read(&n_vopen_enter_lookup_slow));
	seq_printf(m, "resolve: rcu_hit=%d rcu_miss=%d ref_hit=%d ref_miss=%d | slow: wc_hot=%d wc_plain=%d wc_cold=%d wc_commit=%d\n",
		   atomic_read(&n_vopen_fa_rcu_hit), atomic_read(&n_vopen_fa_rcu_miss),
		   atomic_read(&n_vopen_fa_ref_hit), atomic_read(&n_vopen_fa_ref_miss),
		   atomic_read(&n_vopen_wc_hot), atomic_read(&n_vopen_wc_plain),
		   atomic_read(&n_vopen_wc_cold), atomic_read(&n_vopen_wc_commit));
	seq_printf(m, "mode3: discarded=%d cached=%d inval_fail=%d neg_left=%d (vopen_neg=%d)\n",
		   atomic_read(&n_vopen_discarded), atomic_read(&n_vopen_discard_cached),
		   atomic_read(&n_vopen_inval_fail), atomic_read(&n_vopen_neg_left),
		   (int)vopen_neg);
	seq_printf(m, "verdict: calls=%d true=%d | derived name: try=%d neg=%d enoent=%d other=%d collide=%d\n",
		   atomic_read(&n_vopen_verdict_calls), atomic_read(&n_vopen_verdict_true),
		   atomic_read(&n_vopen_fake_try), atomic_read(&n_vopen_fake_neg),
		   atomic_read(&n_vopen_fake_enoent), atomic_read(&n_vopen_fake_other),
		   atomic_read(&n_vopen_collide));
	seq_printf(m, "seen=%d opath=%d hidden=%d faked=%d cold=%d dropped=%d collide=%d err=%d\n",
		   atomic_read(&n_vopen_seen), atomic_read(&n_vopen_opath),
		   atomic_read(&n_vopen_hidden), atomic_read(&n_vopen_faked),
		   atomic_read(&n_vopen_cold), atomic_read(&n_vopen_dropped),
		   atomic_read(&n_vopen_collide), atomic_read(&n_vopen_err));
	return 0;
}

static int vopen_proc_open(struct inode *inode, struct file *file)
{
	/* Root-only with 0777 on the node, like /proc/susfs_opath: DAC has to pass so
	 * that sus_path's LSM layer is the only thing answering a non-root reader. */
	if (current_uid().val != 0)
		return -ENOENT;
	return single_open(file, vopen_proc_show, NULL);
}

/*
 * =====================================================================
 * 10. Load-time assembly, init and exit
 * =====================================================================
 */

/*
 * Bind one point.  This is the whole "kernel entity or our copy" decision, and it is
 * taken once, from what the kernel's own symbol table says - never from a compile-time
 * assumption - so that the same binary serves a vendor kernel that moved, renamed or
 * inlined any of these.
 */
static void susfs_vfs_bind_one(struct susfs_vfs_binding *b)
{
	unsigned long k;

	if (b->kind == SUSFS_VFS_KIND_OURS) {
		/* Not a choice: the kernel's copy of this point cannot carry the hidden
		 * decision, so binding it would turn the layer off while it still looked
		 * armed.  The kallsyms answer is still looked up and recorded, because
		 * that is the evidence the report is for: on this kernel a name can be in
		 * kallsyms while its call sites were inlined away (the project measured
		 * exactly that for do_filp_open/step_into/walk_component), so "the kernel
		 * has this symbol" and "the kernel's entity is on the path" are two
		 * different statements. */
		b->kernel = (void *)find_kernel_symbol_exact(b->name);
		WRITE_ONCE(*b->slot, b->ours);
		susfs_vfs_asm_ours++;
		return;
	}

	k = find_kernel_symbol_exact(b->name);
	b->kernel = (void *)k;
	if (k) {
		WRITE_ONCE(*b->slot, (void *)k);
		susfs_vfs_asm_kernel++;
		return;
	}

	pr_info("susfs_vfs_open: point %s has no kernel symbol (inlined away or renamed) - using this module's copy\n",
		b->name);
	WRITE_ONCE(*b->slot, b->ours);
	susfs_vfs_asm_ours++;
}

static void susfs_vfs_assemble(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(susfs_vfs_bindings); i++)
		susfs_vfs_bind_one(&susfs_vfs_bindings[i]);
}

/*
 * The edge scan.  It answers what the binding above cannot: for each edge of the real
 * path, does the parent have a BODY for the child, and if not, whose body contains it?
 * A refused edge is the forbidden shape - a child we must provide, contained in a
 * parent we do not control.
 */
static int susfs_vfs_check_edges(void)
{
	unsigned int i, j;
	int bad = 0;

	/* Pass 1: resolve both ends of every edge and ask the artifact whether the
	 * parent really has a body for the child. */
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_edges); i++) {
		struct susfs_vfs_edge *e = &susfs_vfs_edges[i];
		struct susfs_vfs_binding *pb = susfs_vfs_find_binding(e->parent_name);
		struct susfs_vfs_binding *cb = susfs_vfs_find_binding(e->child_name);

		if (!pb || !cb) {
			pr_err("susfs_vfs_open: edge %s -> %s names an unknown point\n",
			       e->parent_name, e->child_name);
			bad++;
			continue;
		}

		e->parent = READ_ONCE(*pb->slot);
		e->child = READ_ONCE(*cb->slot);
		e->parent_kind = pb->kind;
		e->child_kind = cb->kind;
		e->child_called = susfs_vfs_parent_calls_child(e->parent, e->child);
	}

	/* Pass 2: decide the OURS_INLINED state.  It is a property of the CHILD across
	 * all its edges, not of one edge: a point the compiler inlined into the parent
	 * that happens to be checked first can still be a real call elsewhere, and
	 * calling a point that is also inlined is exactly the double execution this
	 * state exists to prevent.  So the state is set only when NO edge reaches the
	 * child as a call. */
	for (i = 0; i < ARRAY_SIZE(susfs_vfs_edges); i++) {
		struct susfs_vfs_edge *e = &susfs_vfs_edges[i];
		struct susfs_vfs_binding *cb = susfs_vfs_find_binding(e->child_name);
		bool called_elsewhere = false;

		if (!cb || !e->parent || e->child_called)
			continue;

		for (j = 0; j < ARRAY_SIZE(susfs_vfs_edges); j++) {
			struct susfs_vfs_edge *o = &susfs_vfs_edges[j];

			if (o->child_called && !strcmp(o->child_name, e->child_name)) {
				called_elsewhere = true;
				break;
			}
		}

		if (e->parent_kind == SUSFS_VFS_KIND_OURS && !called_elsewhere) {
			/* Our parent's copy contains the child: the compiler inlined it.
			 * A legitimate way for the child to be provided - as long as it is
			 * not also called, which is what this state records. */
			e->child_kind = SUSFS_VFS_KIND_OURS_INLINED;
			cb->kind = SUSFS_VFS_KIND_OURS_INLINED;
			susfs_vfs_asm_inlined++;
			pr_info("susfs_vfs_open: edge %s -> %s: the child is inlined into our copy of the parent\n",
				e->parent_name, e->child_name);
			continue;
		}

		if (called_elsewhere)
			continue;	/* reached as a call: not an inlining anywhere */

		/* The kernel's parent neither calls nor exposes the child, so the child's
		 * logic sits inside the kernel's parent.  Tolerable for a point nobody
		 * needs to change; a refusal when the child is one of ours. */
		pr_warn("susfs_vfs_open: edge %s -> %s: the kernel's parent neither calls nor exposes the child\n",
			e->parent_name, e->child_name);
		if (cb->kind == SUSFS_VFS_KIND_OURS) {
			pr_err("susfs_vfs_open: %s must be ours and is not on any call path - refusing to arm\n",
			       e->child_name);
			bad++;
		}
	}
	return bad;
}

/*
 * The leaf resolver.  "Missing" here means the copies cannot run, so the layer refuses
 * to arm instead of arming half of itself.  Every name is printed whether it resolved or
 * not: a bring-up that only sees the failures cannot tell "the name is not there" from
 * "the loop did not run".
 */
static int susfs_vfs_resolve_leaves(void)
{
	unsigned int i;
	int missing = 0;

	for (i = 0; i < ARRAY_SIZE(susfs_vfs_leaves); i++) {
		struct susfs_vfs_leaf *l = &susfs_vfs_leaves[i];
		unsigned long a = find_kernel_symbol_exact(l->name);

		WRITE_ONCE(*l->slot, (void *)a);
		if (a)
			continue;
		missing++;
		/* "the name is not there" and "the name is there with no callable
		 * address" are different facts about a device, and only the second is a
		 * device difference worth recording: a 5.15 kallsyms can keep a symbol
		 * whose body was folded away and report it as 0 - measured on this device
		 * for touch_atime, which is why that dependency was removed from this
		 * file rather than worked around.  ksu_find_symbol_all() cannot see that
		 * case (its callback skips `!addr`), so the .cfi_jt sibling is the probe:
		 * a CFI kernel gives one to every indirectly-called function, so "plain
		 * name 0 + .cfi_jt present" IS the signature of present-but-not-callable. */
		if (susfs_vfs_name_present_at_zero(l->name)) {
			n_vopen_leaf_zero++;
			pr_warn("susfs_vfs_open: leaf '%s' IS in this kernel's kallsyms but at address 0 (only a .cfi_jt stub) - no callable entity\n",
				l->name);
		} else {
			n_vopen_leaf_missing++;
			pr_warn("susfs_vfs_open: leaf '%s' is not in this kernel's kallsyms at all\n",
				l->name);
		}
	}

	/* Data: never called, read through the pointer.  mount_lock/rename_lock are the
	 * seqlocks the copied walk takes with read_seqbegin()/read_seqretry();
	 * sysctl_protected_symlinks is only read (by may_follow_link). */
	susfs_k_mount_lock = (seqlock_t *)find_kernel_symbol_exact("mount_lock");
	susfs_k_rename_lock = (seqlock_t *)find_kernel_symbol_exact("rename_lock");
	susfs_k_sysctl_protected_symlinks = (int *)find_kernel_symbol_exact("sysctl_protected_symlinks");

	if (!susfs_k_mount_lock) {
		pr_warn("susfs_vfs_open: 'mount_lock' not resolved - the walk cannot run\n");
		missing++;
	}
	if (!susfs_k_rename_lock) {
		pr_warn("susfs_vfs_open: 'rename_lock' not resolved - the walk cannot run\n");
		missing++;
	}
	if (!susfs_k_sysctl_protected_symlinks)
		pr_warn("susfs_vfs_open: 'sysctl_protected_symlinks' not resolved - may_follow_link() will read 0 (the kernel's default) instead of the configured value\n");

	/* Optional, and missing on the measured device: see the note in OPTIONAL_LEAVES. */
	susfs_k___cond_resched = (int (*)(void))find_kernel_symbol_exact("__cond_resched");
	if (!susfs_k___cond_resched)
		pr_warn("susfs_vfs_open: '__cond_resched' not resolved - the vendored walk will not yield the CPU on a long path (slower for other tasks, not wrong)\n");

	return missing;
}

/*
 * The layout gate.  These three numbers cannot be derived on the build host: struct
 * nameidata is file-local to fs/namei.c and does not exist in the DDK headers.  They are
 * read off the device - the kernel publishes BTF (CONFIG_DEBUG_INFO_BTF=y), so
 * `bpftool btf dump file /sys/kernel/btf/vmlinux format c` or pahole on the device's
 * vmlinux gives all three - and passed in as module parameters.  0 means "not checked",
 * and the layer says so out loud rather than implying it verified something.
 */
static int susfs_vfs_check_layout(void)
{
	int bad = 0;

	if (vopen_nd_size && vopen_nd_size != sizeof(struct nameidata)) {
		pr_err("susfs_vfs_open: struct nameidata is %zu bytes here but %lu on the device - refusing to arm, current->nameidata is shared with the kernel\n",
		       sizeof(struct nameidata), vopen_nd_size);
		bad++;
	}
	if (vopen_nd_internal && vopen_nd_internal != offsetof(struct nameidata, internal)) {
		pr_err("susfs_vfs_open: offsetof(struct nameidata, internal) is %zu here but %lu on the device - EMBEDDED_LEVELS or a field differs\n",
		       offsetof(struct nameidata, internal), vopen_nd_internal);
		bad++;
	}
	if (vopen_nd_state && vopen_nd_state != offsetof(struct nameidata, state)) {
		pr_err("susfs_vfs_open: offsetof(struct nameidata, state) is %zu here but %lu on the device\n",
		       offsetof(struct nameidata, state), vopen_nd_state);
		bad++;
	}
	if (!vopen_nd_size || !vopen_nd_internal || !vopen_nd_state)
		pr_warn("susfs_vfs_open: layout gate is PARTIAL (nd_size=%lu nd_internal=%lu nd_state=%lu) - fill these from the device's BTF before trusting this layer\n",
			vopen_nd_size, vopen_nd_internal, vopen_nd_state);
	return bad;
}

__nocfi int susfs_vfs_open_init(void)
{
	int missing;

	if (susfs_vfs_check_layout())
		return -EINVAL;

	missing = susfs_vfs_resolve_leaves();
	if (missing) {
		pr_warn("susfs_vfs_open: %d required kernel symbol(s) missing - the layer stays OFF and O_PATH keeps the post-check answer\n",
			missing);
		atomic_inc(&n_vopen_err);
		return -ENOENT;
	}

	susfs_vfs_asm_kernel = 0;
	susfs_vfs_asm_ours = 0;
	susfs_vfs_asm_inlined = 0;
	susfs_vfs_assemble();

	if (!susfs_vfs_asm_kernel && !susfs_vfs_asm_ours) {
		/* Cannot happen while the loop above runs.  Kept because the alternative is
		 * a table of NULLs that panics on the first O_PATH open. */
		pr_err("susfs_vfs_open: no point could be assembled - refusing to arm\n");
		return -ENOENT;
	}

	if (susfs_vfs_check_edges()) {
		pr_err("susfs_vfs_open: the hidden decision is not on a real call path - refusing to arm\n");
		return -ENOENT;
	}

	{
		u64 salt = 0;

		susfs_k_get_random_bytes(&salt, sizeof(salt));
		susfs_vfs_salt = salt;
	}

	WRITE_ONCE(susfs_vfs_armed, true);

	if (susfs_control_node_allowed()) {
		vopen_proc_entry = proc_create("susfs_vfs_open", 0777, NULL, &vopen_proc_ops);
		if (!vopen_proc_entry)
			pr_warn("susfs_vfs_open: proc_create(susfs_vfs_open) failed\n");
	} else {
		SUSFS_LOGI("susfs_vfs_open: /proc node not created (expose_proc=%d lsm=%d)\n",
			   (int)susfs_expose_proc, (int)sus_path_lsm_active());
	}

	SUSFS_LOGI("susfs_vfs_open armed: %u points (%u kernel / %u ours / %u inlined), fake=%d drop=%d drop_fake=%d proc=%d\n",
		   (unsigned int)ARRAY_SIZE(susfs_vfs_bindings), susfs_vfs_asm_kernel,
		   susfs_vfs_asm_ours, susfs_vfs_asm_inlined, vopen_fake,
		   (int)vopen_drop, (int)vopen_drop_fake, vopen_proc_entry != NULL);
	susfs_vfs_open_dump();
	return 0;
}

void susfs_vfs_open_exit(void)
{
	if (!READ_ONCE(susfs_vfs_armed))
		return;

	/* Disarm FIRST, then take the node away.  The wrappers in susfs_opath.c test
	 * susfs_vfs_open_ready() on every O_PATH call, and the sys_call_table entries
	 * themselves belong to that file: it restores them and drains RCU after this
	 * layer is off. */
	WRITE_ONCE(susfs_vfs_armed, false);

	if (vopen_proc_entry) {
		proc_remove(vopen_proc_entry);
		vopen_proc_entry = NULL;
	}

	SUSFS_LOGI("susfs_vfs_open disarmed: seen=%d opath=%d hidden=%d faked=%d cold=%d dropped=%d collide=%d err=%d\n",
		   atomic_read(&n_vopen_seen), atomic_read(&n_vopen_opath),
		   atomic_read(&n_vopen_hidden), atomic_read(&n_vopen_faked),
		   atomic_read(&n_vopen_cold), atomic_read(&n_vopen_dropped),
		   atomic_read(&n_vopen_collide), atomic_read(&n_vopen_err));
}

#else	/* !SUSFS_VFS_OPEN_SUPPORTED */

/*
 * Every kernel line other than 5.15.
 *
 * 5.10 is not a smaller version of this file, it is a different one: struct nameidata
 * has no `state` field (the jumped/root-preset state lives in `flags`), set_nameidata()
 * takes no root and does not initialise depth/path, the try_to_unlazy pair is spelled
 * unlazy_walk/unlazy_child, and may_lookup() has no mnt_userns argument.  6.1+ differs
 * again: mnt_idmap instead of user_namespace, dir_vfsuid, next_seq, and six functions
 * that lost their out-parameter forms.  Copying a 5.15 body onto one of those kernels
 * would not fail to compile - it would write the wrong bytes into current->nameidata,
 * which every namei path in the kernel then reads through the kernel's own layout.
 *
 * So the answer on those lines is an empty layer: one log line saying so, and the
 * existing O_PATH post-check layer (kernel/susfs_opath.c) stays the whole
 * implementation.  This is also what keeps the eight CI variants building.
 */
__nocfi int susfs_vfs_open_init(void)
{
	SUSFS_LOGI("susfs_vfs_open: kernel line %u.%u is not supported by the vendored O_PATH open (5.15 only) - keeping the existing O_PATH post-check layer\n",
		   (LINUX_VERSION_CODE >> 16) & 0xff, (LINUX_VERSION_CODE >> 8) & 0xff);
	return 0;
}

void susfs_vfs_open_exit(void) { }

bool susfs_vfs_open_ready(void)
{
	return false;
}

bool susfs_vfs_open_syscall(int site, const struct pt_regs *regs, long *ret)
{
	return false;
}

void susfs_vfs_open_dump(void) { }

#endif	/* SUSFS_VFS_OPEN_SUPPORTED */
