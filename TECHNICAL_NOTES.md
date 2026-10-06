# TECHNICAL_NOTES — the comments that used to live in the shipped sources

The release assets are built from `kernel/` and `tools/`, and those files are kept lean:
about 3% of their lines are comments, and only ones that read as a note beside the code --
the SPDX tags, inline annotations and gate labels such as `#endif /* < 6.12 */`, and short
standalone remarks.  Every longer comment was moved here, verbatim, in source order.

Each entry is the comment that documented the code line in its heading.  Grep the anchor
to find that code:

    grep -n "sus_mount_ida_alloc" kernel/sus_mount.c

What is in here is upstream's own material: measurements taken on the devices this module
was developed against (OPPO PJA110, Android 12-16, kernels 5.10-6.18 and vendor trees),
kernel-version facts, ABI contracts, layout probes, and the traps that were hit once and
should not be hit again.  Numbers are observed values, not estimates.

## `kernel/lsm_hook.c`

### `(file header)`

```c
/*
 * lsm_hook.c - runtime LSM hook installation (ported from KernelSU/SukiSU hook/lsm_hook.c).
 * Both mechanisms write through ksu_patch_text(): every word they touch is read-only text, and the
 * replacement lives in module .text, so a patch has to go through stop_machine.
 *
 *   replace - overwrite the entry's function slot; the old pointer goes to hook->original
 *             for pass-through.  The slot is SELinux's, so a caller LSM returning non-zero
 *             first masks this hook.
 *   insert  - get in front of every registered LSM, so the hook can only ADD a denial:
 *               < 6.12   add our OWN security_hook_list node at the HEAD of the hlist
 *                        (hook->insert, KSU_LSM_HOOK_INSERT): no symbol, no original.
 *               >= 6.12  no hlist exists - dispatch is one static call per (hook, LSM
 *                        slot) - so insertion TAKES OVER SELinux's slot, whose original
 *                        must be called for pass-through (SUS_LSM_PASS_ORIG(), sus_path.c).
 */
```

### `ksu_lsm_hook_head_at()`

```c
/* ---- insertion into a hook list (hook->insert) -------------------------------
 * SELinux's node lives in selinux_hooks[] __lsm_ro_after_init, hence ksu_patch_text()
 * below; our node is writable and becomes reachable only once head->first is patched, so
 * no walk can observe a half-initialised node. */
```

### `static int ksu_lsm_hook_head_at(unsigned long heads_addr, struct ksu_lsm_hook *hook,`

```c
/* Locate the list head for hook->head_name and cross-check it: the address is
 * offsetof(struct security_hook_heads, member), a __randomize_layout struct (RANDSTRUCT is off in
 * every GKI build this module targets), so LSM_HOOK_INIT's entry->head verifies that the first
 * entry at that address points back at it.  A wrong offset would otherwise patch an hlist_head no
 * call site walks - a hook silently never called, which reads like a working layer in every
 * counter - hence a mismatch fails the load, and an empty head is -ENOENT (as in replace). */
```

### `memset(node, 0, sizeof(*node));`

```c
/* Set the hook word through the offset the slot path uses (the per-hook initialiser
     * need not name the union member); `lsm` is char * on 5.10/5.15, const char * on 6.1. */
```

### `ret = ksu_lsm_hook_patch_slot((void **)&first->pprev, &node->list.next);`

```c
/* 2. the displaced node's back pointer, inside selinux_hooks[] (also RO after init):
     *    a later removal of THAT node must not unlink from a stale pointer into ours. */
```

### `if (next) {`

```c
/* 2. the successor's back pointer: not needed for the walk, but a later removal of
     *    THAT node must not write through a pointer into this module's memory. */
```

### `static void (*ksu_static_call_update_fn)(struct static_call_key *key, void *tramp, void *func);`

```c
/* The kernel's own __static_call_update(), resolved by name at load and called through a __nocfi
 * wrapper like every other resolved-address call in this module.
 *
 * Why not the compile-time one: linux/static_call.h defines __static_call_update() as a
 * `static __always_inline` unless the kernel was built with CONFIG_HAVE_STATIC_CALL_INLINE, and
 * the trees this module is compiled against all take the inline arm.  With the inline arm the
 * call SITE has to be patched (arch_static_call_transform()), and the generic
 * `WRITE_ONCE(key->func, func)` only changes what a trampoline reads - so on a kernel that has
 * the inline arm the takeover would silently not take effect.  Resolving the symbol means using
 * the very implementation the running kernel registers its own hooks with, on any config;
 * lsm_static_call_init() itself calls it as __static_call_update(scall->key, scall->trampoline,
 * hl->hook.lsm_func_addr), i.e. with exactly the two values this wrapper passes on.  When the
 * kernel has no such symbol (every tree this module currently builds against:
 * CONFIG_HAVE_STATIC_CALL(_INLINE) unset, so it is an inline) the compile-time call is the same
 * thing and stays the fallback.  Either way the module looks the name up itself, like
 * static_calls_table and every other by-name symbol - nothing new for the loader. */
```

### `#define KSU_LSM_SLOTS_PER_HOOK`

```c
/* ---- insertion on >= 6.12: taking over SELinux's static-call slot ----------------
 *
 * 6.12 replaced the hlist dispatch with one static call per (hook, LSM slot), so there
 * is no list left to insert into: struct security_hook_list (include/linux/lsm_hooks.h)
 * lost its hlist node and its `lsm` field, and each (hook, LSM slot) is now a
 *   struct lsm_static_call { struct static_call_key *key; void *trampoline; struct
 *                            security_hook_list *hl; struct static_key_false *active; }
 * inside `extern struct lsm_static_calls_table static_calls_table __ro_after_init`.
 * security/security.c dispatches with
 *   if (static_branch_unlikely(&SECURITY_HOOK_ACTIVE_KEY(HOOK, NUM)))
 *       R = static_call(LSM_STATIC_CALL(HOOK, NUM))(...);
 * and lsm_static_call_init() filled each slot at boot: it walked hl->scalls, took the
 * first slot with !scall->hl, ran __static_call_update(scall->key, scall->trampoline,
 * hl->hook.lsm_func_addr), set scall->hl and enabled THAT slot's static key.
 *
 * An unregistered LSM cannot get a slot of its own (that needs static-key work this module
 * has no business doing), but it CAN take over a live one, and SELinux's is the right one:
 * its static key is already enabled, and it holds its documented position in the order, so
 * an earlier slot (capabilities) still runs first and later ones (safesetid, landlock,
 * bpf-lsm) still run whenever the hook's default is returned.  The displaced function is
 * called from the replacement (hook->original via SUS_LSM_PASS_ORIG()), so nothing SELinux
 * decided is lost - including the -ECHILD inode_permission's RCU walk depends on.  The only
 * symbol needed is static_calls_table; the switch itself goes through
 * ksu_lsm_hook_update_scall() above, i.e. the kernel's own __static_call_update() whenever
 * the running kernel has it as a symbol.
 *
 * NOTHING IS WRITTEN until the slot passes all five validations below: the failure this must
 * not have is a jump target that is wrong rather than absent.  Every read uses
 * copy_from_kernel_nofault() - a bogus pointer cannot fault the check that exists to catch
 * it - and failing any of them returns without patching, so the hook is simply not armed
 * (-ENOSYS for every insert on this branch before the change) and an unknown layout costs
 * coverage, never a corrupted jump target:
 *   1. key/hl/trampoline are readable, key and hl are plausible kernel addresses, trampoline is
 *      NULL or one.  NULL is NOT a layout problem: security.c's LSM_HOOK_TRAMP() is NULL whenever
 *      the tree lacks CONFIG_HAVE_STATIC_CALL and lsm_static_call_init() hands that same NULL to
 *      __static_call_update() at boot (measured on both DDK trees this branch targets); either arm
 *      ends at key->func, which is what this code reads, saves and replaces;
 *   2. hl->scalls == &static_calls_table.<member>[0]: the entry is registered for THIS hook,
 *      which validates head_offset against the kernel's real layout - a RANDSTRUCT kernel
 *      (or any table whose member order moved) makes the two disagree;
 *   3. hl->lsmid->name reads as "selinux" - only SELinux's slot is ever taken;
 *   4. the slot's current target (key->func, what the dispatch calls) equals the entry's own
 *      hook word (hl + hook_offset): two places lsm_static_call_init() filled from one value;
 *   5. that target really is THIS hook's SELinux implementation: named through kallsyms as
 *      "selinux_<member>" (clone suffix allowed), exact match against the name-resolved symbol as
 *      fallback - the check offsetof() cannot do, a reordered table's slot having a different prototype.
 */
```

### `#define KSU_LSM_KPTR_MIN`

```c
/* arm64 kernel addresses (image, modules, vmalloc) all live in the top of the address space.
 * The bound is loose on purpose: it only has to reject NULL, a small integer, a user address. */
```

### `static int ksu_lsm_read_ptr(const void *addr, void *out)`

```c
/* Read one pointer-sized word without faulting.  @out is `void *`, not `void **`: callers
 * pass the address of a TYPED pointer and -Wincompatible-pointer-types is an error here. */
```

### `static int ksu_lsm_fn_is_selinux_hook(void *fn, const char *member, void *expect)`

```c
/* Is @fn the SELinux implementation of @member?  0 yes, negative no/unknown.
 *
 * Three sources of evidence, strongest first:
 *   1. the kallsyms name is exactly selinux_<member>, clone suffixes allowed
 *      (.cold/.isra/.constprop/.llvm.N) - what a stock kernel registers;
 *   2. the kallsyms name CONTAINS <member>: an OEM wrapper around selinux_<member>, a
 *      vendor-prefixed symbol, or an LTO renaming that does not begin with the base name.
 *      This is the relaxation a vendor device needs - issue #1 (6.12.23-android16) refuses to
 *      load with "holds ... which is not selinux_inode_getattr", and upstream's
 *      lsm_hook_defs.h / lsm_hooks.h / selinux/hooks.c are byte-identical between v6.12.23 and
 *      the v6.12 DDK this module is built from, so that device registers something other than
 *      the stock symbol for this hook.  It does NOT cost the shifted-layout guard: no OTHER
 *      hook name CONTAINS <member> in any hook list this module builds against (234 hooks on
 *      5.10, 238/5.15, 243/6.1, 249/6.6, 268/6.12, 273/6.18 - checked pairwise), so a slot
 *      that belongs to a different hook still cannot match this;
 *   3. the address equals the resolved selinux_<member> (@expect), used when the kallsyms name
 *      could not be read at all.
 *
 * A module-owned function is refused before either name test: the static-call table lives in
 * core (security/security.c) and an LSM registered in it cannot come from a module, so a
 * modname here is a resolution error rather than a renamed hook.
 *
 * Both the accept-by-relaxation and every rejection name the function that was actually
 * found: the caller's message prints only the expected name, which is the one fact a field
 * report cannot supply (issue #1).
 */
```

### `hook->scall = chosen;`

```c
/* Publish in this order on purpose: the replacement reads hook->original on its
     * pass-through path, so it must become visible BEFORE the static call can reach it - a call in
     * between would see original == NULL and drop SELinux's decision.  The fence is needed on arm64
     * (static_call_update is a plain WRITE_ONCE of key->func, and the smp_wmb() inside
     * ksu_lsm_hook_update_scall() comes after that store); SUS_LSM_PASS_ORIG() has the matching
     * smp_rmb(), without which the reader can still load original before the key->func load. */
```

### `ksu_lsm_unhook()`

```c
/* Insertion resolves no symbol on < 6.12 (no original, no slot to match), and both
         * branches validate everything before their first patched write. */
```

### `unsigned long sym_size = sizeof(struct lsm_static_calls_table);`

```c
/* sym_size is sizeof() and not kallsyms_lookup_size_offset(): that symbol is UNEXPORTED
         * in every GKI tree this module targets, so importing it makes the module unloadable by
         * a plain `insmod` (unknown symbol) - it is the fifth name the "Verify sections" CI step
         * refuses in the .ko's undefined list - and the number is the same either way. */
```

### `if (addr)`

```c
/* The STRIDE is the compile-time MAX_LSM_COUNT the table is dimensioned with, NOT the
         * runtime number of active LSMs: lsm_active_cnt counts the enabled SECURITY_ options
         * (plus BPF_LSM etc.) and says nothing about how many slots each hook has.  Using it as
         * the stride picked the wrong struct lsm_static_call whenever the two differ, i.e.
         * patched a function pointer into another hook's slot (kCFI panic at the next call). */
```

### `hook->entry = selected_entry;`

```c
/* Publish BEFORE the switch, exactly like the insert path: the replacement reads
     * hook->original on its pass-through path, so a call arriving between the static-call
     * update and this store would see NULL and fall through to `return 0` - dropping
     * SELinux's decision (fail-open).  smp_wmb() pairs with the smp_rmb() in
     * SUS_LSM_PASS_ORIG(). */
```

### `hook->entry = NULL;`

```c
/* Undo the publication as well: the replacement must not look armed, or a later
         * unhook would try to restore a static call that was never switched. */
```

### `head = (struct hlist_head *)heads_addr;`

```c
/* heads_size is sizeof(), not kallsyms_lookup_size_offset(), which is UNEXPORTED in every
     * GKI tree this module targets - see the same call site in the >= 6.12 branch. */
```

### `if (ksu_lsm_hook_update_scall(hook->scall, hook->original)) {`

```c
/* Symmetric with ksu_lsm_hook_insert_scall(): the takeover only replaced the
         * static call, and the entry's own hook word still holds the original. */
```

### `if (ksu_lsm_hook_remove_head(hook)) {`

```c
/* Our own security_hook_list node is in the list: an insert node, or (legacy) a
         * replace-mode hook that found its head empty; both unlink through list.pprev. */
```

### `ksu_lsm_hook_drain();`

```c
/* Drained after the lock is released: the wait is unbounded (a quiescent state for every
     * task, or the 50 ms fallback) and holding ksu_lsm_hook_lock across it serialises every
     * other hook operation, while the node/slot is already unlinked above and only a task
     * already inside the replacement can still be there. */
```

### `static void (*ksu_lsm_sync_rcu_tasks_fn)(void);`

```c
/* Wait until nothing can still be inside a replacement function.
 * synchronize_rcu() is not enough: the LSM call sites walk their hook list with a plain
 * hlist_for_each_entry (security/security.c), not through an RCU read-side section, so a task already
 * inside the replacement is invisible to that barrier and would still be there when the module text is
 * unmapped - a use-after-free on the next instruction.  synchronize_rcu_tasks() waits for every task to
 * pass a context switch, which does cover it; it is resolved at runtime and reached through a __nocfi
 * wrapper (kCFI checks the type hash at the call site), with a 50 ms delay if it cannot be resolved. */
```

### `void ksu_lsm_hook_init(void)`

```c
/* No __init/__exit annotation on these two on purpose: the layer table (susfs_main.c) holds their
 * addresses and calls the exit from the rollback path of a FAILED load, i.e. from plain .text. */
```

### `ksu_static_call_update_fn = (void *)find_kernel_symbol_exact("__static_call_update");`

```c
/* The device's own implementation, when it has one as a symbol - see the note on
     * ksu_lsm_hook_update_scall().  NULL is the normal case on the trees this module is built
     * against (the header's static inline is not a symbol) and selects the compiled-in call. */
```


## `kernel/patch_memory.c`

### `unsigned long phys_from_virt(unsigned long addr, int *err)`

```c
/* Translate a kernel virtual address to a physical address by walking the init_mm page tables (section/leaf
 * mappings at p4d/pud/pmd included).  Returns the physical address, or 0 and sets *err on failure. */
```

### `#define ksu_flush_dcache`

```c
/* dcache/icache flush: 5.14+ replaced __flush_dcache_area/__flush_icache_range
 * with dcache_clean_inval_poc / caches_clean_inval_pou. */
```


## `kernel/spoof_cmdline.c`

### `(file header)`

```c
/*
 * spoof_cmdline.c - spoof /proc/bootconfig (SUSFS SPOOF_CMDLINE_OR_BOOTCONFIG).  boot_config_proc_show()
 * (fs/proc/bootconfig.c) does `if (saved_boot_config) seq_puts(m, saved_boot_config);`, so rewriting the static
 * pointer spoofs the whole file; that variable is a static BSS pointer resolved at load time by ksud insmod
 * (kallsyms relocation, like selinux_state in kstat) and the write is atomic, so concurrent seq reads are safe.
 * The fake string is heap-allocated (kstrdup): the supercall ABI accepts up to 8192 bytes, and the insmod
 * parameter is copied to the heap as well so a later supercall can free it safely.
 */
```

### `static char param_bootconfig[4096];`

```c
/* The supercall's field is 8192 wide, but this insmod parameter cannot be: module_param_string()'s value goes through a
 * sysfs attribute and a sysfs write is capped at one page, so the parameter tops out at 4095 bytes where the supercall
 * accepts 8191. */
```

### `struct retired_str {`

```c
/* Strings that saved_boot_config used to point at.  A published string must NEVER be freed while saved_boot_config
 * might reach it: /proc/bootconfig is read via seq_puts with no lock of ours, so freeing the old buffer before
 * republishing let a reader touch freed memory, and a set() that then failed kstrdup left saved_boot_config dangling
 * at the buffer it had just freed.  Retiring instead costs one 8 KB string per update. */
```

### `if (spoof_active) {`

```c
/* Unpublish - and deliberately free nothing: a reader that already picked up the pointer can still be printing
	 * it while this runs, and unload is no exception, so a kfree() here only buys a use-after-free. */
```

### `err = -ENOMEM;`

```c
/* The kprobe has already claimed the syscall and answered 0, so returning silently leaves the
		 * caller's pre-seeded 126 (ERR_CMD_NOT_SUPPORTED) in place: the C tool then reports "please
		 * enable SUSFS in kernel" for a command this kernel implements, and ksud's err==126 check turns
		 * it into a silent success.  Upstream writes -ENOMEM here (fs/susfs.c:707-713); task_work
		 * context, so the writeback is safe. */
```


## `kernel/sus_map.c`

### `(file header)`

```c
/*
 * sus_map.c - hide mmapped real files from /proc/<pid>/maps (SUSFS SUS_MAP).
 *
 * Upstream sets AS_FLAGS_SUS_MAP on the inode's address_space and makes
 * show_map_vma()/show_smap() skip the line, the smaps_rollup() loop skip the vma it
 * accumulates and pagemap_read() skip the chunk covering such a vma.  An LKM cannot add a
 * flag bit, so: a listing layer (kprobes on show_map_vma/show_smap, vma = regs->regs[1],
 * skip the line with regs->pc = x30) plus a page-walk layer for the two listings it cannot
 * reach (smaps_rollup, pagemap).  smaps_rollup is deliberately NOT probed directly (see
 * "the sentinel") and the skip is gated like upstream's, apps only (see "the read gate").
 */
```

### `static DEFINE_SPINLOCK(map_table_lock);`

```c
/* Serialises rule PUBLICATION only; the reader stays lock-free: entries are append-only
 * (kstat's are replaced wholesale, hence its reader-side snapshot), so a release/acquire
 * pair on nmap publishes a filled entry or none - and it has to be that on arm64, where
 * plain WRITE_ONCE/READ_ONCE could publish the count first.  The lock itself is for two
 * concurrent supercalls (each in its own task_work), which would otherwise fill one slot
 * and silently drop a rule while both report success. */
```

### `static bool sus_map_gate_ok(void)`

```c
/* ---- the read gate ----
 *
 * Upstream hides behind SUSFS_IS_INODE_SUS_MAP() -> susfs_is_current_proc_umounted_app()
 * = (test_thread_flag(TIF_PROC_UMOUNTED) && current_uid().val >= 10000): apps only, so
 * root/init see the real mapping.  TIF_PROC_UMOUNTED cannot be reproduced in this LKM
 * (KernelSU sets it only with the SUSFS integration compiled into the kernel, which this
 * device's kernel is not - AUDIT_FINDINGS.md), so uid >= 10000 is the project-wide proxy,
 * as in susfs_kstat_gate_ok() (susfs_kstat.c, commit 543b369) and sus_path.
 * Configuration stays ungated: the supercall and map_ino are rule management. */
```

### `static int sus_map_skip_vma_pre(struct kprobe *kp, struct pt_regs *regs)`

```c
/* One handler for show_map_vma (maps) and show_smap (smaps) - both are seq_operations
 * .show callbacks that emit only what they are given, so returning 0 means "handled,
 * nothing printed" (seq_read ignores the value), which is upstream's SUS_MAP effect.
 *
 * ---- the sentinel ----
 *
 * smaps_rollup must NOT be pointed at this handler: show_smaps_rollup() is reached
 * through single_open(), whose single_start() hands .show the iterator sentinel (void *)1
 * instead of a vma, and the function ignores its v argument.  Measured with the probe
 * registered: `cat /proc/<pid>/smaps_rollup` as an app took vma->vm_file at 0xa0 -> ldr
 * from 0xa1 -> "Unable to handle kernel NULL pointer dereference at virtual address
 * 00000000000000a1", pc sus_map_skip_vma_pre+0x3c, then a panic (last_kmsg 41346.347).
 * Unreachable from a kprobe too: upstream skips the vma *inside* the rollup loop, and
 * smap_gather_stats() is inlined by LTO here (absent from /proc/kallsyms), so only
 * walk_page_range() could be intercepted.  TECHNICAL_NOTES.md, "sus_map 与 smaps_rollup". */
```

### `if ((unsigned long)vma < PAGE_SIZE)`

```c
/* Defence in depth against the sentinel above: a vma is always a slab object in
     * the linear map, so anything below one page is not one - this turns a future
     * mis-registration into a lost filter, not a panic. */
```

### `static const void *sus_map_ops_smaps;`

```c
/* ---- the page-walk layer: smaps_rollup and pagemap ----
 *
 * Both listings test a vma upstream holds as a local, so neither is reachable from a
 * kprobe: no local at a function boundary, smap_gather_stats() inlined by LTO, and
 * pagemap_read() only has its vma after taking mmap_lock inside.
 *   show_smaps_rollup() -> for (vma = priv->mm->mmap; vma;) { ... skip ... }
 *   pagemap_read()      -> vma = vma_lookup(mm, start_vaddr); ... skip chunk
 * Both share one exported primitive, called with a caller-unique mm_walk_ops:
 *   smap_gather_stats(): walk_page_range(vma->vm_mm, ..., smaps_walk_ops|smaps_shmem_walk_ops, mss)
 *   pagemap_read():      walk_page_range(mm, start, end, &pagemap_ops, &pm)
 * Those three ops have no other user and every caller holds mmap_lock for read (the walk
 * asserts it), so skipping the call leaves upstream's result: the rollup vma adds nothing
 * to mss, the pagemap chunk stays unfilled and `ret = walk_page_range(...)` sees 0, as
 * upstream leaves it.  The ops are data symbols, so they come from kallsyms by name
 * (sus_mount's mnt_id_ida mechanism); if none resolves, the probe is not registered and both
 * listings stay unfiltered (logged).  The probe sits on a kernel-wide primitive, so it bails
 * out in one load and three compares - ops test first.
 *
 * Which of walk_page_range()/walk_page_vma() is the live call site cannot be assumed: with
 * CONFIG_LTO_CLANG_FULL either may be inlined into its caller (invisible to any probe - the
 * wall smap_gather_stats() hit), so both symbols are probed and walk_dbg=1 records every
 * distinct ops pointer with its call count (walk_ops), naming the real caller. */
```

### `static atomic_t n_map_files_hides = ATOMIC_INIT(0);`

```c
/* map_files symlink resolutions that were turned into ENOENT.  n_getlink_calls vs
 * n_getlink_skip keeps "the probe ran" apart from "the probe matched". */
```

### `regs_set_return_value(regs, 0);`

```c
/* Both primitives return int 0 for "walked, nothing wrong" and both callers expect
     * that from a skipped walk (upstream's own skip leaves the same value).  Leaving
     * x0 = mm would turn pagemap_read()'s `ret` into a kernel pointer handed to read(2). */
```

### `static struct vm_area_struct *sus_map_find_vma(struct mm_struct *mm, unsigned long start)`

```c
/* The VMA container changed in 6.1; both spellings answer the same question - "the first
 * vma whose end is past @start", i.e. the one containing @start or the next after a gap -
 * and the caller still compares the result against vm_start.
 *   <= 6.0  mm_struct.mmap heads a doubly linked list, walked with vma->vm_next
 *   >= 6.1  that list became the mm_struct.mm_mt maple tree, walked with the vma iterator
 *           helpers VMA_ITERATOR() / for_each_vma() (mm_types.h, mm.h) - which is why
 *           "no member named 'mmap' in 'struct mm_struct'" and "'vm_next' in
 *           'struct vm_area_struct'" appeared on android14-6.1 and android15-6.6.
 * Both forms are header-only (macros and static inlines), so neither needs a kernel symbol;
 * mmap_lock is held for read by every caller, as the walk itself requires. */
```

### `static void sus_map_walk_dbg_log(const char *what, struct mm_struct *mm,`

```c
/* walk_dbg >= 2: dump the first few resolutions past the ops test, to tell "no vma for
 * (mm, start)" from "the vma is not the expected one". */
```

### `static int sus_map_skip_walk_pre(struct kprobe *kp, struct pt_regs *regs)`

```c
/* walk_page_range(mm, start, end, ops, private): the vma is resolved from (mm, start) as
 * the walk itself would have done, under the mmap_lock every caller of these three ops
 * holds for read - so sus_map_find_vma()'s container cannot change underneath it. */
```

### `static atomic_t n_gup_calls = ATOMIC_INIT(0);`

```c
/* ---- /proc/<pid>/mem (and ptrace): the page-fetch primitive ----
 *
 * Upstream's fifth SUS_MAP site is __access_remote_vm() (mm/memory.c, patch:5667-5687):
 * after mmap_read_lock it resolves vma = vma_lookup(mm, addr) once and, inside the transfer
 * loop, breaks out when that vma's file is registered - so a read (or write) starting
 * inside a hidden mapping transfers nothing at all.  Its entry cannot be hooked usefully:
 * the lock is taken INSIDE it, and resolving a vma without that lock is a use-after-free
 * waiting for the target process to munmap.  What can be hooked is the primitive the loop
 * calls with the lock held:
 *   __access_remote_vm()       -> get_user_pages_remote(mm, addr, 1, ...)
 *   process_vm_rw_single_vec() -> pin_user_pages_remote(mm, pa, ...)
 *   (both *_remote variants require mmap_read_lock)
 * Short-circuiting that call (x0 = 0, pc = lr) makes the caller see "no page transferred":
 * __access_remote_vm returns the bytes it had already moved - 0 when the read starts inside
 * the mapping, upstream's result - and process_vm_readv takes its `pinned_pages <= 0` error
 * path.  Nothing is pinned, because the call never runs.
 *
 * The second primitive is not needed for upstream parity (upstream patches
 * __access_remote_vm only, and process_vm_readv does not go through it - measured from this
 * kernel's mm/process_vm_access.c: process_vm_rw_single_vec calls pin_user_pages_remote
 * directly); it is hooked because the same short circuit closes one more probe.
 *
 * Cost control: the handler runs on every *_remote page fetch while a rule exists, so the
 * cheapest tests come first (no rules -> one load; uid < 10000 -> the gate) and find_vma()
 * only runs for callers the gate lets through. */
```

### `static struct kprobe kp_gup_remote = {`

```c
/* Both are thin layers of the same code and which one a call site reaches is decided by
 * LTO - measured: the __access_remote_vm path reaches get_user_pages_remote out of line (its
 * probe fired), while process_vm_readv's pin_user_pages_remote was inlined away, so that
 * wrapper's probe was removed after zero hits in every run.  __get_user_pages_remote, what
 * both wrappers end in, takes the same (mm, start) as its first two arguments and is armed
 * too; a short circuit at the outer layer stops the inner one from being reached. */
```

### `static int sus_map_maplink_entry(struct kretprobe_instance *ri, struct pt_regs *regs)`

```c
/* ---- /proc/<pid>/map_files/<start>-<end> ----
 *
 * Each entry is a symlink to the file mapped at that range, so `ls -l` and readlink name a
 * sus_map-registered file outright - measured: this is how the a4 tests found the address of
 * a mapping the maps listing had already dropped, i.e. this listing undid the hiding.
 * Upstream skips the entry in proc_map_files_readdir() (patch:1088-1095); a kprobe cannot
 * skip one entry of a readdir (the decision is a local in the middle of that function), so
 * the symlink still exists but resolving it answers ENOENT - what a checker gets for a file
 * that is not there.  The residual difference (the range is still listed) is in
 * TECHNICAL_NOTES.md.
 *
 * The first attempt hooked `proc_map_files_get_link` (the i_op): it registered fine and was
 * never called.  From this kernel's fs/proc/base.c - do_readlinkat() calls i_op->readlink
 * FIRST and only falls back to vfs_readlink() (-> get_link) when it is NULL, and
 * proc_map_files uses `.readlink = proc_pid_readlink`, which ends in the per-inode callback
 * `ei->op.proc_get_link` = map_files_get_link(), the one place that hands over the MAPPED
 * file's path.  So the hook judges by inode (path->dentry), which is exact and only ever
 * fails a call that would have succeeded: the caller treats a negative return as "no link". */
```

### `static int sus_map_stat_show(char *buf, const struct kernel_param *kp)`

```c
/* Reachability, not configuration: "the probe is registered" says nothing on a kernel built
 * with CONFIG_LTO_CLANG_FULL, where the call site it should catch may have been inlined away
 * (walk_page_range() is EXPORT_SYMBOL_GPL and LTO may still inline the calls inside
 * pagemap_read()/smap_gather_stats()).  walk_seen == 0 while a rule matches fingerprints such
 * an inlined call site, not a rule that failed to match. */
```

### `static int sus_map_register_probes(void)`

```c
/* Registers whichever of the probes are not up yet.  Called from init (when a rule
 * already exists) and from the supercall that adds the first rule, so both paths arm
 * exactly the same set. */
```

### `if (!kr_map_files_ok) {`

```c
/* The map_files hook is a kretprobe, so it lives outside map_probes[] (which
     * holds struct kprobe *) and is tracked on its own; optional like the rest. */
```

### `rc = sus_map_register_probes();`

```c
/* Every probe is optional on its own: without show_smap the maps listing is still
     * filtered, so one missing symbol must not take the rest down. */
```

### `rc = sus_map_add_full(inode->i_ino, inode->i_sb->s_dev);`

```c
/* One call fills both fields: the old two-step form let sus_map_add() return early on
     * ino==0 and then wrote map_entries[nmap-1] regardless - indexing -1 at worst,
     * corrupting the previous rule's device at best. */
```


## `kernel/sus_mount.c`

### `(file header)`

```c
/*
 * sus_mount.c - hide KSU mounts from /proc/mounts and /proc/mountinfo.
 *
 * Upstream SUSFS skips a mount line when r->mnt_id >= DEFAULT_KSU_MNT_ID, and
 * (patch:1561-1585) installs those show functions only for NON-ksu domains
 * (!susfs_is_current_ksu_domain() in mounts_open()/mountinfo_open()/mountstats_open()),
 * so the su/ksu domain keeps seeing its own mounts (zygisk in post-fs-data and ksud
 * break otherwise).  The stock show functions are static but sit behind proc_ops function
 * pointers, so they are NOT LTO-inlined and stay kprobe-able (verified in kallsyms); the
 * LKM hooks all three with a kprobe pre_handler and returns early (regs->pc = x30) for a
 * KSU-range id, under the same domain gate.  struct mount / real_mount() come from the
 * private fs/mount.h (its includes are all public headers, so -I$(srctree)/fs is enough).
 *
 * HOW THE ID RANGE IS PRODUCED: upstream ADDS an allocator
 * (susfs_alloc_non_unshare_ksu_vfsmnt(): ida_alloc_min(&mnt_id_ida,
 * DEFAULT_KSU_MNT_ID, GFP_KERNEL), patch:676-693) and SWAPS THE CALL SITES in
 * vfs_create_mount()/clone_mnt() (patch:764, 800); mnt_alloc_id() itself is never
 * patched.  This LKM patches no kernel text, so the stock allocator (plain ida_alloc,
 * smallest free id) kept handing out small ids - measured on device: 91..39693 - and the
 * fixed 2e9 threshold could never match, i.e. the feature was 100% OFF.
 * sus_mount_mark_ksu_mounts() therefore walks the current namespace at enable time (and
 * at load) and gives every KSU-looking mount a REAL id from the release's own allocator:
 * < 6.18 ida_alloc_range(&mnt_id_ida, DEFAULT_KSU_MNT_ID, INT_MAX - 1, GFP_KERNEL);
 * >= 6.18 __xa_alloc(&mnt_id_xa, &id, NULL, XA_LIMIT(DEFAULT_KSU_MNT_ID, INT_MAX - 1),
 * GFP_KERNEL) under xa_lock().
 *
 * A hand-made id is not an option: mnt_free_id() gives the id back to that same
 * allocator when the mount finally goes away (ida_free(), fs/namespace.c:251 on 6.12;
 * xa_erase(), :242 on 6.18), so an invented number makes lib/idr.c:523-525 fire
 * WARN(1, "ida_free called for id=%d which is not allocated.") plus a stack dump on
 * umount - exactly the trace a root detector greps for.  Upstream is under the same
 * constraint and short-circuits the free for its fake ids (patch:582-588); mnt_free_id()
 * is static + LTO-inlined here, so it cannot be patched.  6.18's erase is by index with
 * no such check (so the WARN is a < 6.18 concern); what both share is that the id must
 * not be one the allocator can hand to another mount.  Degradation is fail-closed: unless
 * ALL of the release's allocator symbols are reachable nothing is marked, min_mnt_id
 * stays false, and each missing piece is named in a pr_warn - on 6.18 the loader counts
 * as a source (see the allocator state below).
 *
 * A mount is one of ours when mnt_devname contains "/data/adb/" (KSU/module bind mounts)
 * or the mount POINT - d_path() of {mnt, mnt_root}, the path show_mountinfo() prints - is
 * under /data/adb (catches meta-overlayfs, whose source is /dev/block/loopNN).  Marked ids
 * are never restored on disable, matching upstream, where an id is assigned once at mount
 * time and stays for the mount's lifetime.
 *
 * IDENTITY, not a wider scan: KernelSU mounts into the ZYGOTE's namespace, the one every
 * app is forked into, and the same filesystem is a different mount OBJECT there, with an
 * id of its own - measured on this device: the meta-overlayfs mount is id 2000000000 in
 * the init namespace and id 1111 in the zygote's.  Marking is what creates the big id, so
 * it can only cover namespaces that already existed, and the id test alone then hid the
 * line in one view while the app's own mount table - the one a checker reads - still
 * showed it.  Sweeping every namespace from the task list would mean walking another
 * namespace's mount list, which a foreign namespace mutates while we walk it; instead the
 * scan remembers the mount's identity (superblock device + root inode, plus a path-shaped
 * source string) and the hide hooks accept identity as well as a KSU-range id, learning
 * an id into the id -> shown-id mapping when they hide by identity.
 *
 * Known blind spots (see AUDIT_FINDINGS.md B10): overlayfs mounts KernelSU places on
 * /system have d_path "/system" and mnt_devname "overlay", so they are NOT recognised
 * (only intercepting vfs_create_mount()/clone_mnt() by su domain would catch those); and
 * only the enabling process's namespace is scanned - one cloned later gets fresh small ids
 * from the stock allocator (upstream covers that in clone_mnt() with CL_COPY_MNT_NS,
 * patch:789-810).
 */
```

### `#define SUS_MOUNT_KEEP_MAX`

```c
/* ---- the "which mounts are ours" prefix list: state ----
 * Up here, not next to the control surface further down, because mount_stat() between
 * the two reports the list length and the rescan count - and declaring it below its
 * first use would be a compile error, not a style issue. */
```

### `static int n_show_probes;`

```c
/* How many of the three mount-table hooks (show_vfsstat / show_mountinfo /
 * show_vfsmnt) are armed; 3 is healthy.  1 or 2 means the feature hides fewer files
 * than it says, which must be visible rather than inferred (see
 * sus_mount_register()).  Declared up here because mount_stat() reports it. */
```

### `#define SUS_MOUNT_MIN_SANE_MNT_ID`

```c
/* min_mnt_id is a raw ulong tunable: 0/1 would make EVERY mount line match the
 * threshold, hiding all of /proc/mounts, /proc/<pid>/mountinfo and mountstats from
 * every process, su included.  Below this it is clamped back to DEFAULT_KSU_MNT_ID. */
```

### `#define SUS_MOUNT_MAX_SCAN`

```c
/* Hard bound on the mount-namespace walk.  A concurrent umount_tree() does
 * list_del_init() on the entry it removes, which makes that node point at
 * itself, so an unbounded list_for_each() can spin forever if it lands on it. */
```

### `#define SUS_MOUNT_KSU_ID_MIN`

```c
/* At/above this is "already a KSU-range id" (upstream's own test, patch:807).  The
 * marking side uses this constant and not the min_mnt_id tunable: a raised tunable
 * would re-mark an already-marked mount and allocate a SECOND id, leaking the first
 * for the mount's lifetime.  With the default tunable the two tests are identical. */
```

### `static char param_su_ctx[128] = "u:r:ksu:s0";`

```c
/* P2-12: SELinux context of the su/ksu domain, resolved to a sid at init.  Keep in sync
 * with susfs_avc_spoof.c's avc_su_ctx ("u:r:ksu:s0", the SukiSU variant; stock KernelSU
 * is "u:r:su:s0", override with susfs_guard_lkm.su_ctx=u:r:su:s0). */
```

### `int()`

```c
/* The kernel's own mount-id allocator, resolved at init.
 *
 * < 6.18: `static DEFINE_IDA(mnt_id_ida)` in fs/namespace.c (6.12:70), the out-of-line
 * ida_alloc_range() (lib/idr.c:380 - ida_alloc_min() is only a header inline over it and has
 * no kallsyms entry, do not try to resolve that one), and ida_free() as a corroborating check
 * only: the paired free is the kernel's own mnt_free_id() (6.12 fs/namespace.c:249-251).
 *
 * >= 6.18 (android17-6.18): that ida is GONE - fs/namespace.c:79 is
 * `static DEFINE_XARRAY_FLAGS(mnt_id_xa, XA_FLAGS_ALLOC);`, mnt_alloc_id() is
 * `xa_lock(); __xa_alloc(&mnt_id_xa, &mnt->mnt_id, mnt, XA_LIMIT(1, INT_MAX), GFP_KERNEL);
 * xa_unlock();` (:228-238), mnt_free_id() is `xa_erase(&mnt_id_xa, mnt->mnt_id);` (:240-243).
 * The erase is by index with no "not allocated" check, so the WARN rationale above is a
 * < 6.18 concern; what both share is that the id must genuinely be OURS - one the allocator
 * will not hand to another mount - and that the kernel erases it itself, we never free a used
 * id.  There is no usable export for that allocator and `mnt_id_xa` is file-static, so the
 * addresses come from kallsyms by name (see the extern block below). */
```

### `static const char *sus_mount_xa_obj_src = "none";`

```c
/* Where each address came from, for the init log: "kallsyms" = in-kernel name lookup,
 * "loader" = the undefined symbol below.  A field from nowhere keeps the feature refused. */
```

### `extern struct xarray mnt_id_xa;`

```c
/* 6.18 keeps its mount ids in an xarray that no header declares, so these three names are
 * written out by hand and carried as UNDEFINED ELF SYMBOLS: tools/susfs_insmod.c rewrites
 * every SHN_UNDEF entry to st_shndx = SHN_ABS / st_value = <address from /proc/kallsyms>
 * before init_module(2), so the kernel's SHN_UNDEF branch - export lookup, namespace import,
 * CRC and KMI checks - is never entered for them.  That is the only way to reach a file-static
 * object from a module, and why the loader (our own, or ksud insmod, which loads with kallsyms
 * access for the same reason) is required for the 6.18 mount-id path rather than a
 * convenience.  Declared only under this gate: an older kernel has no such names, and an
 * undefined symbol the loader cannot resolve fails the whole load (the CI step "Check the
 * getdents probe symbols in the DDK tree" asserts that every undefined symbol of the built .ko
 * is present in that tree's System.map/vmlinux).
 *
 * __xa_alloc()/__xa_erase() are the out-of-line entry points (header inlines over them in most
 * releases), called with xa_lock() held like mnt_alloc_id() because __xa_alloc() may drop and
 * retake the lock to allocate a node.  The entry passed is NULL -> __xa_alloc() turns that into
 * its own XA_ZERO_ENTRY, and nothing ever loads an entry back out of mnt_id_xa (file-static;
 * only the alloc and the erase touch it), so the id is what we take, not the slot's content. */
```

### `static void (*pfn_security_cred_getsecid)(const struct cred *cred, u32 *secid);`

```c
/* security_cred_getsecid() is EXPORT_SYMBOL in security/security.c, but GKI's symbol
 * list is not guaranteed to carry it for modules, so it is resolved from kallsyms like
 * the other optional symbols this LKM uses. */
```

### `static __nocfi bool sus_mount_is_su_domain(void)`

```c
/* __nocfi on every function that reaches a resolved kernel symbol through a function
 * pointer: kCFI validates the type hash at such a call site and panics with
 * "CFI failure (target: ...)" otherwise - measured on this device, so these wrappers
 * keep the attribute. */
```

### `if (!pfn_security_cred_getsecid || !su_sid)`

```c
/* Unresolved symbol or an unresolvable su context: we cannot tell su apart,
     * so nothing is exempted (hide from every process) - loud in the init log. */
```

### `pfn_security_cred_getsecid(current_cred(), &sid);`

```c
/* kprobe pre_handler runs on the probed task with preemption disabled:
     * reading current->cred and the LSM hook list never sleeps. */
```

### `static __nocfi int sus_mount_ida_alloc(void)`

```c
/* Allocate a genuine KSU-range id from the kernel's own allocator.  Process context:
 * GFP_KERNEL may sleep (__xa_alloc() drops and retakes the xarray lock to allocate a
 * node).  Returns the id, or a negative errno - never a bogus id. */
```

### `static __nocfi void sus_mount_ida_release(int id)`

```c
/* Hand an UNUSED id back to the allocator it came from.  Used ids are never freed here:
 * the kernel's own mnt_free_id() erases them by index when the mount dies, which is the
 * pairing both allocators expect.
 *
 * MUST be __nocfi like every other call through a resolved kernel symbol: an indirect
 * call from a normally-instrumented function is type-checked by clang CFI, and an
 * out-of-tree module's type hash for a kernel prototype does not match the kernel's -
 * measured the expensive way:
 *   Kernel panic - not syncing: CFI failure (target: ida_free+0x0/0x480)
 *   Call trace: sus_mount_mark_ksu_mounts+0x9b0 [susfs_guard_lkm] */
```

### `static unsigned long sus_mount_min_mnt_id(void)`

```c
/* Effective threshold: clamped on every read too, because the sysfs knob can be
 * written at any time (init/enable also write the clamped value back). */
```

### `static bool mount_registered;`

```c
/* Declared up here because the new hooks' stat node reports it (it is otherwise
 * set by sus_mount_register() further down). */
```

### `#define SUS_MOUNT_IDMAP_MAX`

```c
/* ---- the same id in the two other places upstream rewrites ----
 *
 * Not enough to skip the mount line: /proc/<pid>/fdinfo/N prints "mnt_id:\t<i>" and statx(2)
 * returns stx_mnt_id, both taken straight from the mount the file lives on, so an app can
 * collect the mnt_ids of the fds it holds and look for ones /proc/self/mountinfo never
 * mentions - a positive indicator that something is hidden, and one that needs no root.
 * Upstream rewrites both to the id of the first mount up the chain that is not a KSU mount
 * (susfs_get_non_sus_mnt_id_from_mnt(), patch:849-858); that value is computed here once per
 * marked mount, at marking time, and kept in a small id table, because at rewrite time all we
 * have is the id (kprobe context: no sleeping, no lookups).
 *
 * The key is the one piece of state the kernel can hand to somebody else: mnt ids go back to
 * mnt_id_ida in mnt_free_id(), and the reuse is immediate, not theoretical - measured on this
 * device: mount tmpfs, note the id, umount, mount again hands out the SAME id.  Each entry
 * therefore carries the s_dev it was learned on and is dropped when (a) its superblock is torn
 * down (kprobe on generic_shutdown_super(), the earliest point where nothing can have taken the
 * id yet), (b) a mount that is NOT ours is seen carrying that id - proof of a recycle, so the
 * hide hook drops the entry right there (sus_mount_idmap_drop()), which is what keeps the table
 * fixed-size by reusing freed slots - or (c) it is refreshed by seeing one of OUR mounts again.
 * Left over is an id recycled while nobody reads a mount table at all: no reader then holds a
 * mount list to compare the rewritten number against.  A shown_id needs no expiry of its own:
 * an ancestor of its mount cannot be unmounted while the child is alive. */
```

### `for (i = 0; i < n_idmap; i++) {`

```c
/* Seen again on every enable and by both paths in, so an existing entry must not be
     * appended twice: the table is fixed size. */
```

### `static void sus_mount_idmap_drop_dev(dev_t s_dev)`

```c
/* Every entry whose mount lived on @s_dev is worthless now: that superblock is
 * being shut down (see the note on sus_mount_ident_drop_dev()). */
```

### `static void sus_mount_idmap_drop(int sus_id)`

```c
/* The id in @sus_id now belongs to a mount that is NOT ours, so what was learned for it
 * described a mount that no longer exists - a recycled id, observable in the hide hooks. */
```

### `static int sus_mount_shown_id(struct mount *mnt)`

```c
/* Upstream's susfs_get_non_sus_mnt_id_from_mnt(): climb past every marked mount
 * and report the id of the first one that is not ours.  Must be called AFTER
 * r->mnt_id has been replaced - upstream relies on the same thing, i.e. on the
 * starting mount already carrying a KSU-range id, or the loop would stop at the
 * mount itself and report its own (hidden) number. */
```

### `#define SUS_MOUNT_DEVNAME_MAX`

```c
/* ---- "is this mount one of ours", by IDENTITY and not only by id ----
 *
 * The id test is a property of ONE mount object in ONE namespace, and the id only
 * exists because the marking scan put it there: a KSU mount inside the app/zygote
 * namespace carries whatever id the stock allocator gave it (measured: the
 * meta-overlayfs mount is 2000000000 in the init namespace and 1111 in the
 * zygote's), so the id test hid the line in one view and left it in the other - the
 * app's own mount table, the one a checker reads.
 *
 * So the scan remembers what survives a namespace boundary (the mount OBJECT does not, its
 * filesystem does): s_dev + root ino, exact and cheap, because the root dentry is shared by
 * every mount of a superblock and a second tmpfs has its own root inode.  The NUMBER is
 * stored, not the dentry pointer: a held pointer would need dget() - pinning dentry and inode
 * past the superblock's shutdown, measured: rmmod of that build dput()'d it and panicked in
 * shmem_evict_inode, "Oops: Fatal exception" - or be used unlocked after the mount is gone.
 * mnt_devname is compared only when it is a path (starts with '/'), so a recorded
 * "tmpfs"/"overlay" cannot hide every mount of that kind.
 *
 * Only mounts the scan ACCEPTS are recorded, so this never widens into "hide anything that
 * looks similar".  A record is valid only while its filesystem is mounted, and its keys are
 * reusable: measured, a tmpfs mounted/recorded/unmounted by this test left s_dev 0:304 and
 * root inode 1 behind and the very next tmpfs got both, i.e. a stale record hid an unrelated
 * filesystem - hence the kprobe on generic_shutdown_super() that drops every record whose
 * s_dev is going away. */
```

### `bool devname_truncated;`

```c
/* strscpy() truncates a longer devname; without this flag the record could never match
     * its own live mount again (a truncated copy is always unequal), silently disabling
     * this fallback. */
```

### `static atomic_t n_dbg_logged = ATOMIC_INIT(0);`

```c
/* Diagnostic: name the fields the identity test compares, for the first few mounts the
 * hook sees, so "why did identity not match" is answerable from dmesg instead of guessed. */
```

### `static void sus_mount_ident_add(struct mount *r)`

```c
/* Process context.  Takes no reference on anything (see the note above): the
 * record is three numbers and a string, so a record whose mount is long gone costs
 * nothing and cannot keep a filesystem alive. */
```

### `static void sus_mount_ident_drop_dev(dev_t s_dev)`

```c
/**
 * sus_mount_ident_drop_dev() - forget every record that lived on @s_dev
 *
 * From a kprobe on generic_shutdown_super(): without it a record outlives its filesystem,
 * and the numbers it is keyed by are recyclable (measured above), so a stale record hides
 * an unrelated filesystem.  Process context, takes only our own spinlock, never sleeps.
 */
```

### `static int sus_mount_sb_down_pre(struct kprobe *kp, struct pt_regs *regs)`

```c
/* generic_shutdown_super(struct super_block *sb) - fs/super.c, EXPORT_SYMBOL, so
 * it is a real function in kallsyms and not an inlined call site.  Runs before the
 * device number is handed back (free_anon_bdev()/blkdev_put() happen in
 * kill_anon_super()/kill_block_super() after this returns), so a record cannot
 * survive into the window where a new filesystem holds the same s_dev. */
```

### `static bool sus_mount_is_ours(struct mount *r)`

```c
/* Is this mount one of KernelSU's?  Two tests, cheapest first:
 *   - the id range, which is upstream's rule and what the marking scan produces;
 *   - the identity recorded by that scan, which is what catches the same mount in
 *     a namespace the scan could not reach (see the note above). */
```

### `static int sus_mount_shown_id_from(struct mount *mnt)`

```c
/* The id the caller is allowed to see for a mount we hide: the first ancestor
 * that is not ours.  Starts at the PARENT when the mount itself is not in the id
 * range, because an identity-recognised mount keeps a normal id and would
 * otherwise report its own (hidden) number. */
```

### `static void sus_mount_note_id(struct mount *r)`

```c
/* Remember the id -> shown-id pair for a mount we are about to hide, so the
 * fdinfo/statx faces rewrite the very same id the app would otherwise see.  The
 * hide hooks are the only place that has a mount pointer in an app's namespace,
 * so learning here is what keeps "the line is gone" and "the number in fdinfo
 * names a line that exists" consistent for namespaces the scan never saw. */
```

### `static atomic_t n_clone_walks = ATOMIC_INIT(0);`

```c
/* ---- namespaces created AFTER the enable ----
 *
 * Marking does NOT travel: clone_mnt() copies every mount through alloc_vfsmnt() ->
 * mnt_alloc_id() (fs/namespace.c:1282/309/238 on 6.12), so a namespace copied by
 * fork/unshare gets BRAND NEW ids - measured: the copy of a marked mount has no 2e9 id.
 * Hiding still works (identity is namespace independent), but the fdinfo/statx face needs
 * an id, and the table only learns one when somebody READS a mount table: a process that
 * opens a file in the new namespace and reads /proc/self/fdinfo/N first gets an id its own
 * mountinfo does not list (measured: mnt_id=29127, listed_in_my_mountinfo=0) until the
 * first mount-table read makes it consistent (29117, listed=1).  Upstream assigns the big
 * id at mount creation, so its copy is marked from the start.
 *
 * On < 6.12 that tree is walked right here (see sus_mount_learn_ns below).  On >= 6.12 it
 * is NOT walked here, because the mount collection is an rb-tree that may only be walked
 * under namespace_sem - a sleeping rwsem this probe cannot take with preemption disabled -
 * and "the namespace is fresh, so nothing else can touch it" is not a proof about that
 * tree: copy_mnt_ns() passes neither CL_PRIVATE nor CL_SLAVE, so the copy of a SHARED
 * mount stays a propagation peer, and another task can insert into the very tree we would
 * be walking (under namespace_sem alone).  The >= 6.12 probe therefore only RECORDS the
 * namespace; a work item walks it later in process context under namespace_sem for read,
 * exactly like the marking scan, with the same refuse-and-log when that lock cannot be
 * resolved.  This trap once panicked the device when it walked a live namespace, and the
 * flags check below (no CLONE_NEWNS -> the CURRENT namespace, the plain fork path) is what
 * keeps the deferred path from being handed one. */
```

### `sus_mount_ns_walk_begin()`

```c
/* ---- how one iterates the mounts of a namespace, per kernel version ----
 *
 * < 6.12: a plain `struct list_head list` of every mount (mnt_list) under ns_lock, with a
 * fake "cursor" mount (MNT_CURSOR) anchored in it that has to be skipped.  >= 6.12: the
 * list, ns_lock and MNT_CURSOR are GONE - mounts live in `struct rb_root mounts` keyed on
 * mnt_id_unique, the kernel's own iterator takes namespace_sem for read and walks
 * rb_next(&mnt->mnt_node) (fs/namespace.c m_start()/m_next()/m_stop(); fs/mount.h:
 * "Protected by namespace_sem"), and the cursor test becomes mnt_ns_attached().
 * namespace_sem is `static DECLARE_RWSEM(namespace_sem)` in fs/namespace.c, so it is
 * resolved BY NAME at load time (KALLSYMS_ALL, set in both GKI defconfigs); if it cannot be
 * resolved the walk REFUSES to run - an unlocked rb-tree walk of a namespace another task
 * is mounting into is a torn tree, and reading it lockless panics the device.  Refusing
 * costs the marking (and says so), never memory.
 *
 * The lock may SLEEP (down_read), so it is process context only - which is why the
 * kretprobe path (sus_mount_learn_ns) walks without it and relies on the namespace being
 * private instead. */
```

### `#define SUS_MOUNT_MNT_NOT_IN_NS`

```c
/* 6.12 has the rb-tree (and MNT_ONRB) but not the helper: mnt_ns_attached() arrived in 6.13,
 * where its body is exactly this test.  Using it unguarded made a plain 6.12 tree an implicit
 * declaration, so the first 6.12 build either failed or linked against nothing. */
```

### `static void sus_mount_learn_ns(struct mnt_namespace *ns)`

```c
/* Immediate walk: only for < 6.12, where ns_lock is a spinlock this probe may take.
 * Unchanged on purpose - the < 6.12 build is shipped and verified, so this body must
 * generate the same code it always did. */
```

### `#define SUS_MOUNT_LEARN_RING`

```c
/* ---- >= 6.12: record the namespace in the probe, walk it in the worker ----
 *
 * The recorded pointer is kept alive with the kernel's own get_mnt_ns() (fs/mount.h, an
 * inline - no symbol needed) and released with put_mnt_ns() (a global in fs/namespace.c,
 * resolved by name at init).  Both halves are load-bearing: the task that cloned the
 * namespace can exit and drop the last reference before the worker runs, and put_mnt_ns()
 * must be called with no read lock held because on 6.18 it takes namespace_sem for write
 * itself.  If put_mnt_ns cannot be resolved nothing is queued at all - a reference we
 * could not drop would be a leak and a walk without one a use-after-free.
 *
 * The ring is fixed size and drops on overflow (counted): the probe may not allocate, and
 * a dropped namespace only means its ids are learned by a later scan instead. */
```

### `static __nocfi void sus_mount_put_mnt_ns(struct mnt_namespace *ns)`

```c
/* Every call through a resolved kernel symbol sits inside a __nocfi function (kCFI checks
 * the type hash at an indirect call site, and an out-of-tree module's hash for a kernel
 * prototype does not match), and that function is itself called DIRECTLY so it needs no
 * hash of its own - the work item below is called indirectly by the workqueue and so must
 * keep its hash, which is why the put goes through here instead. */
```

### `static int sus_mount_learn_ns_walk(struct mnt_namespace *ns)`

```c
/* The walk, in process context: namespace_sem for read, and the same protocol the marking
 * scan uses (rcu_read_lock + the iteration bound), because a namespace that was private
 * when it was recorded is a live one by the time this runs. */
```

### `static void sus_mount_learn_stop(void)`

```c
/* Unload path: the probe is unregistered first (so nothing new is queued), then the worker
 * is waited out, then whatever is still recorded is released - the worker cannot see an
 * entry queued after its last pop. */
```

### `static struct kretprobe kr_clone_ns = {`

```c
/* copy_mnt_ns() is not static (fs/namespace.c:3424) and is on every namespace
 * creation path (fork with CLONE_NEWNS, unshare, clone3). */
```

### `#define SUS_MOUNT_NEWMNT_PATH_MAX`

```c
/* ---- mounts that appear AFTER the enable ----
 *
 * The scan runs once, on the current namespace: a filesystem mounted later - the ordinary
 * case for a module image installed while the phone is up - carried no marked id and no
 * recorded identity, so nothing hid it in ANY namespace (measured before this hook existed:
 * visible to a non-su reader in the init namespace and in a fresh clone).
 *
 * attach_recursive_mnt() is the one function every mount path goes through - exactly two
 * callers, graft_tree() (mount(2)/fsmount and do_loopback binds) and do_move_mount() (a
 * move) - so one kretprobe covers all of them.  Identity is recorded and not an id: it is
 * what the hide hooks compare, needs no allocation and is namespace independent, whereas a
 * KSU-range id needs ida_alloc_range(GFP_KERNEL) and a kprobe handler must not sleep.  The
 * shown id is learned at the RETURN (mnt_parent/mnt_mountpoint exist then), and the
 * acceptance rule is the scan's, so this cannot widen what is hidden - a bind of an already
 * recorded filesystem needs no record at all. */
```

### `static bool sus_mount_should_record(struct mount *r, char *buf, int buflen, char **why)`

```c
/* The scan's rule, verbatim: a devname anchored at /data/adb, or a mountpoint under
 * /data/adb.  @buf is the caller's, small on purpose - this runs from a kretprobe
 * handler, where a PATH_MAX stack buffer would be a stack overflow waiting to happen,
 * and the mountpoints this rule accepts are short (/data/adb/modules/<name>/mnt). */
```

### `if (!r->mnt_parent || r->mnt_parent == r)`

```c
/* A successful attach leaves the mount with a parent; without one there is no
     * mountpoint path to test and no parent chain for the shown id. */
```

### `#define SUS_MOUNT_MNTID_LABEL`

```c
/* ---- /proc/<pid>/fdinfo/N ----
 *
 * fs/proc/fd.c:seq_show() formats pos/flags/mnt_id/ino into the seq_file buffer and
 * returns; a kprobe cannot see the mnt_id (a local), but it can read the text already in
 * m->buf at return time: find the label, parse the decimal after it, replace it with the id
 * the app is supposed to see.  The replacement is never longer (a shown id is a normal,
 * small one), so the buffer is only shortened.  Works whether the kernel formats the line
 * with one seq_printf (AOSP 5.15) or with seq_put_decimal_ull() - both leave
 * "mnt_id:\t<digits>" in the buffer at return. */
```

### `struct sus_mount_kretprobe_state {`

```c
/* Per-instance state for the kretprobes below (fdinfo + the two statx landing points), in
 * ri->data and NOT in per-CPU storage: seq_show() formats through seq_printf(), whose
 * seq_buf_alloc() is GFP_KERNEL and can sleep, so with CONFIG_PREEMPT=y the task can resume
 * on another CPU where a per-CPU slot would hold NULL or a seq_file of an unrelated /proc
 * read that the return handler would then memmove into.  A kretprobe instance is per-task
 * (the getdents64 filter in sus_path.c does the same), and one struct serves all of them
 * because the fields are disjoint. */
```

### `st->m = susfs_ptr_plausible((void *)regs->regs[0])`

```c
/* Not dereferenced here - the return handler checks it - but an implausible
     * value means this kretprobe sits on a function that does not take a seq_file,
     * and the rewrite below would then read an unrelated object. */
```

### `static bool sus_mount_fdinfo_replace_mntid(struct seq_file *m)`

```c
/* Replaces the decimal after the mnt_id label in the seq_file's already formatted buffer
 * when the id has a disguise in sus_mount's table (KSU-range id -> host id).  The
 * replacement never grows, so m->count stays consistent.  The other half of the fdinfo line
 * (the ino) belongs to open_redirect's own kretprobe, which must fire whether or not this
 * feature's hide switch is on. */
```

### `if (n > len && count + (n - len) >= m->size)`

```c
/* In practice a KSU-range id is replaced by a small host id, so this shrinks -
     * but the room check is here so a rule with an unexpectedly long host id
     * cannot overwrite past the seq_file buffer. */
```

### `if (!m->file || !m->file->f_path.dentry || !m->file->f_path.dentry->d_parent ||`

```c
/* Only fdinfo's own file is rewritten, and above 5.15 this probe sits on ALL FOUR
     * functions named seq_show (see the note at kr_fdinfo[]): the file being read is
     * m->file, and /proc/<pid>/fdinfo/<fd> (and .../task/<tid>/fdinfo/<fd>) has a dentry
     * whose parent is named "fdinfo".  The mnt_id label test below already makes the scan a
     * no-op for another file, so this only keeps it off other files' buffers. */
```

### `if (sus_mount_is_su_domain())`

```c
/* The su/ksu domain keeps seeing its own mounts' real ids, exactly like the
     * mount-line skip above. */
```

### `#define SUS_MOUNT_FDINFO_MAX`

```c
/* fs/proc/fd.c's fdinfo callback is registered through single_open(file, seq_show, inode), so
 * no table holds its address - and the name is NOT unique above 5.15: the DDK trees have four
 * symbols called exactly `seq_show` on android14-6.1 / android15-6.6 / android16-6.12 /
 * android17-6.18, and one on 5.10/5.15.  register_kprobe(.symbol_name=...) attaches to
 * whichever kallsyms lists first, which is how the fdinfo rewrite silently stopped working on
 * those kernels (mountinfo showed the disguised id while /proc/<pid>/fdinfo/N printed the real
 * one - a one-file oracle).  So: enumerate every match and hook all of them; the return
 * handler decides by the file it sees, which makes an unrelated seq_show cost one scan and
 * change nothing. */
```

### `static atomic_t n_statx_entry = ATOMIC_INIT(0);`

```c
/* ---- statx(2): stx_mnt_id ----
 *
 * vfs_statx() fills stat->mnt_id right after the getattr callback, so the only place a
 * kprobe can change it is the uapi struct the syscall is about to copy out: entry (take the
 * user pointer) plus return (rewrite if the call succeeded).  Two landing points, because
 * "the wrapper is in kallsyms" says nothing about who is really called: __arm64_sys_statx is
 * the syscall entry, do_statx what it delegates to.  The rewrite is idempotent (a rewritten
 * id is not in the table), so arming both is safe, and which one fires is reported
 * separately.
 *
 * They do NOT read the same register: __arm64_sys_statx is `asmlinkage long
 * __arm64_sys_statx(const struct pt_regs *)`
 * (arch/arm64/include/asm/syscall_wrapper.h), so its buffer is
 * ((struct pt_regs *)regs->regs[0])->regs[4] - reading regs->regs[4] directly works only
 * because the dispatcher leaves x1..x7 untouched, the reason the reboot handler in
 * susfs_supercall.c goes through PT_REAL_REGS.  do_statx(int dfd, const char __user
 * *filename, unsigned flags, unsigned int mask, struct statx __user *buffer) is an ordinary
 * function, so x4 IS the buffer. */
```

### `atomic_inc(&n_statx_nobuf);`

```c
/* Named, because "which landing point had no pointer" is the difference
         * between a wrong register and a wrong understanding of the call. */
```

### `static int sus_mount_idmap_live(void)`

```c
/* Live entries, not slots: after an invalidation the slot is free but the slot
 * count stays where it was, and a diagnostic that reads "idmap=6" while only two
 * entries are usable is the kind of number this project keeps catching. */
```

### `static int sus_mount_stat_show(char *buf, const struct kernel_param *kp)`

```c
/* Reachability/effect counters, one line per hook: "installed" says nothing about
 * whether the rewrite ever happened. */
```

### `if (!sus_mount_is_ours(r)) {`

```c
/* Cheap path first, and NOT only the id: a KSU mount in a namespace the
     * marking scan never reached (the zygote's, hence every app's) keeps a normal
     * id - see the identity note above sus_mount_is_ours(). */
```

### `sus_mount_idmap_drop((int)r->mnt_id);`

```c
/* This mount is not ours but carries this id right now, which is proof the
         * id was recycled if we ever learned it (see the idmap note above). */
```

### `if (mount_dbg && atomic_inc_return(&n_dbg_logged) <= 40)`

```c
/* mount_dbg: say why - the id, s_dev, root dentry and source are exactly
         * what sus_mount_is_ours() compared. */
```

### `if (sus_mount_is_su_domain())`

```c
/* P2-12 domain gate, upstream patch:1561-1585: the su/ksu domain is not
     * touched at all, it must be able to see its own mounts. */
```

### `regs->regs[0] = 0;`

```c
/* These show_* callbacks return int and x0 still holds seq_file*.
     * seq_read() treats a negative return as a hard error, so a stray high
     * bit here would break the whole read; upstream's equivalent site
     * explicitly returns 0. */
```

### `static struct kprobe kp_vfsmnt = {`

```c
/* /proc/mounts and /proc/<pid>/mounts go through show_vfsmnt - a DIFFERENT
 * function from show_vfsstat (which serves mountstats).  Missing this hook left
 * /proc/mounts completely unhidden while mountinfo was filtered.  Upstream hooks
 * all three (patch:1402 susfs_show_vfsmnt, :1439 susfs_show_mountinfo, :1504
 * susfs_show_vfsstat). */
```

### `#define SUS_MOUNT_SHOW_N`

```c
/* The three of them as one list, plus what is armed.  Registration and teardown both
 * go through this: with independent registration (see sus_mount_register()) an
 * unregister of a probe that never armed is not a no-op, so teardown must ask. */
```

### `sus_mount_path_is_ours()`

```c
/* ---- which mounts count as "ours" ----
 *
 * One test, used by both the enable-time scan and the mount-time hook so the two cannot
 * drift: ours when the source string (mnt_devname) or the mountpoint path starts with one of
 * the PREFIXES below.  Runtime configurable - it used to be a hardcoded "/data/adb/"
 * (KernelSU's module store), which never matched a container (proot/chroot) mounting
 * tmpfs/proc/sysfs/devpts at, say, /data/local/tmp/ubuntu2/dev (see the command surface
 * below).  Anchored (strncmp), never a substring search: a devname such as
 * "/mnt/media_rw/x/data/adb/y" is not a KernelSU mount, and matching those hid unrelated
 * mounts (measured: a mount whose source was "x/data/adb/y" disappeared for non-su readers).
 * Changing the list rescans the current namespace, so an already-mounted path is picked up
 * without re-enabling (later ones come from the attach_recursive_mnt hook); entries recorded
 * before a change stay recorded - the list decides what is accepted from now on, not what is
 * already known. */
```

### `#define SUS_MOUNT_ID_BATCH`

```c
/* Retro-fit upstream's "KSU mounts carry an id >= DEFAULT_KSU_MNT_ID" onto the mounts that
 * already exist.  Process context only (kmalloc + d_path + GFP_KERNEL allocation), called
 * from module load and the supercall enable path.  Upstream never needs this - it allocates
 * the big id while the mount is created (patch:676-693), the same allocation at a different
 * moment - and the id is genuinely allocated from the kernel's allocator, so the free the
 * kernel runs in mnt_free_id() (fs/namespace.c:249-251 on 6.12) is paired and does not WARN
 * (lib/idr.c:523-525): that is the whole reason we do not invent the number.  Nothing else
 * rewrites the field, so the assignment sticks until the mount is gone, and the id is reused
 * after the free like any allocator id. */
```

### `#define SUS_MOUNT_ID_BATCH`

```c
/* One namespace's mount list.  fs/mount.h documents the < 6.12 protocol as "namespace_sem
 * for read AND ns_lock"; namespace_sem is static in fs/namespace.c and down_read() is an
 * inline over rwsem internals, so a module can only take the ns_lock half - which keeps us
 * out of the kernel's own list readers and of every list mutation that takes it, while the
 * iteration bound covers the one that does not (umount_tree()'s list_del_init under
 * namespace_sem) and rcu_read_lock keeps a mount being torn down alive (they are freed
 * through call_rcu() in cleanup_mnt()) so a stale pointer cannot be reused under us.
 *
 * ID ALLOCATION happens BEFORE the lock, in a small batch and outside the rcu_read_lock() of
 * the walk: the allocator may sleep (ida_alloc_range() with GFP_KERNEL may allocate a radix
 * node; on >= 6.18 __xa_alloc() drops and retakes the xarray lock for the same reason) and
 * the loop ends up with a spinlock held on < 6.12 and under rcu_read_lock() on >= 6.12.  An
 * unused batch is handed back to the same allocator afterwards, so the pairing the kernel
 * expects stays intact.
 *
 * >= 6.12 replaces all of that with namespace_sem plus an rb-tree (see SUS_MOUNT_ITER_FOR):
 * the lock is taken first because it may sleep, and the "still there" guarantee comes from
 * holding it, not from RCU.  The id source is version-split too (mnt_id_ida < 6.18,
 * mnt_id_xa >= 6.18, documented at the allocator state above). */
```

### `static int sus_mount_keep_command(const char *val, bool bare_list)`

```c
/* Commands, same shape as the hide_modules node: add <prefix> | del <prefix> |
 * set <prefix>... | reset | clear.  `reset` restores the built-in default (/data/adb/);
 * `clear` leaves no prefix at all, which stops NEW mounts from being accepted while the KSU
 * mounts stay hidden by their ids; @bare_list is for the insmod form of the parameter only.
 *
 * The two staging buffers used to be locals, which made this frame 2192 bytes and 6.6
 * rejects that outright - "error: stack frame size (2192) exceeds limit (2048) in
 * 'sus_mount_keep_command' [-Werror,-Wframe-larger-than]", and -Wframe-larger-than is an
 * error in the 6.6 GKI build.  They are kvmalloc'd instead: every caller here is a proc/sysfs
 * write handler or module_param setter, i.e. process context that may sleep, so GFP_KERNEL is
 * safe.  The command semantics are unchanged - the early returns now go through @out. */
```

### `if (current_uid().val != 0)`

```c
/* 0777 node + this check, like every other control node: a restrictive mode would
	 * answer EACCES (advertising that the node exists) before sus_path could answer
	 * ENOENT. */
```

### `if (current_uid().val != 0)`

```c
/* Same reason as the open check: an fd opened before the process dropped
	 * privileges must not become a way in. */
```

### `if (!sus_mount_ns_walk_begin()) {`

```c
/* The namespace lock first, and BEFORE any id is taken out of the allocator:
     * on >= 6.12 this is namespace_sem (down_read, i.e. it may sleep) and it is the
     * only thing that makes a live namespace's rb-tree walkable; on < 6.12 it is a
     * no-op and the ns_lock is taken below instead.  Refusing here is a deliberate
     * fail-closed: the caller reports it (see susfs_sus_mount_supercall), and no id
     * has been allocated yet so nothing leaks either way. */
```

### `sus_mount_ida_release(id);`

```c
/* Below our floor: the resolved mnt_id_ida is not what we think it is.
             * Hand this id back and stop allocating. */
```

### `if (SUS_MOUNT_MNT_NOT_IN_NS(r, ns)) {`

```c
/* < 6.12: proc_mounts cursors are fake mounts anchored in this same list
         * (fs/namespace.c mnt_is_cursor()).  >= 6.12: there is no cursor mount any
         * more, and the equivalent test is that the mount is really attached to a
         * namespace's tree (mnt_node linked) - see SUS_MOUNT_MNT_NOT_IN_NS(). */
```

### `if ((unsigned int)r->mnt_id >= SUS_MOUNT_KSU_ID_MIN) {`

```c
/* Anything already carrying a KSU-range id: the idempotency guard for a re-enable (a
         * second id for the same mount would leak the first for its lifetime) AND the cover
         * for KernelSU's own mounts, which this kernel already hands such an id to - measured
         * on this device: exactly one, the meta-overlayfs loop mount at 2000000000.  Their
         * line is skipped by the id alone, so they need the same "id the app may see" mapping
         * or fdinfo/statx print a number mountinfo no longer lists.  Compares against the
         * constant, not the tunable (SUS_MOUNT_KSU_ID_MIN), and records the identity as well:
         * this namespace's mount is a different OBJECT from the same filesystem's mount in the
         * next namespace (measured: 2000000000 here, 1111 in the zygote's). */
```

### `mnt_path.mnt = &r->mnt;`

```c
/* meta-overlayfs style: the source is /dev/block/loopNN, so only the
             * mount point says /data/adb/... .  d_path() of {mnt, mnt_root} is the
             * mountpoint path show_mountinfo() prints. */
```

### `if (scan_logged < 40) {`

```c
/* Diagnostic while the matching rule is being validated: the first few
             * mounts show what d_path() actually renders for them. */
```

### `sus_mount_idmap_add(new_id, sus_mount_shown_id(r), r->mnt.mnt_sb->s_dev);`

```c
/* After the id is replaced, exactly like upstream: the climb starts at a
         * mount that now carries a KSU-range id and stops at the first ancestor
         * that does not - i.e. the id mountinfo still prints for the host. */
```

### `sus_mount_ident_add(r);`

```c
/* And the identity, so the same filesystem mounted in another namespace
         * (where this scan cannot reach) is recognised by the hide hooks. */
```

### `if (!sus_mount_ida_ready()) {`

```c
/* Fail closed: without the release's full allocator we cannot own a real id, and a
     * self-made id would leave an ida_free WARN behind on umount (< 6.18). */
```

### `marked = sus_mount_scan_ns(current->nsproxy->mnt_ns, buf, min);`

```c
/* ONE namespace: the caller's.  A sweep over every namespace reachable from the task list
     * was tried and is NOT done: walking another namespace's mounts is only safe under
     * namespace_sem, and holding it across N namespaces means holding it while other tasks try
     * to mount.  The zygote's copy of a KSU mount (the one every app inherits) is reached
     * through the identity table instead - same superblock, same root dentry, accepted by the
     * hide hooks as well as a KSU-range id, with no cross-namespace walk at all. */
```

### `void *loader_xa = (void *)&mnt_id_xa;`

```c
/* Two sources per address, in this order, and the log names the one that won: (1) the
     * in-kernel name lookup (find_kernel_symbol_exact(), which needs CONFIG_KALLSYMS_ALL for a
     * static data symbol - GKI sets it); (2) the loader-filled undefined symbol (`mnt_id_xa`
     * and friends above), rewritten from /proc/kallsyms by tools/susfs_insmod.c or ksud insmod
     * before init_module(2) - the source that has to work, since 6.18 has no usable export for
     * the mount-id allocator.  When neither supplied an address the pointer stays NULL and the
     * readiness check refuses, naming every missing piece; a disagreement between the two is
     * reported as well, since both are looked up BY NAME.
     *
     * The loader addresses are read into locals first: `&symbol` is an undefined symbol of this
     * module, known only after the loader or the kernel resolved it, and testing it through a
     * variable keeps the compiler from folding the test away as "address of an object is never
     * NULL" (-Waddress, an error in GKI builds). */
```

### `sus_mount_namespace_sem = (struct rw_semaphore *)find_kernel_symbol_exact("namespace_sem");`

```c
/* >= 6.12 has no ns_lock: the per-namespace mount collection is an rb-tree and the
     * only lock that makes it walkable is namespace_sem, the same one the kernel's own
     * /proc/mounts iterator takes for read (fs/namespace.c m_start()/m_stop()).  It is
     * `static DECLARE_RWSEM(namespace_sem)` there, so it is not an exported symbol -
     * resolved by name like mnt_id_ida above, which works because GKI sets
     * CONFIG_KALLSYMS_ALL.  A NULL here turns the scan into a refusal, never into an
     * unlocked walk of a tree another task is rotating. */
```

### `pfn_put_mnt_ns = (void *)find_kernel_symbol_exact("put_mnt_ns");`

```c
/* put_mnt_ns() releases the reference the copy_mnt_ns probe takes on the namespace it
     * records (see the deferred walk above).  It is a global in fs/namespace.c, so
     * KALLSYMS has it; without it nothing is queued, which is the fail-closed direction -
     * the ids of a namespace created after the enable are then only picked up by a later
     * scan. */
```

### `sus_mount_unregister()`

```c
/* The id side must own real ids; each missing symbol is named explicitly and
     * only disables the marking (the hook itself can still be installed). */
```

### `SUSFS_LOGI("sus_mount: disabled by default (enable via CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS)\n");`

```c
/* upstream defaults this OFF (static key false) so zygisk can see sus
     * mounts during post-fs-data; the LKM mirrors that: no hook until
     * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS enables it.  The id assignment
     * itself is not gated on that flag - the hook compares ids, so the mounts
     * have to carry KSU ids before it is switched on (and the next enable
     * rescans anyway, which picks up mounts created since load). */
```

### `sus_mount_unregister()`

```c
/* Which mounts count as ours, before anything looks at them: the built-in default
     * is KernelSU's module store.  The list is runtime configurable (hide_mounts /
     * /proc/susfs_hide_mounts) - a container at /data/local/tmp/ubuntu2 needs its own
     * prefix to be hidden at all. */
```

### `static void sus_mount_unregister(void)`

```c
/* One unregister path for both callers (module exit and the disable supercall):
 * two copies drifted apart once already in this project, leaving a hook armed
 * after "disabled". */
```

### `for (i = 0; i < SUS_MOUNT_SHOW_N; i++) {`

```c
/* Per probe: with independent registration the list can be partial, and
     * unregister_kprobe() on a probe that never armed walks lists it is not on. */
```

### `sus_mount_learn_stop();`

```c
/* The probe is unregistered above, so nothing new can be recorded; wait the worker
     * out and release whatever is still recorded, or a queued namespace reference would
     * outlive the module. */
```

### `sus_mount_register()`

```c
/* Marked mnt_ids are deliberately NOT restored: upstream assigns an id once
     * per mount and never rewrites it, so a marked id stays for the mount's
     * lifetime (and a later enable only has to scan for new mounts).  The id
     * itself goes back to mnt_id_ida through the kernel's own mnt_free_id()
     * when the mount is finally freed - we never free it ourselves. */
```

### `WRITE_ONCE(n_ident, 0);`

```c
/* Nothing to release: an identity record is numbers and a string, it holds no
     * reference on the dentry or the superblock (see the note above), precisely so
     * an unmounted module image cannot be kept alive by this table.  The records
     * themselves stay; after exit nothing compares against them (the hide hooks are
     * unregistered above) and a later enable re-learns them. */
```

### `spin_lock_irqsave(&idmap_lock, flags);`

```c
/* The id map, on the other hand, IS dropped: it is keyed by an id the kernel
     * recycles, and for as long as the module is disabled nothing observes a
     * recycle.  A re-enable re-learns every pair from the mounts it scans. */
```

### `for (i = 0; i < SUS_MOUNT_SHOW_N; i++) {`

```c
/* The three mount-table hooks, registered INDEPENDENTLY.  They used to be fatal on the
     * first failure and silent about which one it was: -EINVAL from register_kprobe() (its
     * answer when the address is not probeable) came back to userspace as a bare -EINVAL with
     * nothing in the log - measured on a vendor 5.15 kernel, where enabling failed that way
     * while every mount table stayed unhidden, and only the source said which probe it was.
     *
     * Each hook covers a different file - show_vfsstat serves /proc/<pid>/mountstats,
     * show_mountinfo mountinfo, show_vfsmnt /proc/mounts and /proc/<pid>/mounts - so one that
     * cannot be armed must not take the other two down.  Every failure is named and the number
     * armed is on mount_stat as `show_probes=<n>/3`, which makes a partial hide visible instead
     * of silently smaller.  Only "none of the three" is fatal. */
```

### `rc = sus_mount_fdinfo_arm();`

```c
/* The two id rewrites are optional on their own: without them the mount
     * lines are still hidden, so a missing symbol must not take the rest down -
     * but each failure is named, because it leaves the ids visible in exactly
     * the place upstream rewrites them. */
```

### `rc = register_kprobe(&kp_sb_down);`

```c
/* Optional too, but it is the ONLY thing that invalidates a record when its
     * filesystem is unmounted, and the numbers the records are keyed by do get
     * reused (measured).  A missing symbol means records can outlive their fs and
     * falsely match another one, so say so instead of quietly degrading. */
```

### `rc = register_kretprobe(&kr_clone_ns);`

```c
/* Optional as well: without it a namespace copied after the enable keeps
     * working for the mount TABLE (identity hides the lines) but fdinfo/statx stay
     * inconsistent until somebody reads a mount table in that namespace. */
```

### `rc = register_kretprobe(&kr_newmnt);`

```c
/* And the mount-time registration, which is what covers a filesystem mounted while
     * the module is already up (see the note above kr_newmnt).  Also optional in the
     * sense that hiding keeps working for everything the scan saw - but without it a
     * mount that appears later is not hidden anywhere, so a failure is reported. */
```

### `rc = sus_mount_mark_ksu_mounts();`

```c
/* Only now does the threshold matter, so mark the KSU mounts (this also catches
         * everything mounted since the module was loaded).  A failed scan is REPORTED, not just
         * logged: with no mount carrying a KSU-range id the threshold never matches, so nothing
         * is hidden while the hook stays live - "enabled, does nothing", which a caller cannot
         * see from err=0.  (A scan that found zero KSU mounts is not a failure: rc==0.) */
```


## `kernel/sus_path.c`

### `(file header)`

```c
/*
 * sus_path.c - SUSFS SUS_PATH for the LKM, in two independent layers.
 *
 * Upstream sets AS_FLAGS_SUS_PATH on inode->i_mapping, skips the entry inside
 * filldir64() (fs/readdir.c) and hides it from path-based access by patching
 * fs/namei.c (link_path_walk returns -ENOENT; __lookup_slow/lookup_open redo the
 * lookup with the fake qstr "..5.u.S").  This LKM can touch neither - filldir64 is
 * static and LTO-inlined, namei.c is compiled into the kernel - so it reproduces
 * both effects: the getdents64 buffer is rewritten on return (layer 1, by (dev,
 * ino)), and two LSM hooks answer registered inodes with -ENOENT (layer 2:
 * inode_getattr for stat/fstatat/statx, inode_permission for
 * open/exec/chmod/truncate/...).
 *
 * Matching mirrors upstream: exact inode identity (not name substrings), any number
 * of registered paths, hidden wherever that inode is reached ('..', '//', relative
 * paths, symlinks, hard links, /proc/self/root/...), and the upstream gate - app
 * processes only and never a file owned by the caller (sus_path_gate_ok;
 * hide_from_apps=0 disables the gate for a root shell).  A path registered before it
 * exists is kept and hidden once it appears, upstream's CMD_SUSFS_ADD_SUS_PATH_LOOP /
 * LH_SUS_PATH_LOOP behaviour (sus_path_resolve_pending()).
 *
 * Upstream's FUSE_SUPER_MAGIC branch (susfs.c:71-84, :151-166, :195-212) has no
 * equivalent here on purpose - see the note above sus_path_inode_hidden().
 */
```

### `#define DIRENT_BUF_SIZE`

```c
/* Bounce buffer for the dirent rewrite: one record at a time, so only a single
 * record - not a whole listing - has to fit; one that does not fit is left
 * unfiltered and the rewrite stops there (counted and logged). */
```

### `#define SUS_PATH_PENDING_RETRY_S`

```c
/* Deferred resolution of rules whose path does not exist yet - upstream's
 * CMD_SUSFS_ADD_SUS_PATH_LOOP semantics (sus_path_resolve_pending()): retry every
 * SUS_PATH_PENDING_RETRY_S seconds, stop after SUS_PATH_PENDING_TRIES timer attempts
 * (the rule itself stays registered), at most SUS_PATH_PENDING_BUDGET lookups per pass. */
```

### `#define __NR_compat_getdents64`

```c
/* Syscall numbers, spelled out per arch/arm64/include/asm/unistd32.h (asm/unistd.h is
 * unreachable in this build) and include/uapi/asm-generic/unistd.h (native):
 *   native   61  __NR_getdents64
 *   AArch32 217  getdents64 - the SAME native body, so it shares 61's layout
 *   AArch32 141  getdents   - its own compat body (__arm64_compat_sys_getdents)
 *   native  106  __NR_getdents: the native unistd table has NO entry for it (see the
 *                note above sus_path_dirent_filter()), kept only so the dispatcher
 *                stays honest about which numbers it knows.
 * The dispatcher that reaches this file is the sys_exit tracepoint in susfs_kstat.c
 * (kernel/susfs_kstat.c: kstat_sys_exit()), which passes the caller's syscall number. */
```

### `struct sus_path_entry {`

```c
/* One registered path, kept for two independent mechanisms: the dirent filter hides
 * the entry (dev+ino+name) on every listing ABI this kernel reaches, and the LSM
 * hooks reject path-based access by the ihold'ed inode pointer - what upstream's
 * AS_FLAGS_SUS_PATH inode flag achieves.  dev is diagnostics only: the dirent filter
 * never sees the listing's fd or superblock. */
```

### `struct inode *inode;`

```c
/* ihold'ed once resolved, NULL while PENDING (registered for a path that does
     * not exist yet, upstream's _LOOP variant); a pending rule pins nothing. */
```

### `char path[SUS_PATH_LEN];`

```c
/* The path as registered, stored without a trailing slash
     * (path_len == strlen(path)). */
```

### `unsigned int pass;`

```c
/* Resolution pass that last tried this entry (0 = never): stops one pass from
     * retrying the same rule, without holding a pointer across kern_path(). */
```

### `bool self_protect;`

```c
/* One of the module's own control nodes (/proc/susfs_*): hidden from every
     * non-root caller, not only apps - see sus_path_entry_gate_any(). */
```

### `static void sus_path_relax_mode(struct sus_path_entry *e)`

```c
/* Let DAC through, so that the LSM layer is the only thing that can refuse: DAC runs before the
 * LSM chain and answers EACCES for a denying mode before any hook could turn it into ENOENT.
 * Relaxing once at registration - the one moment the inode is in hand - costs nothing afterwards,
 * unlike the old per-check DAC probes.  It is not disguised back on the way out: only non-root
 * callers are hidden at all, and root can see the file anyway.  The inode is ihold'ed for the
 * rule's lifetime, so it cannot be evicted and re-read with the original mode. */
```

### `static atomic_t sus_path_n_pending = ATOMIC_INIT(0);`

```c
/* Rules waiting for their path to appear, counted so every fast path can bail out at
 * once; guarded by sus_path_lock. */
```

### `static DEFINE_MUTEX(sus_path_pending_lock);`

```c
/* One resolution pass at a time: the supercall and the retry timer would race on the
 * same entries and on the per-entry pass marker. */
```

### `static int no_extra;`

```c
/* Isolation test: with no_extra=1 the LSM replacement and the dirent filter are
 * not registered at all. */
```

### `static DEFINE_SPINLOCK(sus_path_buf_lock);`

```c
/* Guards dirent_tmp, one global scratch buffer: the probes can fire concurrently, and without this
 * two listings compact into the same buffer and one process can get another directory's entries.
 * sus_path_lock cannot be reused - sus_path_is_hidden() takes it inside the traversal. */
```

### `static atomic_t n_dirent_rewrite_fail = ATOMIC_INIT(0);`

```c
/* Dirent rewrites that stopped early (record too large for the bounce buffer, or a uaccess fault):
 * the counter and the ratelimited log make "the listing was not filtered" visible. */
```

### `static atomic_t n_dirent_all_hidden = ATOMIC_INIT(0);`

```c
/* Chunks that were entirely hidden and needed a placeholder record instead of EOF -
 * see sus_path_filter(). */
```

### `static struct task_struct *sus_path_resolver;`

```c
/* ---- the resolver's own exemption ----
 * The background resolution of a pending rule has to ask the VFS itself (kern_path), and that walk
 * passes through our own hooks once the rule HAS an inode, so it would be answered -ENOENT and
 * re-resolution could never succeed - measured on the device: without the exemption the rule stays
 * pending forever.  Upstream has no such trap (its hiding is a flag on an inode, not a refusal to
 * answer) and walks under override_creds(ksu_cred) from the workqueue (susfs.c:139, reverted at
 * susfs.c:171) - see sus_path_override_creds().  Exactly one task is exempt, the one inside the
 * resolve call, so every other process keeps being hidden for the whole window; it is cleared right
 * after kern_path() returns, on every path. */
```

### `static const struct cred *sus_path_pending_cred;`

```c
/* Upstream resolves its _LOOP list from a workqueue worker under
 * override_creds(ksu_cred) (susfs.c:139 ... revert_creds() at :171): a worker's creds are not the
 * ones the path should be visible to, and SELinux, DAC and our own gate can tell the difference.
 * Measured on device: a kworker walks as uid 0 in the kernel domain, so
 * kern_path("/data/local/tmp/...") comes back -EACCES and the rule stays pending forever
 * (pend: last-rc=-13).  ksu_cred lives in the `kernelsu` module and
 * find_kernel_symbol_exact() deliberately refuses module symbols ("ignore symbol ... of module
 * ..."), so the creds of whoever registered the rule are saved instead - one reference, released on
 * unload - and that process can by definition reach the path. */
```

### `static const struct cred *sus_path_override_creds(const struct cred **borrowed)`

```c
/* Returns the cred revert_creds() wants, and stores in @borrowed the reference THIS call took.
 * get_cred() is what keeps the cred alive for the walk (the table's entry can be replaced
 * meanwhile), and revert_creds() only puts the reference override_creds() itself took - so
 * @borrowed has to be put here too, or every pass leaks one cred and pins the registering
 * process' user_ns/ucounts until the module is unloaded. */
```

### `static atomic_t sus_path_pend_passes = ATOMIC_INIT(0);      /* resolve passes run */`

```c
/* What the pending machinery did, for hide_list: "still pending" has to be
 * distinguishable from "the timer never ran" and from "the walk keeps failing". */
```

### `sus_path_gate_uid_ok()`

```c
/* ---- gates ----
 * Defined up here because every decision layer below asks the same question. */
```

### `static int hide_from_apps = 1;`

```c
/* Upstream gates on susfs_is_current_proc_umounted_app() && is_i_uid_not_allowed(): only app
 * processes, and never a file owned by the caller.  TIF_PROC_UMOUNTED is a SUSFS-specific thread
 * flag this LKM does not have, so uid >= 10000 is the proxy.  hide_from_apps=0 applies the hidden
 * set to every process including root - handy when testing from an adb shell. */
```

### `static inline bool sus_path_gate_uid_ok(void)`

```c
/* UID half of the upstream gate: a PENDING rule has no inode to ask about ownership
 * (sus_path_entry_gate_any()). */
```

### `static inline bool sus_path_gate_ok(struct inode *inode)`

```c
/* Full upstream gate for the LSM layer: app process, and the file is not owned by the caller
 * (upstream is_i_uid_not_allowed()).  hide_from_apps=0 must bypass the WHOLE gate, ownership check
 * included - otherwise a root-owned file would still be skipped for root (0 != 0 is false) and
 * disabling the gate would silently do nothing for exactly the case it is meant for. */
```

### `static inline bool sus_path_entry_gate_inode(const struct sus_path_entry *e,`

```c
/* Per-rule gate.  A self_protect rule is one of this module's own control nodes, which must be
 * invisible to EVERY non-root caller: the ordinary gate is uid >= 10000, so a probe running as
 * system (1000) or shell (2000) would read /proc/susfs_kstat straight out of the listing - exactly
 * the trace this module exists to avoid.  Root keeps access to manage the module; ordinary rules
 * keep the upstream semantics untouched. */
```

### `static inline bool sus_path_entry_gate_any(const struct sus_path_entry *e)`

```c
/* Gate for the layers that match by (ino, name) or by path string rather than by the inode being
 * accessed: the dirent filter and the path matcher.  Applying the uid half alone made them answer
 * differently from the LSM layer for the case upstream's gate is really about - a file owned by the
 * calling app disappeared from the listing while stat()/open() still succeeded, and a listing that
 * omits a file the caller can open is a far louder signal than either behaviour alone.  The rule
 * keeps its inode ihold'ed, so the ownership question is asked of that very inode: no cached uid,
 * and a chown() moves both layers together.  A rule not resolved yet falls back to the uid half. */
```

### `if (sus_path_is_resolver())`

```c
/* The one resolving task is never answered "hidden": its own walk would be
     * refused by this very table (see the block above sus_path_resolver). */
```

### `if (ino) {`

```c
/* A dirent is identified by (d_ino, name) and nothing else here - the filter never sees the fd
     * or the superblock.  A rule whose inode reports 0 has no identity to match, and d_ino 0 is
     * what some filesystems use for "unknown", so matching it by name alone would hide unrelated
     * entries; such a rule is hidden by the by-inode layers only (sus_path_supercall()). */
```

### `sus_path_basename()`

```c
/* ---- deferred resolution: upstream's CMD_SUSFS_ADD_SUS_PATH_LOOP ----
 * Upstream does not resolve at add time: susfs_add_sus_path_loop() (susfs.c:99-132) checks for an
 * empty string only and stores the path on LH_SUS_PATH_LOOP; susfs_run_sus_path_loop()
 * (susfs.c:134-172) walks that list with kern_path() later, triggered by susfs_run_extra_works()
 * (susfs.c:1451-1457) from ksu_handle_extra_susfs_work()
 * (KernelSU/10_enable_susfs_for_ksu.patch:1599-1607) as zygote marks an app TIF_PROC_UMOUNTED
 * (patch:1669, patch:1719), and entries are never removed, so every spawn retries all of them.
 * Semantics: "registered now, hidden as soon as the path shows up", no attempt limit, the trigger
 * is an event.
 * With no zygote hook here the rule is registered at once with inode == NULL ("pending"): nothing
 * hides it yet (the dirent filter needs (ino, name), the LSM hooks the inode) but it holds its
 * place, and sus_path_resolve_pending() retries from sus_path_supercall() (every add) and from a
 * bounded retry timer.  The resolving task is exempt from our own hiding and walks with the
 * caller's creds (sus_path_resolver, sus_path_override_creds()).  A rule still missing when the
 * timer gives up hides NOTHING until it resolves; the next add re-arms the timer.
 */
```

### `static void sus_path_basename(const char *path, char *dst, size_t size)`

```c
/* Basename of a registered path: what the getdents64 filter compares d_name against,
 * and what the table shows while the inode is unknown.  Stored paths never have a
 * trailing slash, so the text after the last '/' is the whole name. */
```

### `WRITE_ONCE(sus_path_resolver, current);`

```c
/* Exempt THIS task only, for the walk's duration, and undo it immediately
         * whatever the walk answers - every other process stays hidden throughout. */
```

### `atomic_set(&sus_path_pend_logged_rc, rc);`

```c
/* Report each distinct answer once: a rule that never resolves has to be
             * distinguishable from a timer that never ran, and the rc (-ENOENT,
             * -EACCES, -ENOTDIR) says which it is without logging the hidden path. */
```

### `spin_lock(&sus_path_lock);`

```c
/* The entry is re-found rather than used across the sleep: the table can be
         * changed while we are away (another add, or module exit tearing it down), so
         * only the path string is carried over - plus a pass marker no other pass can
         * have set on a fresh entry. */
```

### `sus_path_relax_mode(slot);`

```c
/* Relax INSIDE the section that owns `slot`.  `slot` is a raw pointer into the
             * table, and sus_path_del_path()/sus_path_command("clear") list_del() an entry
             * under this lock but iput()+kfree() it OUTSIDE it without holding
             * sus_path_pending_lock, so touching `slot` after the unlock is a use-after-free
             * write into freed memory (and the freed entry's inode pointer with it).  The
             * inode is ihold'ed here, so relaxing it needs no further lifetime argument. */
```

### `static void sus_path_pending_arm(void)`

```c
/* A rule was registered for a path that is not there yet: try once right away (an
 * earlier add in the same batch may be what made this rule necessary), then let the
 * timer keep trying.  Called from sus_path_supercall()'s task_work, i.e. process
 * context. */
```

### `static void sus_path_pending_work(struct work_struct *w)`

```c
/* Retry timer, bounded on purpose: upstream's equivalent runs once per app spawn (a
 * free trigger) while this one costs a periodic work item, and a rule whose path never
 * appears must not keep it alive forever.  A tick that cannot resolve anything is not
 * silent: the walk's own rc is logged once per distinct value by
 * sus_path_resolve_pending(), and hide_list carries the pass/tick/walk counters, so
 * "the timer never ran" and "the walk keeps failing" are told apart without guessing. */
```

### `sus_path_inode_getattr()`

```c
/* ---------------------------------------------------------------------------
 * LSM hooks - make path-based access report ENOENT.
 *
 * Upstream patches fs/namei.c (link_path_walk returns -ENOENT; __lookup_slow/lookup_open redo the
 * lookup with the fake qstr "..5.u.S") - impossible for a module, so the two hooks every
 * path-based operation has to pass are replaced: inode_getattr (vfs_getattr() calls
 * security_inode_getattr() before it ever looks at the inode: stat/fstatat/statx) and
 * inode_permission (open/exec/chmod/truncate/chdir/readdir/...).  Matching on the inode pointer
 * covers '//', './', relative paths, symlinks (followed), hard links, bind mounts and
 * /proc/self/root/...; unlink/rename operate on the PARENT's inode, hence the name-based hooks.
 * ------------------------------------------------------------------------- */
```

### `static int sus_path_inode_getattr(const struct path *path);`

```c
/* Every replacement in this file is INSERTED at the head of its hook list (KSU_LSM_HOOK_INSERT)
 * and can only ADD a denial, never suppress another LSM.  call_int_hook() returns the first
 * non-zero answer, so where nothing is hidden the replacement returns 0 and the chain continues
 * into SELinux: its decision - including the -ECHILD it answers an RCU walk with in
 * inode_permission - is still what the caller gets.
 * There is deliberately NO `orig` capture and no pass-through call below 6.12: we do not sit in
 * anyone else's slot, so there is no original to find and no NULL-original fallback to get wrong -
 * `return 0` means "no opinion" rather than "allow", and the LSM that would have refused still gets
 * its say.  (Sitting in SELinux's own slot without calling it back would be FAIL OPEN: an operation
 * SELinux denies would be allowed while every rule still looked installed.) */
```

### `#define LSM_HOOK_FN_TYPE`

```c
/* The signatures MUST match the LSM hook types exactly and must NOT be __nocfi: this kernel uses
 * kCFI with cross-module checks, so a mismatched signature panics, and __nocfi panics just as hard
 * because the function then emits no hash at all.  These assertions turn any mistake into a build
 * failure instead of a reboot.  The address-of is required - typeof(fn) is the function type while
 * the hook field is a function pointer.
 * They cover BOTH mechanisms: below 6.12 the dispatcher calls our node through this exact type, and
 * on >= 6.12 our replacement sits in SELinux's static-call slot (same type) AND makes an indirect
 * call back to the stolen original through a pointer of this type, checked against the hook's own
 * hash there. */
```

### `#define SUS_LSM_PASS_ORIG`

```c
/* ---- >= 6.12: the pass-through call to the stolen original ----
 * 6.12 replaced the hook list with static calls, so the insert path takes over the slot SELinux was
 * dispatched through and the call that used to reach SELinux now reaches us.  A bare `return 0`
 * would then NOT mean "no opinion, the chain continues" the way it does for a list node (< 6.12,
 * where our node is simply first and SELinux is still walked): there is no chain here, each hook
 * has one slot per LSM, so SELinux's function would silently never run again - a fail-open in the
 * one place it must not happen.  The stored original is called instead, and the -ENOENT above
 * short-circuits it exactly like a head node would.
 * The call goes through a pointer typed by the hook declaration (the static_asserts above guarantee
 * that type is right), hence the non-__nocfi rule: this call site is itself subject to kCFI. */
```

### `static int sus_path_inode_unlink(struct inode *dir, struct dentry *dentry);`

```c
/* ---- name-based operations ----
 *
 * unlink/rmdir/rename/link never permission-check the FILE, only the PARENT directory
 * (may_delete/may_create), so inode_permission never sees the target and an app that can write the
 * containing directory can delete or rename a hidden file straight out of hiding.  Each operation has
 * a hook carrying the target's dentry: security_inode_unlink/rmdir(dir, dentry),
 * security_inode_rename(old_dir, old_dentry, new_dir, new_dentry),
 * security_inode_link(old_dentry, dir, new_dentry).  Upstream does this earlier, inside namei, which
 * also covers a parent directory that itself denies the caller; being after DAC is enough for the case
 * that matters here (a writable parent).  The create family (inode_create/mkdir/mknod/symlink) is
 * deliberately not here: the target does not exist yet, so there is no inode to match against. */
```

### `#define SUS_XATTR_MNT_ID_DECL`

```c
/* ---- metadata and attribute operations ----
 *
 * These syscalls stop before any check we otherwise hook, so a hidden file could still be probed - in
 * the setattr case modified - while answering "permission denied" rather than "no such file".  Each has
 * an LSM hook carrying the dentry (or the path): sb_statfs for statfs/fstatfs; inode_setattr for
 * chmod/chown/truncate/utimes; inode_getxattr/_listxattr and inode_setxattr/_removexattr for the xattr
 * calls; path_notify for inotify_add_watch and fanotify_mark.  inode_setattr is the one that also
 * closes the error-code leak: without it an app got EPERM or EACCES from the owner check, which says
 * the file exists. */
```

### `#define SUS_XATTR_MNT_ID_DECL`

```c
/* ---- the setxattr/removexattr FIRST argument, per kernel version ----
 *
 * These two are the only hooks here whose first parameter is not a dentry/inode/path: it is the
 * id-mapping the syscall came in through, and its type moved twice (upstream
 * include/linux/lsm_hook_defs.h): no first argument before v5.12; `struct user_namespace *mnt_userns`
 * from v5.12 (added with idmapped mounts), replaced by `struct mnt_idmap *idmap` in v6.3 ("fs: add
 * mnt_idmap").
 * The trees this module builds against agree: android12-5.10 declares no first argument,
 * android13-5.15/android14-6.1 declare mnt_userns, android15-6.6 declares idmap.  Three spellings are
 * needed because the macro has to work in a parameter list (with a name), in a function-pointer type
 * (no name) and as the leading call argument - and before 5.12 all three vanish.  The static_asserts
 * below make a wrong branch a build failure, never a silently mis-typed hook (a mismatched signature
 * is a kCFI panic at load time). */
```

### `#define SUS_SETATTR_MNT_ID_DECL`

```c
/* ---- inode_setattr's FIRST argument, which followed later ----
 *
 * inode_setattr is the one hook of our 13 whose prototype moved between the trees this module
 * supports (per variant, from include/linux/lsm_hook_defs.h): android15-6.6 declares
 * LSM_HOOK(int, 0, inode_setattr, struct dentry *dentry, struct iattr *attr), android16-6.12 adds a
 * leading `struct mnt_idmap *idmap` (android17-6.18 is line-for-line the same).  Upstream the
 * parameter arrived earlier (v6.8 has the dentry/iattr pair only, v6.9 has the idmap), but the ACK
 * 6.6 tree is LTS-frozen and kept the old KMI, so the gate is on the 6.12 tree boundary - the only
 * two mount-id-relevant trees that exist as GKI, each compiled here.  The idmap is unused by the
 * replacement (it matches on the dentry's inode) but the parameter has to be there: the static_assert
 * below turns a missing one into a build failure, and a missing one at RUNTIME would be a kCFI panic
 * on the pass-through call.  Both spellings are needed for the same three positions as the xattr
 * pair. */
```

### `static void sus_path_entry_set_path(struct sus_path_entry *e, const char *path)`

```c
/* Store the registered path without a trailing slash, so "path/" and "path" both match
 * "path" and "path/child". */
```

### `sus_path_inode_hidden()`

```c
/*
 * Inode identity is the whole criterion here: deliberately NO FUSE branch, so do not "port"
 * upstream's (susfs.c:71-84 in add, :151-166 in susfs_run_sus_path_loop(), :195-212 in
 * susfs_is_inode_sus_path()).  It is a no-op: get_fuse_inode() is container_of(inode, struct
 * fuse_inode, inode) (fs/fuse/fuse_i.h) over an inode embedded in that struct and upstream's `inode`
 * comes from d_backing_inode() (include/linux/dcache.h), so it flags fi->inode.i_mapping and
 * inode->i_mapping - the same word twice; only an i_mapping NULL check identical to the generic one
 * above it (susfs.c:65-69) and a log line remain.  Our ihold'ed `struct inode *` is just as
 * object-scoped and cannot be recycled, so FUSE and CONFIG_FUSE_BPF=y passthrough (this kernel's
 * gki_defconfig) need nothing special.
 * The dirent filter is where FUSE costs both implementations something: ilookup(buf->sb, d_ino)
 * upstream and our (d_ino, name) match both fail when a FUSE inode is hashed by nodeid while
 * inode->i_ino is the daemon's attr.ino and d_ino whatever the daemon replied (fs/fuse/inode.c) -
 * upstream then skips the entry unfiltered (patch:1752-1760).  A name-only fallback would hide
 * same-named entries elsewhere in the superblock, so none is added.
 */
```

### `static atomic_t n_identity_hits = ATOMIC_INIT(0);`

```c
/* The key is IDENTITY, not the object: the inode pointer is only a cache in front of it.  A pointer
 * hit cannot be wrong, so it answers immediately; everything else is decided by (dev, i_ino), the
 * same key the mount layer uses for its identity records (s_dev + root inode number), and the
 * slow-path hit counter tells an operator whether the cache is doing its job and, when it is not,
 * that the rule's object is not the object readers get.
 * Why the object alone is not enough (both measured on hardware): after a quick rmmod + insmod a rule
 * can hold an inode no reader ever sees again while a NEW object carries the same (dev, i_ino) - seen
 * as ptr_equal=0 in sus_path_probe with this module's control nodes readable by uid 2000 again; and
 * ihold() keeps an inode alive but NOT hashed, so it can be unhashed while its number is handed out
 * again.  (dev, i_ino) is sound because a rule holds its inode from registration until del / clear /
 * unload: while that inode is the hashed one, its number cannot be reused.
 * One tier more, for this module's own control nodes only: another INSTANCE of the same filesystem
 * keeps the inode number but has its own s_dev (measured, a container's /proc: the same 4026535268
 * with dev 1048754 against the main /proc's 20), so their identity is (filesystem type, i_ino) -
 * procfs numbers come from a global allocator (proc_alloc_inum), so that pair can only be this
 * module's node while it is loaded.  Ordinary rules do not get that tier: across two mounts of one
 * type the same number can stand for two different files. */
```

### `if (sus_path_is_resolver())`

```c
/* See sus_path_resolver: the resolving task must not be answered by its own table,
     * or its walk of that very path is refused. */
```

### `if (!e->ino || e->ino != (u64)inode->i_ino)`

```c
/* Pending rules have no identity yet (ino == 0) and are the LSM layer's blind
         * spot by construction: nothing exists at their path to be accessed. */
```

### `SUS_LSM_PASS_ORIG(sus_path_getattr_hook, inode_getattr, path);`

```c
/* Not hidden: no opinion - SELinux's answer (and its AVC record) is what the caller
     * gets, on >= 6.12 by calling it since we hold the static-call slot it used. */
```

### `SUS_LSM_PASS_ORIG(sus_path_perm_hook, inode_permission, inode, mask);`

```c
/* Not hidden: 0, so SELinux still decides.  This matters most here: for an RCU walk
     * SELinux answers -ECHILD and the ref-walk retry in inode_permission() depends on
     * that answer reaching the caller unchanged. */
```

### `static atomic_t n_enoent_nameop = ATOMIC_INIT(0);`

```c
/* Shared counter: the name-based ops answer one question, and the interesting fact is
 * that they fire at all. */
```

### `if (sus_path_dentry_hidden(old_dentry) || sus_path_dentry_hidden(new_dentry))`

```c
/* Both ends matter: moving a hidden file out of hiding, and overwriting a hidden
     * file through its target name. */
```

### `if (sus_path_dentry_hidden(old_dentry))`

```c
/* A hard link is a second name for the same inode: creating one while the file is
     * hidden leaves the new name unhidden, so it is refused too. */
```

### `static atomic_t n_enoent_meta = ATOMIC_INIT(0);`

```c
/* Counted apart from the name operations: "the object cannot be probed or changed" and
 * "the name is not usable" fail for different reasons (see the block above). */
```

### `if (path && sus_path_dentry_hidden(path->dentry))`

```c
/* inotify_add_watch and fanotify_mark arrive here; their callers do not run an
     * inode permission check on the target. */
```

### `static bool hooks_armed;`

```c
/* The LSM slots go in with the module (pointer swaps, cost-free) and this flag only marks that the
 * layer as a whole is up, plus the one-time arming the kstat layer reports.  It used to gate the
 * dirent kretprobes, which are gone: they cost a brk trap per listing, and the rewrite now rides
 * kstat's already-registered sys_exit tracepoint instead (see above sus_path_dirent_filter()). */
```

### `static int n_lsm_ext_fail;`

```c
/* Secondary LSM hooks that could not be registered: the core two are fatal, these only mean one
 * class of operation is uncovered - reported through hide_list as well as the log. */
```

### `static DEFINE_MUTEX(sus_path_arm_lock);`

```c
/* Serialises the first rule's arming: two rules arriving at once (a supercall task_work and a
 * module_init caller) would both pass the hooks_armed check, and the second arm would stack a
 * second layer on top of the first one's. */
```

### `sus_path_dirent_abi_name()`

```c
/* ---- the listing filter ----
 *
 * The filter has to run AFTER the kernel has built the directory chain, and no LSM hook can do
 * it: the chain is built inside the filesystem, entry by entry, with no per-entry callback a
 * module can reach.  That leaves the syscall body itself.  WHICH bodies are reachable was read
 * off this kernel's tables (include/uapi/asm-generic/unistd.h,
 * arch/arm64/include/asm/unistd32.h): getdents64 native 61 -> __arm64_sys_getdents64 ->
 * __do_sys_getdents64; getdents64 AArch32 217 -> the SAME native wrapper (that table maps 217 to
 * sys_getdents64, not to a compat one); getdents AArch32 141 -> __arm64_compat_sys_getdents ->
 * __do_compat_sys_getdents.  __do_sys_getdents (the native table has no __NR_getdents) and
 * __arm64_compat_sys_old_readdir ("89 was sys_readdir", no AArch32 entry either) are covered
 * upstream through its fill callbacks but reachable from no table here, so nothing is filtered
 * for them.
 *
 * WHERE it runs: the ONE global sys_exit tracepoint that kernel/susfs_kstat.c already registers
 * (kstat_sys_exit()).  Both kernels it was measured on pay for that tracepoint on every syscall
 * already, so one more number in its whitelist costs one more compare (measured: no
 * per-syscall change), while the two getdents kretprobes this replaces cost a trap per listing -
 * measured 906 ns on top of the 23 ns the tracepoint itself adds, i.e. the whole +929 ns the
 * paired bench used to report for a listing.  A kretprobe also carries maxactive (64 here) and
 * silently DROPS a return once 64 are nested, which the tracepoint cannot: it is synchronous
 * with the syscall.
 *
 * The tracepoint handler calls sus_path_dirent_filter() below, i.e. this file still owns the
 * rewrite (the bounce buffer, the per-ABI record layout, the (ino, name) match and the gate);
 * susfs_kstat.c owns only "which syscall number, which user pointer". */
```

### `struct sus_dirent64_compat {`

```c
/* Record layouts: both reachable ABIs are NUL-terminated with an explicit d_reclen, so nothing
 * needs the d_namlen/computed-length variant old_readdir would have needed. */
```

### `static atomic_t n_dirent_calls[SUS_DIRENT_N];`

```c
/* "Did this ABI reach us at all" is a different claim from "did we hide something": only the pair
 * can tell a dead path from a working one, and the AArch32 layout is the one a 64-bit test tool
 * cannot exercise.  Incremented in sus_path_filter() and sus_path_dirent_filter() only, i.e.
 * AFTER the tracepoint's whitelist has already matched - an ordinary syscall still pays one
 * add-immediate in the handler and nothing here. */
```

### `static atomic_t n_dirent_no_filter[SUS_DIRENT_N];   /* sus_path_filter() found no buffer/knows the layout not `

```c
/* Every early-out of this layer, counted per reason: "calls(l64=N) and the entry still showed
 * up" is otherwise indistinguishable from "nothing was registered", and the reasons have
 * different fixes (a dead pointer, a full buffer, a rule that does not match, a gate).  Same
 * reasoning as the kstat per-number counters in susfs_kstat.c. */
```

### `static const char *sus_path_dirent_abi_name(int lay_id)`

```c
/* The numbers this layer answers for - the same list the tracepoint whitelists.  Kept as a
 * function of its own so the log line and the dispatcher cannot drift apart. */
```

### `long sus_path_dirent_filter(long syscall_nr, unsigned long buf, long ret)`

```c
/* Called by the sys_exit tracepoint in susfs_kstat.c, which is the ONLY caller of this file's
 * dirent layer now.
 *
 * Contract:
 *   @syscall_nr  the caller's number (native or AArch32; the tracepoint passes it through)
 *   @buf         the already-converted USER pointer of the listing buffer (the tracepoint does
 *                compat_ptr() for a 32-bit caller - a compat pointer is a zero-extended u32 and
 *                must not be passed raw)
 *   @ret         the syscall's return value
 * Return: what the syscall should now return.  @ret itself whenever nothing was filtered, or
 * when the number is not one this layer handles - so the caller only has to assign it back.
 *
 * Non-sleeping, and it must stay that way: it runs in tracepoint context, which is exactly the
 * constraint the kretprobes it replaces had (see the block above). */
```

### `if (syscall_nr == __NR_native_getdents64 || syscall_nr == __NR_compat_getdents64 ||`

```c
/* -errno, or 0 = end of directory: nothing to filter either way.  A zero return is
         * normal and constant, so it is counted apart from a negative one. */
```

### `return sus_path_filter(buf, ret, &sus_dirent_l64);`

```c
/* No native table entry in this kernel; if one ever appears it is the same record
         * layout as linux_dirent64. */
```

### `int sus_path_dirent_stat_line(char *buf, size_t size)`

```c
/* One line for the kstat counter block, next to the kstat per-number counters: which listing
 * ABIs actually reached the filter, and why a listing that should have been filtered was not.
 * Written with scnprintf so it cannot overrun; the caller passes a PAGE_SIZE buffer. */
```

### `if (no_extra)`

```c
/* Two layers, and neither of them is a syscall entry: the LSM slots (registered with the
     * module above) decide every path-based access by inode - ABI-independent, so 32-bit callers
     * are covered too, and undodgeable through a different spelling, a symlink, a hard link or a
     * bind mount; the dirent rewrite does the listing filter, which no LSM hook can do, and it
     * rides the ONE sys_exit tracepoint susfs_kstat.c registers (no probe of its own, so there is
     * nothing to arm here - see the block above sus_path_dirent_filter()).
     * Nothing else is needed: entry-layer hooks matched the caller's path STRING, which the LSM
     * match already covers more thoroughly, and a hook that cannot fire reads as coverage - so
     * those layers are DELETED, not disabled (see the note above sus_path_init()).
     * no_extra is the isolation switch: no LSM, no dirent filter. */
```

### `static long sus_path_filter(unsigned long buf, long count,`

```c
/* Rewrite the dirent chain the kernel just produced, dropping the entries whose
 * (d_ino, name) pair is registered; returns the byte count the caller may parse.
 * Records move one at a time through dirent_tmp, from `offset` to `written`, always to an
 * address at or before their own, so nothing unread is overwritten and the listing does not
 * have to fit in the buffer at all (the old code gave up once the 64 KB scratch was full).
 * The return value always describes what is really in the caller's buffer: the compacted
 * length on success (0 if every entry was hidden, `count` if none was); on a uaccess failure
 * the bytes handed back whole, which is still a valid record chain the caller re-reads on its
 * next getdents64; and `count` when nothing was written back, i.e. "nothing was filtered" -
 * the old behaviour returned `count` with a *partially* compacted buffer, telling the caller
 * to parse bytes that were no longer records. */
```

### `if (!buf) {`

```c
/* The traced syscall names the buffer, and a NULL one reaches here: getdents64(fd, NULL, n)
     * is a legal call that answers -EFAULT, so a positive return with a NULL buffer is not
     * something to rewrite - but it used to be neither filtered nor reported. */
```

### `if (!READ_ONCE(sus_path_count) && !hide_name[0]) {`

```c
/* Nothing registered, nothing to hide (hide_name is the legacy single-name debug switch):
     * the buffer is left exactly as the kernel wrote it. */
```

### `pagefault_disable();`

```c
/* uaccess under a spinlock may not fault: if the page is not resident the copy would
     * sleep here.  Disabled, a faulting copy fails, and every failure path answers "no
     * filtering" rather than guessing. */
```

### `if (reclen < lay->name_off + 1 ||`

```c
/* d_reclen is filesystem-supplied: bound it before it is used as a copy length, as
         * a step and before the bounce buffer is indexed. */
```

### `if (lay->ino_size == 8) {`

```c
/* The ino is the only fixed-width, ABI-dependent field: 8 bytes in linux_dirent64, 4 in the
         * AArch32 compat record.  A 32-bit record exists only when the number fit
         * (compat_filldir answers -EOVERFLOW otherwise), so the low 4 bytes are the whole value. */
```

### `offset += reclen;`

```c
/* Dropped.  Every record after it moves down by its length, so the
             * remaining records can no longer stay where they are. */
```

### `if (written != offset) {`

```c
/* A record only needs the bounce buffer once something ahead of it was
         * dropped; until then written == offset and it is already in place. */
```

### `if (!failed && count > 0 && written == 0) {`

```c
/* Everything in this chunk was hidden, and returning 0 here would be read as
         * end-of-directory: the caller stops and never sees the visible entries of the next
         * chunk.  So one record is left behind as a placeholder - d_ino = 0 with an empty
         * name.  readdir() skips records whose d_ino is 0 (bionic does), which makes the
         * caller ask again; a hand-written parser sees an entry without a name, still better
         * than a directory that ends early.  The hidden name is gone either way. */
```

### `if (head_reclen >= lay->name_off + 1 && head_reclen <= count &&`

```c
/* head_reclen is the first record's own length, read above with this ABI's layout; the
         * buffer still holds it untouched because written == 0 means nothing was moved. */
```

### `atomic_inc(&n_dirent_rewrite_fail);`

```c
/* Could not build the placeholder: filtering would be worse than not filtering, because the
         * caller would lose the chunk entirely. */
```

### `#define SUS_PATH_LIST_SLACK`

```c
/* Appending to a sysfs .get buffer is bounded HERE, not at each call site: the kernel hands
 * such a callback ONE page and no length at all (fs/sysfs/file.c: sysfs_kf_seq_show() ->
 * seq_get_buf() + memset(buf, 0, PAGE_SIZE) + ops->show(kobj, priv, buf)), so
 * "n += scnprintf(buf + n, PAGE_SIZE - n, ...)" is a heap overflow waiting for the first
 * listing that fills the page: once n passes PAGE_SIZE the expression PAGE_SIZE - n is a
 * size_t underflow (about 2^64), scnprintf believes it has unlimited room, and read(2) hands
 * the caller whatever followed the page in the heap.  About 50 ordinary rules are enough. */
```

### `int sus_path_del_path(const char *path)`

```c
/* Remove every rule whose registered path is @path (normalised as sus_path_entry_set_path()
 * stores it), undoing what those rules changed; returns how many were removed, so 0 is
 * "nothing was registered under that path".  Process context: sus_path_restore_mode() writes
 * inode->i_mode and iput() can sleep and evict - both outside the spinlock, and no matcher can
 * still be holding an entry (matchers walk the list only while holding the lock). */
```

### `static bool sus_path_path_is_ours(const char *path)`

```c
/* View of the registered paths, for verification.  Writable so a rule can be taken back: before
 * this, rules could only be removed by unloading the module, so one mistyped `add_sus_path /data`
 * hid that path machine-wide - and left the target's mode relaxed (sus_path_relax_mode()) for just
 * as long.  Deliberately NOT a new CMD_SUSFS_* command: this node is ours, while the supercall
 * command space has to stay compatible with KernelSU/ksud.
 *
 *   echo clear        > .../hide_list     all rules
 *   echo "del /path"  > .../hide_list     one rule (exact path, trailing / ignored)
 *
 * One command layer for both front ends - /proc/susfs_path and the hide_list parameter - so the two
 * cannot drift apart: add <path> (resolved now, the caller learns the errno), del <path> (restores
 * whatever sus_path_relax_mode() relaxed), clear (every ORDINARY rule).  `clear` and `del` refuse to
 * touch this module's own control nodes (the self_protect rules): those are what makes a non-root
 * caller see ENOENT instead of the control surface at all, and the documented way to expose the
 * nodes is expose_proc=0.  Returns 0 or a negative errno; @removed_out (optional) gets the number of
 * rules dropped. */
```

### `sus_path_store_list()`

```c
/* Normalise exactly like sus_path_del_path() does, or `del /proc/susfs_kstat/`
         * would slip past the guard below and remove the module's own protection. */
```

### `static int sus_path_format_list(char *buf, size_t size)`

```c
/* The listing, into a caller-supplied buffer; shared by /proc/susfs_path and hide_list so the
 * two views cannot say different things.  Returns the bytes written, clamped to the buffer. */
```

### `n = sus_path_list_puts(buf, n, &trunc,`

```c
/* The dirent counters moved next to the kstat ones (/proc/susfs_kstat), because the dirent
     * rewrite is now carried by the tracepoint that file registers: `cat /proc/susfs_kstat` shows
     * that layer's per-number counters followed by the listing filter's.  What stays here is what
     * belongs to this table alone - how many rules are waiting for their path. */
```

### `if (atomic_read(&n_identity_hits))`

```c
/* A normal, expected number rather than an alarm: how often a lookup had to fall through
     * to (dev, ino) because the rule's object was not the one being accessed.  Printed only
     * when non-zero; a steadily growing value is the interesting case. */
```

### `n = sus_path_list_puts(buf, n, &trunc,`

```c
/* passes/ticks == 0 means the retry never ran; walks > 0 with pending > 0 means the walk
     * kept failing (last-rc says how); lost > 0 means a walk succeeded with no rule to
     * publish it. */
```

### `static struct proc_dir_entry *sus_path_node_entry;`

```c
/* ---- /proc/susfs_path: the same table and the same command layer as hide_list ----
 * cat it for the listing; add <path> / del <path> / clear as above.  Same contract as the other
 * control nodes: mode 0777 so DAC does not answer EACCES first, root-only through the uid check
 * in open() AND write() (an fd opened before privileges were dropped is not a way in either),
 * and registered in the self-protected set so everyone else gets ENOENT. */
```

### `if (current_uid().val != 0)`

```c
/* 0777 node + this check: a restrictive mode would answer EACCES (advertising that the
     * node exists) before sus_path could answer ENOENT. */
```

### `if (current_uid().val != 0)`

```c
/* Same reason as the open check: an fd opened before the process dropped
     * privileges must not become a way in. */
```

### `module_param_cb(hide_list, &sus_path_list_ops, NULL, 0600);`

```c
/* 0600, not 0444: this listing names every hidden path, so an app must not be able to read it -
 * that would hand a detector the exact answer it looks for.  The write bit is what makes a
 * mistaken rule removable (see sus_path_store_list). */
```

### `static char sus_path_probe_report[640];`

```c
/* ---- diagnostic: why does a registered rule not match? ----
 * echo /proc/susfs_kstat > .../parameters/sus_path_probe, then cat it: resolves the path as
 * sus_path_add_hidden_ex() does and reports the identity a reader would see next to the rule meant
 * to match it - the one question the counters cannot answer, which otherwise needs a kernel
 * debugger.  Process context only (kern_path sleeps); 0600 for the same reason hide_list is. */
```

### `static int sus_path_add_hidden_ex(const char *path, bool self_protect)`

```c
/* Add a path to the hidden set from kernel code, bypassing the supercall; used by susfs_init() to
 * self-hide the /proc control nodes.  Same entry shape and ihold discipline as
 * sus_path_supercall(): the inode pointer is what the LSM layer matches on and it must outlive
 * path_put() below. */
```

### `e = kzalloc(sizeof(*e), GFP_KERNEL);`

```c
/* kzalloc, NOT kmalloc: the entry has two fields these add paths never set -
	 * `self_protect` (a gate: a garbage non-zero value turns an ordinary app-only rule
	 * into "hidden from every non-root caller") and `orig_mode` (written back into
	 * inode->i_mode by sus_path_restore_mode() at unload).  With kmalloc both held
	 * whatever the slab last contained, and the common case made it certain:
	 * sus_path_relax_mode() returns early - recording nothing - when the target is
	 * already 0777, so unloading wrote uninitialized heap bytes into a real inode mode.
	 * Zero is the right initial value for both: false is the ordinary gate, and
	 * orig_mode == 0 means "this rule did not touch the mode", which is exactly what
	 * restore_mode() tests for. */
```

### `int sus_path_add_self_hidden(const char *path)`

```c
/* Register one of the module's own control nodes: same table, flagged so the gate hides it from
 * every non-root caller rather than only from apps (sus_path_entry_gate_any()). */
```

### `bool sus_path_lsm_active(void)`

```c
/* Whether the path-based layer actually installed: both hooks must be patched, or stat and open
 * would disagree with each other. */
```

### `dirent_tmp = kvmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);`

```c
/* kvmalloc, not kmalloc: 64 KB of physically contiguous order-4 memory is not available on a
     * phone that has been up for a while (measured: MemFree 394 MB, and kmalloc_order failed with a
     * WARN in its call trace), while vmalloc memory is just as usable here - the buffer is only
     * touched from the getdents64 filter, which never faults on it.  A failure is not fatal: listings
     * then go unfiltered and the other layers still come up. */
```

### `SUSFS_LOGI("sus_path: dirent rewrite rides the shared sys_exit tracepoint (no probe of its own)\n");`

```c
/* No probe of our own is registered here any more: the dirent rewrite is called from kstat's
     * sys_exit tracepoint, which exists from module load on (it is what spoofs stat), so the
     * rewrite is reachable as soon as this buffer is.  With no rule registered it returns before
     * touching the buffer, which is the "no rules, no cost" property the kretprobes used to get
     * from being armed late. */
```

### `rc = ksu_register_lsm_hook(&sus_path_getattr_hook);`

```c
/* LSM hooks: reject path-based access to registered inodes outright.  These two ARE the
     * mechanism - a registered path is hidden only because this layer answers ENOENT.  A failure
     * here used to be a warning with a zero return, so add_sus_path() reported success while
     * nothing was hidden; loading now fails instead. */
```

### `kvfree(dirent_tmp);`

```c
/* The scratch buffer is already allocated; the caller is about to fail the load, and a
         * vmalloc'd buffer is not part of the module's own memory, so nobody else would free it. */
```

### `sus_path_exit()`

```c
/* Name-based and metadata operations: without these an app that can write the parent directory
     * can delete or rename a hidden file, and a hidden file can still be probed or modified through
     * statfs/xattr/inotify - or answered with EPERM/EACCES, which says it exists. */
```

### `if (!n_lsm_ext_fail)`

```c
/* Not fatal - the core two hooks are up, so a hidden path is still hidden -
                 * but one class of operation is NOT covered, so it is counted and named in
                 * hide_list rather than only logged. */
```

### `sus_path_exit()`

```c
/* The DAC probes, the syscall-entry kprobes and the path-string probes are DELETED, not
     * merely disabled: the mode relax in sus_path_relax_mode() covers the case where DAC
     * answers EACCES before any LSM hook runs, and a hook that cannot fire reads as coverage.
     * Their history, including the FPAC panic one of them caused, is in TECHNICAL_NOTES.md. */
```

### `if (susfs_control_node_allowed()) {`

```c
/* The control node goes up LAST, and only when the layer that hides it is really installed
     * (susfs_control_node_allowed()): a 0777 world-writable node without the thing that answers
     * ENOENT for it must not exist.  It has to be created before susfs_self_hide_nodes() runs,
     * which is why it is here and not in susfs_main.c - that list is registered after every
     * layer's own init, so paths resolve. */
```

### `if (sus_path_node_entry) {`

```c
/* Our own node goes down first, while the LSM layer that hides it is still armed: the
     * reverse order would expose a 0777 control surface for the duration of the unload. */
```

### `sus_path_supercall()`

```c
/* Unregister the hooks FIRST: after this nothing can match, so the entries (and their inode
     * references) can be torn down safely.  The dirent layer needs no teardown of its own: it is
     * called from kstat's sys_exit tracepoint, which susfs_kstat_exit() unregisters, and kstat's
     * exit runs after this one (susfs_main.c's layer table teardown order). */
```

### `cancel_delayed_work_sync(&sus_path_pending_wq);`

```c
/* The retry timer must be off and no resolution pass may be in flight while the table is
     * emptied below: a pass re-finds its entry under the lock and never frees anything, but it
     * may not run past the teardown either.  The pass uses trylock, so this cannot deadlock. */
```

### `list_for_each_entry_safe(e, tmp, &doomed, list) {`

```c
/* iput outside the lock (it can sleep and evict), and the mode each rule relaxed is put
     * back first and before the inode is released: the relaxed value only lives in memory, so
     * once the last reference is gone there is no telling a relaxed mode from a real one. */
```

### `void sus_path_supercall(unsigned int cmd, void __user **arg)`

```c
/* supercall: CMD_SUSFS_ADD_SUS_PATH (0x55550) / CMD_SUSFS_ADD_SUS_PATH_LOOP (0x55553)
 * Upstream keeps the two apart: susfs_add_sus_path() needs the path to exist and the lookup
 * error IS the command's answer (susfs.c:58-62), while susfs_add_sus_path_loop() checks for an
 * empty string only, stores the path on LH_SUS_PATH_LOOP and resolves it later (susfs.c:99-132,
 * susfs_run_sus_path_loop() susfs.c:134-172).  The dispatcher therefore says which command
 * arrived: treating both as pending made the plain command answer 0 for a path that does not
 * exist, so a caller other than the stock tool (which realpath()s first) believed a rule was
 * installed that upstream would have rejected.
 * A pending rule is not dead weight: it holds its place in the table, so the path is hidden from
 * the moment the background walk resolves its inode; what the pending state delays is every
 * layer - the LSM hooks (by inode) and the dirent filter ((ino, name)) - because none of them can
 * match an inode that does not exist yet. */
```

### `if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {`

```c
/* The field is char[256] and need not be NUL-terminated; kern_path() on an
     * unterminated one reads off the end of our stack copy of the struct. */
```

### `if (rc == -ENOENT && !pending_ok) {`

```c
/* Upstream's plain ADD_SUS_PATH reports a missing path: its `err = kern_path(...)` IS the answer
 * (fs/susfs.c:58-62).  Only the _LOOP variant accepts "not there yet".  (This kern_path() also
 * runs into our own rule when the path is already hidden - upstream is no different, its
 * rejection lives in walk_component(), so both implementations answer the same -ENOENT.) */
```

### `e = kzalloc(sizeof(*e), GFP_KERNEL);`

```c
/* kzalloc, NOT kmalloc: `self_protect` and `orig_mode` must start at zero or unloading
     * writes uninitialized heap bytes into a real inode mode - see sus_path_add_hidden_ex(). */
```

### `ihold(inode);`

```c
/* Hold the inode: the LSM hooks match on this pointer, and the dentry is
         * about to be released by path_put(), which would otherwise be free to
         * evict it and let the address be reused. */
```

### `sus_path_basename(e->path, e->name, sizeof(e->name));`

```c
/* No dentry to take the name from yet: the basename of the registered path is what the
         * table shows until the lookup succeeds, and it is then replaced by the real dentry name,
         * which is what the dirent filter has to compare (following a symlink changes it). */
```

### `if ((inode && cur->inode == inode) ||`

```c
/* Same inode: upstream's set_bit() is idempotent.  Same still-unresolved path:
             * nothing to add but the retry marker. */
```

### `if (inode && !cur->inode && !strcmp(cur->path, e->path)) {`

```c
/* The rule is there as a pending one and this add is what resolved it: complete that
             * entry instead of registering a second one for the same path (a boot script that
             * runs twice would otherwise leave one resolved and one pending entry behind), so
             * re-adding a path is also the manual way to force the resolution. */
```

### `pr_warn("sus_path: '%s' reports ino 0 - hidden by inode, but a directory listing cannot be filtered for it\n",`

```c
/* Stay factual about what an ino-0 filesystem costs: neither implementation filters
         * the listing here (upstream hides by a flag and its ilookup(sb, d_ino) finds nothing
         * for ino 0 either), the by-inode layers still hide the path, and a name-based
         * fallback would hide unrelated entries that report d_ino 0 as well. */
```

### `dirent_tmp = kvmalloc(DIRENT_BUF_SIZE, GFP_KERNEL);`

```c
/* Retry once: the first attempt may have run before the system was settled.  Still not
         * fatal - the rule is registered either way, and the by-inode layers answer the access. */
```

### `sus_path_hooks_arm();`

```c
/* First rule: arm the hooks (the LSM slots are up from init; this is the one that reports
     * the layer as a whole).  Idempotent, safe with a rule already in the list. */
```

### `sus_path_save_caller_cred();`

```c
/* The walk happens later, in a worker whose own creds cannot reach a path under /data
         * (measured: -EACCES), so remember the creds of the process that registered the rule. */
```

### `sus_path_pending_arm();`

```c
/* This add is itself the first retry opportunity (an earlier add in the same batch may
         * be what the rule waits for), then the bounded timer keeps trying.  Upstream
         * re-resolves on every zygote-spawned app instead, an event this kernel does not hand
         * us. */
```


## `kernel/susfs_avc_spoof.c`

### `(file header)`

```c
/*
 * susfs_avc_spoof.c - hide the KernelSU su domain from SELinux AVC audit logs (SUSFS AVC_LOG_SPOOFING), LKM port: upstream
 * prints a priv_app context in place of the su domain, hiding the "denied { ... } tcontext=u:r:su:s0" lines that root-hiding
 * detectors grep for.  Rewriting tsid in place makes the hooked function's own security_sid_to_context() emit the priv_app
 * context - equivalent to upstream's string swap.  The sids are resolved at init time (process context) via EXPORT_SYMBOL
 * security_secctx_to_secid(), with module_param overrides; interface is /proc/susfs_avc_spoof (write "1"/"0", read to query).
 */
```

### `static char avc_su_ctx[128] = "u:r:ksu:s0";`

```c
/* module_param overrides for the two domains: the default su domain is the SukiSU variant ("ksu"), stock
 * KernelSU uses "su".  The sid is resolved at init time via security_secctx_to_secid(). */
```

### `static atomic_t avc_hit_count = ATOMIC_INIT(0);`

```c
/* slow_avc_audit(state, ssid, tsid, tclass, requested, audited, denied, result, a): tsid is arg #3
 * (regs->regs[2]), a u32 in the low bits.  avc_audit_post_callback is static and LTO-inlined into
 * slow_avc_audit (noinline), so its kallsyms symbol is a leftover; slow_avc_audit has a real out-of-line copy.
 * This handler runs in interrupt context (no sleep), so it only rewrites the register. */
```

### `if (!avc_su_sid || tsid != avc_su_sid)`

```c
/* avc_su_sid == 0 means security_secctx_to_secid() failed (see init); a failed resolution must not
	 * turn "sid 0" into a match. */
```

### `if (current_uid().val != 0)`

```c
/* 0777 is deliberate (the ENOENT contract comes from sus_path's hidden set, not from the mode), so
	 * refuse non-root callers here too - see the note in susfs_enable_log.c's log_proc_open(). */
```

### `if (susfs_control_node_allowed()) {`

```c
/* Only the /proc node is optional: avc_register() installs the hook whenever the feature is switched
	 * on, supercall included.  0777 so DAC passes and sus_path's LSM layer gets to answer ENOENT. */
```


## `kernel/susfs_enable_log.c`

### `(file header)`

```c
/*
 * susfs_enable_log.c - toggle SUSFS debug logging (ENABLE_LOG feature).  Upstream gates SUSFS_LOGI() behind the
 * static branch susfs_is_log_enabled; an LKM has no static branch, so the same semantics live in a global flag
 * with a /proc node (write "1"/"0", read to query), ON at load like upstream's DEFINE_STATIC_KEY_TRUE.  Measured
 * before the fix: the flag had no readers and "susfs_guard_lkm: ..." kept appearing after enable_log 0.
 */
```

### `module_param_named(enable_log, log_enabled, bool, 0444);`

```c
/* Load-time switch, read-only in sysfs; the runtime switch is the /proc node and the supercall, the interfaces
 * upstream's userspace drives (ksud insmod ... enable_log=0).  A load that starts silent is the only state in
 * which the unconditional "loaded." line of susfs_main.c matters: without it, silent-but-loaded looks unloaded. */
```

### `static int log_proc_show(struct seq_file *m, void *v)`

```c
/* Deliberately NOT EXPORT_SYMBOL'd: the only user is this module (susfs_log.h wraps it), and an exported name
 * shows up as a [susfs_guard_lkm]-owned symbol in /proc/kallsyms - outward surface upstream SUSFS lacks. */
```

### `if (current_uid().val != 0)`

```c
/* 0777 on purpose: the ENOENT contract for non-root callers comes from sus_path's hidden set, and a
	 * restrictive mode would answer EACCES - which leaks that the node exists.  That makes sus_path's hook the
	 * only thing between an app and this interface, so the handler refuses non-root callers itself as well. */
```

### `if (current_uid().val != 0)`

```c
/* Same reason as the open check: an fd opened before the process dropped privileges must not become a
	 * way in. */
```

### `if (c != '0' && c != '1')`

```c
/* Only '0' and '1' are the protocol.  The old code accepted every other byte, still reported len, and
	 * toggled nothing - a typo was indistinguishable from success. */
```

### `pr_info("susfs: disable logging to kernel\n");`

```c
/* Unconditional on purpose (upstream uses its unconditional SUSFS_LOGE here): the confirmation
		 * that silence is now in effect must not itself be silenced. */
```

### `if (susfs_control_node_allowed()) {`

```c
/* Nothing to register here (logging is toggled over the supercall or by this node), so the node is the
	 * only thing to gate.  See susfs_control_node_allowed(): 0777 so DAC passes, LSM answers ENOENT. */
```


## `kernel/susfs_hide_syms.c`

### `(file header)`

```c
/*
 * susfs_hide_syms.c - hide ksu/susfs symbols from /proc/kallsyms (SUSFS HIDE_KSU_SUSFS_SYMBOLS feature), LKM port.
 * Upstream patches kernel/kallsyms.c s_show() to skip symbols whose name starts with ksu_/__ksu_/susfs_/ksud/...  s_show is
 * static but sits in the kallsyms_op.show seq_operations pointer, so LTO keeps an out-of-line copy and a kprobe can hang
 * on it.  A matching prefix returns early (regs->regs[0] = 0, regs->pc = x30), so the line is never printed - covering
 * BOTH core-kernel and module symbols, since the whole body is skipped before it branches on module_name.  On by default
 * like upstream (a build-time CONFIG there, no runtime toggle).
 */
```

### `#define HIDE_MODULES_MAX`

```c
/* ---- hide_modules: filter other kernel modules out of /proc/modules ----
 * /proc/modules is world-readable (0444) and lists every loaded module, so a checker that greps it sees the whole set
 * including the module doing the hiding.  The feature keeps a list of module NAMES and removes them from: (1)
 * /proc/modules - the m_show() line, for EVERY reader, root included, since a checker may well run as root and this
 * listing is what it compares against; (2) /sys/module/<name> - registered in sus_path with self_protect, so
 * stat/open/readdir answer ENOENT for non-root callers while root keeps access (that is where a module's parameters
 * live) - the one asymmetry to know; (3) /proc/kallsyms lines whose module_name matches, also for every reader.
 * Two frontends over one list: /proc/susfs_hide_modules (`add <name> | del <name> | clear | <name> [<name> ...]`, root
 * only, ENOENT for everyone else) and .../parameters/hide_modules (same commands, settable at insmod).  Both follow the
 * house pattern of the control nodes: 0777 so DAC passes and sus_path's hidden set is the only answer (ENOENT,
 * indistinguishable from "no such file"), plus a uid check in open() AND write() so a passed-on fd is not a way in.  The
 * default list holds just this module, because a built-in SUSFS has no module entry; `clear` is the debugging mode.
 * Not a new CMD_SUSFS_* command: that id space is shared with KernelSU's own copy of SUSFS and a new id there is a
 * compatibility risk that buys nothing. */
```

### `static int hide_modules_parse(const char *val, char dst[][MODULE_NAME_LEN], int max)`

```c
/* Parse @val into @dst and return the count, or a negative errno.  Separators are spaces, commas and tabs, so both the
 * insmod form (hide_modules=a,b) and the /proc form (a b) work.  @buf is 1136 bytes and the caller below is checked against
 * the same 2048-byte frame limit, so it is allocated rather than kept on the stack (see hide_modules_command). */
```

### `static int hide_modules_command(const char *val, bool bare_list)`

```c
/* One implementation for both frontends.  Commands: `clear`, `add <name>`, `del <name>`, `set <name> [<name>...]`.
 *
 * @bare_list is the one difference: insmod hands the parameter a bare value (`hide_modules=a,b`), so its setter accepts a
 * command-less list; the /proc node does NOT - a typo there would otherwise silently *replace* the list with whatever was
 * typed (measured on the first device test, where a bogus command discarded the list and the next read showed a name
 * nobody meant).
 *
 * The two staging buffers (1136 + 1024 bytes) are heap-allocated: as locals they made this function's frame 3024 bytes once
 * the inliner folded hide_modules_parse() (and its own 1136-byte buffer) into it, which the 5.10/5.15 builds reported every
 * build - "ld.lld: warning: stack frame size (3024) exceeds limit (2048) in function 'hide_modules_command'", and
 * 5.15/android14-5.15 as "susfs_hide_syms.c:197:0: stack frame size (3024) exceeds limit (2048)".  6.x turns that warning
 * into an error.  Both callers are proc/module_param setters - process context - so GFP_KERNEL is fine. */
```

### `hide_modules_format()`

```c
/* `found` is kept separate from `i` on purpose: after a del the index and the new count coincide whenever the
		 * removed entry was the last one, and reusing `i` for both questions answered -ENOENT for a name that was right
		 * there (measured: `del <last entry>` always failed). */
```

### `if (current_uid().val != 0)`

```c
/* 0777 node + this check, exactly like the other control nodes: a restrictive mode would answer EACCES (which
	 * advertises that the node exists) before sus_path could answer ENOENT. */
```

### `struct kallsym_iter_local {`

```c
/* Local mirror of kernel/kallsyms.c struct kallsym_iter; only the name field matters here.
 *
 * It is a MIRROR, so the compiler cannot check it against the kernel's own struct, and the
 * layout is not KMI-frozen across the versions this module builds against: v6.5 removed
 * `pos_arch_end` (measured against upstream: v5.10/v5.15/v6.1 have it, v6.6/v6.12/v6.18 do
 * not).  Getting this wrong shifts `name`/`module_name` by 8 bytes, which makes every prefix
 * and module-name test miss while all the counters still report "armed" - a silent no-op, not
 * a crash.  Hence the gate below for the drift that is known, and the plausibility check in
 * hide_syms_s_show_pre() for the drift that is not. */
```

### `if (strstr(name, "ksu") || strstr(name, "susfs"))`

```c
/* Substring form for the names whose prefix differs from the list above.  Measured: with the prefix rules alone a
	 * 257 -> 7 sweep left anon_ksu_fops, anon_ksu_ioctl(.cfi_jt), anon_ksu_release(.cfi_jt), setup_ksu_cred and
	 * is_task_ksu_domain visible - each a plain "KernelSU is loaded here" tell in /proc/kallsyms. */
```

### `static bool hide_syms_iter_plausible(const struct kallsym_iter_local *it)`

```c
/* Is this really a kernel struct kallsym_iter?  Two facts are always true of one: kallsyms
 * fills `type` from its own alphabet, and `name` is NUL-terminated within the field.  The
 * check exists because this kprobe is registered BY NAME and `s_show` is not unique in a
 * kernel that has both kernel/kallsyms.c's and kernel/trace/trace.c's (and mm/vmalloc.c's);
 * if it lands on the wrong one, m->private is some other object and walking it with strncmp
 * and strstr reads whatever is there.  With this gate the string walk below is bounded either
 * way, and a mismatch is counted and reported instead of silently mis-hiding. */
```

### `if (name_should_hide(iter->name)) {`

```c
/* Two different features, counted apart: the prefix list is upstream's HIDE_KSU_SUSFS_SYMBOLS (KernelSU's names),
	 * while the module_name test is hide_modules, which filters the lines of whichever modules the operator listed -
	 * module symbols carry their own spelling (e.g. __kstrtab_foo) with the module's name in module_name. */
```

### `static struct kprobe kp_s_show = {`

```c
/* Registered by name, which is what was measured to work: with this in place `grep -cE 'susfs_|ksu_' /proc/kallsyms` goes 257
 * -> 0.  An audit pointed out that this tree has three different `s_show` functions (kernel/kallsyms.c, kernel/trace/trace.c,
 * mm/vmalloc.c) and that name-based registration gets whichever kallsyms lists first - a real hazard, since the handler reads
 * m->private as struct kallsym_iter *.  Taking the address out of the kallsyms_op table instead and registering with .addr
 * CRASHED the device on the first read of /proc/kallsyms, so the table's .show is not the address a kprobe can be hung on
 * (most likely the arm64 CFI jump-table thunk, which a table's function pointer holds under this config).  So: keep the
 * working registration, and log both addresses so a mismatch is visible. */
```

### `static int hide_syms_m_show_pre(struct kprobe *kp, struct pt_regs *regs)`

```c
/* /proc/modules is 0444 - any app can read it - and nothing in a built-in SUSFS is listed there.  Our own line is printed
 * by m_show(m, p) with p = &module->list; answering success without emitting anything leaves the listing exactly as it
 * would be without the module.  struct module's layout is what this module was built against (RANDSTRUCT is off here). */
```

### `SUSFS_LOGI("susfs_hide_syms: armed at %px (kallsyms_op.show=%px%s)\n",`

```c
/* The two addresses differ by design: a function pointer inside a table holds the CFI jump-table thunk
	 * (bti c ; b func), while the kprobe lands on the function itself.  The check that matters is the one on device -
	 * /proc/kallsyms going from 257 ksu_/susfs_ matches to none - and that is what the line is for. */
```

### `susfs_hide_syms_active()`

```c
/* hide_modules starts with just this module in its list: a built-in SUSFS has no module entry, so leaving ours visible
	 * would be a trace upstream does not have.  The sysfs rule can only be registered now, because sus_path is up (this
	 * layer is last in the init table) - hence the default list is seeded here and not from the parameter's value. */
```

### `if (susfs_control_node_allowed()) {`

```c
/* The runtime control node: created only when the LSM layer that hides it is installed, so an unprotected
	 * world-writable node cannot exist (same shape as the other control nodes - see susfs_control_node_allowed()). */
```


## `kernel/susfs_kstat.c`

### `(file header)`

```c
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
```

### `#define KSTAT_AUTO_SPOOF`

```c
/* KSTAT_SPOOF_* bits live in susfs_abi.h (upstream declares them in susfs.h next to struct
 * st_susfs_sus_kstat).  KSTAT_AUTO_SPOOF* below are /proc-interface masks, not supercall ABI. */
```

### `static DEFINE_SPINLOCK(kstat_table_lock);`

```c
/* Table locking, in two tiers.  kstat_lock (mutex) serialises WRITERS and the /proc read, because
 * writers resolve paths and that sleeps.  kstat_table_lock (spinlock) guards the table for the
 * READERS - the sys_exit tracepoint and the show_map_vma kretprobe, hot paths where kstat_lock
 * cannot be taken; a reader holds it only long enough to copy the matching entry out and must never
 * copy_to_user under it.  Rule: resolve first (sleeping, outside), then swap (non-sleeping, inside) -
 * publishing a slot before it is filled is a bug (an empty slot used to be visible as soon as nkstat
 * was bumped, before kern_path() had even run). */
```

### `static_assert(offsetof(struct stat, st_dev) == ST_DEV_OFF, "stat.st_dev");`

```c
/* The numbers above are a uapi contract, checked at build time instead of trusted: arm64 uses the
 * generic layout (__ARCH_WANT_NEW_STAT), and a DDK header change that moved a member would
 * otherwise corrupt the caller's stat buffer instead of failing this build. */
```

### `static bool susfs_kstat_gate_ok(void)`

```c
/* ---- the read gate ----
 *
 * Upstream gates every sus_kstat read on susfs_is_current_proc_umounted_app(), exactly
 * (TIF_PROC_UMOUNTED && current_uid().val >= 10000).  KernelSU's setuid_hook sets that flag only
 * when SUSFS integration is compiled into the kernel, and this device's kernel has none (zero susfs
 * symbols in kallsyms) - so uid >= 10000 is the available proxy, the same one sus_path uses.
 * Without it the spoofing is visible to root too, wider than upstream.  Writers (supercall, /proc)
 * are configuration and stay ungated. */
```

### `susfs_kstat_table_empty()`

```c
/* ---- table access ----
 * The *_table_* helpers are the ONLY places that modify kstat_entries or nkstat, each under
 * kstat_table_lock; their callers hold kstat_lock, making the index they pass stable. */
```

### `static bool susfs_kstat_table_empty(void)`

```c
/* Cheapest possible gate for the READ paths: with nothing registered no lookup can match, which on
 * the sys_exit tracepoint saves the two copy_from_user() reads the spoofers do before matching, and
 * on the show_map_vma kprobe (still armed after a `clear`) saves an uncontended spinlock per VMA.
 * READ_ONCE is enough: nkstat is published only AFTER the entry it counts has been written, under
 * kstat_table_lock (kstat_table_append stores the entry, then bumps the count), so a stale non-zero
 * value only means work we used to do and a stale zero can cost at most the single read racing the
 * very first add; the authoritative test is the locked lookup.
 * sus_path uses the same idiom (READ_ONCE(sus_path_count)). */
```

### `kstat_buf_replace()`

```c
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
```

### `static bool kstat_buf_replace(struct seq_file *m, const char *old, size_t old_len,`

```c
/* Same buffer edit as the maps name/numbers rewrite in susfs_open_redirect.c: replace the first
 * occurrence of old[] with new[], growing only when the buffer has room. */
```

### `while (new_len < old_len && new_len < (int)sizeof(new) - 1)`

```c
/* Keep the column width, space-padding the run: a SHORTER run would pull the name left by the
	 * difference and a line whose name does not line up with its neighbours is visible on its own.
	 * A LONGER run does shift it - the rare case (a spoofed ino with more digits than the real one). */
```

### `struct kstat_call_counters {`

```c
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
```

### `KSTAT_COUNTERS(nfstatat);`

```c
/* One instance per whitelisted number.  nfstatat = native newfstatat(79), nfstat = native
 * fstat(80), statx = native statx(291); the AArch32 five are fstatat64(327), stat64(195),
 * lstat64(196) and fstat64(197) plus the struct compat_stat family that is NOT wired yet - see the
 * note above STAT64_ST_*: those three numbers get a counter line of their own from the moment they
 * are handled, and until then they are reported by "unlisted-nr" if they are ever issued. */
```

### `#define KSTAT_NR_SCAN_LO`

```c
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
```

### `susfs_kstat_spoof_statbuf()`

```c
/* The whitelist table itself (kstat_nr_table) is defined further down, after the syscall-number
 * constants it is built from: __NR_* come from the uapi headers, but the AArch32 numbers are
 * spelled out in this file next to the struct stat64 layout they belong to, so the table has to
 * come after them or it would reference names that do not exist yet.  Its /proc report and this
 * file's dispatcher both read it, which is what keeps the two from drifting apart. */
```

### `struct kstat_call_state {`

```c
/* The dispatch state for one call.  Passed by pointer into the helpers so a call site never
 * repeats the counter bookkeeping, and typed counters cannot be wired to the wrong line.
 * `compat` is the one thing a helper cannot work out from its counter set: on a 32-bit task the
 * user buffer is a zero-extended u32 and has to go through compat_ptr() first.
 * Defined here - before the helpers, and independent of the whitelist table, which is built
 * further down from the syscall-number constants that live next to the AArch32 struct layouts. */
```

### `static bool susfs_kstat_spoof_statbuf(struct kstat_call_state *st, unsigned long statbuf)`

```c
/* Rewrite the requested fields of the native user statbuf.  Returns true when the buffer was
 * really changed, so the caller can count "matched" from "rewrote". */
```

### `struct sus_kstat_snapshot snap;`

```c
/* Snapshot, not a pointer into the table: a concurrent writer must not be able to retarget the
	 * entry between the match and the copy_to_user below, which must not run under a spinlock. */
```

### `#define STAT64_ST_DEV_OFF`

```c
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
```

### `#define COMPAT_FSTATAT64_NR`

```c
/* ARM EABI syscall numbers that fill struct stat64 (arch/arm64/include/asm/unistd32.h; the
 * statbuf argument position is from fs/stat.c's COMPAT_SYSCALL_DEFINE2/4). */
```

### `#define KSTAT_NR_GETDENTS64`

```c
/* The listing (getdents) numbers sus_path's rewrite answers for.  Spelled out rather than taken
 * from asm/unistd.h, which is unreachable in this build: native getdents64 is 61
 * (include/uapi/asm-generic/unistd.h), and the AArch32 table (arch/arm64/include/asm/unistd32.h)
 * maps 217 to the SAME native body while 141 is its own compat body.  Kept here next to the
 * dispatcher that tests them, in the file that owns the tracepoint. */
```

### `struct kstat_nr_entry {`

```c
/* ---- the whitelist as data ----
 *
 * Defined here, after the numbers above: it is built from the same constants the dispatcher
 * compares against, so a number cannot be handled by one and missing from the other, and /proc's
 * report reads this one list. */
```

### `static struct kstat_nr_entry kstat_nr_table[] = {`

```c
/* The dispatch state (struct kstat_call_state) and the helpers are defined above; the table
 * itself is here because it is built from the numbers below. */
```

### `if (copy_from_user(&ino, (void __user *)(statbuf + STAT64_ST_BROKEN_INO_OFF), sizeof(ino))) {`

```c
/* Key lookup on what the kernel ACTUALLY filled: __st_ino at +12.  stat64 carries the
	 * STAT64_HAS_BROKEN_ST_INO marker (arch/arm64/include/asm/stat.h), so cp_new_stat64() writes
	 * __st_ino and leaves st_ino (+96) alone - reading the key from +96 would compare against
	 * whatever the caller's buffer held and never match.  Both fields are written when spoofing, so
	 * a libc that synthesises st_ino from __st_ino and one that reads st_ino directly both see the
	 * spoofed value. */
```

### `#define STATX_F_INO`

```c
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
```

### `static_assert(offsetof(struct statx, stx_mask) == 0x00, "statx.stx_mask");`

```c
/* A wrong offset here is the whole failure mode: an assert per field, not one for the struct.
 * The numbers were confirmed against the real layout twice - once by these asserts in CI, and once
 * by a host-side copy of the same structs (dist/statx_offs.c, not part of the build), because a
 * wrong offset CORRUPTS the caller's buffer instead of failing anything. */
```

### `static_assert(offsetof(struct statx, stx_dev_major) == 0x88, "statx.stx_dev_major");`

```c
/* stx_dev_major/stx_dev_minor hold MAJOR()/MINOR() of the real dev_t, while the rule stores the
 * userspace new_encode_dev() value the stat buffer shows - so both halves are derived from that
 * encoding (see the write site).  Note they sit at 0x88, before stx_mnt_id, NOT after it: the
 * struct's tail is a sparse area, and an earlier revision of this table had them 8 bytes late. */
```

### `if (copy_from_user(&ino, (void __user *)(sbuf + o->ino), sizeof(ino))) {`

```c
/* The lookup key, taken from what cp_statx() wrote: stx_ino is u64 and stx_dev_major/minor are
	 * two halves of the encoded dev_t the rule stores. */
```

### `if (e->flags & KSTAT_SPOOF_BLKSIZE) {`

```c
/* Unconditional by design - see the mask note above the offset table: no mask bit covers
	 * stx_blksize on this kernel, while cp_statx() always fills it. */
```

### `if ((e->flags & KSTAT_SPOOF_DEV) && (eff & STATX_BASIC_STATS)) {`

```c
/* The device pair: stx_dev_major/minor are always written by cp_statx() and have no mask bit,
	 * so the condition is "the rule spoofs dev" AND "this call fills the basic set at all" - the
	 * second half is what keeps a caller that asked for nothing in particular from getting a
	 * spoofed dev out of a buffer it does not otherwise trust. */
```

### `u16 maj = (u16)((enc & 0xfff00u) >> 8);`

```c
/* e->spoofed_dev is new_encode_dev() (what struct stat shows); split it back into the
		 * major/minor pair this struct carries. */
```

### `if (!rewrote) {`

```c
/* Nothing to raise: vfs_getattr_nosec() sets STATX_BASIC_STATS on this kernel, so the buffer's
	 * mask already names every field written above - and the two fields that are written without a
	 * mask bit (stx_blksize, stx_dev) have no bit to raise.  Re-writing the mask is therefore
	 * deliberately NOT done: a mask write is one more chance to corrupt the caller's buffer for no
	 * gain.  The consequence, stated plainly because it is the sort of thing a reviewer should
	 * check: this rewriter can only ever produce a buffer whose mask is the kernel's own. */
```

### `static void kstat_sys_exit(void *data, struct pt_regs *regs, long ret)`

```c
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
```

### `if (nr == KSTAT_NR_GETDENTS64 || nr == COMPAT_GETDENTS64_NR ||`

```c
/* ---- sus_path's dirent (getdents) rewrite ----
	 *
	 * The listing filter used to be two kretprobes on the getdents wrappers in sus_path.c.  It
	 * rides this tracepoint now: one extra compare per syscall here against a brk trap per
	 * listing there, and no maxactive to silently drop a return under concurrency (see the block
	 * above sus_path_dirent_filter(), which owns the rewrite and its counters).  The numbers are
	 * the ones the probes watched: native getdents64 (61), AArch32 getdents64 (217 - the SAME
	 * native body) and AArch32 getdents (141, its own compat record layout). */
```

### `rc = sus_path_dirent_filter(nr,`

```c
/* getdents64(fd, buf, count) and getdents(fd, buf, count): the buffer is argument 1
		 * in all three cases.  compat_ptr() for a 32-bit task - its pointer is a
		 * zero-extended u32, and that holds for the shared native getdents64 body too. */
```

### `if ((nr >= KSTAT_NR_SCAN_LO && nr <= KSTAT_NR_SCAN_HI) ||`

```c
/* Not a whitelisted number.  Nothing is counted for an ordinary syscall (that is the
		 * whole point of the whitelist), but a number in the stat family's range is worth
		 * knowing about: it means a syscall that fills a user stat buffer reached a return we
		 * did not recognise - a wrong number in the table, or an ABI this build has not met. */
```

### `st.cnt = c;`

```c
/* The helpers take the counter set, not a bare pointer to one of its counters, so a call site
	 * cannot wire a line to the wrong struct. */
```

### `syscall_get_arguments(current, regs, args);`

```c
/* statx(dfd, pathname, flags, mask, statxbuf): the caller's mask is args[3] and the
		 * buffer args[4], and the mask decides which fields may be written - see
		 * susfs_kstat_spoof_statx().
		 *
		 * A 32-bit caller can issue this number too (arm64's compat #293 is NOT what reaches
		 * here - the AArch32 table maps its statx to the native sys_statx), so the buffer
		 * pointer is converted the same way as everywhere else on this path. */
```

### `syscall_get_arguments(current, regs, args);`

```c
/* An AArch32-only number, and the only path that CAN deliver it is a 32-bit task's
		 * syscall, so compat_ptr() is unconditional here: a compat pointer is a zero-extended
		 * u32 and must not be used as an address. */
```

### `syscall_get_arguments(current, regs, args);`

```c
/* stat64/lstat64/fstat64: all three keep statbuf in args[1] and all three fill the same
		 * struct stat64 this helper expects.  AArch32-only numbers, so compat_ptr() is
		 * unconditional: a compat pointer is a zero-extended u32 and must not be used as an
		 * address. */
```

### `susfs_kstat_resolve()`

```c
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
```

### `static int susfs_kstat_fill_from_path(struct sus_kstat_entry *e, const char *path)`

```c
/* resolve <path> and fill the spoofed_* fields with its CURRENT stat (the generic_fillattr
 * mapping).  Fills a DETACHED entry only: callers build here, then commit through one of the
 * kstat_table_* helpers, so nothing half-built is ever visible to a reader. */
```

### `struct timespec64 ctime;`

```c
/* 6.6 renamed the inode field to __i_ctime and marked it private ("use inode_*_ctime
	 * accessors!"), so reading it stopped compiling: "no member named 'i_ctime' in 'struct inode'".
	 * inode_get_ctime() returns the very same struct timespec64 by value; i_atime/i_mtime were NOT
	 * renamed in 6.6, so those two keep being read directly. */
```

### `struct timespec64 atime, mtime;`

```c
/* Same story for atime/mtime, one move later: v6.11 replaced the `struct timespec64
	 * i_atime/i_mtime` fields of struct inode with the split `time64_t i_atime_sec/i_mtime_sec` +
	 * `u32 i_atime_nsec/i_mtime_nsec` (in the trees built here: android16-6.12
	 * include/linux/fs.h:669-674; android15-6.6 still has the old `struct timespec64 i_atime` at
	 * :664), so those two stopped compiling the same way.  inode_get_atime()/inode_get_mtime()
	 * reassemble the very same struct timespec64 by value (fs.h:1616-1622, :1651-1657), which is
	 * what the < 6.12 branch below reads directly.  The gate is on 6.12 rather than on 6.11
	 * because 6.11 is not a GKI kernel: the trees this module is built for are 6.6 (old fields)
	 * and 6.12/6.18 (accessors), and an untested 6.7-6.11 kernel is not something this claims. */
```

### `static int susfs_kstat_update(const char *path, bool full_clone)`

```c
/* re-resolve only target_ino/target_dev; spoofed values stay untouched.  Resolve first (sleeping),
 * then re-target under the lock: a reader sees the old pair or the new pair, never ino-of-B with
 * dev-of-A. */
```

### `static const unsigned int f_flags[12] = {`

```c
/* field index -> flag and setter, ordered as the CLI:
	 * ino dev nlink size atime atime_nsec mtime mtime_nsec
	 * ctime ctime_nsec blocks blksize */
```

### `static int susfs_kstat_add_statically_abi(struct st_susfs_sus_kstat *info)`

```c
/* statically-add from the supercall ABI struct (is_statically=1): copy the caller's 12 spoofed
 * fields + flags verbatim; resolve target ino/dev here. */
```

### `if (!susfs_abi_path_ok(info.target_pathname, sizeof(info.target_pathname))) {`

```c
/* All three commands key on target_pathname, and a caller may fill all 256 bytes of that field -
	 * reject an unterminated one before any strlen() or kern_path() can walk off our stack copy. */
```

### `if (copy_to_user(&((struct st_susfs_sus_kstat __user *)*arg)->err,`

```c
/* Upstream (fs/susfs.c susfs_add_sus_kstat) writes back ONLY the err field for this
	 * input-type command, never the whole struct: copying the full struct back would overrun a
	 * caller whose own struct is smaller/differently laid out (the prebuilt ksu_susfs tool) and
	 * corrupt its stack - match upstream exactly. */
```

### `rc = register_trace_sys_exit(kstat_sys_exit, NULL);`

```c
/* The ONE tracepoint of this module, armed UNCONDITIONALLY, and that is not cosmetic: the
	 * supercall interface (CMD_SUSFS_ADD_SUS_KSTAT) can install rules with no /proc node at all,
	 * so skipping registration when expose_proc=0 silently turned the whole feature into a no-op -
	 * rules accepted, never applied.  expose_proc decides whether the node exists, nothing else.
	 * This registration carries both features that need a syscall return: kstat's stat rewrite and
	 * sus_path's dirent rewrite, which is why the registration is not conditional on either
	 * feature's own rules. */
```

### `if (susfs_control_node_allowed()) {`

```c
/* 0777 is deliberate, not an oversight.  inode_permission() runs the DAC check BEFORE
	 * security_inode_permission(), so a node the app cannot open hands it EACCES - "this exists,
	 * you may not read it" - instead of the ENOENT sus_path is supposed to produce.  0777 lets DAC
	 * pass and leaves the answer to sus_path's LSM layer, which then becomes the ONLY thing
	 * between an app and a world-writable control node - so without that layer the node is not
	 * created at all, see susfs_control_node_allowed(). */
```

### `SUSFS_LOGI("kstat armed: %d rules (sys_exit tp=%d proc=%d); stat rewrite + sus_path dirent rewrite ride that o`

```c
/* Says which mechanism carries what: this line alone answers "is the listing filter armed",
	 * now that no probe of its own exists to report. */
```

### `if (kstat_tp_registered) {`

```c
/* Order matters on unload: this tracepoint calls into sus_path (sus_path_dirent_filter()),
	 * and sus_path_exit() frees that layer's scratch buffer.  The layer table in susfs_main.c
	 * tears down in the reverse of its arming order, so kstat's exit runs AFTER sus_path's -
	 * the tracepoint is therefore removed only once nothing needs it.  tracepoint_synchronize_
	 * unregister() waits out any handler already running, so no call can be in flight past it. */
```

### `seq_printf(m, "maps: armed=%d hits=%d rewrites=%d\n",`

```c
/* "armed" is not "fired": the maps hook has to be readable the same way the other feature
	 * hooks are, or a rewrite that never happens looks identical to one that works. */
```

### `kstat_proc_open()`

```c
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
```

### `seq_printf(m,`

```c
/* Atomic reads, no lock: the printout is a snapshot, and a torn value would
			 * only mean a number read a few calls ago. */
```

### `kstat_proc_open()`

```c
/* sus_path's dirent layer prints its own counters: they belong to that file, and the number
	 * comparisons live here - the two views are next to each other so "which layer ran" is one
	 * read, not two files. */
```

### `if (current_uid().val != 0)`

```c
/* Same gate as kstat_proc_open(): open() alone is not enough - an fd opened by root and
	 * handed on would keep working, which is why the sibling files check both. */
```

### `return err;`

```c
/* Reported to the writer: a command that did not take effect must not look like a
		 * successful full write.  Success still returns len, so callers that expect a complete
		 * write keep working. */
```


## `kernel/susfs_main.c`

### `(file header)`

```c
/*
 * susfs_main.c - SUSFS LKM entry point: the layer table plus this module's control nodes.
 * Loaded via `ksud insmod`, with unexported symbols relocated via kallsyms.
 */
```

### `susfs_self_hide_nodes()`

```c
/* The module's own name lives in susfs.h (SUSFS_LKM_MODULE_NAME / SUSFS_LKM_SYSFS_DIR):
 * /sys/module's directory and the rules that hide it (susfs_hide_syms.c) must agree. */
```

### `bool susfs_expose_proc = true;`

```c
/* The /proc/susfs_* control nodes are created by default and are 0777 on purpose.
 * Measured on device, 0600 plus sus_path hiding does not work: `ls -l /proc/susfs_kstat`
 * -> ENOENT (the inode_getattr hook fired) but `cat` -> Permission denied (it did not), with
 * sus_path's perm counter stuck at 0 - inode_permission() runs the DAC check BEFORE
 * security_inode_permission(), so a 0600 root-owned node fails DAC first, the LSM hook is
 * never reached, and EACCES advertises that the node exists.  General to sus_path's path
 * layer: it can only turn an ENOENT-shaped answer out of files DAC would have ALLOWED.
 * Hence 0777: DAC passes, the LSM layer is the only thing that answers (ENOENT for every
 * non-root caller).
 * The nodes exist only when the layer that hides them is installed
 * (susfs_control_node_allowed()), so an unprotected world-writable node cannot happen, and
 * root-only access is enforced by the handlers' uid checks, not by the mode.  expose_proc=0
 * removes the nodes entirely. */
```

### `SUSFS_PATH_NODE,`

```c
/* sus_path's own interface (the rule listing): it goes through the same table it
     * prints, so a broken rule table is visible in the very view that reports it. */
```

### `susfs_self_hide_nodes()`

```c
/* The module's own sysfs directory is NOT here: it belongs to hide_module
     * (susfs_hide_syms.c), which adds and drops that rule at runtime. */
```

### `static void susfs_self_hide_nodes(void)`

```c
/* Register our control nodes in sus_path's hidden set: probing them must answer ENOENT,
 * not EACCES.  Runs after every feature init (the nodes must exist for kern_path() to
 * resolve them) and after sus_path_init(), so the hooks are already patched. */
```

### `static int layer_lsm_hook_init(void)`

```c
/* ---- layer table: arming order IS the teardown order, reversed --------------
 * A failed load must leave NOTHING armed: when module_init() returns an error the kernel
 * frees this module's memory, so anything still installed - a patched security_hook_heads
 * slot above all - becomes a function pointer into freed memory that the next syscall goes
 * through.  Hence the exits of the already-armed layers run before failing.
 * Teardown runs in the exact reverse of arming, in one place, and the order matters:
 * sus_path's LSM layer is what answers ENOENT for this module's own 0777 control nodes (see
 * the expose_proc note), so unhooking it before the nodes are removed would expose them to
 * every process during the unload - here the nodes go first and the LSM layer last.
 * `fatal` marks the two layers whose absence makes the module useless or silent: sus_path
 * and the supercall hook; the rest log their own failure and degrade to "off".  The exits
 * are idempotent, which lets one path serve rollback and unload alike. */
```

### `static int fail_layer;`

```c
/* Diagnostic: make one layer's init fail, by 1-based index, to exercise the rollback path
 * on the device - a `fatal` layer failing must leave the load with nothing armed. */
```

### `static void susfs_layers_down(int upto)`

```c
/* Not __init/__exit: it is called from both, and an __exit callee in __init code is a
 * modpost section mismatch. */
```

### `susfs_self_hide_nodes();`

```c
/* Registered last and undone implicitly: these are entries in sus_path's table, which
     * sus_path_exit() empties while its LSM layer still answers ENOENT for the nodes. */
```

### `pr_info("loaded. This module is filtered out of /proc/modules for every caller including root, so `lsmod | gre`

```c
/* Operator note.  The module hides its own traces from EVERY caller, root included (a
     * built-in SUSFS has no module entry, so hiding it only from non-root would leave a
     * trace upstream does not have): `lsmod | grep susfs` stays empty and a second `insmod`
     * fails with -EEXIST, which reads like a broken module.
     * THE ONE LINE THAT IGNORES THE LOG SWITCH: everything else follows enable_log
     * (susfs_log.h), but this is the only evidence the module came up and the one thing an
     * operator greps for, so it stays unconditional even for a silent load - otherwise
     * "loaded but logging off" is indistinguishable from "not loaded".  The prefix comes
     * from pr_fmt (susfs_log.h), so the message must not repeat it. */
```

### `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)`

```c
/* The VFS symbol namespace of this kernel's GKI builds.
 * kern_path, ihold (fs/) and override_creds/revert_creds (kernel/cred.c) are exported as
 * EXPORT_SYMBOL_NS(sym, ANDROID_GKI_VFS_EXPORT_ONLY); the Android build maps that name to
 * the long string below with a per-directory ccflag before the compiler stringifies it
 * (fs/Makefile subdir-ccflags-y, plus kernel/Makefile for cred.o on some releases).  A
 * module that does not import the RESULTING string is refused with "module uses symbol
 * (kern_path) from namespace VFS_internal_... but does not import it" -> "Unknown symbol
 * kern_path (err -22)" - why plain insmod failed on the phone before this line existed.
 * 6.13 changed the SPELLING ("module: convert symbol namespace to string literal"):
 *   <= 6.12  #define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, __stringify(ns))
 *   >= 6.13  #define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, ns)
 * so a BARE identifier is required before that and a QUOTED string after - MODULE_IMPORT_NS
 * stringifies its argument up to 6.12, which is also why the long form here has to be
 * literal (measured: passing the macro name left the built .ko's .modinfo with no import_ns
 * entry at all).  Wrong is silent one way (<= 6.12 stringifies the quotes too, importing a
 * namespace no kernel creates) and a hard error the other (>= 6.13 rejects a bare
 * identifier: 'expected ; after top level declarator', measured on android17-6.18).  Both
 * spellings emit the same .modinfo entry, checked per variant by the CI step that fails a
 * .ko with no import_ns entry.
 * Necessary but NOT sufficient for plain insmod: nine further symbols are not in the export
 * table in any of the six GKI variants (kallsyms_lookup_name and friends, saved_boot_config,
 * task_work_add, init_mm, __set_fixmap, copy_to_kernel_nofault, dcache_clean_inval_poc), so
 * tools/susfs_insmod.c rewrites undefined symbols to absolute addresses, as ksud does. */
```


## `kernel/susfs_open_redirect.c`

### `(file header)`

```c
/*
 * susfs_open_redirect.c - redirect open of a target path to another path (SUSFS OPEN_REDIRECT feature), LKM port.
 * Hook: path_openat / do_sys_openat2 / do_filp_open are LTO-inlined into the syscall entry, so none can be kprobed; the
 * only out-of-line symbol on the user-open path is vfs_open(path, file) (measured: 123/123 hits for `cat`).  vfs_open is
 * the inode layer - d_inode is resolved - so rules match by (target_ino, target_dev) exactly like upstream.
 * Interrupt context: handlers must not sleep, so both paths are kern_path()'d at RULE-ADD time (proc write or
 * supercall, process context) and cached in the entry; a handler only matches (ino, dev) and swaps the pointer.  No
 * kretprobe needed - the cached references pin the files for the entry's lifetime, as upstream's re-walk does.
 * uid_scheme: enum UID_SCHEME (susfs.h:28-34), all five values with upstream's predicates (susfs.c:941-964); two of
 * the five need state an LKM cannot read - see or_uid_matches() / or_in_su_domain().
 * Reverse disguise: upstream registers TWO hash entries per rule (susfs.c:844-863), the second with
 * reversed_lookup_only = true and the two pathnames swapped, and every "where did this file come from" reporter answers
 * from it - vfs_readlink() patch:510-548, do_proc_readlink() (/proc/<pid>/fd/N, exe, cwd, root) patch:1062-1083, fdinfo
 * seq_show() (mnt_id + ino) patch:1145-1217, show_map_vma() (maps dev:ino + name) patch:1257-1288, vfs_statfs()
 * (statfs/fstatfs) patch:2038-2056.  Gate: SUSFS_IS_INODE_OPEN_REDIRECT (susfs_def.h:148-151) = inode flag *and*
 * susfs_is_current_proc_umounted_app(), never the rule's uid_scheme - so even a scheme-0 rule is disguised for app
 * processes (or_reverse_visible() keeps that gate with uid >= 10000).
 * Reachability: none of those five is reachable from an LKM here (the first two and seq_show() are static; the
 * maps/fdinfo numbers are locals a kprobe cannot see).  Covered instead: point the caller at the *target's* path
 * (d_path(), vfs_statfs()), and where no shared helper exists rewrite the line the function already formatted, from a
 * kretprobe on its return - show_map_vma()'s line carries "maj:min ino" AND the name, both from the redirected file,
 * and the name cannot be reached that way (seq_file_path() -> seq_path() -> __d_path() is LTO-inlined: a probe on it
 * registers and never fires - measured).
 * Never silent: registration outcome and hit counts are logged and shown by /proc/susfs_open_redirect, because
 * registering only proves the symbol exists - this feature has hit that wall twice (show_vma_header_prefix, then
 * __d_path: both registered, both stayed at 0).
 *
 * /proc/susfs_open_redirect: add_open_redirect <target> <redirected> <uid_scheme> | del <target> | clear
 */
```

### `#define OR_PATH_MAX`

```c
/* The ABI fields are char[256]; matching that width stops a legal long path from being truncated into a rule for a
 * different path. */
```

### `#define FUSE_SUPER_MAGIC`

```c
/* FUSE is the one filesystem upstream refuses outright (susfs.c:824-829): the daemon resolves the name itself, so a
 * kernel-side swap does nothing or makes the request happen twice.  susfs_def.h:49-51 carries the constant for the same
 * reason: neither <linux/magic.h> (absent from this tree) nor <uapi/linux/magic.h> defines it; fs/fuse/fuse_i.h does. */
```

### `#define OR_APP_UID_MIN`

```c
/* Upstream's app threshold: susfs_is_current_proc_umounted_app() is (TIF_PROC_UMOUNTED && current_uid().val >= 10000)
 * (susfs_def.h:122-125); the uid half is the part this kernel can answer. */
```

### `static char or_su_ctx[128] = "u:r:ksu:s0";`

```c
/* SELinux context of the su/ksu domain, resolved to a sid at init.  Upstream gets the sid from KernelSU itself
 * (susfs_set_sid(KERNEL_SU_CONTEXT, &susfs_ksu_sid), 10_enable_susfs_for_ksu.patch:2496); an LKM has to resolve the
 * string.  "u:r:ksu:s0" is the SukiSU variant this device runs (KERNEL_SU_DOMAIN "ksu"), stock KernelSU uses
 * "u:r:su:s0" - override with susfs_guard_lkm.or_su_ctx.  Kept separate from sus_mount's su_ctx and avc_spoof's
 * avc_su_ctx: parameters are per name, and defaulting to the wrong domain must not change other features' gating. */
```

### `static void (*or_cred_getsecid)(const struct cred *cred, u32 *secid);`

```c
/* security_cred_getsecid() is an EXPORT_SYMBOL, but GKI's module symbol list is not guaranteed to
 * carry it, so it is resolved in kallsyms like sus_mount.c does.  The wrapper needs __nocfi: kCFI
 * validates the type hash at a call through a function pointer. */
```

### `unsigned long target_mnt_id;`

```c
/* Reverse direction, second number: fdinfo also prints mnt_id, and for the redirected file that is the mount the
	 * redirection really opened - which can differ from the target's (e.g. /system/etc/hosts vs
	 * /data/local/tmp/hosts).  Cached at add time: the reporter has only numbers to work with. */
```

### `bool dead;`

```c
/* Set while the slot is being rewritten or has been deleted.  The reader checks this with
	 * READ_ONCE and the writer clears it LAST, so false means the rest of the entry is complete. */
```

### `static atomic_t or_rev_dpath_hits = ATOMIC_INIT(0);`

```c
/* Reverse-disguise bookkeeping.  The counters are the only way to tell a hook that never fires from one that fires and
 * matches nothing: a kprobe registers against a symbol's out-of-line copy, which GKI's full LTO may leave with no live
 * call sites (AUDIT_FINDINGS.md: five probes registered, zero hits). */
```

### `static void or_resolve_su_sid(void)`

```c
/* Cached paths are per-entry, released once at unload (file-level note on the rule array).  The handlers run in interrupt
 * context with no lock and hand &e->redirected_path / &e->target_path straight to vfs_open()/d_path()/vfs_statfs(), which
 * read or path_get() it, so freeing an old path on replace/delete raced a concurrent open into a use-after-free (upstream
 * avoids that with SRCU plus a re-walk).  A "retired paths" side list was tried and removed: it duplicated the struct
 * path - one reference, two owners - so unload released it twice and the device died on rmmod.  A deleted rule keeps its
 * paths: dead entries are never reused, stay out of every lookup, and exit releases them. */
```

### `static __nocfi bool or_in_su_domain(void)`

```c
/* Upstream susfs_is_current_ksu_domain() = (current_sid() == susfs_ksu_sid) (10_enable_susfs_for_ksu.patch:2484-2486);
 * current_sid() lives in SELinux's private objsec.h, so the LSM-agnostic security_cred_getsecid() is used instead. */
```

### `if (!or_cred_getsecid || !or_su_sid)`

```c
/* Unresolved symbol or unresolvable context: "not su" would be a guess, and for schemes 1/2 that guess redirects
	 * the very process the rule exists to spare.  or_add() refuses those schemes instead. */
```

### `static bool or_reverse_visible(void)`

```c
/* Upstream's reverse-disguise gate, verbatim in shape: SUSFS_IS_INODE_OPEN_REDIRECT (susfs_def.h:148-151) = flag bit AND
 * susfs_is_current_proc_umounted_app().  TIF_PROC_UMOUNTED is never set on this kernel (no SUSFS integration in it, and
 * nothing calls ksu_handle_setresuid - AUDIT_FINDINGS.md), so uid >= 10000 is the proxy, as in sus_path / sus_kstat. */
```

### `return current_uid().val >= OR_APP_UID_MIN;`

```c
/* Upstream: test_thread_flag(TIF_PROC_UMOUNTED) [&& uid >= 10000 for the _APP variant] (susfs_def.h:98-125).  This
		 * kernel never sets that flag, so uid >= 10000 stands in - schemes 3 and 4 degenerate into the same predicate
		 * here, a strictly narrower gate than scheme 2, and the substitute sus_path / sus_kstat also use. */
```

### `if (READ_ONCE(or_entries[i].dead))`

```c
/* dead is cleared LAST by the writer, so skipping dead entries also skips any entry whose
		 * fields are still being written. */
```

### `bool susfs_open_redirect_spoof_ids(unsigned long ino, unsigned long *out_ino,`

```c
/* Reverse direction for the one caller that has only numbers: /proc/<pid>/fdinfo/N prints "mnt_id:\t<i>" and "ino:\t<j>"
 * for the file an fd points at and no device, so this lookup is by ino alone; two rules sharing that ino refuses to
 * answer (a missed disguise beats disguising an unrelated file).  On success: the target's ino and mount id (0 unknown). */
```

### `static bool or_is_redirected_path(const char *target)`

```c
/* Is `target` another rule's redirected path?  Upstream refuses to touch such a name (susfs.c:867-881): that name
 * belongs to the reverse entry of an existing rule, and replacing it would silently break that rule's disguise. */
```

### `static int or_vfs_open_pre(struct kprobe *kp, struct pt_regs *regs)`

```c
/* ---- forward: vfs_open(path, file) - swap the path on match ----
 * Runs in interrupt context: no sleeping, no kern_path here.  Upstream leaves the lookup loop entirely when the inode
 * matches but the scheme does not (goto out_srcu_read_unlock, susfs.c:945/949/953/957/961), so there a non-matching
 * entry also suppresses the remaining same-inode entries; here the first live (ino, dev) match is the only candidate -
 * the same outcome for distinct inodes, while rules sharing one inode (hard links) differ only in which entry wins
 * (upstream: newest hash_add_rcu first, here: slot order). */
```

### `if (IS_ERR_OR_NULL(path) || !path->dentry)`

```c
/* IS_ERR_OR_NULL on the same principle as the sus_path name handlers: a kprobe runs before the
	 * callee, so a caller that leaves argument checking to it hands us an error pointer. */
```

### `static bool or_dpath_swap(struct pt_regs *regs)`

```c
/* ---- reverse: d_path(path, buf, buflen) ----
 * Covers readlink("/proc/<pid>/fd/N"): proc_pid_readlink() -> do_proc_readlink() -> d_path(&path, tmp, PAGE_SIZE)
 * (fs/proc/base.c, upstream: patch:1062-1083).  Divergence: upstream replays the literal string given at add time, while
 * d_path() renders the canonical name of the cached target path in the *reader's* namespace - a rule registered through a
 * symlink (or another mount namespace) can read back differently.
 * The /proc/<pid>/maps NAME column is NOT here: show_map_vma() prints it with seq_file_path() -> seq_path(), which calls
 * __d_path() directly, never d_path() (fs/seq_file.c); a probe on __d_path registers cleanly and never fires here (full
 * LTO inlines the primitive; measured dpath_seq=0 while the maps line still named the redirected file), so the name is
 * rewritten out of the already-printed line - see or_maps_ret(). */
```

### `static int or_vfs_statfs_pre(struct kprobe *kp, struct pt_regs *regs)`

```c
/* ---- reverse: vfs_statfs(path, buf) ----
 * Upstream answers statfs()/fstatfs() of the redirected file with the target's kstatfs snapshot (susfs.c:1029-1046, taken
 * with vfs_statfs() at add time, susfs.c:851); swapping in the cached target path computes the same from the live target. */
```

### `static atomic_t or_rev_maps_hits = ATOMIC_INIT(0);`

```c
/* ---- reverse face 3: the dev:ino columns of /proc/<pid>/maps (and smaps) ----
 * The first attempt put this on show_vma_header_prefix() - args 6 and 7 of that call ARE the two columns - and it
 * registered and never fired once (measured: the vma_hdr counter stayed 0 over every run; clang's full LTO leaves no
 * out-of-line copy).  So the already-formatted line is rewritten instead: its two numbers come from vma->vm_file, i.e.
 * from the REDIRECTED inode, and replacing the "<maj>:<min> <ino>" run with the target's keeps the line consistent with
 * the name face 1 (d_path) already disguises - without it a detector reads the target's name next to the redirected
 * file's device, which no file on this system can produce.  The run is rendered as fs/proc/task_mmu.c does it
 * (seq_put_hex_ll for major/minor: lowercase, min width 2; seq_put_decimal_ull for the ino), both surrounding spaces
 * included, so pgoff and name stay safe. */
```

### `static bool or_buf_replace(struct seq_file *m, const char *old, size_t old_len,`

```c
/* Replace the first occurrence of old[0..old_len) in the seq_file buffer with new[0..new_len); growing is allowed as
 * long as the buffer has room, and without room the line is left alone rather than truncated. */
```

### `while (new_len < old_len && new_len < (int)sizeof(new) - 1)`

```c
/* Keep the column width: the kernel padded the name out to a fixed column, so a shorter run would pull the name
	 * left - a line that does not line up with its neighbours is visible on its own. */
```

### `if (e->redirected_pathname[0] && e->target_pathname[0]) {`

```c
/* The name column as well: show_map_vma() prints it via seq_file_path()/seq_path()/__d_path(), and (see the d_path
	 * block above) a probe on that primitive never fires here - so the rendered name is matched as the REGISTERED
	 * redirected path, and a rule through a symlink or another mount namespace misses instead of mislabelling a file. */
```

### `static atomic_t or_rev_fdinfo_hits = ATOMIC_INIT(0);`

```c
/* ---- reverse face 4: /proc/<pid>/fdinfo/N ----
 * fdinfo prints "ino:\t<i>" for the file an fd points at - for a rule, the REDIRECTED one - so a detector holding an fd
 * on the target is handed the inode of the file the redirection really opened.  Upstream rewrites it in the same function
 * it rewrites mnt_id in (susfs_open_redirect_spoof_seq_show, patch:1171-1200).
 * It belongs to THIS feature, not to sus_mount's: it has to fire as soon as one rule exists, whether or not the
 * mount-hiding switch is on.  Measured with the first version (a sus_mount seq_show kretprobe, registered only when that
 * feature is enabled): with a rule present and hide off, fdinfo kept naming the redirected inode and the probe had
 * entry=0.  fdinfo has no device column, so the lookup is by ino alone and refuses when two rules share a redirected ino;
 * state is per-instance (ri->data) because seq_show() may sleep in seq_printf() and the task can migrate CPUs. */
```

### `static bool or_fdinfo_find_dec(struct seq_file *m, const char *label, size_t label_len,`

```c
/* Find `label` in the already formatted buffer and parse the decimal that follows it; false when
 * the label is absent or has no digits. */
```

### `static bool or_fdinfo_write_dec(struct seq_file *m, size_t pos, size_t len,`

```c
/* Write new_val over the len digits at pos, growing or shrinking as needed.  The replacement can be LONGER (measured:
 * 926498 -> 10166500 was refused by an earlier shrink-only version, so the hook reported hits with zero rewrites);
 * growing needs room in the seq_file buffer, and without room the line is left alone rather than truncated. */
```

### `if (or_fdinfo_find_dec(m, "ino:\t", 5, &pos, &len, &old) &&`

```c
/* The ino is the rule's key and the same rule knows the target's mount id, so one lookup answers both lines.  ino
	 * first: it sits after mnt_id in the line, so shrinking or growing it cannot move that one. */
```

### `if (new_mnt && or_fdinfo_find_dec(m, "mnt_id:\t", 8, &pos, &len, &old) &&`

```c
/* mnt_id, when a rule matched.  sus_mount rewrites this same label from ITS table and both probes are on the same
	 * function, so for an fd that is both "inside a hidden mount" and "the redirected file" the two return handlers race
	 * for which id wins - cosmetic (both are ids the caller could have been shown), and invisible in either module alone. */
```

### `static int or_register(void)`

```c
/* The forward hook is the feature: a rule that cannot fire is worse than no rule, so its
 * registration failure is reported to the caller. */
```

### `static void or_register_reverse(void)`

```c
/* Reverse-disguise hooks: best effort.  The forward redirect is already live and each of these only closes one report
 * path, so a failure must not reject the rule - but never silent either: registering proves the symbol exists, not that
 * the kernel's call sites reach it (GKI's full LTO inlines across translation units), hence the hit counters read back
 * from /proc/susfs_open_redirect.  Called from the rule-management paths (process context, may sleep). */
```

### `if (susfs_control_node_allowed()) {`

```c
/* Only the /proc node is optional.  The vfs_open hook is registered by or_add() - i.e. by the supercall as well - so
	 * this gate must never return early and skip other work.  0777 so DAC passes and sus_path's LSM layer answers ENOENT;
	 * without that layer the node would be world-writable, so it is not created at all (see susfs_kstat_init()). */
```

### `for (i = 0; i < nor; i++) {`

```c
/* Nothing can reach these any more: the kprobes are already gone.  Every entry is released exactly once here - dead
	 * ones included, which is what makes "a deleted rule keeps its paths" safe. */
```

### `seq_printf(m, "hooks: open=%d dpath=%d statfs=%d maps=%d fdinfo=%d | rev hits: dpath=%d statfs=%d maps=%d/%d/%`

```c
/* "registered" is not "reached": a hook whose counter stays 0 across a real read means GKI inlined its call sites
	 * and that surface is NOT disguised - hence the counters below (fdinfo's surface and provenance are in the face-4
	 * block above).  mnt_id is NOT rewritten here: that id belongs to sus_mount's table. */
```

### `if (current_uid().val != 0)`

```c
/* 0777 is deliberate (the ENOENT contract comes from sus_path's hidden set, not from the mode), so refuse non-root
	 * callers here too - see the note in susfs_enable_log.c's log_proc_open(). */
```

### `if (!susfs_abi_path_ok(target, OR_PATH_MAX) ||`

```c
/* Both come from char[256] ABI fields (supercall) or a NUL-terminated command buffer (proc write); reject the
	 * unterminated case instead of letting strcmp()/kern_path() read past the struct or truncate a path into a rule. */
```

### `if (tp.dentry->d_sb->s_magic == FUSE_SUPER_MAGIC ||`

```c
/* upstream susfs.c:824-829 - FUSE is refused outright, on either side, and rejecting is the whole handling: no
	 * silent rewrite, no partial rule.  (d_sb is the dentry's superblock: what upstream reads through inode->i_sb.) */
```

### `if (scheme == UID_ROOT_PROC_EXCEPT_SU_PROC ||`

```c
/* Schemes 1 and 2 are decisions about the KernelSU su domain.  Upstream always has that sid (KernelSU hands it
	 * over at setuid-hook setup), an LKM resolves the context itself - and if it does not resolve, "not in su domain"
	 * is true for the su process too, i.e. the one process the rule exists to spare would be redirected.  Refuse. */
```

### `rc = or_register();`

```c
/* Register the hooks BEFORE touching any entry: a rule that is listed but cannot fire (hook missing) silently does
	 * nothing while looking configured - worse than no rule at all. */
```

### `e = or_find_by_path(target);`

```c
/* upstream susfs.c:867-881: a name that another rule already uses as its redirected path belongs to that rule's
	 * reverse entry and must not be taken over. */
```

### `WRITE_ONCE(e->dead, true);`

```c
/* Rewriting a rule: mark the old entry dead and leave its paths alone - they stay for the module's life and
		 * unload releases each entry exactly once.  or_del() says why those fields must not be cleared while a reader
		 * may hold them; the entry-array note above covers the retired-list double-free measured on rmmod. */
```

### `if (nor >= SUS_OR_MAX) {`

```c
/* A retired slot is never reused either: reuse would overwrite path fields a reader may still hold and discard the
	 * reference the dead entry owns.  Rules are configuration, so the array growing is fine. */
```

### `static void or_del(const char *target)`

```c
/* Only the rules whose target path matches are dropped; the reverse entry is not
 * a separate object here, so it goes with the rule by definition. */
```

### `WRITE_ONCE(e->dead, true);`

```c
/* Dead, and that is all.  A reader that has already passed its `dead` check still holds a pointer to these fields and
	 * hands them to vfs_open()/d_path()/vfs_statfs(), which dereference path->dentry at once (fs/open.c:1033,
	 * fs/d_path.c:282, fs/statfs.c:90) - clearing them is a NULL-dereference oops any app can reach, since the control
	 * node is 0777 (or_uid_matches() is consulted later, in the probe).  So they stay, pinned until unload. */
```

### `static ssize_t or_proc_write(struct file *file, const char __user *buf,`

```c
/* Slots are never compacted (that array move was itself part of the race).  The kprobes stay registered for the whole
 * module lifetime: unregistering and re-registering them was observed to leave the hook silently gone after a burst of
 * add/del cycles, while an empty rule table already makes the lookups miss - so staying registered costs nothing. */
```


## `kernel/susfs_supercall.c`

### `(file header)`

```c
/*
 * susfs_supercall.c - SUSFS supercall dispatcher (reboot(2) ABI).
 *
 * ksu_susfs (and SukiSU ksud) call syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd_id,
 * &payload) and the handler writes payload.err back.  Upstream SUSFS patches
 * kernel/reboot.c SYSCALL_DEFINE4 to branch into ksu_handle_sys_reboot(); an LKM cannot
 * patch that, so we kprobe __arm64_sys_reboot and match the magics ourselves.
 *  - arm64 syscall-wrapper quirk: the kprobe sees regs->regs[0] == struct pt_regs * (the
 *    wrapper's __regs argument); the real user args are in real_regs->regs[0..3] - SukiSU's
 *    PT_REAL_REGS() / arch.h.
 *  - a pre_handler runs in interrupt context and must not copy_from_user, so the command is
 *    deferred to task_work (TWA_RESUME), i.e. process context - the same trick SukiSU uses.
 * The handlers keep upstream's signature `void xxx(void __user **arg)`, *arg pointing at
 * the userspace payload struct.
 */
```

### `struct feature_entry {`

```c
/* List every feature this LKM implements, using upstream CONFIG macro names.  Entries with
 * an `active` callback are reported only while the feature is really installed:
 * advertising a feature whose registration failed is the exact inconsistency a detector
 * probes for, so failing ones are omitted (and logged by their init). */
```

### `susfs_show_enabled_features()`

```c
/* Not an upstream config: a built-in SUSFS has no module entry to hide, so this
	 * port-only feature is named accordingly (see hide_modules in susfs_hide_syms.c). */
```

### `static struct st_susfs_enabled_features susfs_enabled_features_nomem;`

```c
/* The -ENOMEM answer for CMD_SUSFS_SHOW_ENABLED_FEATURES is the whole ABI struct (8192-byte
 * string + err), copied in one piece.  As a local it broke the 6.1/6.6 builds: "stack frame
 * size (8320) exceeds limit (2048) in 'susfs_tw_func' [-Wframe-larger-than]", an error
 * there.  As a static it is harmless - BSS-zeroed, err = -ENOMEM, same for every caller. */
```

### `susfs_enabled_features_nomem.err = -ENOMEM;`

```c
/* Answering nothing would leave the caller unable to tell "no memory" from
		 * "the kernel said nothing": report it in the ABI's err field. */
```

### `pr_warn("susfs_guard_lkm: supercall: unsupported cmd 0x%x reached the worker (susfs_cmd_handled() and the swit`

```c
/* Unreachable: reboot_pre() only defers a command susfs_cmd_handled()
		 * accepted.  Kept as a net in case the two lists drift apart. */
```

### `static bool susfs_cmd_handled(unsigned int cmd)`

```c
/* Commands susfs_tw_func() above actually dispatches - keep the two in sync.
 *
 * The kprobe consults this BEFORE swallowing the syscall: upstream answers an unrecognised
 * command with `return -EINVAL` from ksu_handle_sys_reboot()
 * (KernelSU/10_enable_susfs_for_ksu.patch:2925-2926), and reboot.c's `if (ret) goto
 * orig_flow;` falls through to the real reboot path, whose magic check rejects
 * 0xDEADBEEF/0xFAFAFAFA with -EINVAL.  Upstream writes NOTHING to payload.err then, and 126
 * (ERR_CMD_NOT_SUPPORTED) is a USERSPACE sentinel the ksu_susfs C tool pre-seeds and reads
 * back as "the kernel never handled this command" (ksu_susfs/jni/features/sus_map.c:51-53,
 * ksu_susfs/jni/includes/susfs_defs.h:16-18).  So an unknown command must NOT be hijacked:
 * leave the regs and err alone, while every command listed here still short-circuits to 0. */
```

### `if (!real_regs)`

```c
/* A prober runs before the callee, so an argument the callee would have checked is
	 * still raw here (see the filename_lookup lesson in sus_path.c). */
```

### `if (!susfs_cmd_handled(cmd)) {`

```c
/* Not ours to answer: leave the syscall alone so reboot(2) reports the -EINVAL
	 * upstream reports and payload.err keeps the caller's value. */
```

### `regs->pc = regs->regs[30];`

```c
/* Upstream's reboot.c patch makes a handled supercall return 0 instead of falling
	 * through to the real reboot path:
	 *     if (ret) goto orig_flow;
	 *     return ret;
	 * We cannot patch reboot.c, so mirror it from the kprobe: skip the rest of
	 * __arm64_sys_reboot and return 0 - with these magic values reboot would otherwise
	 * return -EINVAL, and the prebuilt ksu_susfs tool checks the syscall result.  The
	 * command itself still runs from task_work before we return to userspace. */
```

### `static void __init susfs_abi_layout_check(void)`

```c
/* ---- ABI layout assertions ----
 * These sizes and `err` offsets ARE the userspace contract (ksu_susfs, ksud and
 * tools/susfs_sc compile against these numbers); a drift shows up as "the command returned
 * 0 and userspace printed garbage", not as a build error, and the repository's own
 * abi_layout_check/ harness is not wired into any build step - hence the trip wire here.
 * Values are aarch64 LP64, the only ABI shipped clients use, and match upstream's structs
 * (kernel_patches/include/linux/susfs.h). */
```


## `kernel/susfs_uname.c`

### `(file header)`

```c
/*
 * susfs_uname.c - spoof uname release/version (SUSFS SPOOF_UNAME).  Upstream patches the body of
 * SYSCALL_DEFINE1(newuname) between the memcpy(utsname) and copy_to_user; the LKM equivalent hooks
 * __arm64_sys_newuname with a kretprobe and rewrites the release/version fields of the user buffer just before
 * the syscall returns - the target pages were just faulted in by the original copy_to_user, so the handler's
 * copy_to_user cannot fault, and "default" copies the device's CURRENT utsname()->release/version at runtime.
 * Upstream semantics: OFF by default, enabled by CMD_SUSFS_SET_UNAME alone, kretprobe registered lazily.
 */
```

### `if (!user)`

```c
/* this GKI kernel does NOT auto-adjust syscall-wrapper probe regs:
     * regs->regs[0] is the struct pt_regs* argument, not the user arg */
```


## `kernel/symbol_resolver.c`

### `(file header)`

```c
/*
 * symbol_resolver.c - kernel symbol lookup (ported from KernelSU/SukiSU
 * infra/symbol_resolver.c).
 *
 * No kallsyms_* entry point is an ELF import: on a 6.1 device with KernelSU as a module,
 * kallsyms_lookup_name/lookup/lookup_size_offset/on_each_symbol/on_each_match_symbol all
 * come from kernelsu.ko, so an extern reference to any of them silently makes this module
 * depend on KernelSU.  They are bootstrapped at runtime instead - register_kprobe()
 * resolves a NAME through the kernel's own kallsyms, never the export table - and the
 * "Verify sections" build step fails if any of the five names returns to the .ko's
 * undefined list.
 * GKI does not export kallsyms_lookup_name, so resolution walks kallsyms via
 * kallsyms_on_each_symbol; under LLVM CFI (< 6.1) a function-table slot holds the
 * ".cfi_jt" variant, which ksu_resolve_symbol_for_functable_hook() prefers.
 */
```

### `#define HAVE_ON_EACH_MATCH_SYMBOL`

```c
/* kallsyms_on_each_match_symbol() is NOT in 6.1 (measured against upstream: absent in v6.1,
 * present from v6.5, so 6.6/6.12/6.18 have it).  Gating at 6.1 only bought a spurious
 * "cannot bootstrap" warning on the android14-6.1 variant and then fell back to the
 * kallsyms_lookup_name() path that every other build uses anyway. */
```

### `static unsigned long (*kallsyms_lookup_name_fn)(const char *name) = NULL;`

```c
/* ---- the four entry points, all runtime-bootstrapped: NULL until
 * ksu_init_symbol_resolver(), each called through a __nocfi function because CFI checks
 * indirect call sites - a wrong type panics there on a kCFI kernel (6.1+). */
```

### `int()`

```c
/* The walker lost its `struct module *` argument in 6.6, so the POINTER's type is
 * version-gated like the callbacks below (that argument carried module ownership). */
```

### `static __nocfi void *ksu_bootstrap_symbol(const char *name)`

```c
/* Resolve a symbol NAME at runtime: register_kprobe() looks it up in the kernel's own
 * kallsyms and never touches the export table - which is why nothing here imports a
 * kallsyms_* symbol.  __nocfi because the address is stored in a function pointer and
 * called indirectly, which CFI checks; NULL is a degradation, never a load failure. */
```

### `struct ksu_exact_name_ctx {`

```c
/* Exact-name lookup through the walker - reachable only when kallsyms_lookup() did not
 * bootstrap; before 6.6 it is also the module-ownership check (see ksu_exact_name_cb()). */
```

### `if (unlikely(!kallsyms_lookup_name_fn))`

```c
/* Graceful degradation, decided here: with no bootstrapped kallsyms_lookup_name there
     * is no name lookup at all, so features needing one stay off; the module still loads. */
```

### `char *module_name = NULL;`

```c
/* PATH IN USE on every kernel this module builds against: name -> address through
         * the bootstrapped kallsyms_lookup_name(), ownership check through the bootstrapped
         * kallsyms_lookup() - a non-NULL modname means another module owns it, refused. */
```

### `if (kallsyms_on_each_symbol_fn) {`

```c
/* kallsyms_lookup() is unavailable, so the owner has to come from the walker: before
     * 6.6 its callback is handed the owning `struct module *` and ksu_exact_name_cb()
     * refuses a non-NULL mod.  The walk must also confirm the address, or we would be
     * trusting a symbol we could not check. */
```

### `pr_warn("ignore symbol %s: its owner cannot be checked on this kernel\n", symbol_name);`

```c
/* Neither kallsyms_lookup() nor the walker bootstrapped, and from 6.6 the walker does
     * not carry the owner either: fail closed rather than take a symbol whose owner cannot
     * be verified. */
```

### `int __nocfi ksu_find_symbol_all(const char *name, unsigned long *addrs, int max)`

```c
/* Collect EVERY vmlinux symbol with this exact name, not just the first one.
 *
 * find_kernel_symbol_exact() returns one address, which is all most callers need; but a
 * name is not always unique in kallsyms, and register_kprobe(.symbol_name=...) takes
 * whichever match kallsyms lists first - measured: `seq_show` is one symbol on 5.10/5.15
 * and FOUR on android14-6.1 / android15-6.6 / android16-6.12 / android17-6.18 (fs/proc/fd.c's
 * is only one of them).  A caller that must hook a specific function therefore has to hook
 * all of them and decide at run time; this is the enumeration it needs.
 *
 * Module-owned symbols are dropped (they are not the kernel's function of that name), which
 * is the same ownership rule find_kernel_symbol_exact() applies.  Returns the number of
 * addresses written (0 = unknown/not found); the walker paths are bounded by @max.  __nocfi
 * because it calls the walker through a function pointer, like every other resolved-address
 * call in this file: without it the compiler instruments the call, and under LLVM CFI
 * (< 6.1) the check runs against the kernel's type hash and panics on the first call -
 * measured on a 5.15 device: "Kernel panic - not syncing: CFI failure (target:
 * kallsyms_on_each_symbol+0x0/0x1e4)" with this function inlined into
 * susfs_sus_mount_supercall (the fdinfo arm is on the mount-enable path). */
```

### `unsigned long one = find_kernel_symbol_exact(name);`

```c
/* No walker (pre-5.19) or no match: the single-address lookup is the fallback, and
         * on the kernels where a name is ambiguous the walker exists. */
```

### `int ksu_symbol_name_of(unsigned long addr, char *buf, char **module_out)`

```c
/* The NAME of the function at @addr, through the same bootstrapped kallsyms_lookup() the
 * export check above uses.  The static-call takeover in lsm_hook.c holds the address the
 * kernel registered for SELinux's slot and must confirm it is the implementation of the
 * hook it takes over; comparing against a name-resolved symbol would be weaker, because
 * with LTO the registered function can be a clone (".constprop.0").
 * Returns the length written into @buf (KSYM_SYMBOL_LEN bytes), -ENOSYS when
 * kallsyms_lookup() is unavailable, -ENOENT when the address cannot be named.  @module_out
 * gets the owning module's name or NULL for a vmlinux symbol (refused by the caller). */
```


## `kernel/lsm_hook.h`

### `bool insert;`

```c
/* true = get in front of every registered LSM instead of overwriting the slot of an entry resolved
     * by symbol name (see lsm_hook.c).  WHAT that means depends on the kernel:
     *   < 6.12   our own struct security_hook_list goes at the HEAD of the hook's hlist, so it runs
     *            before every registered LSM (SELinux included) and can only ADD a denial (-ENOENT):
     *            it must NOT call any original and must return 0 on the pass-through path
     *            (target_name/original stay unused).
     *   >= 6.12  there is no list to insert into (dispatch is a static call per hook and LSM slot), so
     *            SELinux's own slot is taken over and the function displaced from it IS called on the
     *            pass-through path (hook->original via SUS_LSM_PASS_ORIG()): a plain `return 0` there
     *            would not continue any chain, it would silently drop SELinux for that hook. */
```

### `#define KSU_LSM_HOOK_INSERT`

```c
/* Insert-shaped initialiser: no symbol is resolved by name (nothing to find), so there is no target_name and `original`
 * starts NULL.  head_offset is cross-checked against the live kernel before anything is patched (see
 * ksu_lsm_hook_head_at() in lsm_hook.c): on < 6.12 the list head of struct security_hook_heads, on >= 6.12 the offset of
 * this hook's struct lsm_static_call ARRAY in struct lsm_static_calls_table - members generated by LSM_HOOK(), so
 * offsetof() resolves, but the table is __randomize_layout, hence validation against the live table. */
```

### `int ksu_lsm_hook(struct ksu_lsm_hook *hook);`

```c
/* Runtime patching of existing LSM hook slots (workaround for out-of-tree modules; the normal
 * path is security_add_hooks()), made coherent by text patching + RCU synchronization. */
```


## `kernel/susfs.h`

### `static inline bool susfs_ptr_plausible(const void *p)`

```c
/* A kernel pointer taken out of a kprobe register, checked before dereference: single_open()'s fake inode is (void *)1
 * and a kretprobe hands that sentinel over as "the argument" - the sus_map vma probe panicked on exactly that (fault
 * address 0xa1) until this test existed.  Every kernel object lives above the first page, so "< PAGE_SIZE" covers a
 * sentinel and a garbage register too, and IS_ERR() covers error pointers; user pointers must NOT go through it. */
```

### `static inline bool susfs_abi_path_ok(const char *field, size_t size)`

```c
/* Bind a fixed-size ABI pathname field to a C string safely: char[N] pathname fields a caller need not NUL-terminate, and
 * strlen()/strcmp()/kern_path() on one walks off the end of the struct, which lives on OUR kernel stack.  Every consumer of
 * an ABI pathname goes through this first. */
```

### `int sus_path_add_self_hidden(const char *path);`

```c
/* Same, for one of this module's own control nodes: flagged so the gate hides it from EVERY non-root caller, not merely
 * from apps (uid>=10000) - otherwise a probe running as system (1000) or shell (2000) reads the node name out of /proc. */
```

### `int sus_path_del_path(const char *path);`

```c
/* Undo sus_path_add_self_hidden(): drops the rule for @path and restores whatever it changed (the relaxed mode, the inode
 * reference); returns the number of rules removed, so 0 means "was not registered".  Process context only (iput). */
```

### `long sus_path_dirent_filter(long syscall_nr, unsigned long buf, long ret);`

```c
/* ---- sus_path's dirent filter, driven by the sys_exit tracepoint in susfs_kstat.c ----
 *
 * There is exactly ONE sys_exit tracepoint in this module and it lives in susfs_kstat.c (it is what
 * spoofs stat).  The listing (getdents) rewrite is called from that handler through these two
 * functions rather than through a second probe of its own: the tracepoint is paid for on every
 * syscall already, so a whitelisted number costs one compare, while the two getdents kretprobes
 * this replaces cost a trap per listing (measured 906 ns) and can silently drop a return once
 * maxactive is reached.  sus_path.c still owns the whole rewrite (bounce buffer, per-ABI record
 * layout, (ino, name) match, gate); susfs_kstat.c owns only "which number, which user pointer".
 *
 *   sus_path_dirent_filter(@syscall_nr, @buf, @ret)
 *       @buf  is the ALREADY-converted user pointer (the caller must apply compat_ptr() for a
 *             32-bit task: a compat pointer is a zero-extended u32 and must not be passed raw)
 *       @ret  is the syscall's return value
 *       returns what the syscall should return now - @ret itself when nothing was filtered or the
 *       number is not one this layer knows, so the caller can always assign the result back.
 *       Non-sleeping (tracepoint context); takes its own spinlock around the shared scratch buffer.
 */
```

### `int sus_path_dirent_stat_line(char *buf, size_t size);`

```c
/* One line of dirent counters for /proc/susfs_kstat's counter block (which ABI reached the filter,
 * and why a listing that should have been filtered was not).  Returns the bytes written. */
```

### `#define SUSFS_LKM_MODULE_NAME`

```c
/* The module's own name: the /sys/module directory and the modinfo name are both the module file name, and the self-hide
 * rules and the /proc/modules filter have to agree with it. */
```

### `#define SUSFS_HIDE_MODULES_NODE`

```c
/* hide_modules (susfs_hide_syms.c): filters module NAMES out of /proc/modules (plus /sys/module and /proc/kallsyms for
 * non-root callers).  Node and same-named parameter are root-only; the node answers ENOENT through sus_path's hidden set. */
```

### `#define SUSFS_PATH_NODE`

```c
/* sus_path's own control node: `cat` is the rule listing (the hide_list parameter view), writing takes add/del/clear.  An
 * operator who cannot see the rule table cannot tell "registered" from "hiding"; root-only, everyone else gets ENOENT. */
```

### `extern bool susfs_expose_proc;`

```c
/* Whether the /proc/susfs_* control nodes are created at all.  Defaults to TRUE; they are created only when the LSM layer
 * that hides them is installed, so nobody ends up with an unprotected control node, and expose_proc=0 removes them. */
```

### `bool susfs_hide_syms_active(void);`

```c
/* Actual install state: enabled_features must not advertise a feature whose registration failed - hide_syms used to fail
 * silently and still be reported as active, the kind of inconsistency a detector looks for. */
```

### `static inline bool susfs_control_node_allowed(void)`

```c
/* Whether a 0777 /proc/susfs_* control node may be created.  Two independent conditions, neither optional: susfs_expose_proc
 * (the operator opted in) and sus_path_lsm_active() (with 0777 DAC passes every caller, so only the LSM layer can still
 * answer ENOENT for an app).  This gates node CREATION ONLY, never hook registration: an earlier revision returned early from
 * the feature inits on !susfs_expose_proc, which silently disabled sus_kstat's tracepoint and kretprobe. */
```

### `bool susfs_open_redirect_spoof_ids(unsigned long ino, unsigned long *out_ino, unsigned long *out_mnt_id);`

```c
/* open_redirect, reverse direction, for callers that only have an inode NUMBER: fdinfo prints "ino:\t<i>" with no device, so
 * this is a lookup by ino alone and returns false when the number is ambiguous (two rules, same redirected ino) or the caller is
 * not one the reverse disguise applies to.  On success *out_ino is the target inode to show, *out_mnt_id the target mount id. */
```


## `kernel/susfs_abi.h`

### `(file header)`

```c
/*
 * susfs_abi.h - SUSFS kernel<->userspace ABI (supercall via reboot(2)).  Mirrors upstream
 * susfs_def.h + susfs.h layouts exactly, so the prebuilt ksu_susfs tool (and SukiSU's ksud
 * bindings) can drive this LKM unmodified; field order/types/sizes MUST match [repr(C)] there.
 * Wire protocol: syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd_id, &mut payload); the
 * kernel writes payload.err back (0 = ok, else errno-style).
 */
```

### `#define CMD_SUSFS_ADD_SUS_PATH`

```c
/* command IDs (shared with ksu_susfs / ksud; identical to upstream susfs_def.h, including the
 * ids upstream marks *deprecated* - defined for ABI completeness only, no handler wired,
 * exactly like upstream kernels, which no longer dispatch them either. */
```

### `#define ERR_CMD_NOT_SUPPORTED`

```c
/* 126 is a USERSPACE-side sentinel the kernel never produces: the ksu_susfs C tool pre-seeds payload.err with it and
 * prints "SUSFS operation not supported, please enable it in kernel" when the field is STILL 126 after the syscall,
 * i.e. when the kernel never wrote err back -
 *   ksu_susfs/jni/includes/susfs_defs.h:16   #define ERR_CMD_NOT_SUPPORTED 126
 *   ksu_susfs/jni/includes/susfs_defs.h:18   PRT_MSG_IF_CMD_NOT_SUPPORTED(err, cmd)
 *   ksu_susfs/jni/features/sus_map.c:51-53   info.err = ERR_CMD_NOT_SUPPORTED; syscall(...); PRT
 *   KernelSU/10_enable_susfs_for_ksu.patch:2925-2926  default: return -EINVAL, payload untouched
 * The kernel half of the contract is only "do not write err for a command you do not handle"; susfs_supercall.c mirrors
 * it (the kprobe does not hijack a command susfs_cmd_handled() rejects and writes nothing).  Userspace defines it only. */
```

### `enum UID_SCHEME {`

```c
/* uid_scheme values of struct st_susfs_open_redirect (upstream enum UID_SCHEME, declared in
 * susfs.h next to the structs) */
```

### `#define KSTAT_SPOOF_INO`

```c
/* KSTAT_SPOOF_* bits of struct st_susfs_sus_kstat's `flags` field (upstream declares these in
 * susfs.h right above that struct).  Intentional deviation from upstream, correcting an earlier
 * note here that got this wrong:
 *   upstream KERNEL    kernel_patches/include/linux/susfs.h:71  #define ..._CTIME_TV_SEC (1 < 8) -> 1
 *   upstream USERSPACE ksu_susfs/jni/features/sus_kstat.c:25    #define ..._CTIME_TV_SEC (1 < 8) -> 1
 *   SukiSU ksud (Rust) userspace/ksud/src/susfs/abi/consts.rs:52 uses the intended (1 << 8) -> 256
 * i.e. the typo lives on BOTH upstream sides, so bit 8 is really an alias of bit 0 (INO) there and
 * upstream's ctime spoof never fires from either side.  We keep the corrected value so bit 8 really
 * does spoof ctime.tv_sec, which also matches what ksud sends; a caller that follows the typo simply
 * spoofs ino, so both sides stay self-consistent.  If upstream ever fixes the typo, the two converge. */
```


## `kernel/susfs_log.h`

### `bool susfs_log_enabled(void);`

```c
/* ENABLE_LOG the way upstream has it: SUSFS_LOGI() is the informational channel (rule add/remove,
 * hook arming, hit paths) behind the switch CMD_SUSFS_ENABLE_LOG / /proc/susfs_enable_log toggles -
 * default ON, matching upstream's DEFINE_STATIC_KEY_TRUE(susfs_is_log_enabled).  pr_warn/pr_err stay
 * unconditional: a failure must be visible whether or not logging is on (upstream's SUSFS_LOGE is
 * unconditional too).  Measured before the fix: the flag had no readers, so `enable_log 0` plus a
 * rule add still printed "susfs_guard_lkm: sus_path: ..." in dmesg - a root-side fingerprint. */
```


## `kernel/symbol_resolver.h`

### `int ksu_find_symbol_all(const char *name, unsigned long *addrs, int max);`

```c
/* EVERY vmlinux symbol with this exact name (not just the first): a kprobe registered with
 * .symbol_name attaches to whichever match kallsyms lists first, and not every name is unique
 * (measured: `seq_show` exists four times from 6.1 on, once on 5.10/5.15).  Writes at most
 * @max addresses and returns how many were written (0 = unknown/not found). */
```

### `int ksu_symbol_name_of(unsigned long addr, char *buf, char **module_out);`

```c
/* Name of the symbol containing @addr (vmlinux only unless @module_out says otherwise): -ENOSYS when
 * kallsyms_lookup() was not bootstrapped, -ENOENT when the address cannot be named, else the length written;
 * @buf must be KSYM_SYMBOL_LEN bytes.  lsm_hook.c's static-call takeover uses it to check that the slot it is
 * about to steal really belongs to the hook it is installing for. */
```


## `tools/susfs_bench.c`

### `(file header)`

```c
/*
 * susfs_bench - micro-benchmark for the syscall interception layers, no libc.
 *
 * The point is to measure what the hook costs per call, which is far below what a
 * shell loop can resolve: the fp layer adds a wrapper call, one strncpy_from_user
 * and one rule match to every hooked syscall, all of it in the hundred-nanosecond
 * range.  So this is a tight loop around four syscalls with only
 * clock_gettime(CLOCK_MONOTONIC) around it - no libc, no printf, no allocation.
 *
 * Run it four times and compare:
 *
 *   no module                       -> baseline
 *   module, no rule                 -> the layers are not armed at all
 *   module, rule that does NOT hit  -> the wrapper's full path, then the original
 *   module, rule that DOES hit      -> the wrapper answers ENOENT before the original
 *
 * Android refuses non-PIE executables and the DDK container has no bionic sysroot,
 * so this is freestanding: -nostdlib -static-pie with our own _start.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_bench tools/susfs_bench.c
 *
 * Usage:
 *
 *     susfs_bench <path> [iterations]      # default 200000 iterations
 *
 * Timing side channel mode.  The question it answers is not "how much does the
 * hook cost" but "can a process tell the difference between a path that is hidden
 * and a path that is simply not there" - both answer ENOENT, so if their timings
 * separate, the denial itself is the leak.  Measuring two paths in separate runs
 * would compare thermal/scheduler drift instead of the paths, so the two are
 * measured ALTERNATELY, one batch each, and the printed statistics are of the
 * paired differences:
 *
 *     susfs_bench -p <kind> <iters-per-sample> <samples> <pathA> <pathB>
 *
 * kinds: 1=faccessat 2=fchownat 3=newfstatat 4=statx 5=openat+close
 *
 * Each sample is the average of <iters-per-sample> calls (the clock is read per
 * batch, not per call - a syscall-based clock costs more than the thing being
 * measured).  The verdict line prints YES only when the paired differences do not
 * change sign, i.e. when a checker could classify a single batch.
 */
```

### `static u64 now_ns(void)`

```c
/* Both of these are system calls here: the ABI passes nanoseconds in the second
 * word, which is all this needs. */
```

### `fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY, 0, 0, 0);`

```c
/* Directory listing: the dirent layer rewrites the buffer, so this is the
		 * face where a per-call cost is most likely to show up. */
```

### `static u64 put_kind(u64 pos, int kind)`

```c
/* Written straight into the output buffer instead of returning a literal: a switch
 * returning string literals made clang emit a table of absolute addresses in
 * .rodata, which ld.lld refuses for a static-PIE binary ("relocation
 * R_AARCH64_ABS64 cannot be used against local symbol; recompile with -fPIC"). */
```

### `static void paired(int kind, u64 k, int n, const char *pa, const char *pb)`

```c
/* Both paths are measured alternately, one batch each, so that a frequency drop
 * or a background task hits both sides of the pair instead of one of them. */
```

### `bench_main()`

```c
/* The differences get sorted for percentiles; the sign test below only needs
	 * the ends, which survive sorting. */
```

### `pos = putstr(pos, "  sign(neg=");`

```c
/* The verdict has to be an error rate, not "did every sample agree": one
		 * disturbed sample out of 120 is not what a checker would trip over, it
		 * would put a threshold at zero and be right the rest of the time. */
```

### `#define ROUNDS`

```c
/* Pin to one CPU.  Without this the loop migrates between the big and the
	 * little cores and the per-call number moves by more than the difference
	 * being measured - the same noise that made single-pass measurements
	 * useless.  CPU 7 is a big core on this SoC. */
```

### `for (i = 0; i < 1000; i++)`

```c
/* Warm up: the first pass over a cold path resolver is not what we measure,
	 * and the rule table/matches are per-call anyway. */
```

### `#define ROUNDS`

```c
/* The interesting difference is a few hundred nanoseconds on a phone that is
	 * also running Android, so a single pass is mostly noise.  Take the best of
	 * several: the minimum is the run that was least disturbed, which is the
	 * number the layer itself is responsible for. */
```

### `best_getpid = ~0ull;`

```c
/* No entry of ours is involved, so this line is the cost of whatever fires on
	 * *every* syscall - tracepoints mainly.  It is the number that shows whether a
	 * per-syscall callback is still being paid. */
```

### `if (rc == 0x7fffffff)`

```c
/* Keep the compiler honest: rc is used so the loops cannot be optimised
	 * away, and its value is not interesting. */
```


## `tools/susfs_compat_stat.c`

### `(file header)`

```c
/*
 * susfs_compat_stat - a 32-bit (AArch32) caller, to test the compat stat path.
 *
 * The kernel-side ABI audit found that the module was spoofing the WRONG compat
 * structure: __NR_fstatat64 (327) and __NR_fstat64 (197) are mapped to
 * sys_fstatat64/sys_fstat64, which fill `struct stat64` (arch/arm64/include/asm/
 * stat.h:19-48) - not `struct compat_stat`, which belongs to __NR_stat/lstat/fstat
 * (106/107/108).  Nothing in the repository could have caught that, because no
 * 32-bit client existed: a 64-bit process cannot make a 32-bit syscall here.
 *
 * This is that client.  It calls fstatat64 (and fstat64) and prints what came
 * back, so a rule's spoofed ino/dev/size/nlink can be compared against the same
 * rule observed from a 64-bit caller.
 *
 * It also walks one directory through BOTH of the listing interfaces an AArch32
 * caller has - getdents64 (217, mapped to the native sys_getdents64) and getdents
 * (141, whose own compat body has a different record layout) - because only a
 * 32-bit caller can reach the second one at all.
 *
 * The struct below must use the SAME alignment the kernel uses.  compat_u64/
 * compat_s64 are `__attribute__((aligned(4)))` only when
 * CONFIG_COMPAT_FOR_U64_ALIGNMENT is set (include/asm-generic/compat.h), and that
 * option is selected by the 32-bit arm architecture only - on arm64 the plain
 * typedefs apply, so the u64 members keep their natural 8-byte alignment and
 * sizeof(struct stat64) is 104, with st_size at +48 and st_ino at +96.
 *
 * Marking this struct `packed` (the first version of this client did) silently
 * makes the client disagree with the kernel: a 6-byte file came back as
 * size=25769803776 = 6 << 32, because the low half of the field was read from the
 * padding the kernel had left.  The size check printed below is what caught it.
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *     clang --target=armv7a-linux-androideabi -march=armv7-a -O2 -nostdlib \
 *           -static-pie -fno-stack-protector -fno-builtin -fuse-ld=lld \
 *           -Wl,-e,_start -o susfs_compat_stat tools/susfs_compat_stat.c
 *
 * Usage: susfs_compat_stat <path> [dir] [needle]
 */
```

### `_Static_assert(sizeof(struct stat64_compat) == 104, "stat64 size");`

```c
/* The layout claim, checked at compile time: if armv7's default alignment ever
 * differed from the arm64 kernel's view, the client would be measuring itself. */
```

### `static u64 u64_div10(u64 v, u64 *rem)`

```c
/* armv7 has no 64-bit division instruction, and a freestanding binary has no
 * libgcc, so `v / 10` would pull in __aeabi_uldivmod and fail to link (it did).
 * Shift-subtract long division instead: 64 iterations, no library call. */
```

### `#define __NR_getdents`

```c
/* ---- the two listing ABIs an AArch32 caller can use ----
 *
 * This is why a 32-bit client is needed for more than stat: the AArch32 table has
 * getdents64 (217) pointing at the NATIVE sys_getdents64 - so the 64-bit probe
 * already covers it - and a SEPARATE getdents (141) whose body has its own record
 * layout.  Upstream calls that body __do_compat_sys_getdents
 * (COMPAT_SYSCALL_DEFINE3 in fs/readdir.c); the module does NOT probe that name any
 * more - it is `static inline` with a single caller and can be inlined away - it
 * arms the __arm64_compat_sys_getdents wrapper and takes the buffer out of the
 * caller's pt_regs (see the candidate list in kernel/sus_path.c).  The two layouts:
 *
 *   getdents64: struct linux_dirent64      { u64 ino; s64 off; u16 reclen; u8 type; char name[]; }
 *               -> reclen at +16, name at +19
 *   getdents:   struct compat_linux_dirent { u32 ino; u32 off; u16 reclen; char name[]; }
 *               -> reclen at +8,  name at +10
 *
 * A hidden entry must be gone from both.  Fields are read byte-wise: the buffer is
 * a char array, and unaligned 64-bit loads are not worth relying on here. */
```

### `if (off + (compat ? 10 : 18) > n)`

```c
/* Bound BEFORE reading the field: reclen is what the bound check
			 * below uses, so reading it first can run past the buffer (and a
			 * garbage length would then classify a hidden entry as visible - a
			 * false negative in the tool that is supposed to be the evidence). */
```

### `rc = sys4(__NR_stat64, (long)path, (long)&st, 0, 0);`

```c
/* stat64/lstat64 take the path (and fstat64 the fd) with statbuf in the SECOND argument -
	 * the same struct stat64 the two calls above fill.  Without these three the client could
	 * not see that the kstat layer's compat dispatch used to handle only 327/197: a 32-bit
	 * caller's stat64()/lstat64()/fstat64() answered with the real ino/dev/size while its
	 * fstatat64() answered with the spoofed ones. */
```

### `fd = sys4(SYS_open, (long)dir, 0, 0, 0);`

```c
/* Both listing interfaces, on the directory that holds the hidden entry:
	 * the needle must be missing from BOTH. */
```


## `tools/susfs_insmod.c`

### `(file header)`

```c
/*
 * susfs_insmod - load susfs_guard_lkm.ko on a stock vendor kernel, without ksud.
 *
 * The problem
 * -----------
 * A vendor kernel's loader refuses this module for three reasons, and all three of
 * them live in the same place: the SHN_UNDEF branch of simplify_symbols().
 *
 *   1. unexported symbols (kallsyms_lookup_name, saved_boot_config, init_mm,
 *      task_work_add, ...) are not in the kernel's export table at all, so
 *      resolve_symbol() fails and the loader prints "Unknown symbol ... (err -22)";
 *   2. namespaced symbols (kern_path, ihold, override_creds, ...) additionally have
 *      to be imported by name - verify_namespace_is_imported() is the
 *      "VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver" refusal that a
 *      plain `insmod` hits;
 *   3. symbol CRCs (check_version()) and the Android KMI whitelist are checked
 *      there too.
 *
 * `case SHN_ABS:` does nothing but break (kernel/module.c, ~2342 in 5.15) and
 * relocation uses st_value verbatim for such a symbol.  So an undefined symbol that
 * has already been rewritten to st_shndx = SHN_ABS / st_value = <runtime address>
 * before the image reaches the kernel never enters any of those checks.  That is
 * exactly what ksud's userspace loader (SukiSU-Ultra userspace/ksuinit/src/lib.rs,
 * load_module()) does, and what this tool does:
 *
 *   1. map the .ko MAP_PRIVATE|PROT_WRITE (writes stay in this process' memory);
 *   2. walk .symtab: for every SHN_UNDEF entry with a non-empty name, look the name
 *      up in /proc/kallsyms and rewrite that Elf64_Sym in place to
 *      st_shndx = SHN_ABS, st_value = <address> (last kallsyms occurrence wins);
 *   3. init_module(2) the patched buffer with the joined module parameters;
 *   4. if that fails and /dev/kmsg says the vermagic is wrong, patch the .modinfo
 *      "vermagic=" value in place and retry once.
 *
 * What it deliberately does NOT do
 * --------------------------------
 *   * no finit_module(2) (no fd, so no signature step at open), no KernelSU
 *     supercall, no /data/adb/ksu or ksud binary dependency;
 *   * no section is resized: the vermagic fixup keeps the .modinfo bytes exactly as
 *     long as they were.  The kernel's next_string() skips NUL padding, so a shorter
 *     required value is NUL-padded in place and a longer one is truncated - and
 *     that truncation is reported, never silent;
 *   * no address guessing: if /proc/kallsyms only prints zeroes (kptr_restrict),
 *     the load is refused rather than attempted with SHN_ABS/0 symbols;
 *   * no vermagic "fix" that the kernel did not ask for: the patch runs only after
 *     the kernel itself printed "version magic '...' should be '...'".
 *
 * Build (this is the recipe the CI tools job uses):
 *
 *   clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *         -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *         -o susfs_insmod tools/susfs_insmod.c
 *
 * Usage: susfs_insmod [-v] <module.ko> [module-params ...]
 * Exit:  0 on a successful load, else the failing syscall's errno (2 for usage).
 */
```

### `typedef __INTPTR_TYPE__ sysarg;`

```c
/* The type a syscall number, argument and return value travels in: pointer-sized.
 * On the target it is plain `long`; a host build (SUSFS_INSMOD_HOSTTEST) must also
 * be able to hand a pointer through it, so it is spelled the compiler's way. */
```

### `#define SYS_exit`

```c
/* -------------------------------------------------------------------------- *
 * syscalls (aarch64, asm-generic numbering)                                   *
 * -------------------------------------------------------------------------- */
```

### `sys6()`

```c
/* The only host-dependent line in this file: the actual svc on the target, a shim
 * when the ELF/kallsyms/vermagic logic is exercised off-device
 * (-DSUSFS_INSMOD_HOSTTEST; nothing else is conditional except the _start block). */
```

### `#define OUT_MAX`

```c
/* -------------------------------------------------------------------------- *
 * output (one line at a time, so a failing load still prints its diagnostics)  *
 * -------------------------------------------------------------------------- */
```

### `static void finish(int code);`

```c
/* Defined below.  o_flush() must go through it instead of calling SYS_exit directly: a failed
 * stdout write (EPIPE - `susfs_insmod x.ko | head`, a reader that went away, a closed fd)
 * would otherwise leave /proc/sys/kernel/kptr_restrict at the 0 this tool wrote, i.e. kernel
 * addresses readable by every process on the device until the next reboot. */
```

### `static u64 s_len(const char *s)`

```c
/* -------------------------------------------------------------------------- *
 * tiny string helpers (no libc: the build is -nostdlib)                       *
 * -------------------------------------------------------------------------- */
```

### `#define EI_CLASS`

```c
/* -------------------------------------------------------------------------- *
 * ELF64 little-endian                                                     *
 * -------------------------------------------------------------------------- */
```

### `typedef char assert_ehdr_size[(sizeof(struct elf64_ehdr) == 64) ? 1 : -1];`

```c
/* The three layouts above are the ABI the kernel parses; a silent padding change
 * would move every field this tool writes, so fail the build instead. */
```

### `#define MAX_UNDEF`

```c
/* -------------------------------------------------------------------------- *
 * kallsyms                                                                    *
 * -------------------------------------------------------------------------- */
```

### `#define MAX_UNDEF`

```c
/* How many undefined symbols this tool is willing to carry.  The module has ~100;
 * 4096 leaves room for a much bigger module and still fits in .bss. */
```

### `static void kptr_relax(void)`

```c
/* Save kptr_restrict and set it to 0, the way ksud does (it writes 1; root sees
 * real addresses at both values, the kernel's kallsyms_show_value() falls through
 * to the CAP_SYSLOG test).  Called before the first kallsyms read. */
```

### `static void ks_record(const char *s, u64 len, u32 *matched, u32 *zero_addr)`

```c
/* One "<hex-address> <type> <name>" kallsyms line.  The type letter is the 2nd
 * field; 'a'/'A' means an absolute symbol whose printed value is NOT a runtime
 * address, so it is skipped.  A name containing '.' is skipped too: kallsyms is
 * full of compiler-generated names (.cold, .llvm.<hash>, $local aliases) and none
 * of them can be the undefined name of a linkable module symbol - matching is
 * exact, so a dotted undefined name would still match a dotted kallsyms name. */
```

### `u->sym->st_shndx = SHN_ABS;`

```c
/* Last occurrence wins: a name may be defined more than once (a static
		 * inline that the compiler emitted in several TUs); the last one is the
		 * one a module link would have taken. */
```

### `static sysarg resolve_symbols(void)`

```c
/* Stream /proc/kallsyms and rewrite the symbol entries as matches arrive.  The
 * file is ~10 MB on a GKI kernel, so it is read in chunks with a line assembler
 * instead of being slurped whole. */
```

### `#define KMSG_MAX`

```c
/* -------------------------------------------------------------------------- *
 * kernel log (/dev/kmsg, /proc/kmsg)                                          *
 * -------------------------------------------------------------------------- */
```

### `static sysarg kmsg_open(void)`

```c
/* Open the record device *before* the load attempt: /proc/kmsg is a read-once
 * stream, and /dev/kmsg needs a seek to the end to mean "only new records". */
```

### `static const char *kmsg_required_vermagic(u64 *out_len)`

```c
/* The kernel's own message is
 *     <name>: version magic '<module magic>' should be '<kernel magic>'
 * and the value we must install is the second one.  Last occurrence wins. */
```

### `modinfo_lookup()`

```c
/* -------------------------------------------------------------------------- *
 * .modinfo                                                                    *
 * -------------------------------------------------------------------------- */
```

### `static int modinfo_lookup(char *base, u64 size, const char *key, char **val, u64 *vlen)`

```c
/* Walk the NUL-separated entries the kernel's next_string() walks.  Returns the
 * value of "vermagic=" with its own (unterminated) length. */
```

### `static void usage(void)`

```c
/* -------------------------------------------------------------------------- *
 * main                                                                        *
 * -------------------------------------------------------------------------- */
```

### `nundef++;`

```c
/* A duplicate name in .symtab would resolve both entries through the
		 * same name lookup, so there is nothing to deduplicate here. */
```

### `ret = sys6(SYS_init_module, (sysarg)img, (sysarg)size,`

```c
/* param_values is NEVER NULL, not even with no parameters: load_module() calls
	 * strndup_user(uargs, ...) unconditionally (5.15 kernel/module.c:4046), and
	 * strndup_user(NULL) is -EFAULT.  ksud passes a CStr for the same reason.  The
	 * buffer below is static and always NUL-terminated, so "" is a valid argument. */
```

### `o_put(P "no \"version magic ... should be ...\" in the kernel log: "`

```c
/* No vermagic complaint: do not invent one.  The kernel's own
			 * records above are the reason. */
```

### `copy_n(val, req + (vlen - vlen_old), vlen_old);`

```c
/* The value does not fit and the section must not grow.
				 * Keep the REQUIRED value's tail: with CONFIG_MODVERSIONS
				 * the kernel compares only the part after the first space
				 * (same_magic()), and the version prefix is exactly the
				 * part that legitimately differs between builds. */
```


## `tools/susfs_memrd.c`

### `(file header)`

```c
/*
 * susfs_memrd - can another process' view of a hidden mapping still be read?
 *
 * sus_map hides a mapped file from /proc/<pid>/maps, /smaps, /smaps_rollup,
 * /pagemap and /map_files, but the CONTENT of that mapping has a second door:
 *
 *   /proc/<pid>/mem       -> mem_rw() -> access_remote_vm() -> __access_remote_vm()
 *   process_vm_readv(2)   -> process_vm_rw_single_vec() -> pin_user_pages_remote()
 *
 * Upstream SUSFS closes the first one (its __access_remote_vm hunk breaks the
 * transfer loop) and, measured from this kernel's mm/process_vm_access.c, does NOT
 * close the second - process_vm_readv never goes through __access_remote_vm.
 *
 * This tool reports both doors from the reading process' own point of view, so the
 * module's hook can be judged by what a caller actually gets:
 *
 *   direct_first  - read straight from the mapping (control: the owner always can)
 *   mem_read      - bytes returned by pread() on /proc/self/mem at that address
 *   mem_first     - the first bytes that came back (0 bytes -> nothing transferred)
 *   pvm_readv     - the return value of process_vm_readv() on the same range
 *   pvm_errno     - its errno when it failed (EFAULT is the expected refusal)
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *   clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie
 *         -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start
 *         -o susfs_memrd tools/susfs_memrd.c
 *
 * Usage: susfs_memrd <path> [len]
 */
```

### `map = (char *)sys6(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE, fd, 0);`

```c
/* One page is enough: the question is whether THIS page can be read through
	 * /proc/self/mem, not how much of the file was mapped. */
```

### `liov.iov_base = rd;`

```c
/* Door 2: process_vm_readv on ourselves - the same address, another reader.
	 *
	 * The pid must be real: this kernel's process_vm_rw_core() calls
	 * find_get_task_by_vpid(pid) unconditionally (no "pid 0 means current"
	 * shortcut), so 0 answers -ESRCH - which is exactly what the first version of
	 * this tool measured in every state, rule or no rule. */
```


## `tools/susfs_mmap.c`

### `(file header)`

```c
/*
 * susfs_mmap - mmap a file, touch it, then report what the kernel tells this very
 * process about that mapping: the pagemap entry of its first page, the
 * process-wide Rss from /proc/self/smaps_rollup, and whether the file is still
 * named in /proc/self/[maps|smaps].
 *
 * Why it has to be one process: /proc/self/pagemap and /proc/self/smaps_rollup
 * describe the *caller's* mm, and a shell cannot read a file without forking -
 * the child that runs dd/od gets its own mm, so an address the shell learned from
 * /proc/self/maps is not an address in that child.  This tool does the mapping,
 * the touching and both reads itself, which is what makes the numbers below
 * meaningful for a rule that hides the mapped file.
 *
 * Android refuses non-PIE executables and the DDK container has no bionic sysroot,
 * so this is freestanding: -nostdlib -static-pie with our own _start.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_mmap tools/susfs_mmap.c
 *
 * Usage:
 *
 *     susfs_mmap <path> [bytes]      # default: whole file
 */
```

### `sys6(SYS_pread64, fd, (long)&e, 8, (long)((addr / PAGE) * 8), 0, 0);`

```c
/* pread64(fd, &e, 8, page * 8) - skipped pages are simply not written by a
	 * walk that did not run, so a zero here can mean "absent" or "not shown to
	 * an unprivileged caller"; the module's walk_skipped counter is the real
	 * observable, this line is the second opinion. */
```

### `static u64 hexval(char c)`

```c
/* ---- the maps line itself, and the numbers a real file would put in it ----
 *
 * The columns after the permission flags are "pgoff major:minor ino".  For an
 * open_redirect rule those last two numbers come from the file the redirection
 * really opened, while the NAME on the same line is the target's - so printing the
 * line verbatim is what makes the two comparable: a line whose name and numbers
 * come from different files is a contradiction no real file can produce.
 *
 * stat(2) is not part of open_redirect's disguise (upstream leaves dev/ino to
 * sus_kstat), so the target path's st_dev/st_ino are the real target values, i.e.
 * exactly what the maps line has to agree with.  st_dev as userspace sees it is
 * the kernel's ENCODED dev_t (cp_new_stat -> new_encode_dev), so major/minor have
 * to be decoded from it: major = enc >> 8, minor = (enc & 0xff) | ((enc >> 20) << 8)
 * - the same numbers the kernel prints as "%02x:%02x". */
```

### `static u64 puthex2(char *dst, u64 pos, u64 v)`

```c
/* lowercase hex, no prefix and no padding - the width the kernel's own %02x uses
 * for major and minor */
```

### `for (i = 7; i >= 0; i--)`

```c
/* st_dev at 0, st_ino at 8 - the first two fields of struct stat, which
		 * is all this needs; byte-wise for the same reason the dirent reader is */
```

### `struct linux_dirent64_min {`

```c
/* /proc/self/map_files/<start>-<end> is a symlink per mapping, and resolving it
 * names the mapped file - which is how the a4 tests located a mapping the maps
 * listing had already dropped.  Count the entries, how many of them still NAME
 * the file this tool mapped, and how many answer ENOENT (the disguise). */
```


## `tools/susfs_mntid.c`

### `(file header)`

```c
/*
 * susfs_mntid - look at the mount ids the way a detector would.
 *
 * Hiding a line from /proc/self/mountinfo is not enough on its own: the same
 * mount id is printed by /proc/self/fdinfo/N ("mnt_id:\t<i>") and returned by
 * statx(2) (stx_mnt_id).  An app needs no root to open an fd on a path, read its
 * fdinfo, call statx and compare both numbers against the ids mountinfo lists -
 * and any id that mountinfo never mentions is a mount that was hidden.
 *
 * This tool does exactly that and prints a verdict, so a rule can be measured
 * instead of assumed:
 *
 *   mountinfo: <lines> lines, <ids> distinct ids, <big> ids >= 2000000000
 *   path=<p> fd=<n> fdinfo_mnt_id=<i> in_mountinfo=<yes|NO>
 *   path=<p> statx_mnt_id=<i> in_mountinfo=<yes|NO>
 *   summary: fdinfo_missing=<n> statx_missing=<n>
 *
 * Freestanding like the other tools (no libc, -nostdlib -static-pie):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_mntid tools/susfs_mntid.c
 *
 * Usage: susfs_mntid <path> [path...]
 */
```


## `tools/susfs_sc.c`

### `(file header)`

```c
/*
 * susfs_sc - minimal SUSFS supercall client, no libc.
 *
 * The module's supercall entry point is the KernelSU reboot ABI:
 *
 *     reboot(KSU_INSTALL_MAGIC1, SUSFS_MAGIC, cmd, payload)
 *
 * (see kernel/susfs_supercall.c: reboot_pre() checks regs[0] against
 * KSU_INSTALL_MAGIC1 and regs[1] against SUSFS_MAGIC -- the second magic is the
 * SUSFS one, not KernelSU's MAGIC2.)
 *
 * The prebuilt ksu_susfs tool covers most commands, but not
 * CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS and not CMD_SUSFS_ADD_SUS_PATH_LOOP,
 * so those have to be sent by hand.  This is the hand: it writes the command
 * number and a caller-supplied payload (as hex) straight to the syscall.
 *
 * Android refuses non-PIE executables, and we have no bionic sysroot in the
 * build container, so this is freestanding: -nostdlib -static-pie with our own
 * _start and raw svc instructions.
 *
 * Build (in the DDK container, same clang that builds the module):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fuse-ld=lld -Wl,-e,_start \
 *           -o susfs_sc tools/susfs_sc.c
 *
 * Usage:
 *
 *     susfs_sc <cmd-hex> [payload-hex]
 *     susfs_sc 0x55561 0100000000000000      # hide_sus_mnts_for_non_su_procs 1
 *
 * Exit status: 0 on a successful syscall, the syscall's (negated) error
 * otherwise, 2 for a usage error.
 */
```

### `#define PAYLOAD_MAX`

```c
/* Large enough for the biggest payload struct in the ABI
 * (st_susfs_spoof_cmdline_or_bootconfig and st_susfs_enabled_features are 8196:
 * a 4096-byte buffer here made the kernel copy 4 KB past its end). */
```

### `#define ERR_SEED`

```c
/* Every reply struct in kernel/susfs_abi.h ends with its `int err` as the LAST
 * field, and all twelve have sizeof - offsetof(err) == 4 (260/256, 376/372,
 * 136/132, 8/4, 520/516, 8196/8192, 20/16), so when the caller supplies the
 * whole struct as hex the err lives at len-4.  Reading it as
 * `*(unsigned long *)(payload + ((len - 8) & ~7))` - which this tool used to do -
 * rounds DOWN to an 8-byte boundary and therefore prints the four bytes BEFORE
 * err for every struct whose size is 4 mod 8, i.e. for most of them. */
```

### `len = parse_hex(argv[2], payload, PAYLOAD_MAX);`

```c
/* parse_hex() returns -1 when the input does not fit in the buffer, so
		 * an oversized struct is refused here instead of being handed to the
		 * kernel truncated (the kernel would copy_from_user the full struct and
		 * read past the end of this buffer). */
```

### `if (len >= 4)`

```c
/* Seed 126 like the stock C tool does: if the kernel does not recognise the
	 * command it leaves the buffer untouched, and "still 126" is how userspace
	 * detects "not supported".  Without the seed this client could never show
	 * that, which was the whole point of its err readback. */
```

### `return (rc == 0 && err == 0) ? 0 : 1;`

```c
/* Non-zero when either half of the contract failed: the syscall result or
	 * the err the kernel wrote back. */
```


## `tools/susfs_stat.c`

### `(file header)`

```c
/*
 * susfs_stat - a 64-bit client that PRINTs what newfstatat(79), fstat(80) and statx(291) return.
 *
 * Why this exists.  The kstat spoofing is verified with `ls -li` and `toybox stat` on the device, and
 * both of those go through newfstatat(79) only.  fstat(80) fills the same struct stat but from an fd,
 * and statx(291) fills a DIFFERENT struct (struct statx) with a mask contract that says which fields
 * the kernel actually filled - neither is reachable from a shell, and there is no strace on the
 * device.  `ls`, `toybox stat` and a 32-bit compat client therefore cannot tell "fstat/statx are
 * spoofed" from "they are not", which is how a feature can look broken (or look fine) without anyone
 * having measured it.
 *
 * Same freestanding shape as tools/susfs_sc.c and tools/susfs_compat_stat.c: no libc, its own
 * _start, static-pie, syscalls through inline asm.  Android rejects non-PIE executables and the DDK
 * container has no bionic sysroot, so this is the only way it can be built there.
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *   clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie -fno-stack-protector \
 *         -fno-builtin -fuse-ld=lld -Wl,-e,_start -o susfs_stat tools/susfs_stat.c
 *
 * Usage:
 *
 *   susfs_stat <path> [mask_hex]
 *
 *     <path>      the path to stat (fstat()/statx(AT_EMPTY_PATH) use it via an open fd)
 *     [mask_hex]  statx's request mask, e.g. 7ff (STATX_BASIC_STATS, the default) or 7fff
 *
 * Every line is `key=value` and printed with one syscall, so a test script can grep/compare:
 *
 *   newfstatat: rc=0 ino=... dev=... nlink=... size=... blocks=... blksize=... mtime=...
 *   fstat     : rc=0 ino=... ...                       (same fields, fd-based)
 *   statx     : rc=0 mask=0x7ff blksize=4096 nlink=1 ino=... size=... blocks=... dev=maj:min atime=... mtime=... ctime=...
 *
 * The statx mask is printed because "the field is spoofed but the mask does not say so" (or the
 * reverse) is exactly the inconsistency a checker looks for, and it is also what tells this tool
 * whether the kernel filled a field the caller asked for.
 */
```

### `#define SYS_write`

```c
/* stddef.h for size_t only (the static_asserts below need it); clang's freestanding headers
 * provide it, and it pulls in no libc code. */
```

### `{`

```c
/* One CPU, so the values do not depend on which core the process landed on (the spoofing is
	 * per-caller-uid, but the inode numbers printed by a filesystem can differ per mount view). */
```

### `fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);`

```c
/* 80: the fd-based one.  Same struct, but the buffer is argument 1 and the kernel reaches it
	 * through vfs_fstat() - a different chain, which is why it needed its own whitelist entry. */
```

### `rc = sys6(SYS_statx, AT_FDCWD, (long)path, 0, (long)req_mask, (long)&sx, 0);`

```c
/* 291: struct statx, with the caller's mask.  Run it twice so the buffer's own stx_mask can be
	 * compared between a request that names the basic set and one that names almost nothing - the
	 * mask is part of what a reader trusts. */
```

