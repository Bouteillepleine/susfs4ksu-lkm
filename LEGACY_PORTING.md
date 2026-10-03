# Porting this module to a pre-5.10 kernel (branch `legacy`)

**This branch is unbuilt and untested, and no binaries are provided.** Nothing below 5.10
can be compiled or exercised in this project: there is no DDK image for it, there is no
device, and CI has no variant for it. The branch exists so that somebody with a pre-5.10
non-GKI kernel (4.14 / 4.19 / 5.4) has the code and an accurate map, instead of a module
that silently assumes a GKI kernel. **A pre-5.10 port is the porter's own verification
problem** - every claim below is about what the *code* assumes today, not about a kernel
anyone has run it on.

What this branch actually adds over `dev`:

* one `< 5.10` gate block of compatibility macros in `kernel/susfs.h` (see §4),
* this document, tracked (`!LEGACY_PORTING.md` in `.gitignore`),
* nothing else: no code path changes for 5.10 and up.

## 1. Upstream release vs GKI release - why the gates sit where they do

The module's version gates follow the **GKI release line**, not the upstream release that
changed an API. Those differ, and the difference is what a non-GKI porter trips over:
building this module against a vanilla kernel between the two (for example 6.7-6.11)
fails to compile rather than misbehaving - the gates are two different questions
("does this GKI tree have it?" vs "which upstream release changed it?").

| API / behaviour | changed upstream in | first GKI/ACK release with the new form | gate in the code |
|---|---|---|---|
| `struct proc_ops` + `proc_create()` | 5.6 (v5.5 proc_fs.h:49 vs v5.6 :15/:64) | 5.10 | shim, `< 5.6` |
| `copy_{from,to}_kernel_nofault()` (replacing `probe_kernel_{read,write}()`) | 5.8 | 5.10 | shim, `< 5.8` |
| `MODULE_IMPORT_NS()` | 5.4 (v5.4 module.h:276) | 5.10 | shim, `< 5.4` |
| `MODULE_IMPORT_NS()` takes a quoted string | 6.13 (v6.12 `__stringify(ns)` vs v6.13 `ns`) | 6.13 | `>= 6.13` |
| `inode_setxattr`/`inode_removexattr` gain `struct user_namespace *` | 5.12 | 5.12 | `>= 5.12` |
| ... the same two gain `struct mnt_idmap *` | 6.3 | 6.6 | `>= 6.3` |
| `inode_get_ctime()` replaces the `i_ctime`/`__i_ctime` field | 6.6 | 6.6 | `>= 6.6` |
| `inode_setattr` gains `struct mnt_idmap *` | 6.9 | 6.12 | `>= 6.12` |
| `i_atime`/`i_mtime` fields split into `i_atime_sec`/`i_atime_nsec` | 6.11 | 6.12 | `>= 6.12` |
| `kallsyms_on_each_symbol` callback loses `struct module *` | 6.4 | 6.6 | `>= 6.6` |
| LSM dispatch: hook list -> one static call per (hook, LSM) | 6.12 | 6.12 | `>= 6.12` |
| mount-id allocator: `mnt_id_ida` -> `mnt_id_xa` (xarray) | (ACK tree; see §3) | 6.18 (ACK tree) | `>= 6.18` |
| `__nocfi` (CFI_CLANG) | n/a upstream at 5.10 (ACK 5.10 compiler_types.h:240) | 5.10 | shim, `< 5.10` |

## 2. Area by area

### a) LSM hooks

**Assumes today.** 13 hooks are installed (`kernel/sus_path.c:624` static asserts the
prototypes; the hook list is built at `kernel/sus_path.c:663`). Below 6.12 they are
inserted as the first node of the kernel's hook list (`kernel/lsm_hook.h:12`, the insert
path at `kernel/lsm_hook.c:143`); from 6.12 the module takes over SELinux's static-call
slot instead (`kernel/lsm_hook.c:345`) and calls the displaced original through
`SUS_LSM_PASS_ORIG()` (`kernel/sus_path.c:604`). Two hooks carry an extra first argument
per release, handled by `SUS_XATTR_MNT_ID_*` (`kernel/sus_path.c:697`) and
`SUS_SETATTR_MNT_ID_*`, and the idmap decision per hook is in §1.

**An older kernel offers.** The hook list (`security_hook_heads`) and the
`security_hook_list` / `LSM_HOOK_INIT` machinery all exist before 5.10 - that half of the
code (`kernel/sus_path.c`'s asserts, `kernel/lsm_hook.c`'s list insertion) is the part
that predates 6.12 anyway. What does *not* exist below 5.10:

* `path_notify` (added 5.2) - the module installs that hook too, and on 4.x it simply is
  not there;
* `sb_statfs` as an LSM hook on the oldest trees - verify it in *your* tree's
  `include/linux/lsm_hook_defs.h`;
* the `struct user_namespace *` first argument on the two xattr hooks (5.12) - the
  module's `< 5.12` branch already covers that;
* CFI, so the prototype-exactness rules stop being enforced at runtime (§3, §4).

**Porter must re-derive.** For each of the 13 hooks, read your tree's own
`include/linux/lsm_hook_defs.h` and compare with the `static_assert`s in
`kernel/sus_path.c`. Hooks that are missing must be dropped from the list (a silently
dropped hook is worse than a build failure - the module's own CI treats a missing hook
name as a hard error). Also decide what to do about `security_hook_heads` if your tree
RANDSTRUCTs it: the module reads the head by offset and validates it; a randomized layout
means the validation refuses and the hook is not installed.

### b) Symbol resolution

**Assumes today.** Nothing in the module imports a `kallsyms_*` symbol: the entry points
are resolved at runtime by name through a kprobe bootstrap
(`kernel/symbol_resolver.c:80`), and lookups go through
`find_kernel_symbol_exact()` (`kernel/symbol_resolver.c:133`), which refuses symbols a
module owns and prefers the `.cfi_jt` variant of a function-table target
(`kernel/symbol_resolver.c:253`). Everything else the module needs that is not exported is
carried as an undefined ELF symbol and filled by the loader (§3).

**An older kernel offers.** `kallsyms_lookup_name()` is exported before 5.7 (so the kprobe
bootstrap is unnecessary, though harmless), `kallsyms_on_each_symbol()` exists from 4.9
with the `struct module *` callback argument, and `kallsyms_on_each_match_symbol()` only
from 5.19 - the gates for both are in `kernel/symbol_resolver.c`. Symbol names differ by
release and platform: the dcache flush pair is chosen at build time by
`kernel/Makefile:22` (`__flush_dcache_area`/`__flush_icache_range` before 5.14,
`dcache_clean_inval_poc`/`caches_clean_inval_pou` after).

**Porter must re-derive.** Which of the module's undefined symbols your kernel actually
has. Android's tree carries symbols a mainline tree does not (`sized_strscpy`, which backs
`strscpy` there, is the clearest example), and a name the loader cannot find is a module
that does not load at all. Do this the way CI does (§5): list `nm -u` of the built `.ko`
and check every name against your `System.map`.

### c) Text patching

**Assumes today.** `kernel/patch_memory.c:137` patches read-only kernel text through
`stop_machine` via `phys_from_virt()` (`:21`), with the instruction header chosen per
release (`kernel/patch_memory.h`: `asm/text-patching.h` from 6.13, `asm/patching.h` from
5.14, `asm/insn.h` before).

**An older kernel offers.** The `< 5.14` branch (`asm/insn.h`) is exactly the pre-5.10
form, and the flush helpers are selected by the Makefile grep above, so this area needs no
new gate on this branch.

**Porter must re-derive.** Nothing structural, but note what patching is used for: on
6.12+ the module does *not* patch text for hook installation (it takes over a static-call
slot instead), so on a pre-5.10 kernel you are on the list-insertion path and text
patching is only used where it always was (the `.modinfo`/`__versions`-free loader path
and the patch features the porter chooses to keep).

### d) Dirent probes

**Assumes today.** The listing filter is a kretprobe on the syscall *wrapper*, tried first
out of a candidate list (`kernel/sus_path.c:1254`, armed at `:1303`), with
`.maxactive = 64` (`:1217`). The reason is measured, not theoretical: `__do_sys_*`/`__se_*`
are `static`/`static inline` with a single caller and are inlined away under LTO, so a
probe on them never fires, while `__arm64_sys_getdents64` is referenced by the syscall
table and therefore always exists.

**An older kernel offers.** The same wrapper names (`__arm64_sys_getdents64`,
`__arm64_compat_sys_getdents`) exist from the arm64 syscall-table generation that predates
5.10, and the candidate list already includes the older spellings. `kretprobe` and
`maxactive` are unchanged.

**Porter must re-derive.** Which candidate your tree's build actually keeps (`grep` your
`System.map`/kallsyms for the list in `kernel/sus_path.c`), and whether your kernel
enables 32-bit compat at all: if it does not, the compat probe is dead weight and its
absence must not be counted as a failure. Note the `maxactive` limit honestly - it bounds
how many concurrent invocations can be tracked, so it is a completeness limit, and
exceeding it loses filtering for those calls, not correctness.

### e) Supercall

**Assumes today.** Commands arrive as a supercall from KernelSU, dispatched by command
number (`kernel/susfs_supercall.c:137`, numbers in `kernel/susfs_abi.h:21`, structures in
`kernel/susfs_abi.h`), with a userspace client for the commands KernelSU does not expose
(`tools/susfs_sc.c`).

**An older kernel offers.** Nothing to widen - this is an ABI between the module and a
userspace caller, independent of the kernel version. What is version-dependent is the
*transport*: KernelSU's own supercall hook exists only on kernels KernelSU supports, and
on a non-GKI kernel you are most likely calling the module through its `/proc` nodes
instead.

**Porter must re-derive.** Whether KernelSU (or your root solution) provides the supercall
entry point at all in your setup; if it does not, drive the features through
`/proc/susfs_*` (§f) and keep `tools/susfs_sc.c` only for the two commands those nodes do
not cover.

### f) /proc interfaces

**Assumes today.** Each feature creates its control node with
`proc_create(name, 0777, NULL, ops)` and a `static const struct proc_ops`
(`kernel/susfs_avc_spoof.c:130/:162`, `kernel/susfs_enable_log.c:77/:92`,
`kernel/susfs_hide_syms.c:374/:558`, `kernel/susfs_kstat.c:1106`,
`kernel/susfs_open_redirect.c:731`, `kernel/sus_mount.c:1802`). The nodes are 0777 on
purpose so that DAC lets every caller through and the LSM layer is the only thing that can
answer ENOENT for a non-root caller, and their creation is gated on the LSM layer being
installed (`kernel/susfs.h:161`).

**An older kernel offers.** `struct file_operations` + the `proc_create()` prototype of
5.5 and earlier, mapped by the `< 5.6` shim in §4. `seq_file`, `single_open` and the rest
of the plumbing are unchanged.

**Porter must re-derive.** Whether the 0777-and-hide design is acceptable on your kernel:
on a kernel without the LSM hiding layer you get world-writable control nodes with no gate
behind them. The module handles this itself by not creating the nodes when the LSM layer is
not installed (`kernel/susfs.h:161`), but that path is worth re-checking on your tree.

### g) Build

**Assumes today.** `kernel/Makefile` builds one module (`obj-m`, `:14`) from the object
list at `:16`, reaching the private `fs/mount.h` with `-I$(srctree)/fs` (`:32`), the flush
helper choice by grepping the tree's `arch/arm64/include/asm/cacheflush.h` (`:22`), and
`KDIR ?= /lib/modules/$(shell uname -r)/build` (`:41`). CI builds against DDK images
(`.github/workflows/build-ddk.yml`) that ship a *prepared* kernel tree, a Module.symvers
and a matching Clang.

**An older kernel offers.** All of that is generic; a pre-5.10 non-GKI kernel built from
source with the same Clang (or GCC) works the same way as long as `fs/mount.h` still
declares `struct mount`/`struct mnt_namespace` as this code expects - which is exactly the
assumption §3 lists as inherently GKI-shaped.

**Porter must re-derive.** Your tree's `fs/mount.h` layout (the module reads
`ns->mounts`/`ns->list`, `mnt_ns_attached()` etc. from it, per release), your compiler's
CFI story, and your module-loading path (§3).

## 3. What is inherently GKI-specific (the most work on a non-GKI kernel)

* **KMI and vermagic.** Every `.ko` is locked to one kernel release's vermagic and, where
  the tree has `__versions`, to its symbol CRCs. A GKI module is loaded by a loader that
  fixes vermagic up; on a non-GKI kernel you build the module against *your* tree, which is
  the normal out-of-tree workflow - but every symbol the module resolves by name must
  exist in *your* kernel (§b).
* **The module loading path.** This module's design assumes symbols can be supplied at load
  time: unexported names are carried as undefined ELF symbols and absolutized by
  `tools/susfs_insmod.c` (or `ksud insmod`) from `/proc/kallsyms` before `init_module(2)`,
  which bypasses the export table, namespace imports, CRC and KMI checks entirely. That is
  a KernelSU/GKI-world mechanism (and the reason the module ships its own loader); on a
  non-GKI kernel with a plain `insmod` it is the single biggest adaptation, and it is the
  reason the CI gate in §5 exists.
* **`__versions` / symbol CRCs.** Empty in the DDK trees (so load-time version checks are
  inert there). A kernel built with `CONFIG_MODVERSIONS=y` and a real `Module.symvers`
  gives you CRCs that must match - the loader path skips them, a plain `insmod` does not,
  and mixing the two is how "it loads" stops meaning "it works".
* **The private header reach-in.** `fs/mount.h` is not a UAPI header; the module includes
  it directly and reads `struct mount`/`struct mnt_namespace` fields from it. That layout
  changes between releases (6.12 replaced the mount list with an rb-tree, 6.18 replaced the
  mount-id allocator with an xarray), so this is the part of the port most likely to need
  real work rather than a gate.
* **Android-only symbols.** A handful of names the module uses exist because Android's tree
  exports them (`sized_strscpy` behind `strscpy`, the `VFS_internal_...` namespace import).
  They do not exist upstream; §6's gate is how you find out.

## 4. What this branch widened, and what it deliberately did not

Widened, all inside the single `< 5.10` gate in `kernel/susfs.h`, each naming the release
that changed the API: `proc_ops`/`proc_create()` (< 5.6), the nofault accessors (< 5.8),
`MODULE_IMPORT_NS()` (< 5.4), and `__nocfi` (< 5.10, where CFI does not exist). A
compile-test of the shim forms (against stand-in types, not a kernel) is the only evidence
these have.

Left to this document on purpose, because they are not mechanical:

* `task_work_add()`'s third argument changed from `bool notify` to the
  `TWA_*` enum, and the mapping is semantic (`TWA_RESUME` is closer to `notify == false`
  than to `true`) - a wrong guess hangs or drops a notification, so it is yours to decide
  against your tree;
* per-hook prototype differences, including hooks that do not exist on 4.x (`path_notify`);
* `fs/mount.h` layout differences and which of the module's name-resolved symbols your tree
  has (§b, §c);
* everything in §3.

## 5. Verifying your own port (what this project checks, and what a port needs)

Build-time, and the single most useful check: **every name in `nm -u <your .ko>` must
exist in your kernel's `System.map`/`vmlinux`.** The loaders absolutize undefined symbols
by name from `/proc/kallsyms`, so a name your kernel does not have is a module that does
not load at all - not a feature that degrades. CI does exactly this per variant and fails
with the offending names; do the same locally before you flash anything. Two related
checks from the same CI run are worth copying: the artifact must carry `import_ns` in
`.modinfo` (if it uses `MODULE_IMPORT_NS`) and must not import any `kallsyms_*` symbol.

On the device, in this order:

1. the loader prints `undefined symbols: N` then `resolved N/N; unresolved 0`, and exits 0;
   judge on the exit status, not on the text;
2. the module is up: `[ -d /sys/module/<name> ]` - `lsmod` and `/proc/modules` cannot show
   it, that is the point of the self-hide;
3. feature-level evidence, never "it loaded": the counters (`/sys/module/<name>/parameters/
   hide_list` and `mount_stat`) must move when a non-root reader touches a hidden path, and
   a rule that is registered must actually disappear from a listing;
4. two unload/reload cycles with `rmmod` returning 0 and zero alarm lines in `dmesg` (clear
   `dmesg` before each window - a vendor kernel writes thousands of lines a second and the
   ring buffer drops the old ones silently);
5. leave the device usable: restore whatever runtime configuration you had (the module does
   not persist rules across a reload).

If the device reboots on load: on a kCFI/kCFI-like kernel a mismatched hook prototype is a
panic, not a warning, and that IS the result. Collect
`/sys/fs/pstore/console-ramoops-0` and the `.ko`, and do not retry blindly.
