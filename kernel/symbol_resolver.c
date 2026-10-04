/* SPDX-License-Identifier: GPL-2.0 */
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
#include "symbol_resolver.h"
#include "susfs_log.h"
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/version.h>

/* https://github.com/torvalds/linux/commit/89245600941e4e0f87d77f60ee269b5e61ef4e49 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define USE_KCFI 1
#else
#define USE_KCFI 0
#endif

#if !USE_KCFI
static const char cfi_suffix[] = ".cfi_jt";
static const size_t cfi_suffix_len = sizeof(cfi_suffix) - 1;
#endif

/* It's not guaranteed kallsyms_on_each_symbol exists in 5.x. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define ALWAYS_HAVE_ON_EACH_SYMBOL 1
#else
#define ALWAYS_HAVE_ON_EACH_SYMBOL 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_ON_EACH_MATCH_SYMBOL 1
#else
#define HAVE_ON_EACH_MATCH_SYMBOL 0
#endif

/* ---- the four entry points, all runtime-bootstrapped: NULL until
 * ksu_init_symbol_resolver(), each called through a __nocfi function because CFI checks
 * indirect call sites - a wrong type panics there on a kCFI kernel (6.1+). */
static unsigned long (*kallsyms_lookup_name_fn)(const char *name) = NULL;
static const char *(*kallsyms_lookup_fn)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset,
                                         char **modname, char *namebuf) = NULL;

/* The walker lost its `struct module *` argument in 6.6, so the POINTER's type is
 * version-gated like the callbacks below (that argument carried module ownership). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
typedef int (*ksu_on_each_symbol_fn_t)(int (*fn)(void *, const char *, unsigned long), void *data);
#else
typedef int (*ksu_on_each_symbol_fn_t)(int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
#endif

static ksu_on_each_symbol_fn_t kallsyms_on_each_symbol_fn = NULL;

#if HAVE_ON_EACH_MATCH_SYMBOL
static int (*kallsyms_on_each_match_symbol_fn)(int (*fn)(void *, unsigned long), const char *name, void *data) = NULL;
static int find_kernel_symbol_exact_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 0;
}
#endif

/* Resolve a symbol NAME at runtime: register_kprobe() looks it up in the kernel's own
 * kallsyms and never touches the export table - which is why nothing here imports a
 * kallsyms_* symbol.  __nocfi because the address is stored in a function pointer and
 * called indirectly, which CFI checks; NULL is a degradation, never a load failure. */
static __nocfi void *ksu_bootstrap_symbol(const char *name)
{
    struct kprobe kp;
    void *addr = NULL;

    memset(&kp, 0, sizeof(kp));
    kp.symbol_name = (void *)name;

    if (!register_kprobe(&kp)) {
        addr = (void *)kp.addr;
        unregister_kprobe(&kp);
    }

    if (!addr)
        pr_warn("symbol_resolver: cannot bootstrap %s (kprobe could not resolve it)\n", name);

    return addr;
}

struct ksu_lookup_symbol_ctx {
    const char *symbol_name;
    size_t symbol_len;
    void *match;
};

/* Exact-name lookup through the walker - reachable only when kallsyms_lookup() did not
 * bootstrap; before 6.6 it is also the module-ownership check (see ksu_exact_name_cb()). */
struct ksu_exact_name_ctx {
    const char *symbol_name;
    unsigned long addr;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int ksu_exact_name_cb(void *data, const char *name, unsigned long addr)
#else
static int ksu_exact_name_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_exact_name_ctx *ctx = data;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
    /* OWNERSHIP before 6.6: a non-NULL `mod` means another module provides the symbol. */
    if (mod)
        return 0;
#endif

    if (!name || strcmp(name, ctx->symbol_name) != 0)
        return 0;

    ctx->addr = addr;
    return 1;	/* stop the walk */
}

unsigned long __nocfi find_kernel_symbol_exact(const char *symbol_name)
{
    unsigned long addr = 0;

    if (!symbol_name || !symbol_name[0])
        return 0;

#if HAVE_ON_EACH_MATCH_SYMBOL
    /* 6.1+ can match the exact name, but carries no ownership check - tried first only. */
    if (likely(kallsyms_on_each_match_symbol_fn)) {
        kallsyms_on_each_match_symbol_fn(find_kernel_symbol_exact_cb, symbol_name, &addr);
        return addr;
    }
#endif

    /* Graceful degradation, decided here: with no bootstrapped kallsyms_lookup_name there
     * is no name lookup at all, so features needing one stay off; the module still loads. */
    if (unlikely(!kallsyms_lookup_name_fn))
        return 0;

    addr = kallsyms_lookup_name_fn(symbol_name);
    if (!addr)
        return 0;	/* walking kallsyms for address 0 answers nothing */

    if (likely(kallsyms_lookup_fn)) {
        /* PATH IN USE on every kernel this module builds against: name -> address through
         * the bootstrapped kallsyms_lookup_name(), ownership check through the bootstrapped
         * kallsyms_lookup() - a non-NULL modname means another module owns it, refused. */
        char *module_name = NULL;
        char buf[KSYM_SYMBOL_LEN];

        kallsyms_lookup_fn(addr, NULL, NULL, &module_name, buf);
        if (unlikely(module_name)) {
            pr_warn("ignore symbol %s of module %s\n", symbol_name, module_name);
            return 0;
        }
        return addr;
    }

    /* kallsyms_lookup() is unavailable, so the owner has to come from the walker: before
     * 6.6 its callback is handed the owning `struct module *` and ksu_exact_name_cb()
     * refuses a non-NULL mod.  The walk must also confirm the address, or we would be
     * trusting a symbol we could not check. */
    if (kallsyms_on_each_symbol_fn) {
        struct ksu_exact_name_ctx ctx = { .symbol_name = symbol_name };

        kallsyms_on_each_symbol_fn(ksu_exact_name_cb, &ctx);
        if (ctx.addr != addr) {
            pr_warn("ignore symbol %s: the kallsyms walk did not confirm it as vmlinux's\n", symbol_name);
            return 0;
        }
        return addr;
    }

    /* Neither kallsyms_lookup() nor the walker bootstrapped, and from 6.6 the walker does
     * not carry the owner either: fail closed rather than take a symbol whose owner cannot
     * be verified. */
    pr_warn("ignore symbol %s: its owner cannot be checked on this kernel\n", symbol_name);
    return 0;
}

static inline bool ksu_symbol_has_suffix(const char *name, size_t name_len, const char *suffix, size_t suffix_len)
{
    return name_len >= suffix_len && strcmp(name + name_len - suffix_len, suffix) == 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int lookup_symbol_variant_cb(void *data, const char *name, unsigned long addr)
#else
static int lookup_symbol_variant_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_lookup_symbol_ctx *ctx = data;
    size_t name_len;

    if (!name || !addr)
        return 0;

    name_len = strlen(name);

    if (strcmp(name, ctx->symbol_name) != 0) {
        if (name_len <= ctx->symbol_len || strncmp(name, ctx->symbol_name, ctx->symbol_len) != 0 ||
            name[ctx->symbol_len] != '.')
            return 0;
    }

#if !USE_KCFI
    if (ksu_symbol_has_suffix(name, name_len, cfi_suffix, cfi_suffix_len)) {
        ctx->match = (void *)addr;
        SUSFS_LOGI("use .cfi_jt variant: %s\n", name);
        return 1;
    }
#endif

    if (!ctx->match) {
        ctx->match = (void *)addr;
        SUSFS_LOGI("found variant: %s\n", name);
#if USE_KCFI
        return 1;
#endif
    }

    return 0;
}

static __nocfi void *resolve_symbol_variant(const char *symbol_name, size_t symbol_len)
{
    struct ksu_lookup_symbol_ctx ctx = {
        .symbol_name = symbol_name,
        .symbol_len = symbol_len,
    };

    if (unlikely(!kallsyms_on_each_symbol_fn))
        return NULL;

    kallsyms_on_each_symbol_fn(lookup_symbol_variant_cb, &ctx);

    return ctx.match;
}

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name)
{
    void *addr;
    size_t symbol_len;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);

#if !USE_KCFI
    char cfi_name[KSYM_NAME_LEN];
    snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", symbol_name);
    addr = (void *)find_kernel_symbol_exact(cfi_name);
    if (addr)
        return addr;

    addr = resolve_symbol_variant(symbol_name, symbol_len);
    if (addr)
        return addr;

    return (void *)find_kernel_symbol_exact(symbol_name);
#else
    addr = (void *)find_kernel_symbol_exact(symbol_name);
    if (addr)
        return addr;

    return resolve_symbol_variant(symbol_name, symbol_len);
#endif
}

void __init ksu_init_symbol_resolver(void)
{
    int match_ok = 0;

    /* Bootstrap by NAME through a kprobe, never linked against; NULL is a degradation. */
    kallsyms_lookup_name_fn = ksu_bootstrap_symbol("kallsyms_lookup_name");
    kallsyms_lookup_fn = ksu_bootstrap_symbol("kallsyms_lookup");
    kallsyms_on_each_symbol_fn = ksu_bootstrap_symbol("kallsyms_on_each_symbol");
#if ALWAYS_HAVE_ON_EACH_SYMBOL
    /* From 5.19 the walker always exists, so its absence is a real loss of coverage. */
    if (!kallsyms_on_each_symbol_fn)
        pr_warn("kallsyms_on_each_symbol exists in every 5.19+ kernel but did not resolve!\n");
#endif
#if HAVE_ON_EACH_MATCH_SYMBOL
    kallsyms_on_each_match_symbol_fn = ksu_bootstrap_symbol("kallsyms_on_each_match_symbol");
    match_ok = !!kallsyms_on_each_match_symbol_fn;
#endif

    /* Whether these came up decides which mechanism resolves symbols. */
    SUSFS_LOGI("symbol_resolver: kprobe bootstrap (1 = usable): lookup_name=%d lookup=%d walker=%d match=%d\n",
               !!kallsyms_lookup_name_fn, !!kallsyms_lookup_fn, !!kallsyms_on_each_symbol_fn, match_ok);
}
