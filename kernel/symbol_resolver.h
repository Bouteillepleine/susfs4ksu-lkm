/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_SYMBOL_RESOLVER_H
#define __SUSFS_SYMBOL_RESOLVER_H

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name);
unsigned long find_kernel_symbol_exact(const char *symbol_name);
/* Name of the symbol containing @addr (vmlinux only unless @module_out says otherwise): -ENOSYS when
 * kallsyms_lookup() was not bootstrapped, -ENOENT when the address cannot be named, else the length written;
 * @buf must be KSYM_SYMBOL_LEN bytes.  lsm_hook.c's static-call takeover uses it to check that the slot it is
 * about to steal really belongs to the hook it is installing for. */
int ksu_symbol_name_of(unsigned long addr, char *buf, char **module_out);
void ksu_init_symbol_resolver(void);

#endif
