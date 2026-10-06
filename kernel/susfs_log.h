/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SUSFS_LOG_H
#define __SUSFS_LOG_H

#include <linux/types.h>
#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "susfs_guard_lkm: " fmt
#endif

bool susfs_log_enabled(void);

#define SUSFS_LOGI(fmt, ...)						\
	do {								\
		if (susfs_log_enabled())				\
			pr_info(fmt, ##__VA_ARGS__);			\
	} while (0)

#endif
