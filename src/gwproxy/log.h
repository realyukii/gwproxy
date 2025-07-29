// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY__LOG_H
#define GWPROXY__LOG_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

#ifndef GWP_STATIC_LOG_LEVEL
#define GWP_STATIC_LOG_LEVEL 4
#endif

__attribute__((__format__(printf, 3, 4)))
void __pr_log(FILE *handle, int level, const char *fmt, ...);

struct log_handle {
	FILE *handle;
	int level;
};

#define pr_log(HANDLE, LEVEL, FMT, ...)				\
do {								\
	struct log_handle *__hd = (HANDLE);			\
	int __level = (LEVEL);					\
	if (__level > GWP_STATIC_LOG_LEVEL)			\
		break;						\
	if (!__hd)						\
		break;						\
	if (__level > __hd->level)				\
		break;						\
	if (!__hd->handle)					\
		break;						\
	__pr_log(__hd->handle, __level, FMT, ##__VA_ARGS__);	\
} while (0)

#define pr_err(HANDLE, FMT, ...) pr_log(HANDLE, 1, FMT, ##__VA_ARGS__)
#define pr_warn(HANDLE, FMT, ...) pr_log(HANDLE, 2, FMT, ##__VA_ARGS__)
#define pr_info(HANDLE, FMT, ...) pr_log(HANDLE, 3, FMT, ##__VA_ARGS__)
#define pr_dbg(HANDLE, FMT, ...) pr_log(HANDLE, 4, FMT, ##__VA_ARGS__)

#endif /* #ifndef GWPROXY__LOG_H */
