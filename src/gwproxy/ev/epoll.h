// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY__EV__EPOLL_H
#define GWPROXY__EV__EPOLL_H

#include <gwproxy/gwproxy.h>

int gwp_ctx_init_thread_epoll(struct gwp_wrk *w);
void gwp_ctx_free_thread_epoll(struct gwp_wrk *w);
int gwp_ctx_thread_entry_epoll(struct gwp_wrk *w);
void gwp_ctx_signal_all_epoll(struct gwp_ctx *ctx);

#endif /* #ifndef GWPROXY__EV__EPOLL_H */
