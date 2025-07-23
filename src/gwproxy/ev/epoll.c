// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <gwproxy/ev/epoll.h>
#include <gwproxy/common.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

__cold
int gwp_ctx_init_thread_epoll(struct gwp_wrk *w)
{
	struct epoll_event ev, *events;
	struct gwp_ctx *ctx = w->ctx;
	int ep_fd, ev_fd, r;

	ep_fd = __sys_epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		r = ep_fd;
		pr_err(&w->ctx->lh, "Failed to create epoll instance: %s\n",
			strerror(-r));
		return r;
	}

	ev_fd = __sys_eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ev_fd < 0) {
		r = ev_fd;
		pr_err(&w->ctx->lh, "Failed to create eventfd: %s\n", strerror(-r));
		goto out_close_ep_fd;
	}

	w->evsz = 512;
	events = calloc(w->evsz, sizeof(*events));
	if (!events) {
		r = -ENOMEM;
		pr_err(&w->ctx->lh, "Failed to allocate memory for events: %s\n",
			strerror(-r));
		goto out_close_ev_fd;
	}

	w->ev_fd = ev_fd;
	w->ep_fd = ep_fd;
	w->events = events;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_EVENTFD;
	r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ev_fd, &ev);
	if (unlikely(r))
		goto out_free_events;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (unlikely(r))
		goto out_free_events;

	if (w->idx == 0 && (ctx->ino_fd >= 0)) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_SOCKS5_AUTH_FILE;
		r = __sys_epoll_ctl(ep_fd, EPOLL_CTL_ADD, ctx->ino_fd, &ev);
		if (unlikely(r))
			goto out_free_events;
	}

	pr_dbg(&w->ctx->lh, "Worker %u epoll (ep_fd=%d, ev_fd=%d)", w->idx,
		ep_fd, ev_fd);
	return 0;

out_free_events:
	free(events);
	w->events = NULL;
out_close_ev_fd:
	__sys_close(ev_fd);
out_close_ep_fd:
	__sys_close(ep_fd);
	w->ev_fd = w->ep_fd = -1;
	return r;
}


__cold
void gwp_ctx_free_thread_epoll(struct gwp_wrk *w)
{
	if (w->ev_fd >= 0) {
		__sys_close(w->ev_fd);
		pr_dbg(&w->ctx->lh, "Worker %u eventfd closed (fd=%d)", w->idx,
		       w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		__sys_close(w->ep_fd);
		pr_dbg(&w->ctx->lh, "Worker %u epoll closed (fd=%d)", w->idx,
		       w->ep_fd);
		w->ep_fd = -1;
	}

	free(w->events);
	w->events = NULL;
}

static int handle_events(struct gwp_wrk *w, int nr_events)
{
	struct epoll_event *events = w->events;
	struct gwp_ctx *ctx = w->ctx;
	int i, r = 0;

	for (i = 0; i < nr_events; i++) {
		if (unlikely(ctx->stop))
			break;

		r = gwp_ctx_handle_event_epoll(w, &events[i]);
		if (unlikely(r < 0))
			break;

		if (w->ev_need_reload)
			break;
	}

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	int r;

	w->ev_need_reload = false;
	r = __sys_epoll_wait(w->ep_fd, w->events, w->evsz, -1);
	if (unlikely(r < 0)) {
		if (r != -EINTR)
			pr_err(&w->ctx->lh, "epoll_wait failed: %s", strerror(-r));
		else
			r = 0;
	}

	return r;
}

int gwp_ctx_thread_entry_epoll(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;

		r = handle_events(w, r);
		if (unlikely(r < 0))
			break;
	}

	return r;
}
