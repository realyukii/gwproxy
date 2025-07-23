// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/ev/epoll.h>
#include <gwproxy/common.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <sys/inotify.h>

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

static int rearm_accept(struct gwp_wrk *w, int nr_fd_closed)
{
	struct gwp_ctx *ctx = w->ctx;
	struct epoll_event ev;
	int x, r;

	/*
	 * Each connection pair consists of at least 3 file descriptors:
	 *
	 *   1. TCP socket for the client connection.
	 *   2. TCP socket for the target connection.
	 *   3. Timer file descriptor (if used).
	 *
	 * Before rearming the main TCP socket, wait until we have free
	 * space for at least 3 connection pairs per worker thread.
	 */
	if (nr_fd_closed <= ((3 * ctx->cfg.nr_workers) * 3))
		return 0;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (unlikely(r))
		return r;

	w->accept_is_stopped = false;
	pr_info(&ctx->lh,
		"Rearmed main TCP socket for accepting new connections (tidx=%u, fd=%d)",
		w->idx, w->tcp_fd);

	x = atomic_fetch_sub(&ctx->nr_accept_stopped, 1);
	if (x == 1)
		atomic_store(&ctx->nr_fd_closed, 0);

	return 0;
}

__hot
static int free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	struct gwp_ctx *ctx = w->ctx;
	int nr_fd_closed = 0;
	int r;

	if (gde) {
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gde->ev_fd, NULL);
		if (unlikely(r))
			return r;
	}

	if (gcp->client.fd >= 0) {
		nr_fd_closed++;
		w->ev_need_reload = true;
	}

	if (gcp->timer_fd >= 0)
		nr_fd_closed++;
	if (gcp->target.fd >= 0)
		nr_fd_closed++;

	r = gwp_free_conn_pair(w, gcp);
	if (unlikely(r)) {
		pr_err(&ctx->lh, "Failed to free connection pair: %s", strerror(-r));
		return r;
	}

	if (unlikely(w->accept_is_stopped)) {
		int x;
		/*
		 * If we have closed at least one file descriptor, we can
		 * rearm the main TCP socket with EPOLLIN to accept new
		 * connections.
		 */
		x = atomic_fetch_add(&ctx->nr_fd_closed, nr_fd_closed);
		r = rearm_accept(w, x);
		if (r)
			return r;
	}

	return 0;
}

static void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_info(&ctx->lh, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

__hot
static int handle_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	int fd, timer_fd, timeout, r;
	struct epoll_event ev;
	uint64_t cl_ev_bit;

	if (ctx->cfg.as_socks5) {
		/*
		 * If we are running as a SOCKS5 proxy, the initial connection
		 * does not have a target socket. We will create the target
		 * socket later, when the client sends a CONNECT command.
		 */
		timeout = cfg->socks5_timeout;
		fd = -1;
		gcp->conn_state = CONN_STATE_SOCKS5_DATA;
		cl_ev_bit = EV_BIT_CLIENT_SOCKS5;
		gcp->is_target_alive = false;
		gcp->s5_conn = gwp_socks5_conn_alloc(ctx->socks5);
		if (unlikely(!gcp->s5_conn))
			return -ENOMEM;
	} else {
		fd = gwp_create_sock_target(w, &gcp->target_addr,
					    &gcp->is_target_alive);
		if (unlikely(fd < 0)) {
			pr_err(&ctx->lh, "Failed to create target socket: %s",
				strerror(-fd));
			return fd;
		}
		timeout = cfg->connect_timeout;
		gcp->conn_state = CONN_STATE_FORWARDING;
		cl_ev_bit = EV_BIT_CLIENT;
	}

	if (timeout > 0) {
		timer_fd = gwp_create_timer(-1, timeout, 0);
		if (unlikely(timer_fd < 0)) {
			pr_err(&ctx->lh, "Failed to create connect timeout timer: %s",
				strerror(-timer_fd));
			__sys_close(fd);
			gwp_socks5_conn_free(gcp->s5_conn);
			gcp->s5_conn = NULL;
			return timer_fd;
		}
		gcp->timer_fd = timer_fd;
	}

	/*
	 * If epoll_ctl() fails, don't bother closing the target socket
	 * because it will be closed in free_conn_pair() anyway.
	 */
	gcp->target.fd = fd;
	gcp->client.ep_mask = EPOLLIN | EPOLLRDHUP;

	if (gcp->target.fd >= 0) {
		gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TARGET;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	} else {
		gcp->target.ep_mask = 0;
	}

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= cl_ev_bit;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	if (gcp->timer_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (gcp->target.fd >= 0)
		log_conn_pair_created(w, gcp);

	return 0;
}

static int handle_accept_error(struct gwp_wrk *w, int e)
{
	int r;

	if (likely(e == -EAGAIN || e == -EINTR))
		return e;

	if (likely(e == -EMFILE || e == -ENFILE || e == -ENOMEM)) {
		/*
		 * We have reached the limit of open files. Delete the
		 * main TCP socket from the epoll instance to avoid
		 * getting EPOLLIN in the next epoll_wait() call.
		 *
		 * Set the accept_is_stopped flag to true to let the
		 * worker thread know that it should rearm the main
		 * TCP socket with EPOLLIN again after it has at least
		 * closed a file descriptor.
		 *
		 * See free_conn_pair() for more details.
		 */
		pr_warn(&w->ctx->lh, "Too many open files, stop accepting new connections");
		w->accept_is_stopped = true;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, w->tcp_fd, NULL);
		if (unlikely(r))
			return r;

		atomic_fetch_add(&w->ctx->nr_accept_stopped, 1);
		return -EAGAIN;
	}

	pr_err(&w->ctx->lh, "Failed to accept new connection: %s", strerror(-e));
	return e;
}

__hot
static int __handle_ev_accept(struct gwp_wrk *w)
{
	static const int flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_conn_pair *gcp;
	struct sockaddr *addr;
	socklen_t addr_len;
	int fd, r;

	gcp = gwp_alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(&ctx->lh, "Failed to allocate connection pair on accept");
		return handle_accept_error(w, -ENOMEM);
	}

	addr = &gcp->client_addr.sa;
	addr_len = sizeof(gcp->client_addr);
	fd = __sys_accept4(w->tcp_fd, addr, &addr_len, flags);
	if (fd < 0) {
		r = handle_accept_error(w, fd);
		goto out_err;
	}

	gwp_setup_cli_sock_options(w, fd);
	gcp->client.fd = fd;
	pr_dbg(&ctx->lh, "New connection from %s (fd=%d)",
		ip_to_str(&gcp->client_addr), fd);

	if (!ctx->cfg.as_socks5)
		gcp->target_addr = ctx->target_addr;

	r = handle_new_client(w, gcp);
	if (r) {
		if (r == -EMFILE || r == -ENFILE)
			r = handle_accept_error(w, r);
		goto out_err;
	}

	return 0;

out_err:
	free_conn_pair(w, gcp);
	return r;
}

__hot
static int handle_ev_accept(struct gwp_wrk *w, struct epoll_event *ev)
{
	static const uint32_t nr_loop = 32;
	uint32_t i;
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on accept event");
		return -EIO;
	}

	for (i = 0; i < nr_loop; i++) {
		r = __handle_ev_accept(w);
		if (r) {
			if (likely(r == -EAGAIN || r == -EINTR)) {
				r = 0;
				break;
			}
		}
	}

	return r;
}

static int handle_ev_eventfd(struct gwp_wrk *w, struct epoll_event *ev)
{
	eventfd_t val;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on eventfd event");
		return -EIO;
	}

	return eventfd_read(w->ev_fd, &val);
}

static bool adj_epl_out(struct gwp_conn *src, struct gwp_conn *dst)
{
	if (src->len > 0) {
		if (!(dst->ep_mask & EPOLLOUT)) {
			dst->ep_mask |= EPOLLOUT;
			return true;
		}
	} else {
		if (dst->ep_mask & EPOLLOUT) {
			dst->ep_mask &= ~EPOLLOUT;
			return true;
		}
	}

	return false;
}

static bool adj_epl_in(struct gwp_conn *src)
{
	if (src->cap - src->len) {
		if (!(src->ep_mask & EPOLLIN)) {
			src->ep_mask |= EPOLLIN;
			return true;
		}
	} else {
		if (src->ep_mask & EPOLLIN) {
			src->ep_mask &= ~EPOLLIN;
			return true;
		}
	}

	return false;
}

__hot
static int adjust_epl_mask(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	bool client_need_ctl = false;
	bool target_need_ctl = false;
	struct epoll_event ev;
	int r;

	client_need_ctl |= adj_epl_out(&gcp->target, &gcp->client);
	target_need_ctl |= adj_epl_out(&gcp->client, &gcp->target);
	client_need_ctl |= adj_epl_in(&gcp->client);
	target_need_ctl |= adj_epl_in(&gcp->target);

	if (client_need_ctl) {
		ev.events = gcp->client.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_CLIENT;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
		if (unlikely(r))
			return r;
	}

	if (target_need_ctl) {
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TARGET;

		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev);
		if (unlikely(r))
			return r;
	}

	return 0;
}

__hot
static void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	conn->len -= len;
	if (conn->len)
		memmove(conn->buf, conn->buf + len, conn->len);
}

__hot
static ssize_t __do_recv(struct gwp_conn *src)
{
	ssize_t ret;
	size_t len;
	char *buf;

	len = src->cap - src->len;
	if (unlikely(len == 0))
		return 0;

	buf = src->buf + src->len;
	ret = __sys_recv(src->fd, buf, len, MSG_NOSIGNAL);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
		ret = 0;
	} else if (!ret) {
		return -ECONNRESET;
	}

	src->len += (size_t)ret;
	assert(src->len <= src->cap);
	return ret;
}

__hot
static ssize_t __do_send(struct gwp_conn *src, struct gwp_conn *dst)
{
	ssize_t ret;

	if (unlikely(src->len == 0))
		return 0;

	ret = __sys_send(dst->fd, src->buf, src->len, MSG_NOSIGNAL);
	if (unlikely(ret < 0)) {
		if (ret != -EAGAIN && ret != -EINTR)
			return ret;
		ret = 0;
	} else if (!ret) {
		return -ECONNRESET;
	}

	gwp_conn_buf_advance(src, (size_t)ret);
	return ret;
}

__hot
static int do_splice(struct gwp_conn *src, struct gwp_conn *dst, bool do_recv,
		     bool do_send)
{
	ssize_t ret;

	if (do_recv) {
		ret = __do_recv(src);
		if (unlikely(ret < 0))
			return ret;
	}

	if (do_send) {
		ret = __do_send(src, dst);
		if (unlikely(ret < 0))
			return ret;
	}

	return 0;
}

static int get_local_addr(struct gwp_ctx *ctx, int fd,
			  struct gwp_socks5_addr *ba)
{
	struct gwp_sockaddr t;
	socklen_t len = sizeof(t);
	int r;

	r = __sys_getsockname(fd, &t.sa, &len);
	if (r < 0) {
		pr_err(&ctx->lh, "getsockname error: %s", strerror(-r));
		return r;
	}

	switch (t.sa.sa_family) {
	case AF_INET:
		ba->ver = GWP_SOCKS5_ATYP_IPV4;
		memcpy(&ba->ip4, &t.i4.sin_addr, 4);
		ba->port = ntohs(t.i4.sin_port);
		return 0;
	case AF_INET6:
		ba->ver = GWP_SOCKS5_ATYP_IPV6;
		memcpy(&ba->ip6, &t.i6.sin6_addr, 16);
		ba->port = ntohs(t.i6.sin6_port);
		return 0;
	default:
		pr_err(&ctx->lh, "Unsupported address family %d for local socket",
			t.sa.sa_family);
		return -EAFNOSUPPORT;
	}
}

static int socks5_translate_err(int err)
{
	switch (err) {
	case 0:
		return GWP_SOCKS5_REP_SUCCESS;
	case -EPERM:
	case -EACCES:
		return GWP_SOCKS5_REP_NOT_ALLOWED;
	case -ENETUNREACH:
		return GWP_SOCKS5_REP_NETWORK_UNREACHABLE;
	case -EHOSTUNREACH:
		return GWP_SOCKS5_REP_HOST_UNREACHABLE;
	case -ECONNREFUSED:
		return GWP_SOCKS5_REP_CONN_REFUSED;
	case -ETIMEDOUT:
		return GWP_SOCKS5_REP_TTL_EXPIRED;
	default:
		return GWP_SOCKS5_REP_FAILURE;
	}
}

__hot
static int prep_and_send_socks5_rep_connect(struct gwp_wrk *w,
					    struct gwp_conn_pair *gcp,
					    int err)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr ba;
	size_t out_len;
	ssize_t sr;
	void *out;
	int r;

	if (err == 0) {
		r = get_local_addr(w->ctx, gcp->target.fd, &ba);
		if (unlikely(r))
			return r;
	} else {
		memset(&ba, 0, sizeof(ba));
		ba.ver = GWP_SOCKS5_ATYP_IPV4;
	}

	err = socks5_translate_err(err);
	out = gcp->target.buf + gcp->target.len;
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_cmd_connect_res(sc, &ba, err, out, &out_len);
	if (r < 0)
		return r;

	gcp->target.len += out_len;
	sr = __do_send(&gcp->target, &gcp->client);
	if (unlikely(sr < 0))
		return sr;

	return 0;
}

__hot
static int handle_ev_target_conn_result(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	socklen_t l = sizeof(int);
	int r, err = 0;
	ssize_t sr;

	r = __sys_getsockopt(gcp->target.fd, SOL_SOCKET, SO_ERROR, &err, &l);
	if (unlikely(r < 0)) {
		pr_err(&ctx->lh, "getsockopt error: %s", strerror(-r));
		goto out_conn_err;
	}

	if (likely(!err)) {
		pr_info(&ctx->lh, "Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
			gcp->target.fd, gcp->idx, ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
	} else {
		pr_err(&ctx->lh, "Target socket connect error: %s (fd=%d, idx=%u, ca=%s, ta=%s)",
			strerror(err), gcp->target.fd, gcp->idx,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
		r = -err;
		goto out_conn_err;
	}

	if (gcp->timer_fd >= 0) {
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_CMD_CONNECT) {
		r = prep_and_send_socks5_rep_connect(w, gcp, 0);
		if (r)
			return r;
	}

	gcp->is_target_alive = true;
	gcp->conn_state = CONN_STATE_FORWARDING;

	if (gcp->client.len) {
		sr = __do_send(&gcp->client, &gcp->target);
		if (unlikely(sr < 0))
			return sr;
	}

	return adjust_epl_mask(w, gcp);

out_conn_err:
	if (gcp->conn_state == CONN_STATE_SOCKS5_CMD_CONNECT) {
		int x = prep_and_send_socks5_rep_connect(w, gcp, err);
		if (x)
			return x;
	}
	return r;
}

__hot
static int handle_ev_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on target connection event");
		return -ECONNRESET;
	}

	if (!gcp->is_target_alive)
		return handle_ev_target_conn_result(w, gcp);

	assert(gcp->conn_state == CONN_STATE_FORWARDING);
	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->client, &gcp->target, true, true);
		if (r)
			return r;
	}

	if (ev->events & (EPOLLRDHUP | EPOLLHUP))
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

__hot
static int handle_ev_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(&w->ctx->lh, "EPOLLERR on client connection event");
		return -ECONNRESET;
	}

	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->client, &gcp->target, true, gcp->is_target_alive);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & (EPOLLRDHUP | EPOLLHUP))
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

__hot
static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gcp->timer_fd < 0)
		return 0;

	pr_warn(&ctx->lh, "Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));

	return -ETIMEDOUT;
}

__hot
static int handle_socks5_connect_domain_async(struct gwp_wrk *w,
					      struct gwp_conn_pair *gcp,
					      const char *host,
					      const char *port)
{
	struct gwp_dns_ctx *dns = w->ctx->dns;
	struct gwp_dns_entry *gde;
	struct epoll_event ev;
	int r;

	gde = gwp_dns_queue(dns, host, port);
	if (unlikely(!gde)) {
		pr_err(&w->ctx->lh, "Failed to allocate DNS entry for %s:%s", host, port);
		return -ENOMEM;
	}

	ev.events = EPOLLIN;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_DNS_QUERY;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gde->ev_fd, &ev);
	if (unlikely(r)) {
		gwp_dns_entry_put(gde);
		return r;
	}

	gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
	gcp->gde = gde;
	return -EINPROGRESS;
}

static int socks5_prepare_target_addr_domain(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_socks5_addr *dst;
	const char *host;
	char portstr[6];
	uint16_t port;
	int r;

	dst = &gcp->s5_conn->dst_addr;
	port = ntohs(dst->port);
	host = dst->domain.str;
	snprintf(portstr, sizeof(portstr), "%hu", port);
	r = gwp_dns_cache_lookup(ctx->dns, host, portstr, &gcp->target_addr);
	if (!r) {
		/*
		 * Found the address in the DNS cache!
		 */
		pr_dbg(&ctx->lh, "Found %s:%s in DNS cache %s", host, portstr,
			ip_to_str(&gcp->target_addr));
		return 0;
	}

	return handle_socks5_connect_domain_async(w, gcp, host, portstr);
}

static int socks5_prepare_target_addr(struct gwp_wrk *w,
				      struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *ta = &gcp->target_addr;
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	struct gwp_socks5_addr *dst;

	assert(sc);
	assert(sc->state == GWP_SOCKS5_ST_CMD_CONNECT);

	dst = &sc->dst_addr;
	memset(ta, 0, sizeof(*ta));
	switch (dst->ver) {
	case GWP_SOCKS5_ATYP_IPV4:
		memcpy(&ta->i4.sin_addr, &dst->ip4, 4);
		ta->i4.sin_port = dst->port;
		ta->i4.sin_family = AF_INET;
		return 0;
	case GWP_SOCKS5_ATYP_IPV6:
		memcpy(&ta->i6.sin6_addr, &dst->ip6, 16);
		ta->i6.sin6_port = dst->port;
		ta->i6.sin6_family = AF_INET6;
		return 0;
	case GWP_SOCKS5_ATYP_DOMAIN:
		return socks5_prepare_target_addr_domain(w, gcp);
	}

	return -ENOSYS;
}

__hot
static int handle_socks5_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	int tfd, r;

	if (gcp->timer_fd >= 0) {
		/*
		 * If we already have a timer fd, close it and use the new
		 * timer fd instead. There are two timers used in the socks5
		 * case:
		 *
		 *    1. Timer for waiting socks5 auth and command.
		 *    2. Timer for waiting target connect().
		 *
		 * If we've reached this point. Timer no (1) has already
		 * served its purpose and we can close it.
		 */
		__sys_close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	tfd = gwp_create_sock_target(w, &gcp->target_addr,
				     &gcp->is_target_alive);
	if (unlikely(tfd < 0)) {
		pr_err(&w->ctx->lh, "Failed to create target socket: %s", strerror(-tfd));
		return tfd;
	}

	r = w->ctx->cfg.connect_timeout;
	if (r > 0) {
		r = gwp_create_timer(-1, r, 0);
		if (unlikely(r < 0))
			return r;
		gcp->timer_fd = r;
	}

	gcp->target.fd = tfd;
	gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	/*
	 * If epoll_ctl() calls fail, don't bother closing the
	 * newly created file descriptors as they will be closed
	 * in free_conn_pair() anyway.
	 */
	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_CLIENT;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	ev.events = gcp->target.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_TARGET;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->target.fd, &ev);
	if (unlikely(r))
		return r;

	if (gcp->timer_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &ev);
		if (unlikely(r))
			return r;
	}

	gcp->conn_state = CONN_STATE_SOCKS5_CMD_CONNECT;
	log_conn_pair_created(w, gcp);
	return 0;
}

__hot
static int handle_socks5_pollout(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	ssize_t sr;
	int r;

	sr = __do_send(&gcp->target, &gcp->client);
	if (unlikely(sr < 0))
		return sr;

	if (likely(!adj_epl_out(&gcp->target, &gcp->client)))
		return 0;

	pr_dbg(&w->ctx->lh, "Handling short send on client SOCKS5 data");
	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_CLIENT_SOCKS5;
	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
	if (unlikely(r))
		return r;

	return -EAGAIN;
}

static int handle_socks5_data(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_socks5_conn *sc = gcp->s5_conn;
	size_t out_len, in_len;
	void *in, *out;
	int r;

	assert(sc);

	in = gcp->client.buf;
	in_len = gcp->client.len;
	out = gcp->target.buf + gcp->target.len;
	out_len = gcp->target.cap - gcp->target.len;
	r = gwp_socks5_conn_handle_data(sc, in, &in_len, out, &out_len);
	gwp_conn_buf_advance(&gcp->client, in_len);
	gcp->target.len += out_len;
	if (r)
		return (r == -EAGAIN) ? 0 : r;

	if (sc->state == GWP_SOCKS5_ST_CMD_CONNECT) {
		r = socks5_prepare_target_addr(w, gcp);
		if (r)
			return (r == -EINPROGRESS) ? 0 : r;

		r = handle_socks5_connect(w, gcp);
	}

	return r;
}

__hot
static int handle_ev_client_socks5(struct gwp_wrk *w,
				   struct gwp_conn_pair *gcp,
				   struct epoll_event *ev)
{
	struct gwp_ctx *ctx = w->ctx;
	ssize_t sr;
	int r = 0;

	assert(ctx->cfg.as_socks5);

	if (unlikely(ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		pr_info(&ctx->lh, "(EPOLLERR|EPOLLHUP|EPOLLRDHUP) on client SOCKS5 event");
		return -ECONNRESET;
	}

	if (ev->events & EPOLLOUT) {
		r = handle_socks5_pollout(w, gcp);
		if (r)
			return (r == -EAGAIN) ? 0 : r;
	}

	if (ev->events & EPOLLIN) {
		sr = __do_recv(&gcp->client);

		/*
		 * sr == 0 is fine, but must be back to
		 * epoll_wait() before continuing.
		 */
		if (unlikely(sr <= 0))
			return sr;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_DATA) {
		r = handle_socks5_data(w, gcp);
		if (gcp->target.len) {
			r = handle_socks5_pollout(w, gcp);
			if (r && r != -EAGAIN)
				return r;
		}
	}

	return r;
}

static void log_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  struct gwp_dns_entry *gde)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gde->res) {
		pr_dbg(&ctx->lh, "DNS query failed: %s:%s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
			gde->name, gde->service, gde->res,
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr));
		return;
	}

	pr_dbg(&ctx->lh, "DNS query resolved: %s:%s -> %s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
		gde->name, gde->service, ip_to_str(&gde->addr), gde->res,
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr));
}

__hot
static int handle_ev_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_entry *gde = gcp->gde;
	int r;

	assert(gde);
	assert(gde->ev_fd >= 0);
	assert(gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY);

	r = __sys_epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gde->ev_fd, NULL);
	if (unlikely(r))
		return r;

	log_dns_query(w, gcp, gde);
	if (likely(!gde->res)) {
		gcp->target_addr = gde->addr;
		r = handle_socks5_connect(w, gcp);
	} else {
		r = prep_and_send_socks5_rep_connect(w, gcp, gde->res);
	}

	gwp_dns_entry_put(gde);
	gcp->gde = NULL;

	if (unlikely(gcp->conn_state == CONN_STATE_SOCKS5_ERR))
		return -ECONNRESET;

	return r;
}

static int handle_ev_socks5_auth_file(struct gwp_wrk *w)
{
	static const size_t l = sizeof(struct inotify_event) + NAME_MAX + 1;
	ssize_t r;

	assert(w->ctx->cfg.as_socks5);
	assert(w->ctx->socks5);

	r = __sys_read(w->ctx->ino_fd, w->ctx->ino_buf, l);
	if (unlikely(r < 0)) {
		if (r == -EINTR || r == -EAGAIN)
			return 0;

		pr_err(&w->ctx->lh, "Failed to read inotify event: %s", strerror(-r));
		return r;
	}

	gwp_socks5_auth_reload(w->ctx->socks5);
	pr_info(&w->ctx->lh, "Reloaded SOCKS5 authentication file");
	return 0;
}

static bool is_ev_bit_conn_pair(uint64_t ev_bit)
{
	static const uint64_t conn_pair_ev_bit =
		EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER |
		EV_BIT_CLIENT_SOCKS5 | EV_BIT_DNS_QUERY;

	return !!(ev_bit & conn_pair_ev_bit);
}

static int handle_event(struct gwp_wrk *w, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *udata;
	int r;

	ev_bit = GET_EV_BIT(ev->data.u64);
	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	udata = ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_ACCEPT:
		r = handle_ev_accept(w, ev);
		break;
	case EV_BIT_EVENTFD:
		r = handle_ev_eventfd(w, ev);
		break;
	case EV_BIT_TARGET:
		r = handle_ev_target(w, udata, ev);
		break;
	case EV_BIT_CLIENT:
		r = handle_ev_client(w, udata, ev);
		break;
	case EV_BIT_TIMER:
		r = handle_ev_timer(w, udata);
		break;
	case EV_BIT_CLIENT_SOCKS5:
		r = handle_ev_client_socks5(w, udata, ev);
		break;
	case EV_BIT_DNS_QUERY:
		r = handle_ev_dns_query(w, udata);
		break;
	case EV_BIT_SOCKS5_AUTH_FILE:
		r = handle_ev_socks5_auth_file(w);
		break;
	default:
		pr_err(&w->ctx->lh, "Unknown event bit: %" PRIu64, ev_bit);
		return -EINVAL;
	}

	if (r && is_ev_bit_conn_pair(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;
		r = free_conn_pair(w, gcp);
	}

	return r;
}

static int handle_events(struct gwp_wrk *w, int nr_events)
{
	struct epoll_event *events = w->events;
	struct gwp_ctx *ctx = w->ctx;
	int i, r = 0;

	for (i = 0; i < nr_events; i++) {
		if (unlikely(ctx->stop))
			break;

		r = handle_event(w, &events[i]);
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
