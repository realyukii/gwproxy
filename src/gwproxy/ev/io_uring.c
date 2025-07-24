// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <gwproxy/ev/io_uring.h>
#include <gwproxy/gwproxy.h>
#include <gwproxy/common.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <sys/inotify.h>
#include <liburing.h>
#include <poll.h>

__cold
int gwp_ctx_init_thread_io_uring(struct gwp_wrk *w)
{
	struct iou *iou;
	int r;

	iou = calloc(1, sizeof(*iou));
	if (!iou)
		return -ENOMEM;

	r = io_uring_queue_init(1024, &iou->ring, 0);
	if (r < 0)
		goto err_free_iou;

	w->iou = iou;
	return 0;

err_free_iou:
	free(iou);
	return r;
}

__cold
void gwp_ctx_free_thread_io_uring(struct gwp_wrk *w)
{
	io_uring_queue_exit(&w->iou->ring);
	free(w->iou);
	w->iou = NULL;
}

static void log_submit_err(struct gwp_wrk *w, int r)
{
	pr_err(&w->ctx->lh, "io_uring_submit(): %s", strerror(-r));
}

static struct io_uring_sqe *get_sqe_nofail(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	struct io_uring_sqe *sqe;
	struct iou *iou = w->iou;
	int r;

	sqe = io_uring_get_sqe(&iou->ring);
	if (unlikely(!sqe)) {
		r = io_uring_submit(&iou->ring);
		if (unlikely(r < 0)) {
			log_submit_err(w, r);
			return NULL;
		}

		sqe = io_uring_get_sqe(&iou->ring);
		if (unlikely(!sqe))  {
			/* io_uring bug? */
			pr_err(&ctx->lh, "io_uring_get_sqe() failed!");
			return NULL;
		}
	}

	return sqe;
}

static int prep_nr_sqes(struct gwp_wrk *w, unsigned nr)
{
	if (io_uring_sq_space_left(&w->iou->ring) < nr) {
		int r = io_uring_submit(&w->iou->ring);
		if (unlikely(r < 0)) {
			log_submit_err(w, r);
			return r;
		}
	}

	return 0;
}

static int arm_accept(struct gwp_wrk *w)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);
	struct iou *iou = w->iou;
	struct sockaddr *addr = &iou->accept_addr.sa;
	socklen_t *addr_len = &iou->accept_addr_len;

	if (unlikely(!s)) {
		pr_err(&w->ctx->lh, "Failed to get io_uring sqe for accept");
		return -ENOMEM;
	}

	*addr_len = sizeof(iou->accept_addr);
	io_uring_prep_accept(s, w->tcp_fd, addr, addr_len, SOCK_CLOEXEC);
	s->flags |= IOSQE_ASYNC;
	s->user_data = EV_BIT_ACCEPT;
	return 0;
}

static void prep_close(struct gwp_wrk *w, int fd)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);
	if (unlikely(!s)) {
		pr_err(&w->ctx->lh, "Failed to get io_uring sqe for close");
		__sys_close(fd);
		return;
	}

	io_uring_prep_close(s, fd);
	s->flags |= IOSQE_CQE_SKIP_SUCCESS;
	s->user_data = EV_BIT_CLOSE | (unsigned)fd;
	pr_dbg(&w->ctx->lh, "Prepared close for fd=%d", fd);
}

static void get_gcp(struct gwp_conn_pair *gcp)
{
	gcp->ref_cnt++;
}

static bool put_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	int tm_fd, tg_fd, cl_fd;

	pr_dbg(&w->ctx->lh,
		"Put connection pair (idx=%u, cfd=%d, tfd=%d, tmfd=%d, ca=%s, ta=%s, ref_cnt=%hhu)",
		gcp->idx,
		gcp->client.fd,
		gcp->target.fd,
		gcp->timer_fd,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr),
		gcp->ref_cnt);
	if (gcp->ref_cnt-- > 1)
		return false;

	tm_fd = gcp->timer_fd;
	tg_fd = gcp->target.fd;
	cl_fd = gcp->client.fd;
	gcp->client.fd = gcp->target.fd = gcp->timer_fd = -1;
	gwp_free_conn_pair(w, gcp);

	if (tm_fd >= 0)
		prep_close(w, tm_fd);
	prep_close(w, tg_fd);
	prep_close(w, cl_fd);
	return true;
}

static struct io_uring_sqe *prep_connect_target(struct gwp_wrk *w,
						struct gwp_conn_pair *gcp)
{
	struct sockaddr *addr = &gcp->target_addr.sa;
	int fd = gcp->target.fd;
	struct io_uring_sqe *s;
	socklen_t addr_len;

	if (addr->sa_family == AF_INET)
		addr_len = sizeof(struct sockaddr_in);
	else
		addr_len = sizeof(struct sockaddr_in6);

	s = get_sqe_nofail(w);
	fd = gcp->target.fd;
	io_uring_prep_connect(s, fd, addr, addr_len);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_TARGET_CONNECT;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared connect for target fd=%d, addr=%s, ref_cnt=%hhu",
		fd, ip_to_str(&gcp->target_addr), gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_recv_target(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.cap - gcp->target.len;
	char *buf = gcp->target.buf + gcp->target.len;
	int fd = gcp->target.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
	io_uring_prep_recv(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_TARGET_RECV;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared recv for target fd=%d, len=%zu, buf=%p, ref_cnt=%hhu",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_recv_client(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->client.cap - gcp->client.len;
	char *buf = gcp->client.buf + gcp->client.len;
	int fd = gcp->client.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
	io_uring_prep_recv(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_CLIENT_RECV;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared recv for client fd=%d, len=%zu, buf=%p, ref_cnt=%hhu",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_send_target(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->client.len;
	char *buf = gcp->client.buf;
	int fd = gcp->target.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
	io_uring_prep_send(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_TARGET_SEND;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared send for target fd=%d, len=%zu, buf=%p, ref_cnt=%hhu",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_send_client(struct gwp_wrk *w,
					     struct gwp_conn_pair *gcp)
{
	size_t len = gcp->target.len;
	char *buf = gcp->target.buf;
	int fd = gcp->client.fd;
	struct io_uring_sqe *s;

	s = get_sqe_nofail(w);
	io_uring_prep_send(s, fd, buf, len, MSG_NOSIGNAL);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_CLIENT_SEND;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared send for client fd=%d, len=%zu, buf=%p, ref_cnt=%hhu",
		fd, len, buf, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_add_timer_target(struct gwp_wrk *w,
						  struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s = get_sqe_nofail(w);
	int fd = gcp->timer_fd;
	assert(fd >= 0);
	io_uring_prep_read(s, fd, &gcp->timer_mem, sizeof(gcp->timer_mem), 0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_TIMER;
	s->flags |= IOSQE_ASYNC;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared add timer for target fd=%d, ref_cnt=%hhu",
		fd, gcp->ref_cnt);
	return s;
}

static struct io_uring_sqe *prep_del_timer_target(struct gwp_wrk *w,
						  struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s;
	int fd = gcp->timer_fd;

	if (fd < 0)
		return NULL;

	s = get_sqe_nofail(w);
	io_uring_prep_cancel64(s, EV_BIT_TIMER | (uintptr_t)gcp, 0);
	io_uring_sqe_set_data(s, gcp);
	s->user_data |= EV_BIT_TIMER_DEL;
	s->flags |= IOSQE_IO_HARDLINK;
	prep_close(w, fd);
	gcp->timer_fd = -1;
	get_gcp(gcp);
	pr_dbg(&w->ctx->lh,
		"Prepared delete timer for target fd=%d, ref_cnt=%hhu",
		fd, gcp->ref_cnt);
	return s;
}

static void shutdown_gcp(struct gwp_ctx *ctx, struct gwp_conn_pair *gcp)
{
	if (gcp->is_shutdown)
		return;

	if (gcp->target.fd >= 0) {
		pr_dbg(&ctx->lh, "Shutting down target connection (fd=%d)", gcp->target.fd);
		__sys_shutdown(gcp->target.fd, SHUT_RDWR);
	}

	if (gcp->client.fd >= 0) {
		pr_dbg(&ctx->lh, "Shutting down client connection (fd=%d)", gcp->client.fd);
		__sys_shutdown(gcp->client.fd, SHUT_RDWR);
	}

	gcp->is_shutdown = true;
}

static int arm_gcp(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct io_uring_sqe *s;
	int fd, r;

	r = prep_nr_sqes(w, 4);
	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Failed to prepare sqes for connection pair");
		return r;
	}

	s = prep_connect_target(w, gcp);
	s->flags |= IOSQE_ASYNC | IOSQE_IO_LINK;

	s = prep_recv_client(w, gcp);

	s = prep_recv_target(w, gcp);
	s->flags |= IOSQE_ASYNC;

	fd = gcp->timer_fd;
	if (fd >= 0) {
		s = prep_add_timer_target(w, gcp);
		s->flags |= IOSQE_ASYNC;
	}

	return 0;
}

static int __handle_ev_accept(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	int fd = cqe->res, tg_fd, tm_fd, r;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_conn_pair *gcp;

	if (unlikely(fd < 0)) {
		if (fd == -EAGAIN || fd == -EINTR)
			return 0;

		/*
		 * TODO(ammarfaizi2): Handle -EMFILE and -ENFILE.
		 */
		pr_err(&ctx->lh, "accept() failed: %s", strerror(-fd));
		return fd;
	}

	tg_fd = gwp_create_sock_target(w, &ctx->target_addr, NULL, false);
	if (unlikely(tg_fd < 0)) {
		pr_err(&ctx->lh, "Create target socket: %s", strerror(-tg_fd));
		goto out_close;
	}

	if (ctx->cfg.connect_timeout > 0) {
		tm_fd = gwp_create_timer(-1, ctx->cfg.connect_timeout, 0);
		if (unlikely(tm_fd < 0)) {
			pr_err(&ctx->lh, "gwp_create_timer: %s", strerror(-tm_fd));
			goto out_close_tg_fd;
		}
	} else {
		tm_fd = -1;
	}

	gcp = gwp_alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(&ctx->lh, "Allocate connection pair: %s", strerror(ENOMEM));
		goto out_close_tm_fd;
	}
	gcp->ref_cnt = 0;
	gcp->is_dying = false;
	gcp->is_shutdown = false;

	gcp->client.fd = fd;
	gcp->target.fd = tg_fd;
	gcp->timer_fd = tm_fd;
	gcp->client_addr = w->iou->accept_addr;
	gcp->target_addr = ctx->target_addr;
	gcp->is_target_alive = false;
	r = arm_gcp(w, gcp);
	if (unlikely(r))
		goto out_free_pair;

	log_conn_pair_created(w, gcp);
	return r;

out_free_pair:
	gcp->client.fd = gcp->target.fd = gcp->timer_fd = -1;
	gwp_free_conn_pair(w, gcp);
out_close_tm_fd:
	if (tm_fd >= 0)
		prep_close(w, tm_fd);
out_close_tg_fd:
	prep_close(w, tg_fd);
out_close:
	prep_close(w, fd);
	return -ENOMEM;
}

static int handle_ev_accept(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	int r = __handle_ev_accept(w, cqe);

	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Failed to handle accept event: %s", strerror(-r));
		return r;
	}

	return arm_accept(w);
}

static int handle_ev_target_connect(struct gwp_wrk *w, void *udata, int res)
{
	struct gwp_conn_pair *gcp = udata;

	if (unlikely(res < 0)) {
		pr_err(&w->ctx->lh, "Target connect failed: %s", strerror(-res));
		gcp->is_dying = true;
		return 0;
	}

	prep_del_timer_target(w, gcp);
	gcp->is_target_alive = true;
	pr_info(&w->ctx->lh,
		"Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		gcp->target.fd, gcp->idx,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));

	return 0;
}

static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			   bool is_timer_del, int res)
{
	struct gwp_ctx *ctx = w->ctx;

	if (!gcp->is_target_alive) {
		gcp->is_dying = true;
		assert(is_timer_del == false);
		pr_warn(&ctx->lh,
			"Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
	}

	pr_dbg(&ctx->lh,
		"Timer event handled (idx=%u, cfd=%d, tfd=%d, tmfd=%d, ca=%s, ta=%s, itd=(b)%d, res=%d)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		gcp->timer_fd, ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr), is_timer_del, res);

	return 0;
}

static int handle_ev_client_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	struct io_uring_sqe *s;
	int r = cqe->res;

	if (unlikely(r < 0)) {
		if (r == -EAGAIN || r == -EINTR) {
			s = prep_recv_client(w, gcp);
			s->flags |= IOSQE_ASYNC;
			return 0;
		}

		if (r)
			pr_err(&w->ctx->lh, "Client recv: %s", strerror(-r));

		gcp->is_dying = true;
		return 0;
	} else if (unlikely(!r)) {
		gcp->is_dying = true;
		return 0;
	}

	gcp->client.len += (size_t)r;
	prep_send_target(w, gcp);
	return 0;
}

static int handle_ev_target_recv(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	struct io_uring_sqe *s;
	int r = cqe->res;

	if (unlikely(r < 0)) {
		if (r == -EAGAIN || r == -EINTR) {
			s = prep_recv_target(w, gcp);
			s->flags |= IOSQE_ASYNC;
			return 0;
		}

		if (!r)
			pr_err(&w->ctx->lh, "Target recv: %s", strerror(-r));

		gcp->is_dying = true;
		return 0;
	} else if (unlikely(!r)) {
		gcp->is_dying = true;
		return r;
	}

	gcp->target.len += (size_t)r;
	prep_send_client(w, gcp);
	return 0;
}

static int handle_ev_client_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Client send failed: %s", strerror(-r));
		gcp->is_dying = true;
		return 0;
	} else if (unlikely(!r)) {
		gcp->is_dying = true;
		return 0;
	}

	gwp_conn_buf_advance(&gcp->target, (size_t)r);
	prep_recv_target(w, gcp);
	return 0;
}

static int handle_ev_target_send(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				 struct io_uring_cqe *cqe)
{
	int r = cqe->res;

	if (unlikely(r < 0)) {
		pr_err(&w->ctx->lh, "Target send failed: %s", strerror(-r));
		gcp->is_dying = true;
		return 0;
	} else if (unlikely(!r)) {
		gcp->is_dying = true;
		return 0;
	}

	gwp_conn_buf_advance(&gcp->client, (size_t)r);
	prep_recv_client(w, gcp);
	return 0;
}

static bool is_udata_gcp(uint64_t ev_bit)
{
	switch (ev_bit) {
	case EV_BIT_CLIENT_RECV:
	case EV_BIT_TARGET_RECV:
	case EV_BIT_CLIENT_SEND:
	case EV_BIT_TARGET_SEND:
	case EV_BIT_TARGET_CONNECT:
	case EV_BIT_TIMER:
	case EV_BIT_TIMER_DEL:
		return true;
	default:
		return false;
	}
}

static int handle_event(struct gwp_wrk *w, struct io_uring_cqe *cqe)
{
	void *udata = (void *)CLEAR_EV_BIT(cqe->user_data);
	uint64_t ev_bit = GET_EV_BIT(cqe->user_data);
	struct gwp_ctx *ctx = w->ctx;
	const char *inv_op;
	int r;

	switch (ev_bit) {
	case EV_BIT_ACCEPT:
		pr_dbg(&ctx->lh, "Handling accept event");
		r = handle_ev_accept(w, cqe);
		break;
	case EV_BIT_TARGET_CONNECT:
		pr_dbg(&ctx->lh, "Handling target connect event");
		r = handle_ev_target_connect(w, udata, cqe->res);
		break;
	case EV_BIT_TIMER:
		pr_dbg(&ctx->lh, "Handling timer event: %d", cqe->res);
		r = handle_ev_timer(w, udata, false, cqe->res);
		break;
	case EV_BIT_TIMER_DEL:
		pr_dbg(&ctx->lh, "Handling timer event delete: %d", cqe->res);
		r = handle_ev_timer(w, udata, true, cqe->res);
		break;
	case EV_BIT_CLIENT_RECV:
		pr_dbg(&ctx->lh, "Handling client recv event: %d", cqe->res);
		r = handle_ev_client_recv(w, udata, cqe);
		break;
	case EV_BIT_TARGET_RECV:
		pr_dbg(&ctx->lh, "Handling target recv event: %d", cqe->res);
		r = handle_ev_target_recv(w, udata, cqe);
		break;
	case EV_BIT_CLIENT_SEND:
		pr_dbg(&ctx->lh, "Handling client send event: %d", cqe->res);
		r = handle_ev_client_send(w, udata, cqe);
		break;
	case EV_BIT_TARGET_SEND:
		pr_dbg(&ctx->lh, "Handling target send event: %d", cqe->res);
		r = handle_ev_target_send(w, udata, cqe);
		break;
	case EV_BIT_CLOSE:
		inv_op = "close";
		goto out_bug;
	case EV_BIT_TARGET_SHUTDOWN:
		inv_op = "target shutdown";
		goto out_bug;
	case EV_BIT_CLIENT_SHUTDOWN:
		inv_op = "client shutdown";
		goto out_bug;
		break;
	default:
		pr_err(&ctx->lh, "Unknown event bit: %" PRIu64 "; res=%d", ev_bit, cqe->res);
		r = -EINVAL;
		break;
	}

	if (is_udata_gcp(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;

		if (gcp->is_dying && !gcp->is_shutdown)
			shutdown_gcp(w->ctx, gcp);

		put_gcp(w, gcp);
	}

	return r;

out_bug:
	pr_err(&ctx->lh, "Bug, invalid %s: res=%d, fd=%ld, s=%s", inv_op,
		cqe->res, (intptr_t)udata, strerror(-cqe->res));
	return cqe->res;
}

static int handle_events(struct gwp_wrk *w)
{
	struct iou *iou = w->iou;
	struct io_uring_cqe *cqe;
	unsigned head, i = 0;
	int r = 0;

	io_uring_for_each_cqe(&iou->ring, head, cqe) {
		i++;
		r = handle_event(w, cqe);
		if (unlikely(r))
			break;
	}

	if (i)
		io_uring_cq_advance(&iou->ring, i);

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	struct iou *iou = w->iou;
	int r;

	r = io_uring_submit_and_wait(&iou->ring, 1);
	if (unlikely(r < 0)) {
		log_submit_err(w, r);
		return r;
	}

	return 0;
}

static void submit_unconsumed_sqes(struct gwp_wrk *w)
{
	int r;

	if (io_uring_sq_ready(&w->iou->ring) > 0) {
		r = io_uring_submit(&w->iou->ring);
		if (unlikely(r < 0))
			log_submit_err(w, r);
	}
}

int gwp_ctx_thread_entry_io_uring(struct gwp_wrk *w)
{
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	r = arm_accept(w);
	if (unlikely(r < 0)) {
		pr_err(&ctx->lh, "Failed to arm accept: %s", strerror(-r));
		return r;
	}

	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;

		r = handle_events(w);
		if (unlikely(r < 0))
			break;
	}

	/*
	 * Just in case we errored out before prep_close() SQEs
	 * were submitted, we need to submit them now. Otherwise,
	 * we risk leaking file descriptors.
	 */
	submit_unconsumed_sqes(w);
	return r;
}
