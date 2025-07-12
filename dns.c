// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sys/eventfd.h>

struct gwp_dns_ctx;

struct gwp_dns_wrk {
	struct gwp_dns_ctx	*ctx;
	uint32_t		id;
	pthread_t		thread;
};

struct gwp_dns_ctx {
	volatile bool		should_stop;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	uint32_t		nr_sleeping;
	uint32_t		nr_entries;
	struct gwp_dns_entry	*head;
	struct gwp_dns_entry	*tail;
	struct gwp_dns_wrk	*workers;
	struct gwp_dns_cfg	cfg;
};

static bool iterate_addr_list(struct addrinfo *res, struct gwp_sockaddr *gs,
			      uint32_t restyp)
{
	struct addrinfo *ai;

	if (restyp == GWP_DNS_RESTYP_IPV4_ONLY) {
		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET)
				continue;
			gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			return true;
		}
		return false;
	}
	
	if (restyp == GWP_DNS_RESTYP_IPV6_ONLY) {
		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET6)
				continue;
			gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}
		return false;
	}

	if (restyp == GWP_DNS_RESTYP_PREFER_IPV6) {
		struct sockaddr_in *fi4 = NULL;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family == AF_INET6) {
				gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
				return true;
			} else if (ai->ai_family == AF_INET) {
				fi4 = (struct sockaddr_in *)ai->ai_addr;
			}
		}

		if (fi4) {
			gs->i4 = *fi4;
			return true;
		}
		return false;
	}

	if (restyp == GWP_DNS_RESTYP_PREFER_IPV4) {
		struct sockaddr_in6 *fi6 = NULL;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family == AF_INET) {
				gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
				return true;
			} else if (ai->ai_family == AF_INET6) {
				fi6 = (struct sockaddr_in6 *)ai->ai_addr;
			}
		}

		if (fi6) {
			gs->i6 = *fi6;
			return true;
		}
		return false;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			return true;
		} else if (ai->ai_family == AF_INET6) {
			gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}
	}

	return false;
}

static void prep_hints(struct addrinfo *hints, uint32_t restyp)
{
	memset(hints, 0, sizeof(*hints));
	hints->ai_family = AF_UNSPEC;
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_flags = AI_ADDRCONFIG;

	if (restyp == GWP_DNS_RESTYP_IPV4_ONLY)
		hints->ai_family = AF_INET;
	else if (restyp == GWP_DNS_RESTYP_IPV6_ONLY)
		hints->ai_family = AF_INET6;
}

int gwp_dns_resolve(const char *name, const char *service,
		    struct gwp_sockaddr *addr, uint32_t restyp)
{
	struct addrinfo *res, hints;
	bool found;
	int r;

	prep_hints(&hints, restyp);
	r = getaddrinfo(name, service, &hints, &res);
	if (r || !res)
		return -EHOSTUNREACH;

	found = iterate_addr_list(res, addr, restyp);
	freeaddrinfo(res);
	return found ? 0 : -EHOSTUNREACH;
}

static void gwp_dns_entry_free(struct gwp_dns_entry *e)
{
	if (!e)
		return;

	if (e->ev_fd >= 0)
		close(e->ev_fd);
	free(e->name);
	free(e);
}

/*
 * Must be called with ctx->lock held.
 */
static void wait_for_queue_entry(struct gwp_dns_ctx *ctx)
{
	ctx->nr_sleeping++;
	pthread_cond_wait(&ctx->cond, &ctx->lock);
	ctx->nr_sleeping--;
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry_batch(struct gwp_dns_ctx *ctx)
{
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry_single(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry *e = ctx->head;

	if (!e)
		return;

	e = ctx->head;
	ctx->head = e->next;
	if (!ctx->head)
		ctx->tail = NULL;

	ctx->nr_entries--;
	pthread_mutex_unlock(&ctx->lock);

	if (atomic_load(&e->refcnt) == 1) {
		/*
		 * If the refcnt is 1, it means we are the last reference
		 * to this entry. The client no longer cares about the
		 * result. We can free it immediately. No need to resolve
		 * the query nor to signal the eventfd.
		 */
		gwp_dns_entry_free(e);
		goto out;
	}

	e->res = gwp_dns_resolve(e->name, e->service, &e->addr, ctx->cfg.restyp);
	eventfd_write(e->ev_fd, 1);
	gwp_dns_entry_put(e);
out:
	pthread_mutex_lock(&ctx->lock);
}

/*
 * Must be called with ctx->lock held. May release the lock, but
 * it will reacquire it before returning.
 */
static void process_queue_entry(struct gwp_dns_ctx *ctx)
{
	if ((ctx->nr_entries + 16) > ctx->nr_sleeping)
		process_queue_entry_batch(ctx);
	else
		process_queue_entry_single(ctx);
}

static void *gwp_dns_thread_entry(void *arg)
{
	struct gwp_dns_wrk *w = arg;
	struct gwp_dns_ctx *ctx = w->ctx;

	pthread_mutex_lock(&ctx->lock);
	while (!ctx->should_stop) {
		if (ctx->head)
			process_queue_entry(ctx);
		else
			wait_for_queue_entry(ctx);
	}
	pthread_mutex_unlock(&ctx->lock);

	return NULL;
}

static void free_worker(struct gwp_dns_wrk *w)
{
	struct gwp_dns_ctx *ctx;

	if (!w)
		return;

	ctx = w->ctx;
	pthread_mutex_lock(&ctx->lock);
	ctx->should_stop = true;
	pthread_cond_broadcast(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
	pthread_join(w->thread, NULL);
}

static void free_workers(struct gwp_dns_ctx *ctx)
{
	uint32_t i;

	if (!ctx->workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		free_worker(&ctx->workers[i]);

	free(ctx->workers);
	ctx->workers = NULL;
}

static int init_workers(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_wrk *workers, *w;
	uint32_t i;
	int r;

	if (ctx->cfg.nr_workers == 0)
		return -EINVAL;

	workers = calloc(ctx->cfg.nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->workers = workers;
	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		w = &workers[i];
		w->ctx = ctx;
		w->id = i;
		r = pthread_create(&w->thread, NULL, gwp_dns_thread_entry, w);
		if (r) {
			r = -r;
			goto out_err;
		}
	}

	return 0;

out_err:
	while (i--)
		free_worker(&workers[i]);
	free(workers);
	ctx->workers = NULL;
	return r;
}

int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg)
{
	struct gwp_dns_ctx *ctx;
	int r;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	r = pthread_mutex_init(&ctx->lock, NULL);
	if (r) {
		r = -r;
		goto out_free_ctx;
	}

	r = pthread_cond_init(&ctx->cond, NULL);
	if (r) {
		r = -r;
		goto out_destroy_mutex;
	}

	ctx->cfg = *cfg;
	ctx->nr_sleeping = 0;
	ctx->nr_entries = 0;
	ctx->workers = NULL;
	ctx->head = NULL;
	ctx->tail = NULL;
	ctx->should_stop = false;
	r = init_workers(ctx);
	if (r)
		goto out_destroy_cond;

	*ctx_p = ctx;
	return 0;
out_destroy_cond:
	pthread_cond_destroy(&ctx->cond);
out_destroy_mutex:
	pthread_mutex_destroy(&ctx->lock);
out_free_ctx:
	free(ctx);
	*ctx_p = NULL;
	return r;
}

static void put_all_queued_entries(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry *e, *next;

	for (e = ctx->head; e; e = next) {
		next = e->next;
		gwp_dns_entry_put(e);
	}

	ctx->head = ctx->tail = NULL;
}

void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx)
{
	free_workers(ctx);
	pthread_mutex_destroy(&ctx->lock);
	pthread_cond_destroy(&ctx->cond);
	put_all_queued_entries(ctx);
	free(ctx);
}

static void push_queue(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e)
{
	pthread_mutex_lock(&ctx->lock);
	if (ctx->tail)
		ctx->tail->next = e;
	else
		ctx->head = e;
	ctx->tail = e;
	e->next = NULL;

	ctx->nr_entries++;
	if (ctx->nr_sleeping)
		pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
}

struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx,
				    const char *name, const char *service)
{
	struct gwp_dns_entry *e;
	size_t nl, sl;

	e = malloc(sizeof(*e));
	if (!e)
		return NULL;

	e->ev_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (e->ev_fd < 0)
		goto out_free_e;

	/*
	 * Merge name and service into a single allocated string to
	 * avoid multiple allocations.
	 *
	 * The format is: "<name>\0<service>\0" where both name and
	 * service are null-terminated strings.
	 */
	nl = strlen(name);
	sl = service ? strlen(service) : 0;
	e->name = malloc(nl + 1 + sl + 1);
	if (!e->name)
		goto out_close_ev_fd;

	e->service = e->name + nl + 1;
	memcpy(e->name, name, nl + 1);
	if (service)
		memcpy(e->service, service, sl + 1);
	else
		e->service[0] = '\0';

	atomic_init(&e->refcnt, 2);
	e->res = 0;
	push_queue(ctx, e);
	return e;

out_close_ev_fd:
	close(e->ev_fd);
out_free_e:
	free(e);
	return NULL;
}

bool gwp_dns_entry_put(struct gwp_dns_entry *e)
{
	int x;

	if (!e)
		return false;

	x = atomic_fetch_sub(&e->refcnt, 1);
	assert(x > 0);
	if (x == 1) {
		gwp_dns_entry_free(e);
		return true;
	}

	return false;
}
