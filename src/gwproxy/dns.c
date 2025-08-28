// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "dns.h"
#include "dns_cache.h"

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
#include <signal.h>

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
	struct gwp_dns_cache	*cache;
	time_t			last_scan;
	struct gwp_dns_cfg	cfg;
};

static void put_all_entries(struct gwp_dns_entry *head)
{
	struct gwp_dns_entry *e, *next;

	for (e = head; e; e = next) {
		next = e->next;
		gwp_dns_entry_put(e);
	}
}

static bool iterate_addr_list(struct addrinfo *res, struct gwp_sockaddr *gs,
			      uint32_t rt)
{
	struct addrinfo *ai;

	if (!res)
		return false;

	/*
	 * Handle IPV4_ONLY and IPV6_ONLY cases together.
	 */
	if (rt == GWP_DNS_RESTYP_IPV4_ONLY ||
	    rt == GWP_DNS_RESTYP_IPV6_ONLY) {
		int fm = (rt == GWP_DNS_RESTYP_IPV4_ONLY) ? AF_INET : AF_INET6;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != fm)
				continue;
			if (fm == AF_INET)
				gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			else
				gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}
		return false;
	}

	/*
	 * Handle PREFER_IPV6 and PREFER_IPV4 cases together.
	 */
	if (rt == GWP_DNS_RESTYP_PREFER_IPV6 ||
	    rt == GWP_DNS_RESTYP_PREFER_IPV4) {
		int prm = (rt == GWP_DNS_RESTYP_PREFER_IPV6) ? AF_INET6
							     : AF_INET;
		int sec = (prm == AF_INET6) ? AF_INET : AF_INET6;
		struct sockaddr *fallback = NULL;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != prm) {
				if (ai->ai_family == sec && !fallback)
					fallback = ai->ai_addr;
				continue;
			}

			if (prm == AF_INET)
				gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			else
				gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			return true;
		}

		if (!fallback)
			return false;

		if (sec == AF_INET)
			gs->i4 = *(struct sockaddr_in *)fallback;
		else
			gs->i6 = *(struct sockaddr_in6 *)fallback;

		return true;
	}

	/*
	 * Default case: first available address (IPv4 or IPv6).
	 */
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

static void try_pass_result_to_cache(struct gwp_dns_ctx *ctx, const char *name,
				     const struct addrinfo *ai)
{
	int x;

	if (!ctx->cache)
		return;

	x = ctx->cfg.cache_expiry;
	gwp_dns_cache_insert(ctx->cache, name, ai, time(NULL) + x);
}

int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    const char *service, struct gwp_sockaddr *addr,
		    uint32_t restyp)
{
	struct addrinfo *res = NULL, hints;
	bool found;
	int r;

	prep_hints(&hints, restyp);
	r = getaddrinfo(name, service, &hints, &res);
	if (r)
		return -r;

	found = iterate_addr_list(res, addr, restyp);
	if (found)
		try_pass_result_to_cache(ctx, name, res);

	if (res)
		freeaddrinfo(res);

	return found ? 0 : -EHOSTUNREACH;
}

static void gwp_dns_entry_free(struct gwp_dns_entry *e)
{
	if (!e)
		return;

	assert(e->ev_fd >= 0);
	close(e->ev_fd);
	free(e->name);
	free(e);
}

/*
 * Must be called with ctx->lock held. May release the lock, but it
 * will reacquire it before returning.
 *
 * If the DNS cache is enabled, do:
 *   - Compare the last scan time with the current time.
 *   - If it's more than ctx->cfg.cache_expiry seconds ago, scan the
 *     cache to find expired entries and delete them.
 *   - Save the current time as the last scan time.
 */
static void cond_scan_cache(struct gwp_dns_ctx *ctx)
{
	if (!ctx->cache)
		return;

	if (time(NULL) - ctx->last_scan < ctx->cfg.cache_expiry)
		return;

	pthread_mutex_unlock(&ctx->lock);
	gwp_dns_cache_housekeep(ctx->cache);
	pthread_mutex_lock(&ctx->lock);

	/*
	 * Call time(NULL) again because the scan might have taken
	 * several seconds if the number of entries is large or
	 * it got contended by other threads.
	 */
	ctx->last_scan = time(NULL);
}

/*
 * Must be called with ctx->lock held.
 */
static void wait_for_queue_entry(struct gwp_dns_ctx *ctx)
{
	ctx->nr_sleeping++;
	pthread_cond_wait(&ctx->cond, &ctx->lock);
	ctx->nr_sleeping--;
	cond_scan_cache(ctx);
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
	if (!ctx->head) {
		ctx->tail = NULL;
		assert(ctx->nr_entries == 1);
	}

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

	e->res = gwp_dns_resolve(ctx, e->name, e->service, &e->addr, ctx->cfg.restyp);
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

static bool fetch_i4(struct gwp_dns_cache_entry *e, struct gwp_sockaddr *addr,
		     uint16_t port)
{
	uint8_t *b = gwp_dns_cache_entget_i4(e);
	if (!b)
		return false;

	memset(addr, 0, sizeof(*addr));
	addr->i4.sin_family = AF_INET;
	addr->i4.sin_port = htons(port);
	memcpy(&addr->i4.sin_addr, b, 4);
	return true;
}

static bool fetch_i6(struct gwp_dns_cache_entry *e, struct gwp_sockaddr *addr,
		     uint16_t port)
{
	uint8_t *b = gwp_dns_cache_entget_i6(e);
	if (!b)
		return false;

	memset(addr, 0, sizeof(*addr));
	addr->i6.sin6_family = AF_INET6;
	addr->i6.sin6_port = htons(port);
	memcpy(&addr->i6.sin6_addr, b, 16);
	return true;
}

static int fetch_addr(struct gwp_dns_cache_entry *e, struct gwp_sockaddr *addr,
		      uint16_t port, uint32_t restyp)
{
	if (restyp == GWP_DNS_RESTYP_IPV4_ONLY) {
		if (!fetch_i4(e, addr, port))
			return -EHOSTUNREACH;
	} else if (restyp == GWP_DNS_RESTYP_IPV6_ONLY) {
		if (!fetch_i6(e, addr, port))
			return -EHOSTUNREACH;
	} else if (restyp == GWP_DNS_RESTYP_PREFER_IPV6) {
		if (!fetch_i6(e, addr, port)) {
			if (!fetch_i4(e, addr, port))
				return -EHOSTUNREACH;
		}
	} else if (restyp == GWP_DNS_RESTYP_PREFER_IPV4 ||
		   restyp == GWP_DNS_RESTYP_DEFAULT) {
		if (!fetch_i4(e, addr, port)) {
			if (!fetch_i6(e, addr, port))
				return -EHOSTUNREACH;
		}
	} else {
		return -EINVAL;
	}

	return 0;
}

int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 const char *service, struct gwp_sockaddr *addr)
{
	struct gwp_dns_cache_entry *e;
	int r;

	if (!ctx->cache)
		return -ENOSYS;

	r = gwp_dns_cache_getent(ctx->cache, name, &e);
	if (r)
		return r;

	r = fetch_addr(e, addr, service ? atoi(service) : 0, ctx->cfg.restyp);
	gwp_dns_cache_putent(e);
	return r;
}

static int init_cache(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_cache *cache;
	int r;

	if (ctx->cfg.cache_expiry <= 0) {
		/*
		 * Cache is disabled.
		 */
		ctx->cache = NULL;
		return 0;
	}

	r = gwp_dns_cache_init(&cache, 8192);
	if (r)
		return r;

	ctx->cache = cache;
	return 0;
}

static void free_cache(struct gwp_dns_cache *cache)
{
	if (!cache)
		return;

	gwp_dns_cache_free(cache);
	cache = NULL;
}

static inline bool validate_restyp(int restyp)
{
	switch (restyp) {
	case GWP_DNS_RESTYP_DEFAULT:
	case GWP_DNS_RESTYP_IPV4_ONLY:
	case GWP_DNS_RESTYP_IPV6_ONLY:
	case GWP_DNS_RESTYP_PREFER_IPV4:
	case GWP_DNS_RESTYP_PREFER_IPV6:
		return true;
	default:
		return false;
	}
}

int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg)
{
	struct gwp_dns_ctx *ctx;
	int r;

	if (!validate_restyp(cfg->restyp))
		return -EINVAL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;

	ctx->cfg = *cfg;
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

	r = init_cache(ctx);
	if (r)
		goto out_destroy_cond;

	ctx->nr_sleeping = 0;
	ctx->nr_entries = 0;
	ctx->workers = NULL;
	ctx->head = NULL;
	ctx->tail = NULL;
	ctx->should_stop = false;
	ctx->last_scan = time(NULL);
	r = init_workers(ctx);
	if (r)
		goto out_free_cache;

	*ctx_p = ctx;
	return 0;
out_free_cache:
	free_cache(ctx->cache);
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
	put_all_entries(ctx->head);
	ctx->head = ctx->tail = NULL;
}

void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx)
{
	free_workers(ctx);
	pthread_mutex_destroy(&ctx->lock);
	pthread_cond_destroy(&ctx->cond);
	put_all_queued_entries(ctx);
	free_cache(ctx->cache);
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
