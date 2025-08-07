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
#include <gwproxy/dnsparser.h>

struct gwp_dns_ctx;

struct gwp_dns_ctx {
	int			nr_entries;
	int			entry_cap;
	struct gwp_dns_entry	**entries;
	int			sockfd;
	int			ns_family;
	struct gwp_sockaddr	ns_addr;
	uint8_t			ns_addrlen;
	volatile bool		should_stop;
	pthread_mutex_t		lock;
	struct gwp_dns_cache	*cache;
	time_t			last_scan;
	struct gwp_dns_cfg	cfg;
};

void cp_nsaddr(struct gwp_dns_ctx *ctx, struct gwp_sockaddr *addr, uint8_t *addrlen)
{
	*addr = ctx->ns_addr;
	*addrlen = ctx->ns_addrlen;
}

__attribute__((unused))
static bool iterate_addr_list(struct gwdns_addrinfo_node *res, struct gwp_sockaddr *gs,
			      uint32_t rt)
{
	struct gwdns_addrinfo_node *ai;

	assert(res);

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
				gs->i4 = ai->ai_addr.i4;
			else
				gs->i6 = ai->ai_addr.i6;
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
		struct gwp_sockaddr *fallback = NULL;

		for (ai = res; ai; ai = ai->ai_next) {
			if (ai->ai_family != prm) {
				if (ai->ai_family == sec && !fallback)
					fallback = &ai->ai_addr;
				continue;
			}

			if (prm == AF_INET)
				gs->i4 = ai->ai_addr.i4;
			else
				gs->i6 = ai->ai_addr.i6;
			return true;
		}

		if (!fallback)
			return false;

		if (sec == AF_INET)
			gs->i4 = fallback->i4;
		else
			gs->i6 = fallback->i6;

		return true;
	}

	/*
	 * Default case: first available address (IPv4 or IPv6).
	 */
	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			gs->i4 = ai->ai_addr.i4;
			return true;
		} else if (ai->ai_family == AF_INET6) {
			gs->i6 = ai->ai_addr.i6;
			return true;
		}
	}

	return false;
}

__attribute__((unused))
static void try_pass_result_to_cache(struct gwp_dns_ctx *ctx, const char *name,
				     const struct addrinfo *ai)
{
	int x;

	if (!ctx->cache)
		return;

	x = ctx->cfg.cache_expiry;
	gwp_dns_cache_insert(ctx->cache, name, ai, time(NULL) + x);
}

// static int gwp_dns_find_preferred_addr(struct gwp_dns_ctx *ctx, struct gwdns_addrinfo_node *ai, const char *name,
// 					struct gwp_sockaddr *addr, uint32_t restyp)
// {
// 	bool found;

// 	found = iterate_addr_list(ai, addr, restyp);
// 	if (found)
// 		try_pass_result_to_cache(ctx, name, ai);

// 	return found ? 0 : -EHOSTUNREACH;
// }

static void _gwp_dns_entry_free(struct gwp_dns_entry *e)
{
	assert(e);
	assert(e->udp_fd >= 0);
	close(e->udp_fd);
	free(e->name);
	free(e);
}

void gwp_dns_entry_free(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e)
{
	struct gwp_dns_entry *new_e;

	assert(e);

	new_e = ctx->entries[--ctx->nr_entries];
	assert(ctx->nr_entries == new_e->idx);
	new_e->idx = e->idx;
	ctx->entries[e->idx] = new_e;
	ctx->entries[ctx->nr_entries] = NULL;

	_gwp_dns_entry_free(e);
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
__attribute__((unused))
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

	r = init_cache(ctx);
	if (r)
		goto out_destroy_mutex;

	r = convert_str_to_ssaddr(cfg->ns_addr_str, &ctx->ns_addr, 53);
	if (r)
		goto out_destroy_mutex;
	ctx->ns_addrlen = ctx->ns_addr.sa.sa_family == AF_INET
			? sizeof(ctx->ns_addr.i4)
			: sizeof(ctx->ns_addr.i6);
	ctx->should_stop = false;
	ctx->last_scan = time(NULL);
	ctx->nr_entries = 0;
	ctx->entry_cap = DEFAULT_ENTRIES_CAP;
	ctx->entries = malloc(ctx->entry_cap * sizeof(*ctx->entries));
	if (!ctx->entries)
		goto out_destroy_mutex;

	*ctx_p = ctx;
	return 0;
out_destroy_mutex:
	pthread_mutex_destroy(&ctx->lock);
out_free_ctx:
	free(ctx);
	*ctx_p = NULL;
	return r;
}

static void free_all_queued_entries(struct gwp_dns_ctx *ctx)
{
	int i;
	for (i = 0; i < ctx->nr_entries; i++) {
		struct gwp_dns_entry *e = ctx->entries[i];
		_gwp_dns_entry_free(e);
	}

	free(ctx->entries);
}

void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx)
{
	pthread_mutex_destroy(&ctx->lock);
	free_all_queued_entries(ctx);
	free_cache(ctx->cache);
	free(ctx);
}

static bool realloc_entries(struct gwp_dns_ctx *ctx)
{
	struct gwp_dns_entry **tmp;
	int new_cap;

	new_cap = ctx->entry_cap * 2;
	tmp = realloc(ctx->entries, new_cap * sizeof(*tmp));
	if (!tmp)
		return 1;

	ctx->entries = tmp;
	ctx->entry_cap = new_cap;

	return 0;
}

struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx,
				    const char *name, const char *service)
{
	struct gwp_dns_entry *e;
	uint16_t txid;
	size_t nl, sl;
	ssize_t r;

	if (ctx->nr_entries == ctx->entry_cap && realloc_entries(ctx))
		return NULL;

	e = malloc(sizeof(*e));
	if (!e)
		return NULL;

	r = __sys_socket(ctx->ns_addr.sa.sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (r < 0)
		goto out_free_e;
	e->udp_fd = (int)r;

	txid = (uint16_t)rand();
	// TODO(reyuki): avoid hard-coded AF_INET and use restyp instead
	r = gwdns_build_query(txid, name, AF_INET, e->payload, sizeof(e->payload));
	if (r < 0)
		goto out_free_e;
	e->payloadlen = (int)r;

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
		goto out_free_e;

	e->service = e->name + nl + 1;
	memcpy(e->name, name, nl + 1);
	if (service)
		memcpy(e->service, service, sl + 1);
	else
		e->service[0] = '\0';

	e->res = 0;
	e->idx = ctx->nr_entries++;
	ctx->entries[e->idx] = e;

	return e;

out_free_e:
	free(e);
	return NULL;
}

int gwp_dns_process(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e)
{
	struct gwdns_addrinfo_node *ai;
	uint8_t buff[UDP_MSG_LIMIT];
	ssize_t r;

	r = __sys_recvfrom(
		e->udp_fd, buff, sizeof(buff), 0,
		&ctx->ns_addr.sa, (socklen_t *)&ctx->ns_addrlen
	);
	if (r <= 0)
		return (int)r;

	r = gwdns_parse_query(e->txid, e->service, buff, r, &ai);
	if (r)
		goto exit_free_ai;

	e->addr = ai->ai_addr;
	// gwp_dns_find_preferred_addr(ctx, ai, e->name, &e->addr, ctx->cfg.restyp);

exit_free_ai:
	gwdns_free_parsed_query(ai);
	return (int)r;
}

