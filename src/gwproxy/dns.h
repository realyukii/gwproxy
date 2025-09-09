// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWP_DNS_H
#define GWP_DNS_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <gwproxy/common.h>
#include <gwproxy/net.h>
#include <gwproxy/dnsparser.h>
#include <gwproxy/syscall.h>

struct gwp_dns_entry {
#ifdef CONFIG_RAW_DNS
	uint32_t		idx;
	int			payloadlen;
	union {
		uint16_t	txid;
		uint8_t		payload[UDP_MSG_LIMIT];
	};
#endif
	char			*name;
	char			*service;
	_Atomic(int)		refcnt;
	int			res;
	int			ev_fd;
	struct gwp_sockaddr	addr;
	struct gwp_dns_entry	*next;
};

enum {
	GWP_DNS_RESTYP_DEFAULT		= 0,
	GWP_DNS_RESTYP_IPV4_ONLY	= 1,
	GWP_DNS_RESTYP_IPV6_ONLY	= 2,
	GWP_DNS_RESTYP_PREFER_IPV4	= 3,
	GWP_DNS_RESTYP_PREFER_IPV6	= 4,
};

#define DEFAULT_ENTRIES_CAP 255

struct gwp_dns_cfg {
	int		cache_expiry;	/* In seconds. <= 0 to disable cache. */
	uint32_t	nr_workers;
	uint32_t	restyp;
	bool		use_raw_dns;
#ifdef CONFIG_RAW_DNS
	const char	*ns_addr_str;
#endif
};

struct gwp_dns_ctx {
#ifdef CONFIG_RAW_DNS
	uint32_t		entry_cap;
	struct gwp_dns_entry	**entries;
	struct gwp_sockaddr	ns_addr;
	socklen_t		ns_addrlen;
#endif
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

/**
 * Initialize the DNS context. Stores the context in `*ctx_p`. When
 * the context is no longer needed, it should be freed using
 * gwp_dns_ctx_free().
 *
 * @param ctx_p	Pointer to a pointer where the context will be stored.
 * @param cfg	Pointer to the configuration structure.
 * @return	0 on success, negative error code on failure.
 *
 * Error values:
 * -ENOMEM: Memory allocation failed.
 * -EINVAL: Invalid configuration parameters.
 */
int gwp_dns_ctx_init(struct gwp_dns_ctx **ctx_p, const struct gwp_dns_cfg *cfg);

/**
 * Free the DNS context.
 *
 * @param ctx	Pointer to the context to be freed.
 */
void gwp_dns_ctx_free(struct gwp_dns_ctx *ctx);

/**
 * Queue a DNS resolution request. It returns a pointer to a gwp_dns_entry
 * with eventfd set to a valid file descriptor that can be used to wait for
 * the resolution result. The caller's responsible to call gwp_dns_entry_put()
 * to release the entry when it is no longer needed.
 *
 * The returned eventfd file descriptor is non-blocking.
 *
 * @param ctx		Pointer to the DNS context.
 * @param name		Name to resolve.
 * @param service 	Service to resolve in port number ascii format.
 * @return		Pointer to a gwp_dns_entry on success, NULL on failure.
 */
struct gwp_dns_entry *gwp_dns_queue(struct gwp_dns_ctx *ctx,
				    const char *name, const char *service);

/**
 * Release a DNS entry. This function decrements the reference count of the
 * entry. If the reference count reaches zero, the entry is freed.
 *
 * @param entry		Pointer to the DNS entry to release. If the entry is
 *			NULL, this function does nothing.
 * @return		True if the entry was freed, false otherwise.
 */
bool gwp_dns_entry_put(struct gwp_dns_entry *entry);

#ifdef CONFIG_RAW_DNS
struct gwp_dns_entry *gwp_raw_dns_queue(uint16_t txid, struct gwp_dns_ctx *ctx,
				    const char *name, const char *service);

void gwp_dns_raw_entry_free(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e);

int gwp_dns_process(uint8_t buff[UDP_MSG_LIMIT], int bufflen, struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e);
#else
static inline struct gwp_dns_entry *gwp_raw_dns_queue(__maybe_unused uint16_t txid, __maybe_unused struct gwp_dns_ctx *ctx,
				    __maybe_unused const char *name, __maybe_unused const char *service)
{
	return NULL;
}

static inline void gwp_dns_raw_entry_free(__maybe_unused struct gwp_dns_ctx *ctx, __maybe_unused struct gwp_dns_entry *e)
{
}
#endif

/**
 * Lookup a DNS entry in the cache. If the entry is found, it fills the
 * `addr` structure with the resolved address and returns 0. If the entry is
 * not found, it returns -ENOENT.
 *
 * @param ctx		Pointer to the DNS context.
 * @param name		Pointer to the name to look up.
 * @param service	Pointer to the service to look up.
 * @param addr		Pointer to the sockaddr structure to fill in.
 * @return		0 on success, negative error code on failure.
 *
 * Error values:
 * -ENOSYS: Cache is disabled.
 * -ENOENT: Entry not found in the cache.
 * -EINVAL: Invalid parameters.
 */
int gwp_dns_cache_lookup(struct gwp_dns_ctx *ctx, const char *name,
			 const char *service, struct gwp_sockaddr *addr);


int gwp_dns_resolve(struct gwp_dns_ctx *ctx, const char *name,
		    const char *service, struct gwp_sockaddr *addr,
		    uint32_t restyp);

#endif /* #ifndef GWP_DNS_H */
