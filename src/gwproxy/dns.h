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
#include <gwproxy/net.h>
#include <gwproxy/dnsparser.h>
#include <gwproxy/syscall.h>

struct gwp_dns_entry {
	int			idx;
	char			*name;
	char			*service;
	int			res;
	int			udp_fd;
	struct gwp_sockaddr	addr;
	int			payloadlen;
	union {
		uint16_t	txid;
		uint8_t		payload[UDP_MSG_LIMIT];
	};
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
	const char	*ns_addr_str;
	uint32_t	restyp;
};

struct gwp_dns_ctx;

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
 * the resolution result. The caller's responsible to call gwp_dns_entry_free()
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

void cp_nsaddr(struct gwp_dns_ctx *ctx, struct gwp_sockaddr *addr, uint8_t *addrlen);

void gwp_dns_entry_free(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e);

int gwp_dns_process(struct gwp_dns_ctx *ctx, struct gwp_dns_entry *e);

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
