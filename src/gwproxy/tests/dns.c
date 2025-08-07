// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <stdio.h>
#include <assert.h>
#include <gwproxy/dns.h>
#include <poll.h>
#include <errno.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct req_template {
	const char *domain, *service;
};

struct poll_map {
	struct gwp_dns_entry *e;
	int fd;
};

static const struct req_template req_template[] = {
	{ "facebook.com",	"80" },
};

static struct gwp_dns_entry *find_item(struct poll_map *map, int n, int fd)
{
	struct gwp_dns_entry *e;
	int i;

	e = NULL;
	for (i = 0; i < n; i++) {
		if (map[i].fd == fd)
			e = map[i].e;
	}

	return e;
}

static int poll_all_in(struct gwp_dns_ctx *ctx, struct poll_map *map, struct pollfd *pfd, int n, int timeout)
{
	int ret, i, t = 0;

	while (1) {
		ret = poll(pfd, n, timeout);
		if (ret < 0) {
			perror("poll");
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "poll timed out\n");
			return -ETIMEDOUT;
		}

		for (i = 0; i < n; i++) {
			struct gwp_dns_entry *e;
			if (pfd[i].revents & POLLIN) {
				e = find_item(map, n, pfd[i].fd);
				assert(e);
				ret = gwp_dns_process(ctx, e);
				assert(!ret);
				pfd[i].events = 0;
				t++;
			}
		}

		if (t == n)
			return 0;
	}
}

static void test_basic_dns_multiple_requests(void)
{
	struct gwp_dns_cfg cfg = { .nr_workers = 1, .ns_addr_str = "1.1.1.1" };
	struct poll_map pollfd_map[ARRAY_SIZE(req_template)];
	struct pollfd pfd[ARRAY_SIZE(req_template)];
	struct gwp_sockaddr addr;
	struct gwp_dns_ctx *ctx;
	uint8_t addrlen;
	ssize_t r;
	int i, n;

	r = gwp_dns_ctx_init(&ctx, &cfg);
	assert(!r);
	assert(ctx != NULL);

	n = (int)ARRAY_SIZE(req_template);
	for (i = 0; i < n; i++) {
		const struct req_template *rt = &req_template[i];
		struct gwp_dns_entry *e;
		e = gwp_dns_queue(ctx, rt->domain, rt->service);
		assert(e);
		assert(e->udp_fd >= 0);
		pfd[i].fd = e->udp_fd;
		pfd[i].events = POLLIN;
		cp_nsaddr(ctx, &addr, &addrlen);
		r = __sys_sendto(
			e->udp_fd, e->payload, e->payloadlen, MSG_NOSIGNAL,
			&addr.sa, addrlen
		);
		assert(r > 0);
		pollfd_map[i].fd = e->udp_fd;
		pollfd_map[i].e = e;
	}

	r = poll_all_in(ctx, pollfd_map, pfd, n, 5000);
	assert(!r);

	for (i = 0; i < n; i++) {
		assert(pollfd_map[i].e->res == 0);
		r = pollfd_map[i].e->addr.sa.sa_family;
		assert(r == AF_INET || r == AF_INET6);
	}

	gwp_dns_ctx_free(ctx);
}

int main(void)
{
	test_basic_dns_multiple_requests();
	printf("All tests passed.\n");
	return 0;
}
