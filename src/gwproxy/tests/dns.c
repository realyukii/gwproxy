// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
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

static const struct req_template req_template[] = {
	{ "localhost",		"80" },
	{ "facebook.com",	"80" },
	{ "google.com",		"443" },
	{ "github.com",		"443" },
	{ "example.com",	"80" },
	{ "twitter.com",	"443" },
	{ "reddit.com",		"80" },
	{ "youtube.com",	"443" },
	{ "wikipedia.org",	"80" },
	{ "stackoverflow.com",	"443" },
	{ "amazon.com",		"80" },
	{ "microsoft.com",	"443" },
	{ "apple.com",		"80" },
	{ "linkedin.com",	"443" },
	{ "bing.com",		"80" },
};

static int poll_all_in(struct pollfd *pfd, int n, int timeout)
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
			if (pfd[i].revents & (POLLIN | POLLERR | POLLHUP)) {
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
	struct gwp_dns_cfg cfg = { .nr_workers = 1 };
	struct gwp_dns_entry *earr[ARRAY_SIZE(req_template)];
	struct pollfd pfd[ARRAY_SIZE(req_template)];
	struct gwp_dns_ctx *ctx;
	int i, n;
	int ret;

	ret = gwp_dns_ctx_init(&ctx, &cfg);
	assert(ret == 0);
	assert(ctx != NULL);

	n = (int)ARRAY_SIZE(req_template);
	for (i = 0; i < n; i++) {
		const struct req_template *r = &req_template[i];
		earr[i] = gwp_dns_queue(ctx, r->domain, r->service);
		assert(earr[i] != NULL);
		assert(earr[i]->ev_fd >= 0);
		pfd[i].fd = earr[i]->ev_fd;
		pfd[i].events = POLLIN;
	}

	ret = poll_all_in(pfd, n, 5000);
	assert(ret == 0);

	for (i = 0; i < n; i++) {
		assert(earr[i]->res == 0);
		assert(earr[i]->addr.sa.sa_family == AF_INET ||
		       earr[i]->addr.sa.sa_family == AF_INET6);
	}

	for (i = 0; i < n; i++)
		gwp_dns_entry_put(earr[i]);
	gwp_dns_ctx_free(ctx);
}

int main(void)
{
	test_basic_dns_multiple_requests();
	printf("All tests passed.\n");
	return 0;
}
