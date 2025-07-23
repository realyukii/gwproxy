// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef GWPROXY_H
#define GWPROXY_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <gwproxy/syscall.h>
#include <gwproxy/socks5.h>
#include <gwproxy/dns.h>
#include <gwproxy/log.h>

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	bool		socks5_prefer_ipv6;
	int		socks5_timeout;
	const char	*socks5_auth_file;
	int		socks5_dns_cache_secs;
	int		nr_workers;
	int		nr_dns_workers;
	int		connect_timeout;
	int		target_buf_size;
	int		client_buf_size;
	bool		tcp_nodelay;
	bool		tcp_quickack;
	bool		tcp_keepalive;
	int		tcp_keepidle;
	int		tcp_keepintvl;
	int		tcp_keepcnt;
	int		log_level;
	const char	*log_file;
	const char	*pid_file;
};

struct gwp_ctx;

enum {
	EV_BIT_ACCEPT		= (1ull << 48ull),
	EV_BIT_EVENTFD		= (2ull << 48ull),
	EV_BIT_TARGET		= (3ull << 48ull),
	EV_BIT_CLIENT		= (4ull << 48ull),
	EV_BIT_TIMER		= (5ull << 48ull),
	EV_BIT_CLIENT_SOCKS5	= (6ull << 48ull),
	EV_BIT_DNS_QUERY	= (7ull << 48ull),
	EV_BIT_SOCKS5_AUTH_FILE	= (8ull << 48ull),
};

enum {
	CONN_STATE_INIT			= 101,

	CONN_STATE_SOCKS5_DATA		= 100,
	CONN_STATE_SOCKS5_CMD_CONNECT	= 221,
	CONN_STATE_SOCKS5_ERR		= 250,
	CONN_STATE_SOCKS5_DNS_QUERY	= 260,

	CONN_STATE_FORWARDING		= 301,
};

struct gwp_conn {
	int		fd;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
	uint32_t	ep_mask;
};

struct gwp_dns_query;

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	bool			is_target_alive;
	int			conn_state;
	int			timer_fd;
	uint32_t		idx;
	struct gwp_socks5_conn	*s5_conn;
	struct gwp_dns_query	*gdq;
	struct gwp_dns_entry	*gde;
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;
};


struct gwp_conn_slot {
	struct gwp_conn_pair	**pairs;
	size_t			nr;
	size_t			cap;
};

struct gwp_wrk {
	int			tcp_fd;
	int			ep_fd;
	int			ev_fd;
	struct gwp_conn_slot	conn_slot;

	/*
	 * If it's true, the worker MUST call epoll_wait() again
	 * before continue iterating over the events.
	 */
	bool			ev_need_reload;

	bool			accept_is_stopped;

	struct gwp_ctx		*ctx;
	struct epoll_event	*events;
	uint16_t		evsz;
	uint32_t		idx;
	pthread_t		thread;
};

enum {
	GWP_EV_EPOLL,
	GWP_EV_IO_URING
};

struct gwp_ctx {
	volatile bool			stop;
	uint8_t				ev_used;
	struct log_handle		lh;
	struct gwp_wrk			*workers;
	struct gwp_sockaddr		target_addr;
	struct gwp_socks5_ctx		*socks5;
	struct gwp_dns_ctx		*dns;
	struct gwp_cfg			cfg;
	int				ino_fd;
	char				*ino_buf;
	_Atomic(int32_t)		nr_fd_closed;
	_Atomic(int32_t)		nr_accept_stopped;
};

/*
 * TODO(ammarfaizi2): Once epoll is further migrated, remove this.
 */
int gwp_ctx_handle_event_epoll(struct gwp_wrk *w, struct epoll_event *ev);

#endif /* #ifndef GWPROXY_H */
