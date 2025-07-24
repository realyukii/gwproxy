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
#include <assert.h>
#ifdef CONFIG_IO_URING
#include <liburing.h>
#endif

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

	EV_BIT_CLOSE		= (9ull << 48ull),
	EV_BIT_TARGET_CONNECT	= (10ull << 48ull),
	EV_BIT_TARGET_SHUTDOWN	= (11ull << 48ull),
	EV_BIT_CLIENT_SHUTDOWN	= (12ull << 48ull),
	EV_BIT_TIMER_DEL	= (13ull << 48ull),
	EV_BIT_TARGET_SEND	= (14ull << 48ull),
	EV_BIT_CLIENT_SEND	= (15ull << 48ull),
	EV_BIT_CLIENT_RECV	= EV_BIT_CLIENT,
	EV_BIT_TARGET_RECV	= EV_BIT_TARGET,
	EV_BIT_MSG_RING		= (16ull << 48ull)
};


#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)

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

#if CONFIG_IO_URING
	/*
	 * @is_dying and @ref_cnt are only used by io_uring.
	 *
	 * @is_dying is set to true when either target or client
	 * connection is closed, and it is used to prevent further
	 * processing of the connection pair.
	 *
	 * @ref_cnt is used to track the number of references
	 * to the connection pair. It is incremented when the
	 * connection pair is allocated and decremented when it
	 * is freed. When the reference count reaches zero, the
	 * connection pair is freed.
	 * 
	 * @ref_cnt does not need to be atomic because the reference
	 * is only incremented and decremented in the same thread
	 * that processes the connection pair.
	 */
	bool				is_dying;
	bool				is_shutdown;
	uint8_t				ref_cnt;
	struct __kernel_timespec	ts;
#endif

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

#ifdef CONFIG_IO_URING
struct iou {
	struct io_uring		ring;
	struct gwp_sockaddr	accept_addr;
	socklen_t		accept_addr_len;
};
#endif

struct gwp_wrk {
	int			tcp_fd;
	struct gwp_conn_slot	conn_slot;

	union {
		struct {
			int			ep_fd;
			int			ev_fd;
			struct epoll_event	*events;
			uint16_t		evsz;
			/*
			 * If it's true, the worker MUST call epoll_wait() again
			 * before continue iterating over the events.
			 */
			bool			ev_need_reload;
		};
#ifdef CONFIG_IO_URING
		struct iou	*iou;
#endif
	};

	bool			accept_is_stopped;
	struct gwp_ctx		*ctx;
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

struct gwp_conn_pair *gwp_alloc_conn_pair(struct gwp_wrk *w);
int gwp_free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			   bool *is_target_alive, bool non_block);
int gwp_create_timer(int fd, int sec, int nsec);
void gwp_setup_cli_sock_options(struct gwp_wrk *w, int fd);
const char *ip_to_str(const struct gwp_sockaddr *gs);

static inline void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	assert(len <= conn->len);
	conn->len -= len;
	if (conn->len)
		memmove(conn->buf, conn->buf + len, conn->len);
}

static inline
void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_info(&ctx->lh, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

#endif /* #ifndef GWPROXY_H */
