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

#include <gwproxy/http1.h>

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		use_raw_dns;
	bool		as_socks5;
	bool		as_http;
	bool		socks5_prefer_ipv6;
	int		protocol_timeout;
	const char	*socks5_auth_file;
	int		socks5_dns_cache_secs;
	int		nr_workers;
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
#ifdef CONFIG_RAW_DNS
	const char	*ns_addr_str;
#endif
};

struct gwp_ctx;

enum {
	EV_BIT_ACCEPT			= (1ull << 48ull),
	EV_BIT_EVENTFD			= (2ull << 48ull),
	EV_BIT_TARGET			= (3ull << 48ull),
	EV_BIT_CLIENT			= (4ull << 48ull),
	EV_BIT_TIMER			= (5ull << 48ull),
	EV_BIT_CLIENT_SOCKS5		= (6ull << 48ull),
	EV_BIT_DNS_QUERY		= (7ull << 48ull),
	EV_BIT_SOCKS5_AUTH_FILE		= (8ull << 48ull),

	EV_BIT_HTTP_CONN		= (18ull << 48ull),

	/*
	 * This ev_bit is used for user_data masking during protocol
	 * initalization.
	 *
	 * Supported protocols:
	 *   - SOCKS5
	 *   - HTTP
	 *
	 * It means it waits for the data specific protocol before
	 * solely forwarding the received data to the destination host.
	 */
	EV_BIT_CLIENT_PROT		= (1000ull << 48ull),

#ifdef CONFIG_IO_URING
	/*
	 * Only used by io_uring.
	 */
	EV_BIT_IOU_DNS_QUERY		= EV_BIT_DNS_QUERY,
	EV_BIT_IOU_SOCKS5_AUTH_FILE	= EV_BIT_SOCKS5_AUTH_FILE,
	EV_BIT_IOU_TIMER		= EV_BIT_TIMER,
	EV_BIT_IOU_ACCEPT		= EV_BIT_ACCEPT,
	EV_BIT_IOU_CLIENT_SOCKS5	= EV_BIT_CLIENT_SOCKS5,
	EV_BIT_IOU_CLIENT_RECV		= EV_BIT_CLIENT,
	EV_BIT_IOU_TARGET_RECV		= EV_BIT_TARGET,
	EV_BIT_IOU_TARGET_SEND		= (9ull << 48ull),
	EV_BIT_IOU_CLIENT_SEND		= (10ull << 48ull),
	EV_BIT_IOU_CLOSE		= (11ull << 48ull),
	EV_BIT_IOU_TARGET_CONNECT	= (12ull << 48ull),
	EV_BIT_IOU_TARGET_CANCEL	= (13ull << 48ull),
	EV_BIT_IOU_CLIENT_CANCEL	= (14ull << 48ull),
	EV_BIT_IOU_TIMER_DEL		= (15ull << 48ull),
	EV_BIT_IOU_MSG_RING		= (16ull << 48ull),
	EV_BIT_IOU_CLIENT_SEND_NO_CB	= (17ull << 48ull),
#endif
};


#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)

enum {
	CONN_STATE_INIT			= 0,
	CONN_STATE_FORWARDING		= 1,

	CONN_STATE_SOCKS5_MIN		= 100,
	CONN_STATE_SOCKS5_DATA		= 101,
	CONN_STATE_SOCKS5_CONNECT	= 102,
	CONN_STATE_SOCKS5_DNS_QUERY	= 104,
	CONN_STATE_SOCKS5_MAX		= 199,

	CONN_STATE_HTTP_MIN		= 400,
	CONN_STATE_HTTP_HDR		= 401,
	CONN_STATE_HTTP_CONNECT		= 402,
	CONN_STATE_HTTP_DNS_QUERY	= 403,
	CONN_STATE_HTTP_MAX		= 499,

	/*
	 * Still waiting for protocol specific. Can be one of these:
	 *    - SOCKS5
	 *    - HTTP
	 */
	CONN_STATE_PROT			= 500,
};

struct gwp_conn {
	int		fd;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
	uint32_t	ep_mask;
};

struct gwp_dns_query;

enum {
	/*
	 * Don't close the file descriptor when freeing the connection pair.
	 */
	GWP_CONN_FLAG_NO_CLOSE_FD	= (1ull << 0ull),
	GWP_CONN_FLAG_IS_DYING		= (1ull << 1ull),
	GWP_CONN_FLAG_IS_CANCEL		= (1ull << 2ull),
};

enum {
	GWP_PROT_TYPE_NONE	= 0,
	GWP_PROT_TYPE_SOCKS5	= 1,
	GWP_PROT_TYPE_HTTP	= 2,
};

struct gwp_http_conn {
	struct gwnet_http_hdr_pctx	ctx_hdr;
	struct gwnet_http_req_hdr	req_hdr;
};

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	bool			is_target_alive;
	uint8_t			prot_type;

#ifdef CONFIG_IO_URING
	int				ref_cnt;
	struct __kernel_timespec	ts;
#endif

	uint64_t		flags;
	int			conn_state;
	int			timer_fd;
	uint32_t		idx;
	union {
		struct gwp_socks5_conn	*s5_conn;
		struct gwp_http_conn	*http_conn;
	};
	struct gwp_dns_query	*gdq;
	struct gwp_dns_entry	*gde;
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;
};


struct gwp_conn_slot {
	struct gwp_conn_pair	**pairs;
	uint32_t		nr;
	uint32_t		cap;
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
	int			udp_fd;
	uint16_t		current_txid;
	/* Mapping DNS queries to the corresponding proxy session */
	struct gwp_conn_pair	*session_map[65536];
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
	bool			need_join;
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

int gwp_socks5_prep_connect_reply(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
				  int err);
int gwp_socks5_prepare_target_addr(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

struct gwp_http_conn *gwp_http_conn_alloc(void);
void gwp_http_conn_free(struct gwp_http_conn *conn);
int gwp_socks5_handle_data(struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_prot(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_socks5(struct gwp_wrk *w, struct gwp_conn_pair *gcp);
int gwp_handle_conn_state_http(struct gwp_wrk *w, struct gwp_conn_pair *gcp);

#endif /* #ifndef GWPROXY_H */
