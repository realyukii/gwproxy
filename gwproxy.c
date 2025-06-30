// SPDX-License-Identifier: GPL-2.0-only
/*
 * gwproxy - A simple TCP proxy server.
 *
 * Copyright (C) 2025 Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <inttypes.h>
#include <stdatomic.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <netinet/tcp.h>
#include <sys/timerfd.h>
#include <sys/resource.h>
#include <sys/inotify.h>

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifdef __CHECKER__
#define __must_hold(x) __attribute__((context(x,1,1)))
#define __acquires(x)  __attribute__((context(x,0,1)))
#define __releases(x)  __attribute__((context(x,1,0)))
#else
#define __must_hold(x)
#define __acquires(x)
#define __releases(x)
#endif

static const struct option long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "event-loop",		required_argument,	NULL,	'e' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "as-socks5",		required_argument,	NULL,	'S' },
	{ "socks5-timeout",	required_argument,	NULL,	'o' },
	{ "socks5-auth-file",	required_argument,	NULL,	'A' },
	{ "nr-workers",		required_argument,	NULL,	'w' },
	{ "nr-dns-workers",	required_argument,	NULL,	'W' },
	{ "connect-timeout",	required_argument,	NULL,	'c' },
	{ "target-buf-size",	required_argument,	NULL,	'T' },
	{ "client-buf-size",	required_argument,	NULL,	'C' },
	{ "tcp-nodelay",	required_argument,	NULL,	'd' },
	{ "tcp-quickack",	required_argument,	NULL,	'K' },
	{ "tcp-keepalive",	required_argument,	NULL,	'k' },
	{ "tcp-keepidle",	required_argument,	NULL,	'i' },
	{ "tcp-keepintvl",	required_argument,	NULL,	'l' },
	{ "tcp-keepcnt",	required_argument,	NULL,	'g' },
	{ "log-level",		required_argument,	NULL,	'm' },
	{ "log-file",		required_argument,	NULL,	'f' },
	{ "pid-file",		required_argument,	NULL,	'p' },
	{ NULL,			0,			NULL,	0 }
};

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	int		socks5_timeout;
	const char	*socks5_auth_file;
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

static const struct gwp_cfg default_opts = {
	.event_loop		= "epoll",
	.bind			= "[::]:1080",
	.target			= NULL,
	.as_socks5		= false,
	.socks5_timeout		= 10,
	.socks5_auth_file	= NULL,
	.nr_workers		= 4,
	.nr_dns_workers		= 4,
	.connect_timeout	= 5,
	.target_buf_size	= 2048,
	.client_buf_size	= 2048,
	.tcp_nodelay		= 1,
	.tcp_quickack		= 1,
	.tcp_keepalive		= 1,
	.tcp_keepidle		= 60,
	.tcp_keepintvl		= 10,
	.tcp_keepcnt		= 5,
	.log_level		= 3,
	.log_file		= "/dev/stdout",
	.pid_file		= NULL,
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

#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)

enum {
	CONN_STATE_INIT			= 101,

	CONN_STATE_SOCKS5_MIN		= 200,
	CONN_STATE_SOCKS5_INIT		= CONN_STATE_SOCKS5_MIN,
	CONN_STATE_SOCKS5_AUTH_USERPASS	= 211,
	CONN_STATE_SOCKS5_CMD		= 220,
	CONN_STATE_SOCKS5_CMD_CONNECT	= 221,
	CONN_STATE_SOCKS5_ERR		= 250,
	CONN_STATE_SOCKS5_DNS_QUERY	= 260,
	CONN_STATE_SOCKS5_MAX		= 299,

	CONN_STATE_FORWARDING		= 301,
};

struct gwp_conn {
	int		fd;
	uint32_t	len;
	uint32_t	cap;
	char		*buf;
	uint32_t	ep_mask;
};

struct gwp_sockaddr {
	union {
		struct sockaddr		sa;
		struct sockaddr_in	i4;
		struct sockaddr_in6	i6;
	};
};

struct gwp_dns_query;

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	bool			is_target_alive;
	int			conn_state;
	int			timer_fd;
	uint32_t		idx;
	struct gwp_dns_query	*gdq;
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

struct gwp_wrk_dns {
	pthread_t		thread;
	struct gwp_ctx		*ctx;
	uint32_t		idx;
};

struct gwp_dns_query {
	int			res;
	int			ev_fd;
	char			host[256];
	char			service[sizeof("65535")];
	struct gwp_sockaddr	result;
	struct gwp_dns_query	*next;
	_Atomic(int32_t)	ref_count;
};

struct gwp_dns {
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
	struct gwp_dns_query	*head;
	struct gwp_dns_query	*tail;
	struct gwp_wrk_dns	*workers;
	uint32_t		nr_sleeping;
	uint32_t		nr_queries;
};

struct gwp_socks5_user {
	char	*u, *p;
	uint8_t	ulen, plen;
};

struct gwp_socks5_auth {
	FILE			*handle;
	struct gwp_socks5_user	*users;
	int			ino_fd;
	size_t			nr;
	size_t			cap;
	pthread_rwlock_t	lock;
};

struct gwp_ctx {
	volatile bool			stop;
	FILE				*log_file;
	struct gwp_wrk			*workers;
	struct gwp_dns			*gdns;
	struct gwp_socks5_auth		*s5auth;
	struct gwp_sockaddr		target_addr;
	struct gwp_cfg			cfg;
	_Atomic(int32_t)		nr_fd_closed;
	_Atomic(int32_t)		nr_accept_stopped;
};

static void show_help(const char *app)
{
	printf("Usage: %s [options]\n", app);
	printf("Options:\n");
	printf("  -h, --help                      Show this help message and exit\n");
	printf("  -e, --event-loop=name           Specify the event loop to use (default: %s)\n", default_opts.event_loop);
	printf("                                  Available values: epoll, io_uring\n");
	printf("  -b, --bind=addr:port            Bind to the specified address (default: %s)\n", default_opts.bind);
	printf("  -t, --target=addr_port          Target address to connect to\n");
	printf("  -S, --as-socks5=0|1             Run as a SOCKS5 proxy (default: %d)\n", default_opts.as_socks5);
	printf("  -o, --socks5-timeout=sec        SOCKS5 auth timeout in seconds (default: %d)\n", default_opts.socks5_timeout);
	printf("  -A, --socks5-auth-file=file     File containing username:password for SOCKS5 auth (default: no auth)\n");
	printf("  -w, --nr-workers=nr             Number of worker threads (default: %d)\n", default_opts.nr_workers);
	printf("  -W, --nr-dns-workers=nr         Number of DNS worker threads for SOCKS5 (default: %d)\n", default_opts.nr_dns_workers);
	printf("  -c, --connect-timeout=sec       Connection to target timeout in seconds (default: %d)\n", default_opts.connect_timeout);
	printf("  -T, --target-buf-size=nr        Target buffer size in bytes (default: %d)\n", default_opts.target_buf_size);
	printf("  -C, --client-buf-size=nr        Client buffer size in bytes (default: %d)\n", default_opts.client_buf_size);
	printf("  -d, --tcp-nodelay=0|1           Enable/disable TCP_NODELAY (default: %d)\n", default_opts.tcp_nodelay);
	printf("  -K, --tcp-quickack=0|1          Enable/disable TCP_QUICKACK (default: %d)\n", default_opts.tcp_quickack);
	printf("  -k, --tcp-keepalive=0|1         Enable/disable TCP_KEEPALIVE (default: %d)\n", default_opts.tcp_keepalive);
	printf("  -i, --tcp-keepidle=sec          TCP_KEEPIDLE in seconds (default: %d)\n", default_opts.tcp_keepidle);
	printf("  -l, --tcp-keepintvl=sec         TCP_KEEPINTVL in seconds (default: %d)\n", default_opts.tcp_keepintvl);
	printf("  -g, --tcp-keepcnt=nr            TCP_KEEPCNT (default: %d)\n", default_opts.tcp_keepcnt);
	printf("  -m, --log-level=level           Set log level (0=none, 1=error, 2=warning, 3=info, 4=debug, default: %d)\n", default_opts.log_level);
	printf("  -f, --log-file=file             Log to the specified file (default: %s)\n", default_opts.log_file);
	printf("  -p, --pid-file=file             Write PID to the specified file (default is no pid file)\n");
	printf("\n");
}


static int parse_options(int argc, char *argv[], struct gwp_cfg *cfg)
{
	#define NR_OPTS ((sizeof(long_opts) / sizeof(long_opts[0])) - 1)
	char short_opts[(NR_OPTS * 2) + 1], *p;
	size_t i;
	int c;

	p = short_opts;
	for (i = 0; i < NR_OPTS; i++) {
		*p++ = long_opts[i].val;
		if (long_opts[i].has_arg == required_argument ||
		    long_opts[i].has_arg == optional_argument)
			*p++ = ':';
	}
	*p = '\0';
	#undef NR_OPTS

	*cfg = default_opts;
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_help(argv[0]);
			exit(0);
		case 'e':
			cfg->event_loop = optarg;
			break;
		case 'b':
			cfg->bind = optarg;
			break;
		case 't':
			cfg->target = optarg;
			break;
		case 'S':
			cfg->as_socks5 = !!atoi(optarg);
			break;
		case 'o':
			cfg->socks5_timeout = atoi(optarg);
			break;
		case 'A':
			cfg->socks5_auth_file = optarg;
			break;
		case 'w':
			cfg->nr_workers = atoi(optarg);
			break;
		case 'W':
			cfg->nr_dns_workers = atoi(optarg);
			break;
		case 'c':
			cfg->connect_timeout = atoi(optarg);
			break;
		case 'T':
			cfg->target_buf_size = atoi(optarg);
			break;
		case 'C':
			cfg->client_buf_size = atoi(optarg);
			break;
		case 'd':
			cfg->tcp_nodelay = !!atoi(optarg);
			break;
		case 'K':
			cfg->tcp_quickack = !!atoi(optarg);
			break;
		case 'k':
			cfg->tcp_keepalive = !!atoi(optarg);
			break;
		case 'i':
			cfg->tcp_keepidle = atoi(optarg);
			break;
		case 'l':
			cfg->tcp_keepintvl = atoi(optarg);
			break;
		case 'g':
			cfg->tcp_keepcnt = atoi(optarg);
			break;
		case 'm':
			cfg->log_level = atoi(optarg);
			break;
		case 'f':
			cfg->log_file = optarg;
			break;
		case 'p':
			cfg->pid_file = optarg;
			break;
		default:
			fprintf(stderr, "Unknown option: %c\n", c);
			show_help(argv[0]);
			return -EINVAL;
		}
	}

	if (!cfg->as_socks5 && !cfg->target) {
		fprintf(stderr, "Error: --target is required unless --as-socks5 is specified.\n");
		return -EINVAL;
	}

	if (cfg->nr_workers <= 0) {
		fprintf(stderr, "Error: --nr-workers must be at least 1.\n");
		return -EINVAL;
	}

	if (cfg->target_buf_size <= 1) {
		fprintf(stderr, "Error: --target-buf-size must be greater than 1.\n");
		return -EINVAL;
	}

	if (cfg->client_buf_size <= 1) {
		fprintf(stderr, "Error: --client-buf-size must be greater than 1.\n");
		return -EINVAL;
	}

	return 0;
}

__attribute__((__format__(printf, 3, 4)))
static void __pr_log(FILE *handle, int level, const char *fmt, ...)
{
	char loc_buf[4096], *tmp, *pb, time_buf[64];
	va_list ap, ap2;
	const char *ls;
	struct tm tm;
	time_t now;
	int r;

	if (!handle)
		return;

	switch (level) {
	case 1:  ls = "error "; break;
	case 2:  ls = "warn  "; break;
	case 3:  ls = "info  "; break;
	case 4:  ls = "debug "; break;
	default: ls = "????? "; break;
	}

	va_start(ap, fmt);
	va_copy(ap2, ap);
	r = vsnprintf(loc_buf, sizeof(loc_buf), fmt, ap);
	if (unlikely((size_t)r >= sizeof(loc_buf))) {
		tmp = malloc(r + 1);
		if (!tmp)
			goto out;

		vsnprintf(tmp, r + 1, fmt, ap2);
		pb = tmp;
	} else {
		pb = loc_buf;
	}

	now = time(NULL);
	if (likely(localtime_r(&now, &tm)))
		strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm);
	else
		time_buf[0] = '\0';

	fprintf(handle, "[%s][%s][%08d]: %s\n", time_buf, ls, gettid(), pb);
	if (unlikely(pb != loc_buf))
		free(pb);
out:
	va_end(ap2);
	va_end(ap);
}

#ifndef GWP_STATIC_LOG_LEVEL
#define GWP_STATIC_LOG_LEVEL 4
#endif

#define pr_log(CTX, LEVEL, FMT, ...)		\
do {						\
	struct gwp_ctx *__ctx = (CTX);		\
	int __level = (LEVEL);			\
	if (__level > GWP_STATIC_LOG_LEVEL)	\
		break;				\
	if (__level > __ctx->cfg.log_level)	\
		break;				\
	if (!__ctx->log_file)			\
		break;				\
	__pr_log(__ctx->log_file, __level, FMT, ##__VA_ARGS__);	\
} while (0)

#define pr_err(CTX, FMT, ...)	\
	pr_log((CTX), 1, FMT, ##__VA_ARGS__)

#define pr_warn(CTX, FMT, ...)	\
	pr_log((CTX), 2, FMT, ##__VA_ARGS__)

#define pr_info(CTX, FMT, ...)	\
	pr_log((CTX), 3, FMT, ##__VA_ARGS__)

#define pr_dbg(CTX, FMT, ...)	\
	pr_log((CTX), 4, FMT, ##__VA_ARGS__)



#define FULL_ADDRSTRLEN (INET6_ADDRSTRLEN + sizeof(":65535[]") - 1)
static int convert_ssaddr_to_str(char buf[FULL_ADDRSTRLEN],
				 const struct gwp_sockaddr *gs)
{
	int f = gs->sa.sa_family;
	uint16_t port = 0;
	size_t l;

	if (f == AF_INET) {
		if (!inet_ntop(f, &gs->i4.sin_addr, buf, INET_ADDRSTRLEN))
			return -EINVAL;
		l = strlen(buf);
		port = ntohs(gs->i4.sin_port);
	} else if (f == AF_INET6) {
		buf[0] = '[';
		if (!inet_ntop(f, &gs->i6.sin6_addr, buf + 1, INET6_ADDRSTRLEN))
			return -EINVAL;
		l = strlen(buf);
		buf[l++] = ']';
		port = ntohs(gs->i6.sin6_port);
	} else {
		return -EINVAL;
	}

	buf[l++] = ':';
	snprintf(buf + l, FULL_ADDRSTRLEN - l, "%hu", port);
	return 0;
}

static const char *ip_to_str(const struct gwp_sockaddr *gs)
{
	static __thread char buf[8][FULL_ADDRSTRLEN];
	static __thread uint8_t idx = 0;
	char *bp = buf[idx++ % 8];

	return convert_ssaddr_to_str(bp, gs) ? NULL : bp;
}

static int convert_str_to_ssaddr(const char *str, struct gwp_sockaddr *gs)
{
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	char host[NI_MAXHOST], port[6], *p;
	struct addrinfo *res, *ai;
	bool found = false;
	size_t l;
	int r;

	if (*str == '[') {
		p = strchr(++str, ']');
		if (!p)
			return -EINVAL;
		l = p - str;
		if (l >= sizeof(host))
			return -EINVAL;
		p++;
		if (*p != ':')
			return -EINVAL;
	} else {
		p = strchr(str, ':');
		if (!p)
			return -EINVAL;
		l = p - str;
		if (l >= sizeof(host))
			return -EINVAL;
	}

	strncpy(host, str, l);
	host[l] = '\0';
	strncpy(port, p + 1, sizeof(port) - 1);
	port[sizeof(port) - 1] = '\0';

	r = getaddrinfo(host, port, &hints, &res);
	if (r)
		return -EINVAL;
	if (!res)
		return -EINVAL;

	memset(gs, 0, sizeof(*gs));
	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			gs->i4 = *(struct sockaddr_in *)ai->ai_addr;
			found = true;
			break;
		} else if (ai->ai_family == AF_INET6) {
			gs->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			found = true;
			break;
		}
	}

	freeaddrinfo(res);
	return found ? 0 : -EINVAL;
}

static int gwp_ctx_init_log(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	int r = 0;

	if (!strcmp("/dev/stdout", cfg->log_file)) {
		ctx->log_file = stdout;
	} else if (!strcmp("/dev/stderr", cfg->log_file)) {
		ctx->log_file = stderr;
	} else if (!*cfg->log_file) {
		ctx->log_file = NULL;
	} else {
		ctx->log_file = fopen(cfg->log_file, "ab");
		if (!ctx->log_file) {
			r = -errno;
			pr_err(ctx, "Failed to open log file '%s': %s",
				cfg->log_file, strerror(-r));
		}
	}

	return r;
}

static void gwp_ctx_free_log(struct gwp_ctx *ctx)
{
	if (ctx->log_file &&
	    ctx->log_file != stdout &&
	    ctx->log_file != stderr) {
		fclose(ctx->log_file);
		ctx->log_file = NULL;
	}
}

static int gwp_ctx_init_pid_file(struct gwp_ctx *ctx)
{
	FILE *f;
	int r;

	f = fopen(ctx->cfg.pid_file, "wb");
	if (!f) {
		r = -errno;
		pr_warn(ctx, "Failed to open PID file '%s': %s",
			ctx->cfg.pid_file, strerror(-r));
		return r;
	}

	r = getpid();
	pr_info(ctx, "Writing PID to '%s' (pid=%d)", ctx->cfg.pid_file, r);
	fprintf(f, "%d\n", r);
	fclose(f);
	return 0;
}

static int gwp_ctx_init_thread_sock(struct gwp_wrk *w,
				    const struct gwp_sockaddr *ba)
{
	static const int type = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_cfg *cfg = &w->ctx->cfg;
	socklen_t slen;
	int fd, r, v;

	r = ba->sa.sa_family;
	if (r == AF_INET) {
		slen = sizeof(struct sockaddr_in);
	} else if (r == AF_INET6) {
		slen = sizeof(struct sockaddr_in6);
	} else {
		pr_err(w->ctx, "Unsupported address family: %d", r);
		return -EAFNOSUPPORT;
	}

	fd = socket(r, type, 0);
	if (fd < 0) {
		r = -errno;
		pr_err(w->ctx, "Failed to create socket: %s", strerror(-r));
		return r;
	}

	v = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v));

	r = bind(fd, (struct sockaddr *)ba, slen);
	if (r < 0) {
		r = -errno;
		pr_err(w->ctx, "Failed to bind socket: %s", strerror(-r));
		goto out_close;
	}

	r = listen(fd, SOMAXCONN);
	if (r < 0) {
		r = -errno;
		pr_err(w->ctx, "Failed to listen on socket: %s", strerror(-r));
		goto out_close;
	}

	w->tcp_fd = fd;
	pr_info(w->ctx, "Worker %u is listening on %s (fd=%d)", w->idx,
		cfg->bind, fd);
	return 0;

out_close:
	close(fd);
	w->tcp_fd = -1;
	return r;
}

static void gwp_ctx_free_thread_sock(struct gwp_wrk *w)
{
	if (w->tcp_fd >= 0) {
		close(w->tcp_fd);
		pr_dbg(w->ctx, "Worker %u socket closed (fd=%d)", w->idx,
			w->tcp_fd);
		w->tcp_fd = -1;
	}
}

static int gwp_ctx_init_thread_epoll(struct gwp_wrk *w)
{
	struct epoll_event ev, *events;
	struct gwp_ctx *ctx = w->ctx;
	int ep_fd, ev_fd, r;

	ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0) {
		r = -errno;
		pr_err(w->ctx, "Failed to create epoll instance: %s\n",
		       strerror(-r));
		return r;
	}

	ev_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ev_fd < 0) {
		r = -errno;
		pr_err(w->ctx, "Failed to create eventfd: %s\n", strerror(-r));
		goto out_close_ep_fd;
	}

	w->evsz = 512;
	events = calloc(w->evsz, sizeof(*events));
	if (!events) {
		r = -ENOMEM;
		pr_err(w->ctx, "Failed to allocate memory for events: %s\n",
		       strerror(-r));
		goto out_close_ev_fd;
	}

	w->ev_fd = ev_fd;
	w->ep_fd = ep_fd;
	w->events = events;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_EVENTFD;
	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, ev_fd, &ev))
		goto out_err_ctl;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev))
		goto out_err_ctl;

	if (w->idx == 0 && ctx->s5auth) {
		ev.events = EPOLLIN;
		ev.data.u64 = EV_BIT_SOCKS5_AUTH_FILE;
		if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, ctx->s5auth->ino_fd, &ev))
			goto out_err_ctl;
	}

	pr_dbg(w->ctx, "Worker %u epoll (ep_fd=%d, ev_fd=%d)", w->idx,
		ep_fd, ev_fd);
	return 0;

out_err_ctl:
	r = -errno;
	free(events);
	w->events = NULL;
out_close_ev_fd:
	close(ev_fd);
out_close_ep_fd:
	close(ep_fd);
	w->ev_fd = w->ep_fd = -1;
	return r;
}

static void gwp_ctx_free_thread_epoll(struct gwp_wrk *w)
{
	if (w->ev_fd >= 0) {
		close(w->ev_fd);
		pr_dbg(w->ctx, "Worker %u eventfd closed (fd=%d)", w->idx,
		       w->ev_fd);
		w->ev_fd = -1;
	}

	if (w->ep_fd >= 0) {
		close(w->ep_fd);
		pr_dbg(w->ctx, "Worker %u epoll closed (fd=%d)", w->idx,
		       w->ep_fd);
		w->ep_fd = -1;
	}

	free(w->events);
	w->events = NULL;
}

static int gwp_ctx_init_thread(struct gwp_wrk *w,
			       const struct gwp_sockaddr *bind_addr)
{
	int r;

	r = gwp_ctx_init_thread_sock(w, bind_addr);
	if (r < 0) {
		pr_err(w->ctx, "Failed to initialize thread socket: %s\n",
		       strerror(-r));
		return r;
	}

	r = gwp_ctx_init_thread_epoll(w);
	if (r < 0) {
		pr_err(w->ctx, "Failed to initialize epoll for worker %u: %s\n",
			w->idx, strerror(-r));
		goto out_free_sock;
	}

	return 0;

out_free_sock:
	gwp_ctx_free_thread_sock(w);
	return -r;
}

static void free_conn(struct gwp_conn *conn);

static void log_conn_pair_close(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	pr_info(w->ctx,
		"Closing connection pair (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));
}

static void gwp_ctx_free_thread_sock_pairs(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	size_t i;

	if (!gcs->pairs)
		return;

	for (i = 0; i < gcs->nr; i++) {
		struct gwp_conn_pair *gcp = gcs->pairs[i];
		if (!gcp)
			continue;

		log_conn_pair_close(w, gcp);
		free_conn(&gcp->target);
		free_conn(&gcp->client);
		if (gcp->timer_fd >= 0)
			close(gcp->timer_fd);
		free(gcp);
	}

	free(gcs->pairs);
	gcs->pairs = NULL;
	gcs->nr = 0;
	gcs->cap = 0;
}

static void gwp_ctx_free_thread(struct gwp_wrk *w)
{
	if (w->idx > 0)
		pthread_join(w->thread, NULL);
	gwp_ctx_free_thread_sock_pairs(w);
	gwp_ctx_free_thread_epoll(w);
	gwp_ctx_free_thread_sock(w);
}

static int gwp_ctx_init_threads(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_sockaddr bind_addr;
	struct gwp_wrk *workers, *w;
	int i, r;

	if (cfg->nr_workers <= 0) {
		pr_err(ctx, "Number of workers must be at least 1\n");
		return -EINVAL;
	}

	r = convert_str_to_ssaddr(cfg->bind, &bind_addr);
	if (r) {
		pr_err(ctx, "Invalid bind address '%s'\n", cfg->bind);
		return r;
	}

	workers = calloc(cfg->nr_workers, sizeof(*workers));
	if (!workers)
		return -ENOMEM;

	ctx->workers = workers;
	for (i = 0; i < cfg->nr_workers; i++) {
		w = &workers[i];
		w->ctx = ctx;
		w->idx = i;
		r = gwp_ctx_init_thread(w, &bind_addr);
		if (r < 0)
			goto out_err;
	}

	return 0;

out_err:
	while (i--)
		gwp_ctx_free_thread(&workers[i]);
	free(workers);
	ctx->workers = NULL;
	return r;
}

static void gwp_ctx_free_threads(struct gwp_ctx *ctx)
{
	struct gwp_wrk *workers = ctx->workers;
	int i;

	if (!workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++)
		gwp_ctx_free_thread(&workers[i]);

	free(workers);
	ctx->workers = NULL;
}

static int resolve_domain(const char *host, const char *service,
			  struct gwp_sockaddr *addr)
{
	static const struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *res = NULL, *ai;
	bool found = false;
	int r;

	r = getaddrinfo(host, service, &hints, &res);
	if (r < 0 || !res)
		return -EHOSTUNREACH;

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			addr->i4 = *(struct sockaddr_in *)ai->ai_addr;
			found = true;
			break;
		} else if (ai->ai_family == AF_INET6) {
			addr->i6 = *(struct sockaddr_in6 *)ai->ai_addr;
			found = true;
			break;
		}
	}
	freeaddrinfo(res);
	return found ? 0 : -EHOSTUNREACH;
}

static struct gwp_dns_query *gwp_gdns_push_query(const char host[256],
						 const char port[6],
						 struct gwp_dns *gdns)
{
	struct gwp_dns_query *gdq;
	size_t l;
	int fd;

	gdq = calloc(1, sizeof(*gdq));
	if (!gdq)
		return NULL;

	fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd < 0) {
		free(gdq);
		return NULL;
	}

	gdq->ev_fd = fd;
	atomic_init(&gdq->ref_count, 2);

	l = sizeof(gdq->host) - 1;
	strncpy(gdq->host, host, l);
	gdq->host[l] = '\0';

	l = sizeof(gdq->service) - 1;
	strncpy(gdq->service, port, l);
	gdq->service[l] = '\0';

	pthread_mutex_lock(&gdns->lock);
	if (gdns->tail)
		gdns->tail->next = gdq;
	else
		gdns->head = gdq;
	gdns->tail = gdq;
	gdq->next = NULL;
	gdns->nr_queries++;
	if (gdns->nr_sleeping)
		pthread_cond_signal(&gdns->cond);
	pthread_mutex_unlock(&gdns->lock);
	return gdq;
}

static struct gwp_dns_query *__gwp_gdns_pop_query(struct gwp_dns *gdns)
	__must_hold(&gdns->lock)
{
	struct gwp_dns_query *gdq = gdns->head;

	if (!gdq)
		return NULL;

	gdns->head = gdq->next;
	if (!gdns->head)
		gdns->tail = NULL;

	gdns->nr_queries--;
	return gdq;
}

static void gwp_gdns_free_query(struct gwp_dns_query *gdq)
{
	if (!gdq)
		return;

	if (gdq->ev_fd >= 0) {
		close(gdq->ev_fd);
		gdq->ev_fd = -1;
	}
	free(gdq);
}

static void gwp_gdns_put_query(struct gwp_dns_query *gdq)
{
	if (!gdq)
		return;

	if (atomic_fetch_sub(&gdq->ref_count, 1) == 1)
		gwp_gdns_free_query(gdq);
}

static void __gwp_gdns_reap_query(struct gwp_wrk_dns *wdns, struct gwp_ctx *ctx,
				  struct gwp_dns *gdns)
	__must_hold(&gdns->lock)
{
	struct gwp_dns_query *gdq;

	gdq = __gwp_gdns_pop_query(gdns);
	if (!gdq)
		return;

	pthread_mutex_unlock(&gdns->lock);
	if (atomic_load(&gdq->ref_count) == 1) {
		/*
		 * The client closed the connection before the
		 * DNS query is processed.
		 */
		pr_dbg(ctx, "DNS query put early (idx=%u, host=%s, service=%s)",
			wdns->idx, gdq->host, gdq->service);
		gwp_gdns_free_query(gdq);
		goto out_lock;
	}

	memset(&gdq->result, 0, sizeof(gdq->result));
	gdq->res = resolve_domain(gdq->host, gdq->service, &gdq->result);
	eventfd_write(gdq->ev_fd, 1);
	gwp_gdns_put_query(gdq);

out_lock:
	pthread_mutex_lock(&gdns->lock);
}

static void __gwp_gdns_cond_wait(struct gwp_wrk_dns *wdns, struct gwp_ctx *ctx,
				 struct gwp_dns *gdns)
	__must_hold(&gdns->lock)
{
	gdns->nr_sleeping++;

	pr_dbg(ctx, "DNS worker %u is waiting for queries (nr_sleeping=%u)",
		wdns->idx, gdns->nr_sleeping);

	pthread_cond_wait(&gdns->cond, &gdns->lock);
	gdns->nr_sleeping--;

	pr_dbg(ctx, "DNS worker %u woke up (nr_sleeping=%u)", wdns->idx,
		gdns->nr_sleeping);
}

static void *gwp_ctx_dns_thread_entry(void *arg)
{
	struct gwp_wrk_dns *wdns = arg;
	struct gwp_ctx *ctx = wdns->ctx;
	struct gwp_dns *gdns = ctx->gdns;

	pr_info(ctx, "DNS worker %u started", wdns->idx);

	pthread_mutex_lock(&gdns->lock);
	while (!ctx->stop) {
		if (gdns->head)
			__gwp_gdns_reap_query(wdns, ctx, gdns);
		else
			__gwp_gdns_cond_wait(wdns, ctx, gdns);
	}
	pthread_mutex_unlock(&gdns->lock);

	pr_info(ctx, "DNS worker %u is stopping", wdns->idx);
	return NULL;
}

static int gwp_ctx_init_dns(struct gwp_ctx *ctx)
{
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_dns *gdns;
	int i, r;

	if (!cfg->as_socks5 || cfg->nr_dns_workers <= 0) {
		ctx->gdns = NULL;
		return 0;
	}

	gdns = calloc(1, sizeof(*gdns));
	if (!gdns) {
		pr_err(ctx, "Failed to allocate memory for DNS context");
		return -ENOMEM;
	}

	gdns->workers = calloc(cfg->nr_dns_workers, sizeof(*gdns->workers));
	if (!gdns->workers) {
		r = -ENOMEM;
		pr_err(ctx, "Failed to allocate memory for DNS workers: %s",
			strerror(-r));
		goto out_free_gdns;
	}

	r = pthread_mutex_init(&gdns->lock, NULL);
	if (r) {
		r = -r;
		pr_err(ctx, "Failed to initialize DNS mutex: %s", strerror(r));
		goto out_free_workers;
	}

	r = pthread_cond_init(&gdns->cond, NULL);
	if (r) {
		r = -r;
		pr_err(ctx, "Failed to initialize DNS condvar: %s", strerror(r));
		goto out_free_lock;
	}

	ctx->gdns = gdns;
	for (i = 0; i < cfg->nr_dns_workers; i++) {
		struct gwp_wrk_dns *wdns = &gdns->workers[i];
		char tmp[128];

		wdns->ctx = ctx;
		wdns->idx = (uint32_t)i;
		r = pthread_create(&wdns->thread, NULL,
				   &gwp_ctx_dns_thread_entry, wdns);
		if (r) {
			r = -r;
			pr_err(ctx, "Failed to create DNS worker thread %d: %s",
			       i, strerror(r));
			goto out_join_workers;
		}

		snprintf(tmp, sizeof(tmp), "gwproxy-dns-%d", i);
		pthread_setname_np(wdns->thread, tmp);
	}

	return 0;
out_join_workers:
	pthread_mutex_lock(&gdns->lock);
	ctx->stop = true;
	pthread_cond_broadcast(&gdns->cond);
	pthread_mutex_unlock(&gdns->lock);
	while (i--) {
		struct gwp_wrk_dns *wdns = &gdns->workers[i];
		pthread_join(wdns->thread, NULL);
	}
	pthread_cond_destroy(&gdns->cond);
out_free_lock:
	pthread_mutex_destroy(&gdns->lock);
out_free_workers:
	free(gdns->workers);
out_free_gdns:
	free(gdns);
	ctx->gdns = NULL;
	return r;
}

static void gwp_ctx_free_dns(struct gwp_ctx *ctx)
{
	struct gwp_dns *gdns = ctx->gdns;
	struct gwp_dns_query *gdq, *next;
	int i;

	if (!gdns)
		return;

	pthread_mutex_lock(&gdns->lock);
	ctx->stop = true;
	pthread_cond_broadcast(&gdns->cond);
	pthread_mutex_unlock(&gdns->lock);

	for (i = 0; i < ctx->cfg.nr_dns_workers; i++) {
		struct gwp_wrk_dns *wdns = &gdns->workers[i];
		pthread_join(wdns->thread, NULL);
	}

	gdq = gdns->head;
	i = 0;
	while (gdq) {
		next = gdq->next;
		if (gdq->ev_fd >= 0)
			close(gdq->ev_fd);
		free(gdq);
		gdq = next;
		i++;
	}
	(void)i;
	pr_dbg(ctx, "Freed %u unprocessed DNS queries", i);

	free(gdns->workers);
	pthread_mutex_destroy(&gdns->lock);
	pthread_cond_destroy(&gdns->cond);
	free(gdns);
	ctx->gdns = NULL;
	pr_dbg(ctx, "DNS workers stopped and resources freed");
}

static int gwp_load_s5auth_add_user(struct gwp_socks5_auth *s5a,
				    const char *line)
{
	char *u, *p;

	if (s5a->nr >= s5a->cap) {
		size_t new_cap = s5a->cap ? s5a->cap * 2 : 16;
		struct gwp_socks5_user *new_users;
		new_users = realloc(s5a->users, new_cap * sizeof(*new_users));
		if (!new_users)
			return -ENOMEM;
		s5a->users = new_users;
		s5a->cap = new_cap;
	}

	u = strdup(line);
	if (!u)
		return -ENOMEM;

	p = strchr(u, ':');
	if (p)
		*p++ = '\0';

	if (unlikely(strlen(u) > 255)) {
		free(u);
		return -EINVAL;
	}

	if (unlikely(p && strlen(p) > 255)) {
		free(u);
		return -EINVAL;
	}

	s5a->users[s5a->nr].u = u;
	s5a->users[s5a->nr].p = p;
	s5a->users[s5a->nr].ulen = strlen(u);
	s5a->users[s5a->nr].plen = p ? strlen(p) : 0;
	s5a->nr++;
	return 0;
}

static void gwp_load_s5auth_free_users(struct gwp_socks5_auth *s5a)
{
	size_t i;

	if (!s5a->users)
		return;

	for (i = 0; i < s5a->nr; i++)
		free(s5a->users[i].u);

	free(s5a->users);
	s5a->users = NULL;
	s5a->nr = 0;
	s5a->cap = 0;
}

static bool is_space(unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static char *trim_str(char *str)
{
	char *end;

	while (is_space((unsigned char)*str))
		str++;

	end = str + strlen(str) - 1;
	while (end > str && is_space((unsigned char)*end))
		end--;

	end[1] = '\0';
	return str;
}

static int gwp_load_s5auth(struct gwp_ctx *ctx)
{
	const char *s5a_file = ctx->cfg.socks5_auth_file;
	struct gwp_socks5_auth *s5a = ctx->s5auth;
	char buf[512], *t;
	int r = 0;
	size_t l;

	pr_info(ctx, "Loading SOCKS5 authentication from '%s'", s5a_file);
	pthread_rwlock_wrlock(&s5a->lock);
	gwp_load_s5auth_free_users(s5a);
	while (1) {
		t = fgets(buf, sizeof(buf), s5a->handle);
		if (!t)
			break;

		t = trim_str(t);
		l = strlen(t);
		if (!l)
			continue;

		r = gwp_load_s5auth_add_user(s5a, t);
		if (r)
			continue;
	}
	rewind(s5a->handle);
	l = s5a->nr;
	pthread_rwlock_unlock(&s5a->lock);
	pr_info(ctx, "Loaded %zu users from '%s'", l, s5a_file);
	return 0;
}

static int gwp_ctx_init_s5auth(struct gwp_ctx *ctx)
{
	const char *s5a_file = ctx->cfg.socks5_auth_file;
	struct gwp_socks5_auth *s5a;
	int r;

	if (!ctx->cfg.as_socks5 || !s5a_file || !*s5a_file) {
		ctx->s5auth = NULL;
		return 0;
	}

	s5a = calloc(1, sizeof(*s5a));
	if (!s5a)
		return -ENOMEM;

	r = pthread_rwlock_init(&s5a->lock, NULL);
	if (r) {
		r = -r;
		pr_err(ctx, "Failed to initialize SOCKS5 auth lock: %s",
			strerror(r));
		goto out_free_s5a;
	}

	s5a->handle = fopen(s5a_file, "rb");
	if (!s5a->handle) {
		r = -errno;
		pr_err(ctx, "Failed to open SOCKS5 auth file '%s': %s",
			s5a_file, strerror(-r));
		goto out_destroy_lock;
	}

	s5a->ino_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (s5a->ino_fd < 0) {
		r = -errno;
		pr_err(ctx, "Failed to create inotify instance: %s",
		       strerror(-r));
		goto out_fclose_handle;
	}

	r = inotify_add_watch(s5a->ino_fd, s5a_file, IN_CLOSE_WRITE | IN_DELETE);
	if (r < 0) {
		r = -errno;
		pr_err(ctx, "Failed to add inotify watch for '%s': %s",
		       s5a_file, strerror(-r));
		goto out_close_ino_fd;
	}

	ctx->s5auth = s5a;
	r = gwp_load_s5auth(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to load SOCKS5 authentication: %s",
		       strerror(-r));
		goto out_close_ino_fd;
	}

	return 0;

out_close_ino_fd:
	close(s5a->ino_fd);
out_fclose_handle:
	fclose(s5a->handle);
out_destroy_lock:
	pthread_rwlock_destroy(&s5a->lock);
out_free_s5a:
	free(s5a);
	ctx->s5auth = NULL;
	return r;
}

static void gwp_ctx_free_s5auth(struct gwp_ctx *ctx)
{
	struct gwp_socks5_auth *s5a = ctx->s5auth;

	if (!s5a)
		return;

	gwp_load_s5auth_free_users(s5a);
	close(s5a->ino_fd);
	fclose(s5a->handle);
	pthread_rwlock_destroy(&s5a->lock);
	free(s5a);
	ctx->s5auth = NULL;
}

static int gwp_ctx_init(struct gwp_ctx *ctx)
{
	int r;

	r = gwp_ctx_init_log(ctx);
	if (r < 0)
		return r;
	r = gwp_ctx_init_s5auth(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize SOCKS5 authentication: %s",
			strerror(-r));
		goto out_free_log;
	}

	r = gwp_ctx_init_dns(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize DNS workers: %s", strerror(-r));
		goto out_free_s5auth;
	}

	if (!ctx->cfg.as_socks5) {
		const char *t = ctx->cfg.target;
		r = convert_str_to_ssaddr(t, &ctx->target_addr);
		if (r) {
			pr_err(ctx, "Invalid target address '%s'", t);
			goto out_free_dns;
		}
	}

	if (ctx->cfg.pid_file)
		gwp_ctx_init_pid_file(ctx);

	r = gwp_ctx_init_threads(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize worker threads: %s",
			strerror(-r));
		goto out_free_dns;
	}

	return 0;
out_free_dns:
	gwp_ctx_free_dns(ctx);
out_free_s5auth:
	gwp_ctx_free_s5auth(ctx);
out_free_log:
	gwp_ctx_free_log(ctx);
	return r;
}

static void gwp_ctx_signal_all_workers(struct gwp_ctx *ctx)
{
	int i;

	if (!ctx->workers)
		return;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		eventfd_write(w->ev_fd, 1);
	}
}

static void gwp_ctx_stop(struct gwp_ctx *ctx)
{
	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
}

static void gwp_ctx_free(struct gwp_ctx *ctx)
{
	gwp_ctx_stop(ctx);
	gwp_ctx_free_threads(ctx);
	gwp_ctx_free_dns(ctx);
	gwp_ctx_free_s5auth(ctx);
	gwp_ctx_free_log(ctx);
}

static int init_conn(struct gwp_conn *conn, uint32_t buf_size)
{
	conn->fd = -1;
	conn->len = 0;
	conn->cap = buf_size;
	conn->ep_mask = 0;
	conn->buf = malloc(buf_size);
	return conn->buf ? 0 : -ENOMEM;
}

static void free_conn(struct gwp_conn *conn)
{
	if (!conn)
		return;

	if (conn->buf)
		free(conn->buf);

	if (conn->fd >= 0)
		close(conn->fd);

	conn->len = 0;
	conn->cap = 0;
	conn->ep_mask = 0;
}

static struct gwp_conn_pair *alloc_conn_pair(struct gwp_wrk *w)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct gwp_conn_pair *gcp;
	int r;

	if (gcs->nr >= gcs->cap) {
		struct gwp_conn_pair **new_pairs;
		size_t new_cap = gcs->cap + 4;

		new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs)
			return NULL;

		gcs->pairs = new_pairs;
		gcs->cap = new_cap;
		pr_dbg(ctx, "Increased connection slot capacity to %zu", gcs->cap);
	}

	gcp = calloc(1, sizeof(*gcp));
	if (!gcp)
		return NULL;

	assert(cfg->target_buf_size > 1);
	assert(cfg->client_buf_size > 1);
	r = init_conn(&gcp->target, cfg->target_buf_size);
	if (r)
		goto out_free_gcp;
	r = init_conn(&gcp->client, cfg->client_buf_size);
	if (r)
		goto out_free_target_conn;

	gcp->timer_fd = -1;
	gcp->idx = gcs->nr;
	gcp->conn_state = CONN_STATE_INIT;
	gcs->pairs[gcs->nr++] = gcp;
	return gcp;

out_free_target_conn:
	free_conn(&gcp->target);
out_free_gcp:
	free(gcp);
	pr_err(ctx, "Failed to allocate connection pair: %s", strerror(-r));
	return NULL;
}

static int rearm_accept(struct gwp_wrk *w, int nr_fd_closed)
{
	struct gwp_ctx *ctx = w->ctx;
	struct epoll_event ev;
	int x;

	/*
	 * Each connection pair consists of at least 3 file descriptors:
	 *
	 *   1. TCP socket for the client connection.
	 *   2. TCP socket for the target connection.
	 *   3. Timer file descriptor (if used).
	 *
	 * Before rearming the main TCP socket, wait until we have free
	 * space for at least 3 connection pairs per worker thread.
	 */
	if (nr_fd_closed <= ((3 * ctx->cfg.nr_workers) * 3))
		return 0;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	if (epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev))
		return -errno;

	w->accept_is_stopped = false;
	pr_info(ctx,
		"Rearmed main TCP socket for accepting new connections (tidx=%u, fd=%d)",
		w->idx, w->tcp_fd);

	x = atomic_fetch_sub(&ctx->nr_accept_stopped, 1);
	if (x == 1)
		atomic_store(&ctx->nr_fd_closed, 0);

	return 0;
}

static int free_conn_pair(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn_slot *gcs = &w->conn_slot;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_dns_query *gdq;
	struct gwp_conn_pair *tmp;
	uint32_t i = gcp->idx;
	int nr_fd_closed = 0;
	int r;

	tmp = gcs->pairs[i];
	assert(tmp == gcp);
	if (unlikely(tmp != gcp))
		return -EINVAL;

	gdq = gcp->gdq;
	if (gdq) {
		if (epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, gdq->ev_fd, NULL))
			return -errno;

		gwp_gdns_put_query(gdq);
		gcp->gdq = NULL;
	}

	if (gcp->client.fd >= 0) {
		nr_fd_closed++;
		w->ev_need_reload = true;
		log_conn_pair_close(w, gcp);
	}

	if (gcp->timer_fd >= 0) {
		nr_fd_closed++;
		close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	if (gcp->target.fd >= 0)
		nr_fd_closed++;

	tmp = gcs->pairs[--gcs->nr];
	gcs->pairs[gcs->nr] = NULL;
	gcs->pairs[i] = tmp;
	tmp->idx = i;
	free_conn(&gcp->target);
	free_conn(&gcp->client);
	free(gcp);

	if (!gcs->nr) {
		free(gcs->pairs);
		gcs->pairs = NULL;
		gcs->cap = 0;
		pr_dbg(ctx, "Decreased connection slot capacity to 0");
	} else if ((gcs->cap - gcs->nr) >= 16) {
		struct gwp_conn_pair **new_pairs;
		size_t new_cap = gcs->nr;

		new_pairs = realloc(gcs->pairs, new_cap * sizeof(*new_pairs));
		if (new_pairs) {
			gcs->pairs = new_pairs;
			gcs->cap = new_cap;
			pr_dbg(ctx, "Decreased connection slot capacity to %zu",
				gcs->cap);
		}
	}

	if (unlikely(w->accept_is_stopped)) {
		int x;
		/*
		 * If we have closed at least one file descriptor, we can
		 * rearm the main TCP socket with EPOLLIN to accept new
		 * connections.
		 */
		x = atomic_fetch_add(&ctx->nr_fd_closed, nr_fd_closed);
		r = rearm_accept(w, x);
		if (r)
			return r;
	}

	return 0;
}

static int setskopt_int(int fd, int level, int optname, int value)
{
	return setsockopt(fd, level, optname, &value, sizeof(value));
}

static void setup_sock_options(struct gwp_wrk *w, int fd)
{
	struct gwp_cfg *cfg = &w->ctx->cfg;

	if (cfg->tcp_nodelay)
		setskopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1);

	if (cfg->tcp_keepalive)
		setskopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, 1);

	if (cfg->tcp_keepidle > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPIDLE, cfg->tcp_keepidle);

	if (cfg->tcp_keepintvl > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPINTVL, cfg->tcp_keepintvl);

	if (cfg->tcp_keepcnt > 0)
		setskopt_int(fd, IPPROTO_TCP, TCP_KEEPCNT, cfg->tcp_keepcnt);
}

static int create_sock_target(struct gwp_wrk *w, struct gwp_sockaddr *addr,
			      bool *is_target_alive)
{
	static const int t = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	socklen_t len;
	int fd, r;

	fd = socket(addr->sa.sa_family, t, 0);
	if (fd < 0)
		return -errno;

	setup_sock_options(w, fd);
	len = (addr->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in)
					      : sizeof(struct sockaddr_in6);
	r = connect(fd, &addr->sa, len);
	if (likely(r)) {
		r = -errno;
		if (r != -EINPROGRESS) {
			close(fd);
			return -r;
		}
		*is_target_alive = false;
	} else {
		*is_target_alive = true;
	}

	return fd;
}

static int create_timer(int fd, int sec, int nsec)
{
	const struct itimerspec its = {
		.it_value.tv_sec = sec,
		.it_value.tv_nsec = nsec,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 0,
	};
	bool need_close = false;
	int r;

	if (fd < 0) {
		fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
		if (fd < 0)
			return -errno;

		need_close = true;
	}


	r = timerfd_settime(fd, 0, &its, NULL);
	if (r < 0) {
		r = -errno;
		if (need_close)
			close(fd);
		return r;
	}

	return fd;
}

static void log_conn_pair_created(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	pr_info(ctx, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
}

static int handle_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	int r, fd, timer_fd, timeout;
	struct epoll_event ev;
	uint64_t cl_ev_bit;

	if (ctx->cfg.as_socks5) {
		/*
		 * If we are running as a SOCKS5 proxy, the initial connection
		 * does not have a target socket. We will create the target
		 * socket later, when the client sends a CONNECT command.
		 */
		timeout = cfg->socks5_timeout;
		fd = -1;
		gcp->conn_state = CONN_STATE_SOCKS5_INIT;
		cl_ev_bit = EV_BIT_CLIENT_SOCKS5;
	} else {
		fd = create_sock_target(w, &gcp->target_addr,
					&gcp->is_target_alive);
		if (unlikely(fd < 0)) {
			pr_err(ctx, "Failed to create target socket: %s",
				strerror(-fd));
			return fd;
		}
		timeout = cfg->connect_timeout;
		gcp->conn_state = CONN_STATE_FORWARDING;
		cl_ev_bit = EV_BIT_CLIENT;
	}

	if (timeout > 0) {
		timer_fd = create_timer(-1, timeout, 0);
		if (unlikely(timer_fd < 0)) {
			pr_err(ctx, "Failed to create connect timeout timer: %s",
			       strerror(-timer_fd));
			close(fd);
			return timer_fd;
		}
		gcp->timer_fd = timer_fd;
	}

	/*
	 * If epoll_ctl() fails, don't bother closing the target socket
	 * because it will be closed in free_conn_pair() anyway.
	 */
	gcp->target.fd = fd;
	gcp->target.ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;
	gcp->client.ep_mask = EPOLLIN | EPOLLRDHUP;

	if (gcp->target.fd >= 0) {
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TARGET;
		r = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, fd, &ev);
		if (unlikely(r < 0)) {
			r = -errno;
			pr_err(ctx, "Failed to add target socket to epoll: %s",
				strerror(-r));
			return r;
		}
	}

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= cl_ev_bit;
	r = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->client.fd, &ev);
	if (unlikely(r < 0)) {
		r = -errno;
		pr_err(ctx, "Failed to add client socket to epoll: %s",
			strerror(-r));
		return r;
	}

	if (gcp->timer_fd >= 0) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TIMER;
		r = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->timer_fd, &ev);
		if (unlikely(r < 0)) {
			r = -errno;
			pr_err(ctx, "Failed to add timer to epoll: %s",
				strerror(-r));
			return r;
		}
	}

	if (gcp->target.fd >= 0)
		log_conn_pair_created(w, gcp);

	return 0;
}

static int handle_accept_error(struct gwp_wrk *w, int e)
{
	int r;

	if (likely(e == -EAGAIN || e == -EINTR))
		return e;

	if (likely(e == -EMFILE || e == -ENFILE || e == -ENOMEM)) {
		/*
		 * We have reached the limit of open files. Delete the
		 * main TCP socket from the epoll instance to avoid
		 * getting EPOLLIN in the next epoll_wait() call.
		 *
		 * Set the accept_is_stopped flag to true to let the
		 * worker thread know that it should rearm the main
		 * TCP socket with EPOLLIN again after it has at least
		 * closed a file descriptor.
		 *
		 * See free_conn_pair() for more details.
		 */
		pr_warn(w->ctx, "Too many open files, stop accepting new connections");
		w->accept_is_stopped = true;
		r = epoll_ctl(w->ep_fd, EPOLL_CTL_DEL, w->tcp_fd, NULL);
		if (r)
			return -errno;

		atomic_fetch_add(&w->ctx->nr_accept_stopped, 1);
		return -EAGAIN;
	}

	pr_err(w->ctx, "Failed to accept new connection: %s", strerror(-e));
	return e;
}

static int __handle_ev_accept(struct gwp_wrk *w)
{
	static const int flags = SOCK_NONBLOCK | SOCK_CLOEXEC;
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_conn_pair *gcp;
	struct sockaddr *addr;
	socklen_t addr_len;
	int fd, r;

	gcp = alloc_conn_pair(w);
	if (unlikely(!gcp)) {
		pr_err(ctx, "Failed to allocate connection pair on accept");
		return handle_accept_error(w, -ENOMEM);
	}

	addr = &gcp->client_addr.sa;
	addr_len = sizeof(gcp->client_addr);
	fd = accept4(w->tcp_fd, addr, &addr_len, flags);
	if (fd < 0) {
		r = handle_accept_error(w, -errno);
		goto out_err;
	}

	setup_sock_options(w, fd);
	gcp->client.fd = fd;
	pr_dbg(ctx, "New connection from %s (fd=%d)",
		ip_to_str(&gcp->client_addr), fd);

	if (!ctx->cfg.as_socks5)
		gcp->target_addr = ctx->target_addr;

	r = handle_new_client(w, gcp);
	if (r) {
		if (r == -EMFILE || r == -ENFILE)
			r = handle_accept_error(w, r);
		goto out_err;
	}

	return 0;

out_err:
	free_conn_pair(w, gcp);
	return r;
}

static int handle_ev_accept(struct gwp_wrk *w, struct epoll_event *ev)
{
	static const uint32_t nr_loop = 32;
	uint32_t i;
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on accept event");
		return -EIO;
	}

	for (i = 0; i < nr_loop; i++) {
		r = __handle_ev_accept(w);
		if (r) {
			if (likely(r == -EAGAIN || r == -EINTR)) {
				r = 0;
				break;
			}
		}
	}

	return r;
}

static int handle_ev_eventfd(struct gwp_wrk *w, struct epoll_event *ev)
{
	eventfd_t val;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on eventfd event");
		return -EIO;
	}

	return eventfd_read(w->ev_fd, &val);
}

static bool adj_epl_out(struct gwp_conn *src, struct gwp_conn *dst)
{
	if (src->len > 0) {
		if (!(dst->ep_mask & EPOLLOUT)) {
			dst->ep_mask |= EPOLLOUT;
			return true;
		}
	} else {
		if (dst->ep_mask & EPOLLOUT) {
			dst->ep_mask &= ~EPOLLOUT;
			return true;
		}
	}

	return false;
}

static bool adj_epl_in(struct gwp_conn *src)
{
	if (src->cap - src->len) {
		if (!(src->ep_mask & EPOLLIN)) {
			src->ep_mask |= EPOLLIN;
			return true;
		}
	} else {
		if (src->ep_mask & EPOLLIN) {
			src->ep_mask &= ~EPOLLIN;
			return true;
		}
	}

	return false;
}

static int adjust_epl_mask(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	bool client_need_ctl = false;
	bool target_need_ctl = false;
	struct epoll_event ev;

	client_need_ctl |= adj_epl_out(&gcp->target, &gcp->client);
	target_need_ctl |= adj_epl_out(&gcp->client, &gcp->target);
	client_need_ctl |= adj_epl_in(&gcp->client);
	target_need_ctl |= adj_epl_in(&gcp->target);

	if (client_need_ctl) {
		ev.events = gcp->client.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_CLIENT;

		if (epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev))
			return -errno;
	}

	if (target_need_ctl) {
		ev.events = gcp->target.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TARGET;

		if (epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->target.fd, &ev))
			return -errno;
	}

	return 0;
}

static void gwp_conn_buf_advance(struct gwp_conn *conn, size_t len)
{
	conn->len -= len;
	if (conn->len)
		memmove(conn->buf, conn->buf + len, conn->len);
}

static int do_splice(struct gwp_conn *src, struct gwp_conn *dst, bool do_recv,
		     bool do_send)
{
	ssize_t ret = 0;
	size_t len;
	char *buf;

	buf = src->buf + src->len;
	len = src->cap - src->len;
	if (do_recv && len > 0) {
		ret = recv(src->fd, buf, len, MSG_NOSIGNAL);
		if (unlikely(ret < 0)) {
			ret = -errno;
			if (ret != -EAGAIN && ret != -EINTR)
				return ret;
			ret = 0;
		} else if (!ret) {
			return -ECONNRESET;
		}

		src->len += (size_t)ret;
	}

	if (do_send && src->len > 0) {
		ret = send(dst->fd, src->buf, src->len, MSG_NOSIGNAL);
		if (unlikely(ret < 0)) {
			ret = -errno;
			if (ret != -EAGAIN && ret != -EINTR)
				return ret;
			ret = 0;
		} else if (!ret) {
			return -ECONNRESET;
		}

		gwp_conn_buf_advance(src, (size_t)ret);
	}

	return 0;
}

static int exec_socks5_connect_reply(struct gwp_wrk *w,
				     struct gwp_conn_pair *gcp,
				     int err);

static int handle_ev_target_conn_result(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	socklen_t l = sizeof(int);
	int r, err = 0;

	r = getsockopt(gcp->target.fd, SOL_SOCKET, SO_ERROR, &err, &l);
	if (unlikely(r < 0)) {
		r = -errno;
		pr_err(ctx, "Failed to get target socket error: %s", strerror(-r));
		goto out_conn_err;
	}

	if (unlikely(err)) {
		pr_err(ctx, "Target socket connection failed: %s", strerror(err));
		r = -err;
		goto out_conn_err;
	}

	pr_dbg(ctx, "Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		gcp->target.fd, gcp->idx, ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));

	if (gcp->timer_fd >= 0) {
		close(gcp->timer_fd);
		gcp->timer_fd = -1;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_CMD_CONNECT) {
		r = exec_socks5_connect_reply(w, gcp, 0);
		if (r)
			return r;
	}

	gcp->is_target_alive = true;
	if (gcp->client.len) {
		r = do_splice(&gcp->client, &gcp->target, false, true);
		if (r)
			return r;
	}

	return adjust_epl_mask(w, gcp);

out_conn_err:
	if (gcp->conn_state == CONN_STATE_SOCKS5_CMD_CONNECT) {
		int x = exec_socks5_connect_reply(w, gcp, err);
		if (x)
			return x;
	}
	return r;
}

static int handle_ev_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	assert(gcp->conn_state == CONN_STATE_FORWARDING);

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on target connection event");
		return -ECONNRESET;
	}

	if (!gcp->is_target_alive)
		return handle_ev_target_conn_result(w, gcp);

	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->client, &gcp->target, true, true);
		if (r)
			return r;
	}

	if (ev->events & (EPOLLRDHUP | EPOLLHUP))
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

static int handle_ev_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(w->ctx, "EPOLLERR on client connection event");
		return -ECONNRESET;
	}

	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->client, &gcp->target, true, gcp->is_target_alive);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->target, &gcp->client, true, true);
		if (r)
			return r;
	}

	if (ev->events & (EPOLLRDHUP | EPOLLHUP))
		return -ECONNRESET;

	return adjust_epl_mask(w, gcp);
}

static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gcp->timer_fd < 0)
		return 0;

	pr_warn(ctx, "Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));

	return -ETIMEDOUT;
}

static int gwp_conn_buf_append(struct gwp_conn *conn, const void *data,
			       size_t len)
{
	if (unlikely(conn->len + len > conn->cap)) {
		size_t new_cap = conn->cap + len + 1024;
		char *new_buf;

		new_buf = realloc(conn->buf, new_cap);
		if (!new_buf)
			return -ENOMEM;

		conn->buf = new_buf;
		conn->cap = new_cap;
	}

	memcpy(conn->buf + conn->len, data, len);
	conn->len += len;
	return 0;
}

static int read_timer(int fd)
{
	uint64_t val;
	ssize_t r;

	r = read(fd, &val, sizeof(val));
	return (r < 0) ? -errno : 0;
}

static int exec_socks5_connect(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_conn *t = &gcp->target;
	bool timer_need_ctl = false;
	int tafd, r, timeout, tmfd;
	struct epoll_event ev;

	tafd = create_sock_target(w, &gcp->target_addr, &gcp->is_target_alive);
	if (unlikely(tafd < 0)) {
		pr_err(w->ctx, "Failed to create target socket: %s", strerror(-tafd));
		return tafd;
	}

	t->fd = tafd;
	t->ep_mask = EPOLLOUT | EPOLLIN | EPOLLRDHUP;

	timeout = w->ctx->cfg.connect_timeout;
	if (timeout > 0) {
		int old_fd = gcp->timer_fd;

		tmfd = create_timer(old_fd, timeout, 0);
		if (unlikely(tmfd < 0))
			return tmfd;

		gcp->timer_fd = tmfd;
		timer_need_ctl = (old_fd < 0);
		if (!timer_need_ctl) {
			r = read_timer(old_fd);
			if (unlikely(r < 0 && r != -EAGAIN))
				return r;
			assert(gcp->timer_fd == old_fd);
		}
	} else {
		timer_need_ctl = false;
	}

	/*
	 * If epoll_ctl() fails, don't bother closing the target socket
	 * and timer fd as they will be closed in free_conn_pair() anyway.
	 */
	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_CLIENT;
	if (unlikely(epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev)))
		return -errno;

	ev.events = t->ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_TARGET;
	if (unlikely(epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, tafd, &ev)))
		return -errno;

	if (timer_need_ctl) {
		ev.events = EPOLLIN;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_TIMER;
		if (unlikely(epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, tmfd, &ev)))
			return -errno;
	}

	gcp->conn_state = CONN_STATE_SOCKS5_CMD_CONNECT;
	log_conn_pair_created(w, gcp);
	return 0;
}

/*
 *   Link: https://datatracker.ietf.org/doc/html/rfc1928#section-3
 *
 *   3.  Procedure for TCP-based clients
 *
 *      When a TCP-based client wishes to establish a connection to an object
 *      that is reachable only via a firewall (such determination is left up
 *      to the implementation), it must open a TCP connection to the
 *      appropriate SOCKS port on the SOCKS server system.  The SOCKS service
 *      is conventionally located on TCP port 1080.  If the connection
 *      request succeeds, the client enters a negotiation for the
 *      authentication method to be used, authenticates with the chosen
 *      method, then sends a relay request.  The SOCKS server evaluates the
 *      request, and either establishes the appropriate connection or denies
 *      it.
 *
 *      Unless otherwise noted, the decimal numbers appearing in packet-
 *      format diagrams represent the length of the corresponding field, in
 *      octets.  Where a given octet must take on a specific value, the
 *      syntax X'hh' is used to denote the value of the single octet in that
 *      field. When the word 'Variable' is used, it indicates that the
 *      corresponding field has a variable length defined either by an
 *      associated (one or two octet) length field, or by a data type field.
 *
 *      The client connects to the server, and sends a version
 *      identifier/method selection message:
 *
 *                      +----+----------+----------+
 *                      |VER | NMETHODS | METHODS  |
 *                      +----+----------+----------+
 *                      | 1  |    1     | 1 to 255 |
 *                      +----+----------+----------+
 *
 *      The VER field is set to X'05' for this version of the protocol.  The
 *      NMETHODS field contains the number of method identifier octets that
 *      appear in the METHODS field.
 *
 *      The server selects from one of the methods given in METHODS, and
 *      sends a METHOD selection message:
 *
 *                            +----+--------+
 *                            |VER | METHOD |
 *                            +----+--------+
 *                            | 1  |   1    |
 *                            +----+--------+
 *
 *      If the selected METHOD is X'FF', none of the methods listed by the
 *      client are acceptable, and the client MUST close the connection.
 *
 *      The values currently defined for METHOD are:
 *
 *             o  X'00' NO AUTHENTICATION REQUIRED
 *             o  X'01' GSSAPI
 *             o  X'02' USERNAME/PASSWORD
 *             o  X'03' to X'7F' IANA ASSIGNED
 *             o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 *             o  X'FF' NO ACCEPTABLE METHODS
 *
 *      The client and server then enter a method-specific sub-negotiation.
 *
 *      Descriptions of the method-dependent sub-negotiations appear in
 *      separate memos.
 *
 *      Developers of new METHOD support for this protocol should contact
 *      IANA for a METHOD number.  The ASSIGNED NUMBERS document should be
 *      referred to for a current list of METHOD numbers and their
 *      corresponding protocols.
 *
 *      Compliant implementations MUST support GSSAPI and SHOULD support
 *      USERNAME/PASSWORD authentication methods.
 */
static int handle_ev_client_socks5_init(struct gwp_wrk *w,
					struct gwp_conn_pair *gcp)
{
	uint8_t *buf = (uint8_t *)gcp->client.buf, nr_methods, wanted_method;
	uint32_t len = gcp->client.len, exp_len, resp_len;
	struct gwp_ctx *ctx = w->ctx;
	uint8_t resp[2];
	bool found;
	int r, s;

	exp_len = 2; /* VER + NMETHODS */
	if (unlikely(len < exp_len))
		return -EAGAIN;

	if (unlikely(buf[0] != 0x05))
		return -EINVAL;

	nr_methods = buf[1];
	exp_len += (uint32_t)nr_methods;
	if (unlikely(len < exp_len))
		return -EAGAIN;

	/*
	 * USERNAME/PASSWORD or NO AUTHENTICATION.
	 */
	wanted_method = ctx->s5auth ? 0x02 : 0x00;

	found = !!memchr(buf + 2, wanted_method, nr_methods);
	resp_len = 2; /* VER + METHOD */
	resp[0] = 0x05; /* VER */
	if (found) {
		gcp->conn_state = ctx->s5auth ? CONN_STATE_SOCKS5_AUTH_USERPASS
					      : CONN_STATE_SOCKS5_CMD;
		r = 0;
	} else {
		gcp->conn_state = CONN_STATE_SOCKS5_ERR;
		wanted_method = 0xFF; /* NO ACCEPTABLE METHODS */
		r = -ENOSYS;
		pr_dbg(ctx, "No acceptable SOCKS5 method found, expecting %s",
			ctx->s5auth ? "USERNAME/PASSWORD" : "NO AUTHENTICATION");
	}

	resp[1] = wanted_method; /* METHOD */
	gwp_conn_buf_advance(&gcp->client, exp_len);
	s = gwp_conn_buf_append(&gcp->target, resp, resp_len);
	if (s)
		return s;

	return r;
}

/*
 *   Link: https://datatracker.ietf.org/doc/html/rfc1928#section-4
 *
 *   4.  Requests
 *
 *      Once the method-dependent subnegotiation has completed, the client
 *      sends the request details.  If the negotiated method includes
 *      encapsulation for purposes of integrity checking and/or
 *      confidentiality, these requests MUST be encapsulated in the method-
 *      dependent encapsulation.
 *
 *      The SOCKS request is formed as follows:
 *
 *           +----+-----+-------+------+----------+----------+
 *           |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *           +----+-----+-------+------+----------+----------+
 *           | 1  |  1  | X'00' |  1   | Variable |    2     |
 *           +----+-----+-------+------+----------+----------+
 *
 *        Where:
 *
 *             o  VER    protocol version: X'05'
 *             o  CMD
 *                o  CONNECT X'01'
 *                o  BIND X'02'
 *                o  UDP ASSOCIATE X'03'
 *             o  RSV    RESERVED
 *             o  ATYP   address type of following address
 *                o  IP V4 address: X'01'
 *                o  DOMAINNAME: X'03'
 *                o  IP V6 address: X'04'
 *             o  DST.ADDR       desired destination address
 *             o  DST.PORT desired destination port in network octet
 *                order
 *
 *      The SOCKS server will typically evaluate the request based on source
 *      and destination addresses, and return one or more reply messages, as
 *      appropriate for the request type.
 *
 *
 *   5.  Addressing
 *
 *      In an address field (DST.ADDR, BND.ADDR), the ATYP field specifies
 *      the type of address contained within the field:
 *
 *             o  X'01'
 *
 *      the address is a version-4 IP address, with a length of 4 octets
 *
 *             o  X'03'
 *
 *      the address field contains a fully-qualified domain name.  The first
 *      octet of the address field contains the number of octets of name that
 *      follow, there is no terminating NUL octet.
 *
 *             o  X'04'
 *
 *      the address is a version-6 IP address, with a length of 16 octets.
 *
 *   6.  Replies
 *
 *      The SOCKS request information is sent by the client as soon as it has
 *      established a connection to the SOCKS server, and completed the
 *      authentication negotiations.  The server evaluates the request, and
 *      returns a reply formed as follows:
 *
 *           +----+-----+-------+------+----------+----------+
 *           |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *           +----+-----+-------+------+----------+----------+
 *           | 1  |  1  | X'00' |  1   | Variable |    2     |
 *           +----+-----+-------+------+----------+----------+
 *
 *        Where:
 *
 *             o  VER    protocol version: X'05'
 *             o  REP    Reply field:
 *                o  X'00' succeeded
 *                o  X'01' general SOCKS server failure
 *                o  X'02' connection not allowed by ruleset
 *                o  X'03' Network unreachable
 *                o  X'04' Host unreachable
 *                o  X'05' Connection refused
 *                o  X'06' TTL expired
 *                o  X'07' Command not supported
 *                o  X'08' Address type not supported
 *                o  X'09' to X'FF' unassigned
 *             o  RSV    RESERVED
 *             o  ATYP   address type of following address
 *                o  IP V4 address: X'01'
 *                o  DOMAINNAME: X'03'
 *                o  IP V6 address: X'04'
 *             o  BND.ADDR       server bound address
 *             o  BND.PORT       server bound port in network octet order
 *
 *
 *      Fields marked RESERVED (RSV) must be set to X'00'.
 *
 *      If the chosen method includes encapsulation for purposes of
 *      authentication, integrity and/or confidentiality, the replies are
 *      encapsulated in the method-dependent encapsulation.
 *
 *   CONNECT
 *
 *      In the reply to a CONNECT, BND.PORT contains the port number that the
 *      server assigned to connect to the target host, while BND.ADDR
 *      contains the associated IP address.  The supplied BND.ADDR is often
 *      different from the IP address that the client uses to reach the SOCKS
 *      server, since such servers are often multi-homed.  It is expected
 *      that the SOCKS server will use DST.ADDR and DST.PORT, and the
 *      client-side source address and port in evaluating the CONNECT
 *      request.
 *
 *   BIND
 *
 *      The BIND request is used in protocols which require the client to
 *      accept connections from the server.  FTP is a well-known example,
 *      which uses the primary client-to-server connection for commands and
 *      status reports, but may use a server-to-client connection for
 *      transferring data on demand (e.g. LS, GET, PUT).
 *
 *      It is expected that the client side of an application protocol will
 *      use the BIND request only to establish secondary connections after a
 *      primary connection is established using CONNECT.  In is expected that
 *      a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND
 *      request.
 *
 *      Two replies are sent from the SOCKS server to the client during a
 *      BIND operation.  The first is sent after the server creates and binds
 *      a new socket.  The BND.PORT field contains the port number that the
 *      SOCKS server assigned to listen for an incoming connection.  The
 *      BND.ADDR field contains the associated IP address.  The client will
 *      typically use these pieces of information to notify (via the primary
 *      or control connection) the application server of the rendezvous
 *      address.  The second reply occurs only after the anticipated incoming
 *      connection succeeds or fails.
 *
 *      In the second reply, the BND.PORT and BND.ADDR fields contain the
 *      address and port number of the connecting host.
 *
 *   UDP ASSOCIATE
 *
 *      The UDP ASSOCIATE request is used to establish an association within
 *      the UDP relay process to handle UDP datagrams.  The DST.ADDR and
 *      DST.PORT fields contain the address and port that the client expects
 *      to use to send UDP datagrams on for the association.  The server MAY
 *      use this information to limit access to the association.  If the
 *      client is not in possesion of the information at the time of the UDP
 *      ASSOCIATE, the client MUST use a port number and address of all
 *      zeros.
 *
 *      A UDP association terminates when the TCP connection that the UDP
 *      ASSOCIATE request arrived on terminates.
 *
 *      In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
 *      fields indicate the port number/address where the client MUST send
 *      UDP request messages to be relayed.
 *
 *   Reply Processing
 *
 *      When a reply (REP value other than X'00') indicates a failure, the
 *      SOCKS server MUST terminate the TCP connection shortly after sending
 *      the reply.  This must be no more than 10 seconds after detecting the
 *      condition that caused a failure.
 *
 *      If the reply code (REP value of X'00') indicates a success, and the
 *      request was either a BIND or a CONNECT, the client may now start
 *      passing data.  If the selected authentication method supports
 *      encapsulation for the purposes of integrity, authentication and/or
 *      confidentiality, the data are encapsulated using the method-dependent
 *      encapsulation.  Similarly, when data arrives at the SOCKS server for
 *      the client, the server MUST encapsulate the data as appropriate for
 *      the authentication method in use.
 */

static int exec_socks5_rep_cmd_err(struct gwp_conn_pair *gcp, uint8_t rep)
{
	uint32_t resp_len;
	uint8_t resp[10];

	gcp->conn_state = CONN_STATE_SOCKS5_ERR;
	resp_len = 10; /* VER + REP + RSV + ATYP + BND.ADDR + BND.PORT */
	resp[0] = 0x05; /* VER */
	resp[1] = rep;  /* REP */
	resp[2] = 0x00; /* RSV */
	resp[3] = 0x01; /* ATYP: IPv4 */
	memset(&resp[4], 0, 4); /* BND.ADDR */
	memset(&resp[8], 0, 2); /* BND.PORT */
	return gwp_conn_buf_append(&gcp->target, resp, resp_len);
}

static int exec_socks5_resolve_domain_async(struct gwp_wrk *w, const char *host,
					    const char *port,
					    struct gwp_conn_pair *gcp)
{
	struct gwp_dns *gdns = w->ctx->gdns;
	struct gwp_dns_query *gdq;
	struct epoll_event ev;
	int r;

	pr_dbg(w->ctx, "Resolving %s:%s (nr_queries=%u)", host, port, gdns->nr_queries);
	gdq = gwp_gdns_push_query(host, port, gdns);
	if (unlikely(!gdq))
		return -ENOMEM;

	ev.events = EPOLLIN | EPOLLONESHOT;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_DNS_QUERY;
	if (unlikely(epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gdq->ev_fd, &ev))) {
		r = -errno;
		gwp_gdns_put_query(gdq);
		return r;
	}

	gcp->conn_state = CONN_STATE_SOCKS5_DNS_QUERY;
	gcp->gdq = gdq;
	return 0;
}

static int handle_ev_client_socks5_cmd_connect(struct gwp_wrk *w,
					       struct gwp_conn_pair *gcp)
{
	struct gwp_sockaddr *gs = &gcp->target_addr;
	struct gwp_conn *c = &gcp->client;
	uint8_t *buf = (uint8_t *)c->buf, atyp;
	uint32_t len = c->len, exp_len;

	exp_len = 4; /* VER + CMD + RSV + ATYP */
	if (unlikely(len < exp_len))
		return -EAGAIN;

	if (unlikely(buf[2] != 0x00))
		return -EINVAL;

	atyp = buf[3];
	switch (atyp) {
	case 0x01: /* IPv4 address and Port */
		exp_len += 4 + 2;
		break;
	case 0x03: /* Domain name and Port */
		if (unlikely(len < exp_len + 1))
			return -EAGAIN;
		exp_len += 1 + (uint32_t)buf[4] + 2;
		break;
	case 0x04: /* IPv6 address and Port */
		exp_len += 16 + 2;
		break;
	default:
		/*
		 * 0x08 = "Address type not supported".
		 */
		return exec_socks5_rep_cmd_err(gcp, 0x08);
	}

	if (unlikely(len < exp_len))
		return -EAGAIN;

	memset(gs, 0, sizeof(*gs));
	switch (atyp) {
	case 0x01: /* IPv4 address */
		gs->sa.sa_family = AF_INET;
		memcpy(&gs->i4.sin_addr, &buf[4], 4);
		memcpy(&gs->i4.sin_port, &buf[8], 2);
		break;
	case 0x04: /* IPv6 address */
		gs->sa.sa_family = AF_INET6;
		memcpy(&gs->i6.sin6_addr, &buf[4], 16);
		memcpy(&gs->i6.sin6_port, &buf[20], 2);
		break;
	case 0x03: { /* Domain name */
		uint8_t hlen = buf[4];
		char h[256], p[6];
		uint16_t port;
		int r;

		memcpy(h, &buf[5], hlen);
		h[hlen] = '\0';
		memcpy(&port, &buf[5 + hlen], 2);
		port = ntohs(port);
		snprintf(p, sizeof(p), "%hu", port);

		if (w->ctx->gdns) {
			r = exec_socks5_resolve_domain_async(w, h, p, gcp);
			if (r)
				return r;
		}

		r = resolve_domain(h, p, gs);
		if (r) {
			r = exec_socks5_connect_reply(w, gcp, r);
			if (r)
				return r;
		}

		break;
	}
	}

	gwp_conn_buf_advance(c, exp_len);
	return exec_socks5_connect(w, gcp);
}

static int exec_socks5_connect_reply(struct gwp_wrk *w,
				     struct gwp_conn_pair *gcp,
				     int err)
{
	uint8_t tmp[128];
	uint32_t len;
	int r;

	tmp[0] = 0x05; /* VER */
	switch (err) {
	case 0:
		tmp[1] = 0x00; /* REP: succeeded */
		break;
	case -ECONNREFUSED:
		tmp[1] = 0x05; /* REP: Connection refused */
		break;
	case -ETIMEDOUT:
		tmp[1] = 0x06; /* REP: TTL expired */
		break;
	case -ENETUNREACH:
		tmp[1] = 0x03; /* REP: Network unreachable */
		break;
	case -EHOSTUNREACH:
		tmp[1] = 0x04; /* REP: Host unreachable */
		break;
	case -EACCES:
	case -EPERM:
		tmp[1] = 0x02; /* REP: Connection not allowed by ruleset */
		break;
	default:
		tmp[1] = 0x01; /* REP: General SOCKS server failure */
		break;
	}
	tmp[2] = 0x00; /* RSV */
	len = 4; /* VER + REP + RSV + ATYP */

	if (!err) {
		struct gwp_sockaddr gs;
		socklen_t l = sizeof(gs);
		int f;

		memset(&gs, 0, sizeof(gs));
		r = getsockname(gcp->target.fd, &gs.sa, &l);
		if (unlikely(r < 0)) {
			r = -errno;
			pr_err(w->ctx, "Failed to get target socket name: %s",
				strerror(-r));
			return r;
		}

		f = gs.sa.sa_family;
		if (f == AF_INET) {
			tmp[3] = 0x01; /* ATYP: IPv4 address */
			memcpy(&tmp[4], &gs.i4.sin_addr, 4);
			memcpy(&tmp[8], &gs.i4.sin_port, 2);
			len += 4 + 2;
		} else if (f == AF_INET6) {
			tmp[3] = 0x04; /* ATYP: IPv6 address */
			memcpy(&tmp[4], &gs.i6.sin6_addr, 16);
			memcpy(&tmp[20], &gs.i6.sin6_port, 2);
			len += 16 + 2;
		} else {
			pr_err(w->ctx, "Unsupported address family: %d", f);
			return -EAFNOSUPPORT;
		}
	} else {
		tmp[3] = 0x01; /* ATYP: IPv4 address */
		memset(&tmp[4], 0, 4);
		memset(&tmp[8], 0, 2);
		len += 4 + 2;
	}

	r = gwp_conn_buf_append(&gcp->target, tmp, len);
	if (unlikely(r < 0))
		return r;

	gcp->conn_state = err ? CONN_STATE_SOCKS5_ERR : CONN_STATE_FORWARDING;
	return do_splice(&gcp->target, &gcp->client, false, true);
}

static int handle_ev_client_socks5_cmd(struct gwp_wrk *w,
				       struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;
	uint8_t *buf = (uint8_t *)c->buf;
	uint32_t len = c->len;
	int r;

	if (unlikely(len < 3))
		return -EAGAIN;

	if (unlikely(buf[0] != 0x05))
		return -EINVAL;

	/*
	 * TODO(ammarfaizi2): Implement BIND and UDP ASSOCIATE commands.
	 */
	switch (buf[1]) {
	case 0x01: /* CONNECT */
		r = handle_ev_client_socks5_cmd_connect(w, gcp);
		break;
	case 0x02: /* BIND */
	case 0x03: /* UDP ASSOCIATE */
	default:
		r = -ENOSYS;
		break;
	}

	if (unlikely(r == -ENOSYS)) {
		/*
		 * 0x07 = "Command not supported".
		 */
		return exec_socks5_rep_cmd_err(gcp, 0x07);
	}

	return r;
}

static bool gwp_s5auth_authenticate(struct gwp_ctx *ctx,
				    const char *u, uint32_t ulen,
				    const char *p, uint32_t plen)
{
	struct gwp_socks5_auth *s5a = ctx->s5auth;
	bool r = false;
	size_t i;

	pthread_rwlock_rdlock(&s5a->lock);
	for (i = 0; i < s5a->nr; i++) {
		struct gwp_socks5_user *ui = &s5a->users[i];
		if (ui->ulen != ulen)
			continue;
		if (ui->plen != plen)
			continue;
		if (memcmp(ui->u, u, ulen))
			continue;
		if (ui->p && memcmp(ui->p, p, plen))
			continue;
		r = true;
		break;
	}
	pthread_rwlock_unlock(&s5a->lock);
	return r;
}

/*
 *    Link: https://datatracker.ietf.org/doc/html/rfc1929#section-2
 *
 *    2.  Initial negotiation
 *
 *      Once the SOCKS V5 server has started, and the client has selected the
 *      Username/Password Authentication protocol, the Username/Password
 *      subnegotiation begins.  This begins with the client producing a
 *      Username/Password request:
 *
 *              +----+------+----------+------+----------+
 *              |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *              +----+------+----------+------+----------+
 *              | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *              +----+------+----------+------+----------+
 *
 *      The VER field contains the current version of the subnegotiation,
 *      which is X'01'. The ULEN field contains the length of the UNAME field
 *      that follows. The UNAME field contains the username as known to the
 *      source operating system. The PLEN field contains the length of the
 *      PASSWD field that follows. The PASSWD field contains the password
 *      association with the given UNAME.
 *
 *      The server verifies the supplied UNAME and PASSWD, and sends the
 *      following response:
 *
 *                            +----+--------+
 *                            |VER | STATUS |
 *                            +----+--------+
 *                            | 1  |   1    |
 *                            +----+--------+
 *
 *      A STATUS field of X'00' indicates success. If the server returns a
 *      `failure' (STATUS value other than X'00') status, it MUST close the
 *      connection.
 */
static int handle_ev_client_socks5_auth_userpass(struct gwp_wrk *w,
						 struct gwp_conn_pair *gcp)
{
	struct gwp_conn *c = &gcp->client;
	uint8_t *buf = (uint8_t *)c->buf, resp[2];
	uint32_t len = c->len, exp_len;
	uint32_t ulen, plen;
	char *u, *p;
	int r;

	exp_len = 2; /* VER + ULEN */
	if (unlikely(len < exp_len))
		return -EAGAIN;

	if (unlikely(buf[0] != 0x01))
		return -EINVAL;

	ulen = buf[1];
	exp_len += ulen + 1; /* UNAME + PLEN */
	if (unlikely(len < exp_len))
		return -EAGAIN;

	plen = buf[2 + ulen];
	exp_len += plen;
	if (unlikely(len < exp_len))
		return -EAGAIN;

	u = (char *)&buf[2];
	p = (char *)&buf[2 + ulen + 1];
	if (gwp_s5auth_authenticate(w->ctx, u, ulen, p, plen)) {
		resp[0] = 0x01; /* VER */
		resp[1] = 0x00; /* STATUS: success */
		r = 0;
		gcp->conn_state = CONN_STATE_SOCKS5_CMD;
		pr_info(w->ctx, "SOCKS5 authentication succeeded for user: %.*s",
			(int)ulen, u);
	} else {
		resp[0] = 0x01; /* VER */
		resp[1] = 0x01; /* STATUS: failure */
		r = -EPERM;
		gcp->conn_state = CONN_STATE_SOCKS5_ERR;
		pr_info(w->ctx, "SOCKS5 authentication failed for user: %.*s",
			(int)ulen, u);
	}

	if (gwp_conn_buf_append(&gcp->target, resp, 2))
		return -ENOMEM;

	gwp_conn_buf_advance(c, exp_len);
	return r;
}

static int handle_short_send_socks5_data(struct gwp_wrk *w,
					 struct gwp_conn_pair *gcp)
{
	struct epoll_event ev;
	int r;

	if (adj_epl_out(&gcp->target, &gcp->client)) {
		ev.events = gcp->client.ep_mask;
		ev.data.u64 = 0;
		ev.data.ptr = gcp;
		ev.data.u64 |= EV_BIT_CLIENT_SOCKS5;
		r = epoll_ctl(w->ep_fd, EPOLL_CTL_MOD, gcp->client.fd, &ev);
		if (unlikely(r < 0))
			return -errno;

		r = -EAGAIN;
	} else {
		r = 0;
	}

	return r;
}

static int handle_ev_client_socks5(struct gwp_wrk *w,
				   struct gwp_conn_pair *gcp,
				   struct epoll_event *ev)
{
	struct gwp_ctx *ctx = w->ctx;
	int r, s;

	assert(ctx->cfg.as_socks5);

	if (unlikely(ev->events & EPOLLERR)) {
		pr_err(ctx, "EPOLLERR on client SOCKS5 event");
		return -ECONNRESET;
	}

repeat:
	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->target, &gcp->client, false, true);
		if (r)
			return r;

		r = handle_short_send_socks5_data(w, gcp);
		if (r)
			return (r == -EAGAIN) ? 0 : r;

		if (gcp->target.len)
			return 0;
	}

	if (ev->events & EPOLLIN) {
		r = do_splice(&gcp->client, &gcp->target, true, false);
		if (r)
			return r;
	}

	s = gcp->conn_state;
	assert(CONN_STATE_SOCKS5_MIN <= s && s <= CONN_STATE_SOCKS5_MAX);

	if (gcp->conn_state == CONN_STATE_SOCKS5_ERR)
		return -EBADMSG;

	r = -EINVAL;
	switch (s) {
	case CONN_STATE_SOCKS5_INIT:
		r = handle_ev_client_socks5_init(w, gcp);
		break;
	case CONN_STATE_SOCKS5_AUTH_USERPASS:
		r = handle_ev_client_socks5_auth_userpass(w, gcp);
		break;
	case CONN_STATE_SOCKS5_CMD:
		r = handle_ev_client_socks5_cmd(w, gcp);
		break;
	default:
		pr_err(ctx, "Invalid SOCKS5 connection state: %d", s);
		return -EINVAL;
	}

	if (r == -EAGAIN)
		return 0;

	if (gcp->target.len) {
		ev->events |= EPOLLOUT;
		goto repeat;
	}

	if (gcp->conn_state == CONN_STATE_SOCKS5_ERR)
		return -EBADMSG;

	if (!r && gcp->client.len)
		goto repeat;

	return r;
}

static void log_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			  struct gwp_dns_query *gdq)
{
	struct gwp_ctx *ctx = w->ctx;

	if (gdq->res) {
		pr_dbg(ctx, "DNS query failed: %s:%s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
			gdq->host, gdq->service, gdq->res,
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr));
		return;
	}

	pr_dbg(ctx, "DNS query resolved: %s:%s -> %s (res=%d; idx=%u; cfd=%d; tfd=%d; ca=%s)",
		gdq->host, gdq->service, ip_to_str(&gdq->result), gdq->res,
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr));
}

static int handle_ev_dns_query(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_dns_query *gdq = gcp->gdq;
	int r;

	assert(gdq);
	assert(gdq->ev_fd >= 0);
	assert(gcp->conn_state == CONN_STATE_SOCKS5_DNS_QUERY);

	gcp->gdq = NULL;
	log_dns_query(w, gcp, gdq);
	if (likely(!gdq->res)) {
		gcp->target_addr = gdq->result;
		r = exec_socks5_connect(w, gcp);
	} else {
		r = exec_socks5_connect_reply(w, gcp, gdq->res);
	}

	gwp_gdns_put_query(gdq);
	return r;
}

static int handle_ev_socks5_auth_file(struct gwp_wrk *w)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
	struct gwp_ctx *ctx = w->ctx;
	ssize_t r;

	assert(ctx->cfg.as_socks5);
	assert(ctx->s5auth);

	r = gwp_load_s5auth(ctx);
	if (unlikely(r))
		return r;

	r = read(ctx->s5auth->ino_fd, buf, sizeof(buf));
	if (unlikely(r < 0)) {
		r = -errno;
		if (r == -EINTR || r == -EAGAIN)
			return 0;
		return r;
	}

	return 0;
}

static bool is_ev_bit_conn_pair(uint64_t ev_bit)
{
	static const uint64_t conn_pair_ev_bit =
		EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER |
		EV_BIT_CLIENT_SOCKS5 | EV_BIT_DNS_QUERY;

	return !!(ev_bit & conn_pair_ev_bit);
}

static int handle_event(struct gwp_wrk *w, struct epoll_event *ev)
{
	uint64_t ev_bit;
	void *udata;
	int r = 0;

	ev_bit = GET_EV_BIT(ev->data.u64);
	ev->data.u64 = CLEAR_EV_BIT(ev->data.u64);
	udata = ev->data.ptr;

	switch (ev_bit) {
	case EV_BIT_ACCEPT:
		r = handle_ev_accept(w, ev);
		break;
	case EV_BIT_EVENTFD:
		r = handle_ev_eventfd(w, ev);
		break;
	case EV_BIT_TARGET:
		r = handle_ev_target(w, udata, ev);
		break;
	case EV_BIT_CLIENT:
		r = handle_ev_client(w, udata, ev);
		break;
	case EV_BIT_TIMER:
		r = handle_ev_timer(w, udata);
		break;
	case EV_BIT_CLIENT_SOCKS5:
		r = handle_ev_client_socks5(w, udata, ev);
		break;
	case EV_BIT_DNS_QUERY:
		r = handle_ev_dns_query(w, udata);
		break;
	case EV_BIT_SOCKS5_AUTH_FILE:
		r = handle_ev_socks5_auth_file(w);
		break;
	default:
		pr_err(w->ctx, "Unknown event bit: %" PRIu64, ev_bit);
		return -EINVAL;
	}

	if (r && is_ev_bit_conn_pair(ev_bit)) {
		struct gwp_conn_pair *gcp = udata;
		r = free_conn_pair(w, gcp);
	}

	return r;
}

static int handle_events(struct gwp_wrk *w, int nr_events)
{
	struct epoll_event *events = w->events;
	struct gwp_ctx *ctx = w->ctx;
	int i, r = 0;

	for (i = 0; i < nr_events; i++) {
		if (unlikely(ctx->stop))
			break;

		r = handle_event(w, &events[i]);
		if (unlikely(r < 0))
			break;

		if (w->ev_need_reload)
			break;
	}

	return r;
}

static int fish_events(struct gwp_wrk *w)
{
	int r;

	w->ev_need_reload = false;
	r = epoll_wait(w->ep_fd, w->events, w->evsz, -1);
	if (unlikely(r < 0)) {
		r = -errno;
		if (r == -EINTR)
			r = 0;
		else
			pr_err(w->ctx, "epoll_wait failed: %s", strerror(-r));
	}

	return r;
}

static void *gwp_ctx_thread_entry(void *arg)
{
	struct gwp_wrk *w = arg;
	struct gwp_ctx *ctx = w->ctx;
	int r = 0;

	pr_info(ctx, "Worker %u started", w->idx);
	while (!ctx->stop) {
		r = fish_events(w);
		if (unlikely(r < 0))
			break;
		r = handle_events(w, r);
		if (unlikely(r < 0))
			break;
	}

	ctx->stop = true;
	gwp_ctx_signal_all_workers(ctx);
	pr_info(ctx, "Worker %u stopped", w->idx);
	return (void *)(intptr_t)r;
}

static int gwp_ctx_run(struct gwp_ctx *ctx)
{
	int i, r;

	for (i = 0; i < ctx->cfg.nr_workers; i++) {
		struct gwp_wrk *w = &ctx->workers[i];
		char tmp[128];

		/*
		 * Skip the first worker as it will
		 * run on the main thread.
		 */
		if (i == 0)
			continue;

		r = pthread_create(&w->thread, NULL, &gwp_ctx_thread_entry, w);
		if (r) {
			gwp_ctx_stop(ctx);
			pr_err(ctx, "Failed to create worker thread %d: %s",
				i, strerror(r));
			return -r;
		}

		snprintf(tmp, sizeof(tmp), "gwproxy-wrk-%d", i);
		pthread_setname_np(w->thread, tmp);
	}

	return (int)(intptr_t)gwp_ctx_thread_entry(&ctx->workers[0]);
}

static struct gwp_ctx *g_ctx = NULL;

static void sig_handler(int sig)
{
	if (g_ctx)
		gwp_ctx_stop(g_ctx);

	(void)sig;
}

static void prepare_rlimit(void)
{
	struct rlimit rl;
	int r;

	r = getrlimit(RLIMIT_NOFILE, &rl);
	if (r < 0) {
		fprintf(stderr, "Failed to get RLIMIT_NOFILE: %s\n", strerror(errno));
		return;
	}

	rl.rlim_cur = rl.rlim_max;
	r = setrlimit(RLIMIT_NOFILE, &rl);
	if (r < 0) {
		fprintf(stderr, "Failed to set RLIMIT_NOFILE: %s\n", strerror(errno));
		return;
	}
}

int main(int argc, char *argv[])
{
	struct sigaction sa = { .sa_handler = &sig_handler };
	struct gwp_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = parse_options(argc, argv, &ctx.cfg);
	if (r < 0)
		goto out;

	prepare_rlimit();
	r = gwp_ctx_init(&ctx);
	if (r < 0)
		goto out;

	g_ctx = &ctx;
	r |= sigaction(SIGINT, &sa, NULL);
	r |= sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	r |= sigaction(SIGPIPE, &sa, NULL);
	if (r < 0) {
		r = -errno;
		fprintf(stderr, "Failed to set signal handlers: %s\n", strerror(-r));
		goto out_free;
	}

	r = gwp_ctx_run(&ctx);
out_free:
	gwp_ctx_free(&ctx);
out:
	return -r;
}
