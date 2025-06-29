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

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

static const struct option long_opts[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "event-loop",		required_argument,	NULL,	'e' },
	{ "bind",		required_argument,	NULL,	'b' },
	{ "target",		required_argument,	NULL,	't' },
	{ "as-socks5",		no_argument,		NULL,	'S' },
	{ "socks5-timeout",	required_argument,	NULL,	'o' },
	{ "nr-workers",		required_argument,	NULL,	'w' },
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

enum {
	EV_BIT_ACCEPT	= (1ull << 48ull),
	EV_BIT_EVENTFD	= (2ull << 48ull),
	EV_BIT_TARGET	= (3ull << 48ull),
	EV_BIT_CLIENT	= (4ull << 48ull),
	EV_BIT_TIMER	= (5ull << 48ull),
};

#define EV_BIT_ALL	(0xffffull << 48ull)
#define GET_EV_BIT(X)	((X) & EV_BIT_ALL)
#define CLEAR_EV_BIT(X)	((X) & ~EV_BIT_ALL)

struct gwp_cfg {
	const char	*event_loop;
	const char	*bind;
	const char	*target;
	bool		as_socks5;
	int		socks5_timeout;
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
};

static const struct gwp_cfg default_opts = {
	.event_loop		= "epoll",
	.bind			= "[::]:1080",
	.target			= NULL,
	.as_socks5		= false,
	.socks5_timeout		= 10,
	.nr_workers		= 4,
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

struct gwp_conn_pair {
	struct gwp_conn		target;
	struct gwp_conn		client;
	struct gwp_sockaddr	client_addr;
	struct gwp_sockaddr	target_addr;
	uint32_t		idx;
	int			timer_fd;
	bool			is_target_alive;
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

struct gwp_ctx {
	volatile bool			stop;
	FILE				*log_file;
	struct gwp_wrk			*workers;
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
	printf("  -b, --bind=addr_port            Bind to the specified address (default: %s)\n", default_opts.bind);
	printf("  -t, --target=addr_port          Target address to connect to\n");
	printf("  -S, --as-socks5=0|1             Run as a SOCKS5 proxy (default: %d)\n", default_opts.as_socks5);
	printf("  -o, --socks5-timeout=sec        SOCKS5 auth timeout in seconds (default: %d)\n", default_opts.socks5_timeout);
	printf("  -w, --nr-workers=nr             Number of worker threads (default: %d)\n", default_opts.nr_workers);
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
		case 'w':
			cfg->nr_workers = atoi(optarg);
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
	r = epoll_ctl(ep_fd, EPOLL_CTL_ADD, ev_fd, &ev);
	if (r < 0)
		goto out_err_ctl;

	ev.events = EPOLLIN;
	ev.data.u64 = EV_BIT_ACCEPT;
	r = epoll_ctl(ep_fd, EPOLL_CTL_ADD, w->tcp_fd, &ev);
	if (r < 0)
		goto out_err_ctl;

	pr_dbg(w->ctx, "Worker %u epoll (ep_fd=%d, ev_fd=%d)", w->idx,
		ep_fd, ev_fd);
	return 0;

out_err_ctl:
	r = -errno;
	pr_err(w->ctx, "Failed to add eventfd to epoll: %s\n", strerror(-r));
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

		pr_dbg(w->ctx,
			"Freeing connection pair %zu (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
			i, gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));

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

static int gwp_ctx_init(struct gwp_ctx *ctx)
{
	int r;

	r = gwp_ctx_init_log(ctx);
	if (r < 0)
		return r;

	if (!ctx->cfg.as_socks5) {
		const char *t = ctx->cfg.target;
		r = convert_str_to_ssaddr(t, &ctx->target_addr);
		if (r) {
			pr_err(ctx, "Invalid target address '%s'", t);
			goto out_free_log;
		}
	}

	if (ctx->cfg.pid_file)
		gwp_ctx_init_pid_file(ctx);

	r = gwp_ctx_init_threads(ctx);
	if (r < 0) {
		pr_err(ctx, "Failed to initialize worker threads: %s",
			strerror(-r));
		goto out_free_log;
	}

	return 0;

out_free_log:
	gwp_ctx_free_log(ctx);
	return r;
}

static void gwp_ctx_signal_all_workers(struct gwp_ctx *ctx)
{
	int i;

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
	struct gwp_conn_pair *tmp;
	uint32_t i = gcp->idx;
	int nr_fd_closed = 0;
	int r;

	tmp = gcs->pairs[i];
	assert(tmp == gcp);
	if (unlikely(tmp != gcp))
		return -EINVAL;

	if (gcp->client.fd >= 0) {
		nr_fd_closed++;
		w->ev_need_reload = true;
		pr_info(ctx,
			"Freeing connection pair (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
			gcp->idx, gcp->client.fd, gcp->target.fd,
			ip_to_str(&gcp->client_addr),
			ip_to_str(&gcp->target_addr));
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

static int handle_new_client(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;
	struct gwp_cfg *cfg = &ctx->cfg;
	struct epoll_event ev;
	int r, fd, timer_fd;

	fd = create_sock_target(w, &gcp->target_addr, &gcp->is_target_alive);
	if (unlikely(fd < 0)) {
		pr_err(ctx, "Failed to create target socket: %s", strerror(-fd));
		return fd;
	}

	if (cfg->connect_timeout > 0) {
		timer_fd = create_timer(-1, cfg->connect_timeout, 0);
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

	ev.events = gcp->target.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_TARGET;
	r = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, fd, &ev);
	if (unlikely(r < 0)) {
		r = -errno;
		pr_err(ctx, "Failed to add target socket to epoll: %s", strerror(-r));
		return r;
	}

	ev.events = gcp->client.ep_mask;
	ev.data.u64 = 0;
	ev.data.ptr = gcp;
	ev.data.u64 |= EV_BIT_CLIENT;
	r = epoll_ctl(w->ep_fd, EPOLL_CTL_ADD, gcp->client.fd, &ev);
	if (unlikely(r < 0)) {
		r = -errno;
		pr_err(ctx, "Failed to add client socket to epoll: %s", strerror(-r));
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
			pr_err(ctx, "Failed to add timer to epoll: %s", strerror(-r));
			return r;
		}
	}

	pr_info(ctx, "New connection pair created (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));
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

		src->len -= (size_t)ret;
		if (src->len)
			memmove(src->buf, src->buf + ret, src->len);
	}

	return 0;
}

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
		return r;
	}

	if (unlikely(err)) {
		pr_err(ctx, "Target socket connection failed: %s", strerror(err));
		return -err;
	}

	pr_dbg(ctx, "Target socket connected (fd=%d, idx=%u, ca=%s, ta=%s)",
		gcp->target.fd, gcp->idx, ip_to_str(&gcp->client_addr),
		ip_to_str(&gcp->target_addr));

	gcp->is_target_alive = true;
	if (gcp->client.len) {
		r = do_splice(&gcp->client, &gcp->target, false, true);
		if (r)
			return r;
	}

	return adjust_epl_mask(w, gcp);
}

static int handle_ev_target(struct gwp_wrk *w, struct gwp_conn_pair *gcp,
			    struct epoll_event *ev)
{
	int r;

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
		r = do_splice(&gcp->client, &gcp->target, true, false);
		if (r)
			return r;
	}

	if (ev->events & EPOLLOUT) {
		r = do_splice(&gcp->target, &gcp->client, false, false);
		if (r)
			return r;
	}

	return adjust_epl_mask(w, gcp);
}

static int handle_ev_timer(struct gwp_wrk *w, struct gwp_conn_pair *gcp)
{
	struct gwp_ctx *ctx = w->ctx;

	pr_warn(ctx, "Connection timeout! (idx=%u, cfd=%d, tfd=%d, ca=%s, ta=%s)",
		gcp->idx, gcp->client.fd, gcp->target.fd,
		ip_to_str(&gcp->client_addr), ip_to_str(&gcp->target_addr));

	return -ETIMEDOUT;
}

static bool is_ev_bit_conn_pair(uint64_t ev_bit)
{
	static const uint64_t conn_pair_ev_bit =
		EV_BIT_CLIENT | EV_BIT_TARGET | EV_BIT_TIMER;

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

int main(int argc, char *argv[])
{
	struct sigaction sa = { .sa_handler = &sig_handler };
	struct gwp_ctx ctx;
	int r;

	memset(&ctx, 0, sizeof(ctx));
	r = parse_options(argc, argv, &ctx.cfg);
	if (r < 0)
		goto out;

	r = gwp_ctx_init(&ctx);
	if (r < 0)
		goto out_free;

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
