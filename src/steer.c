// SPDX-License-Identifier: GPL-2.0
/*
 * steer.c —— loader + relay + CLI（单文件，静态链接，可直接跑在 Android 上）
 *
 *   steer daemon            加载 eBPF、attach 到 /sys/fs/cgroup、pin 各 map、跑 relay
 *   steer list   [--json]   列出分应用策略（uid / mode / pkg）
 *   steer set    <pkg|uid> <direct|proxy|block>
 *   steer del    <pkg|uid>
 *   steer default <direct|proxy|block>
 *   steer stats  [--json]   读取内核侧计数
 *   steer status [--json]   运行状态
 *
 * 文件即真相：/data/adb/steer/policy  (uid mode pkg)
 *              /data/adb/steer/cfg     (key=value)
 * map 即实时状态：pin 在 /sys/fs/bpf/steer 下
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <linux/pkt_sched.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#define BASE_DIR   "/data/adb/steer"
#define POLICY_F   BASE_DIR "/policy"
#define CFG_F      BASE_DIR "/cfg"
#define PID_F      BASE_DIR "/steer.pid"
#define LOCK_F     BASE_DIR "/steer.lock"
#define LOG_F      BASE_DIR "/steer.log"
#define BPFOBJ_F   BASE_DIR "/steer.bpf.o"
#define PIN_DIR    "/sys/fs/bpf/steer"
#define CGROUP_F   "/sys/fs/cgroup"
#define MODULE_DIR "/data/adb/modules/steer"
#define HB_F       BASE_DIR "/hb"      /* accept 循环心跳 */
#define HB_MAX_AGE 12                   /* 超过这么久没心跳 = 循环卡住 */
/* 版本号由 build.sh 用 module.prop 的值注入（-DSTEER_VERSION=...），
 * 保证"二进制自称的版本"永远等于"模块显示的版本"，不可能再对不上。 */
#ifndef STEER_VERSION
#define STEER_VERSION "steer (unknown build)"
#endif
/* 构建戳：由 build.sh 注入；与 /data/adb/steer/steer.stamp 对比即可发现
 * "模块装了新版但二进制没换掉"（ETXTBSY 那类事故）。 */
#ifndef STEER_STAMP
#define STEER_STAMP "nostamp"
#endif

#define LOG_MAX    (1u << 20)      /* 单份日志上限 1 MiB */
#define MAX_CONNS  512             /* 中继并发上限，防 fd/线程耗尽 */

/* 已知 map 名（cleanup / unpin 用） */
static const char *MAPNAMES[] = { "policy", "cfg", "pending", "by_port", "stats",
	"rstats", "dmap", "dtable", "dalloc", "hbmap", "dbgmap", "uidtop" };
#define NMAPS ((int)(sizeof(MAPNAMES) / sizeof(MAPNAMES[0])))

#define MODE_DIRECT 0
#define MODE_PROXY  1
#define MODE_BLOCK  2

struct orig {
	uint32_t ip4;    /* network order */
	uint16_t port;   /* network order */
	uint16_t _pad;
};
struct cfg_t {
	uint8_t  default_mode;
	uint8_t  _pad0[3];
	uint32_t relay_ip4;
	uint16_t relay_port;
	uint16_t _pad1;
	uint32_t flags;
	uint32_t armed;          /* 运行时安全阀，守护进程控制，不落盘 */
	uint32_t enabled;        /* 总开关，用户控制，落盘到 cfg */
	uint32_t udp_on;         /* UDP(TC) 接管开关 */
	uint32_t relay_udp_port; /* UDP 中继端口 */
	uint32_t lo_ifindex;     /* loopback ifindex（运行时填） */
	uint32_t redir_flags;    /* bpf_redirect flags（0 / BPF_F_INGRESS） */
};

struct dstkey { uint32_t ip4; uint16_t port; uint16_t _pad; };
struct dbg_t { uint64_t calls, last_uid, last_direct_uid, last_proxy_uid, n_proxy, n_direct, n_nouid, last_prio, last_mark, last_daddr, last_dport, lastp_daddr, lastp_dport, n_loopback, n_privskip, n_rewrite; };
struct stats_t {
	uint64_t direct, proxied, blocked, failed;
	uint64_t udp_direct, udp_proxied, udp_blocked, udp_failed;
};
struct rstats_t { uint64_t ok, miss, socksfail, active, bytes_up, bytes_down; };

/* 中继侧计数：写进内核 map，这样 CLI 也能读到 */
#define RSTAT_OK      0
#define RSTAT_MISS    1
#define RSTAT_SOCKS   2
#define RSTAT_ACTIVE  3
#define RSTAT_BYTESUP 4
#define RSTAT_BYTESDN 5

static int g_rmap = -1;
static pthread_mutex_t g_rlock = PTHREAD_MUTEX_INITIALIZER;

static void rstat_add(int which, long long d)
{
	if (g_rmap < 0 || !d) return;
	pthread_mutex_lock(&g_rlock);
	uint32_t k = 0;
	struct rstats_t v;
	if (!bpf_map_lookup_elem(g_rmap, &k, &v)) {
		switch (which) {
		case RSTAT_OK:      v.ok         += d; break;
		case RSTAT_MISS:    v.miss       += d; break;
		case RSTAT_SOCKS:   v.socksfail  += d; break;
		case RSTAT_ACTIVE:  v.active     += d; break;
		case RSTAT_BYTESUP: v.bytes_up   += d; break;
		case RSTAT_BYTESDN: v.bytes_down += d; break;
		}
		bpf_map_update_elem(g_rmap, &k, &v, BPF_ANY);
	}
	pthread_mutex_unlock(&g_rlock);
}

static struct {
	char  socks_host[64];
	int   socks_port;
	char  socks_user[64];
	char  socks_pass[64];
	int   relay_port;
	int   default_mode;
	int   flags;
	int   enabled;        /* 总开关：1=开启接管，0=全部直连（策略表保留） */
	int   takeover;       /* 1=启动时把平台独占的程序摘下来（可还原） */
	int   udp_on;         /* 1=接管 UDP（走 TC） */
	int   relay_udp_port; /* UDP 中继端口 */
	int   redir_flags;    /* bpf_redirect 的 flags（0 或 BPF_F_INGRESS=1） */
} G = { "127.0.0.1", 1180, "", "", 25200, MODE_DIRECT, 1, 1, 1, 1, 25201, 0 };


/* ---------------------------------------------------------------- 小工具 */

/* 日志轮转：超过 LOG_MAX 就改名 .1（覆盖上一个 .1）。保证不会撑爆 /data */
static void rotate_log(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0 && (unsigned)st.st_size > LOG_MAX) {
		char old[256];
		snprintf(old, sizeof(old), "%s.1", path);
		rename(path, old);
	}
}

static void logmsg(const char *fmt, ...)
{
	rotate_log(LOG_F);
	FILE *f = fopen(LOG_F, "a");
	if (!f) return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fputc('\n', f);
	fclose(f);
}

static const char *mode_name(int m)
{
	return m == MODE_PROXY ? "proxy" : m == MODE_BLOCK ? "block" : "direct";
}
static int mode_from(const char *s)
{
	if (!strcmp(s, "proxy"))  return MODE_PROXY;
	if (!strcmp(s, "block"))  return MODE_BLOCK;
	if (!strcmp(s, "direct")) return MODE_DIRECT;
	return -1;
}

static int is_all_digits(const char *s)
{
	if (!*s) return 0;
	for (; *s; s++) if (*s < '0' || *s > '9') return 0;
	return 1;
}

static void mkdirs(void)
{
	mkdir(BASE_DIR, 0700);
}


static int map_fd(const char *name)
{
	char p[128];
	snprintf(p, sizeof(p), "%s/%s", PIN_DIR, name);
	int fd = bpf_obj_get(p);
	return fd;   /* -1 表示守护进程没在跑 */
}

/* ---------------------------------------------------------------- 配置 */

static void cfg_load(void)
{
	FILE *f = fopen(CFG_F, "r");
	if (!f) return;
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');
		if (!eq) continue;
		*eq = 0;
		char *k = line, *v = eq + 1;
		v[strcspn(v, "\r\n")] = 0;
		if      (!strcmp(k, "socks_host")) strncpy(G.socks_host, v, 63);
		else if (!strcmp(k, "socks_port")) G.socks_port = atoi(v);
		else if (!strcmp(k, "socks_user")) strncpy(G.socks_user, v, 63);
		else if (!strcmp(k, "socks_pass")) strncpy(G.socks_pass, v, 63);
		else if (!strcmp(k, "relay_port")) G.relay_port = atoi(v);
		else if (!strcmp(k, "default_mode")) G.default_mode = mode_from(v);
		else if (!strcmp(k, "flags")) G.flags = atoi(v);
		else if (!strcmp(k, "enabled")) G.enabled = atoi(v) ? 1 : 0;
		else if (!strcmp(k, "takeover")) G.takeover = atoi(v) ? 1 : 0;
		else if (!strcmp(k, "udp")) G.udp_on = atoi(v) ? 1 : 0;
		else if (!strcmp(k, "relay_udp_port")) G.relay_udp_port = atoi(v);
		else if (!strcmp(k, "redirect_flags")) G.redir_flags = atoi(v);
	}
	fclose(f);
}
static void cfg_save(void)
{
	mkdirs();
	FILE *f = fopen(CFG_F, "w");
	if (!f) return;
	fprintf(f,
		"socks_host=%s\nsocks_port=%d\nsocks_user=%s\nsocks_pass=%s\n"
		"relay_port=%d\ndefault_mode=%s\nflags=%d\nenabled=%d\ntakeover=%d\n"
		"udp=%d\nrelay_udp_port=%d\nredirect_flags=%d\n",
		G.socks_host, G.socks_port, G.socks_user, G.socks_pass,
		G.relay_port, mode_name(G.default_mode), G.flags, G.enabled, G.takeover,
		G.udp_on, G.relay_udp_port, G.redir_flags);
	fclose(f);
	chmod(CFG_F, 0600);   /* 里面有 socks 口令，别让它世界可读 */
}

/* ---------------------------------------------------------------- 策略文件 */

struct entry { uint32_t uid; int mode; char pkg[128]; };
static struct entry EL[1024];
static int ELN;

static void policy_load(void)
{
	ELN = 0;
	FILE *f = fopen(POLICY_F, "r");
	if (!f) return;
	char line[256];
	while (fgets(line, sizeof(line), f) && ELN < 1024) {
		if (line[0] == '#' || line[0] == '\n') continue;
		unsigned u; int m; char pkg[128] = "";
		if (sscanf(line, "%u %d %127s", &u, &m, pkg) >= 2) {
			EL[ELN].uid = u; EL[ELN].mode = m;
			memcpy(EL[ELN].pkg, pkg, 127);
			EL[ELN].pkg[127] = 0;
			ELN++;
		}
	}
	fclose(f);
}
static void policy_save(void)
{
	mkdirs();
	FILE *f = fopen(POLICY_F, "w");
	if (!f) return;
	fprintf(f, "# uid mode package\n");
	for (int i = 0; i < ELN; i++)
		fprintf(f, "%u %d %s\n", EL[i].uid, EL[i].mode, EL[i].pkg);
	fclose(f);
}

/* 把文件里的策略推给内核 map；deny 时同步删除多余的 */
static void policy_push(void)
{
	int fd = map_fd("policy");
	if (fd < 0) return;

	/* 先把现有 key 收集出来，再删（遍历中删除会破坏迭代） */
	uint32_t key, next, keys[1024];
	int n = 0, r = bpf_map_get_next_key(fd, NULL, &key);
	while (r == 0) {
		if (n < 1024) keys[n++] = key;
		r = bpf_map_get_next_key(fd, &key, &next);
		key = next;
	}
	for (int i = 0; i < n; i++)
		bpf_map_delete_elem(fd, &keys[i]);

	for (int i = 0; i < ELN; i++) {
		uint8_t v = (uint8_t)EL[i].mode;
		bpf_map_update_elem(fd, &EL[i].uid, &v, BPF_ANY);
	}
	close(fd);
}

/* ---------------------------------------------------------------- 包名 -> uid */

/* 直接 exec /system/bin/cmd，不依赖 shell，避免静态 glibc 下的 popen 兼容问题 */
static int resolve_uid(const char *pkg, uint32_t *out)
{
	if (is_all_digits(pkg)) { *out = (uint32_t)strtoul(pkg, NULL, 10); return 0; }

	int pfd[2];
	if (pipe(pfd)) return -1;
	pid_t pid = fork();
	if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
	if (pid == 0) {
		dup2(pfd[1], 1);
		close(pfd[0]); close(pfd[1]);
		int devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) dup2(devnull, 2);
		execl("/system/bin/cmd", "cmd", "package", "list", "packages", "-U", (char *)NULL);
		_exit(127);
	}
	close(pfd[1]);
	char needle[160];
	snprintf(needle, sizeof(needle), "package:%s ", pkg);
	size_t nl = strlen(needle);

	/* 包多时输出会超过一次 read 的长度，必须循环读到 EOF，否则解析不到 */
	size_t cap = 1u << 20;
	char *buf = malloc(cap);
	if (!buf) { close(pfd[0]); waitpid(pid, NULL, 0); return -1; }
	size_t total = 0;
	for (;;) {
		if (total + 1 >= cap) break;
		ssize_t n = read(pfd[0], buf + total, cap - 1 - total);
		if (n > 0) { total += (size_t)n; continue; }
		if (n < 0 && errno == EINTR) continue;
		break;
	}
	close(pfd[0]);
	waitpid(pid, NULL, 0);
	if (total == 0) { free(buf); return -1; }
	buf[total] = 0;

	char *p = buf;
	int ok = -1;
	while (*p) {
		char *nl2 = strchr(p, '\n');
		if (nl2) *nl2 = 0;
		if (!strncmp(p, needle, nl)) {
			char *u = strstr(p, "uid:");
			if (u) { *out = (uint32_t)strtoul(u + 4, NULL, 10); ok = 0; break; }
		}
		if (!nl2) break;
		p = nl2 + 1;
	}
	free(buf);
	return ok;
}

/* ---------------------------------------------------------------- SOCKS5 relay */

static int socks_connect(uint32_t ip4_net, uint16_t port_net)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)G.socks_port);
	if (inet_pton(AF_INET, G.socks_host, &sa.sin_addr) != 1) {
		logmsg("socks_host 必须是 IP 字面量，当前为 '%s'", G.socks_host);
		close(fd);
		return -1;
	}
	/* connect 也要有超时：出口的 listen backlog 可能满，阻塞 connect 会长时间挂住 */
	{
		int fl = fcntl(fd, F_GETFL, 0);
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
		int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
		if (rc < 0 && errno == EINPROGRESS) {
			struct pollfd cp = { .fd = fd, .events = POLLOUT };
			rc = (poll(&cp, 1, 5000) == 1) ? 0 : -1;
			if (rc == 0) {
				int soerr = 0; socklen_t sl = sizeof(soerr);
				if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) || soerr) rc = -1;
			}
			if (rc) errno = ETIMEDOUT;
		} else if (rc < 0) {
			rc = -1;
		}
		fcntl(fd, F_SETFL, fl);          /* 恢复阻塞 */
		if (rc < 0) {
			logmsg("connect %s:%d 失败/超时: %s", G.socks_host, G.socks_port, strerror(errno));
			close(fd);
			return -1;
		}
	}

	/* 握手设超时，避免出口卡住时长期占用线程 */
	struct timeval tv = { 10, 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	uint8_t buf[512];
	int n;
	if (G.socks_user[0]) {
		buf[0] = 5; buf[1] = 2; buf[2] = 0; buf[3] = 2;
		if (write(fd, buf, 4) != 4) goto fail;
		if (read(fd, buf, 2) != 2) goto fail;
		if (buf[1] == 0x02) {
			int ul = strlen(G.socks_user), pl = strlen(G.socks_pass);
			int o = 0; buf[o++] = 1; buf[o++] = ul;
			memcpy(buf + o, G.socks_user, ul); o += ul;
			buf[o++] = pl; memcpy(buf + o, G.socks_pass, pl); o += pl;
			if (write(fd, buf, o) != o) goto fail;
			if (read(fd, buf, 2) != 2 || buf[1] != 0) goto fail;
		} else if (buf[1] != 0x00) goto fail;
	} else {
		buf[0] = 5; buf[1] = 1; buf[2] = 0;
		if (write(fd, buf, 3) != 3) goto fail;
		if (read(fd, buf, 2) != 2 || buf[1] != 0x00) goto fail;
	}

	/* CONNECT */
	int o = 0;
	buf[o++] = 5; buf[o++] = 1; buf[o++] = 0; buf[o++] = 1;
	memcpy(buf + o, &ip4_net, 4); o += 4;
	memcpy(buf + o, &port_net, 2); o += 2;
	if (write(fd, buf, o) != o) goto fail;
	if (read(fd, buf, 4) != 4 || buf[1] != 0) goto fail;
	int skip;
	switch (buf[3]) {
	case 1: skip = 4 + 2; break;
	case 4: skip = 16 + 2; break;
	case 3: { if (read(fd, buf, 1) != 1) goto fail; skip = buf[0] + 2; break; }
	default: goto fail;
	}
	while (skip > 0) {
		n = read(fd, buf, skip > (int)sizeof(buf) ? (int)sizeof(buf) : skip);
		if (n <= 0) goto fail;
		skip -= n;
	}

	/* 握手完成，解除超时：数据面要能长时间保持空闲连接 */
	tv.tv_sec = 0; tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	return fd;
fail:
	close(fd);
	return -1;
}

/* 前置声明：relay_loop 会用到（TC 部分定义在后面） */
#define MAX_TC_DEV 64
static int g_tc_fd;
static int g_ntc;
static int tc_attach_devs(int prog_fd);
static void hb_write(void);
static volatile time_t g_hb_ts;      /* 最近一次心跳时刻（供信号处理器读） */
static int g_alog = -1;              /* 信号处理器只能 write()，预留一个 fd */
static long hb_age(void);

static volatile int g_conns = 0;   /* 中继在途连接数（资源护栏） */

/* closing 由另一方向在返回时置 1：若对端一直不发 FIN，我们最多再等 IDLE_AFTER_EOF 秒，
 * 避免半开连接把线程与 fd 永久占住。 */
#define IDLE_AFTER_EOF 60

struct pump_arg { int from, to; volatile int *closing; long long moved; };

static void *pump(void *p)
{
	struct pump_arg *a = p;
	char buf[65536];
	struct pollfd pfd = { .fd = a->from, .events = POLLIN };
	time_t last = time(NULL);

	for (;;) {
		if (*a->closing && time(NULL) - last > IDLE_AFTER_EOF)
			break;
		int r = poll(&pfd, 1, 1000);
		if (r < 0) { if (errno == EINTR) continue; break; }
		if (r == 0) continue;

		ssize_t n = read(a->from, buf, sizeof(buf));
		if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
		last = time(NULL);

		a->moved += n;
		ssize_t off = 0;
		while (off < n) {
			ssize_t w = send(a->to, buf + off, n - off, MSG_NOSIGNAL);
			if (w <= 0) goto done;
			off += w;
		}
	}
done:
	shutdown(a->to, SHUT_WR);
	return NULL;
}

static void *conn_thread(void *p)
{
	int cfd = (int)(intptr_t)p;
	int sfd = -1, bfd = -1;

	rstat_add(RSTAT_ACTIVE, 1);

	struct sockaddr_in peer;
	socklen_t pl = sizeof(peer);
	if (getpeername(cfd, (struct sockaddr *)&peer, &pl) < 0)
		goto done;
	uint32_t lport = ntohs(peer.sin_port);          /* == 客户端源端口 */
	logmsg("relay: 连接进来 peer_port=%u", lport);

	struct orig o;
	bfd = map_fd("by_port");
	if (bfd < 0 || bpf_map_lookup_elem(bfd, &lport, &o)) {
		rstat_add(RSTAT_MISS, 1);
		logmsg("relay: 找不到 by_port(lport=%u) —— sock_ops 时序或已过期", lport);
		goto done;
	}
	bpf_map_delete_elem(bfd, &lport);
	{
		struct in_addr a = { .s_addr = o.ip4 };
		logmsg("relay: 原目标 %s:%u", inet_ntoa(a), ntohs(o.port));
	}

	logmsg("relay: 正在连出口 %s:%d ...", G.socks_host, G.socks_port);
	sfd = socks_connect(o.ip4, o.port);
	if (sfd < 0) {
		rstat_add(RSTAT_SOCKS, 1);
		struct in_addr a = { .s_addr = o.ip4 };
		logmsg("relay: socks5 connect %s:%u 失败: %s",
		       inet_ntoa(a), ntohs(o.port), strerror(errno));
		goto done;
	}
	rstat_add(RSTAT_OK, 1);
	logmsg("relay: 已连上出口，开始转发");

	int one = 1;
	setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	volatile int closing = 0;
	pthread_t t;
	struct pump_arg a1 = { cfd, sfd, &closing, 0 }, a2 = { sfd, cfd, &closing, 0 };
	if (pthread_create(&t, NULL, pump, &a1) == 0) {
		pump(&a2);
		closing = 1;                 /* 通知仍在跑的那一方向：最多再等 60s */
		pthread_join(t, NULL);
		rstat_add(RSTAT_BYTESUP, a1.moved);
		rstat_add(RSTAT_BYTESDN, a2.moved);
		logmsg("relay: 结束 up=%lld down=%lld", a1.moved, a2.moved);
	}

done:
	if (bfd >= 0) close(bfd);
	if (sfd >= 0) close(sfd);
	close(cfd);
	rstat_add(RSTAT_ACTIVE, -1);
	__atomic_sub_fetch(&g_conns, 1, __ATOMIC_RELAXED);
	return NULL;
}

static volatile int g_run = 1;

static void on_sig(int s) { (void)s; g_run = 0; }

/* 看门狗：故意不用线程。若 pthread 本身有问题，线程看门狗会一起坏。
 * 只做"读变量 + time() + write() + _exit"，全部 async-signal-safe。 */
static void on_alarm(int s)
{
	(void)s;
	alarm(15);
	time_t now = time(NULL);
	time_t last = g_hb_ts;
	if (last && now - last > 30) {
		static const char m[] = "*** accept 循环超过 30s 无心跳，主动退出让 watchdog 重拉 ***\n";
		if (g_alog >= 0) { ssize_t r = write(g_alog, m, sizeof(m) - 1); (void)r; }
		_exit(3);            /* 不管日志写没写成功，都要退出自愈 */
	}
}

static void install_sigs(void)
{
	struct sigaction sa = {0};
	sa.sa_handler = on_sig;              /* 不带 SA_RESTART：好让 poll/accept 被中断 */
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	struct sigaction aa = {0};
	aa.sa_handler = on_alarm;
	sigaction(SIGALRM, &aa, NULL);
	alarm(15);
}

/* 只监听 127.0.0.1，绝不对外暴露 */
static int relay_listen(void)
{
	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0) return -1;
	int one = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)G.relay_port);
	inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		logmsg("relay bind 127.0.0.1:%d 失败: %s", G.relay_port, strerror(errno));
		close(lfd);
		return -1;
	}
	if (listen(lfd, 512) < 0) { close(lfd); return -1; }
	logmsg("relay listening 127.0.0.1:%d -> socks5 %s:%d", G.relay_port, G.socks_host, G.socks_port);
	return lfd;
}

static void relay_loop(int lfd)
{
	struct pollfd pfd = { .fd = lfd, .events = POLLIN };
	int trace = 0;
	int tick = 0;
	while (g_run) {
		hb_write();
		g_hb_ts = time(NULL);
		/* 每 ~20 秒重扫一次网卡：切 Wi-Fi/移动数据后新接口也要挂上 TC */
		if (G.udp_on && g_tc_fd >= 0 && ++tick >= 10) {
			tick = 0;
			if (g_ntc < MAX_TC_DEV) tc_attach_devs(g_tc_fd);
		}
		if (trace < 40) logmsg("loop#%d: 进入循环体", trace);
		/* 模块被禁用 -> 自己退场（并把 eBPF 一起带走） */
		if (access(MODULE_DIR "/disable", F_OK) == 0) {
			logmsg("检测到 disable 标记，主动退出");
			break;
		}
		if (trace < 40) logmsg("loop#%d: 调 poll ...", trace);
		int r = poll(&pfd, 1, 2000);
		if (trace < 40) logmsg("loop#%d: poll 返回 %d", trace, r);
		if (r < 0) { if (errno == EINTR) continue; break; }
		if (r == 0) continue;
		if (trace < 40) logmsg("loop#%d: 调 accept ...", trace);
		int c = accept(lfd, NULL, NULL);
		if (trace < 40) logmsg("loop#%d: accept 返回 %d (%s)", trace, c,
		                       c < 0 ? strerror(errno) : "ok");
		trace++;
		if (c < 0) {
			/* 瞬时错误绝不能把中继循环打死 */
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == ECONNABORTED || errno == EPROTO ||
			    errno == EMFILE || errno == ENFILE) {
				if (errno == EMFILE || errno == ENFILE) {
					usleep(100000);
					logmsg("accept: fd 用尽（EMFILE/ENFILE）");
				}
				continue;
			}
			break;
		}
		if (__atomic_load_n(&g_conns, __ATOMIC_RELAXED) >= MAX_CONNS) {
			logmsg("并发已达上限 %d，拒绝新连接", MAX_CONNS);
			close(c);
			continue;
		}
		__atomic_add_fetch(&g_conns, 1, __ATOMIC_RELAXED);
		pthread_t t;
		logmsg("relay: 即将创建线程 fd=%d", c);
		int pr = pthread_create(&t, NULL, conn_thread, (void *)(intptr_t)c);
		logmsg("relay: pthread_create 返回 %d (%s)", pr, pr ? strerror(pr) : "ok");
		if (pr == 0) {
			pthread_detach(t);
		} else {
			__atomic_sub_fetch(&g_conns, 1, __ATOMIC_RELAXED);
			close(c);
		}
	}
	/* 给在途连接一点收尾时间，但不强杀 */
	close(lfd);
}

/* ---------------------------------------------------------------- daemon */

static struct bpf_link *g_link[4];

/* MAX_CONNS 条连接约需 2×MAX_CONNS 个 fd，默认 1024 不够，先抬高上限 */
static void raise_fds(void)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl)) return;
	rl.rlim_cur = rl.rlim_max = 8192;
	if (setrlimit(RLIMIT_NOFILE, &rl))
		logmsg("setrlimit(NOFILE) 失败: %s（并发上限仍为 %d）", strerror(errno), MAX_CONNS);
}

/* Android 默认把 memlock 设得很小（常见 64KB），libbpf 建 map 时可能因此失败。
 * 我们是 root，先把上限抬到无穷；抬不动也不致命（5.11+ 走 memcg 记账）。 */
static void raise_memlock(void)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_MEMLOCK, &rl)) return;
	if (rl.rlim_cur == RLIM_INFINITY) return;
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_MEMLOCK, &rl))
		logmsg("setrlimit(MEMLOCK) 失败: %s（libbpf 可能报警告，通常仍可用）", strerror(errno));
	else
		logmsg("RLIMIT_MEMLOCK -> infinity");
}

/* 把 libbpf 自己的报错也写进我们的日志，否则真机上只看得到“未运行” */
static int libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	va_list ap2;
	va_copy(ap2, ap);
	vfprintf(stderr, fmt, ap);
	rotate_log(LOG_F);
	FILE *f = fopen(LOG_F, "a");
	if (f) { fputs("[libbpf] ", f); vfprintf(f, fmt, ap2); fclose(f); }
	va_end(ap2);
	return 0;
}

static int cmd_restart(void);   /* 前置声明：cmd_switch 里会用到 */
static void hb_write(void);
static long hb_age(void);

/* 不再用"map 是否被 pin"来判断——pin 在进程死后依然存在，会骗人。
 * 现在：读 pid 文件 + 确认该 pid 真的是我们的 daemon。 */
static int daemon_running(void)
{
	FILE *f = fopen(PID_F, "r");
	if (!f) return 0;
	int pid = 0;
	if (fscanf(f, "%d", &pid) != 1) pid = 0;
	fclose(f);
	if (pid <= 1) return 0;
	if (kill(pid, 0) && errno == ESRCH) return 0;

	char p[64], buf[64] = "";
	snprintf(p, sizeof(p), "/proc/%d/comm", pid);
	FILE *c = fopen(p, "r");
	if (c) { if (!fgets(buf, sizeof(buf), c)) buf[0] = 0; fclose(c); }
	if (!strstr(buf, "steer")) return 0;
	return 1;
}

/* 心跳：accept 循环每轮写一次时间戳；用它区分"进程活着"和"循环卡住" */
static void hb_write(void)
{
	FILE *f = fopen(HB_F, "w");
	if (f) { fprintf(f, "%ld\n", (long)time(NULL)); fclose(f); }
	/* 同时刷内核侧心跳（TC 程序用它做死手开关） */
	static int hbfd = -1;
	if (hbfd < 0) hbfd = map_fd("hbmap");
	if (hbfd >= 0) {
		uint32_t k = 0;
		uint64_t ns = 0;
		struct timespec ts;
		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
			ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
		if (ns) bpf_map_update_elem(hbfd, &k, &ns, BPF_ANY);
	}
}
static long hb_age(void)
{
	FILE *f = fopen(HB_F, "r");
	if (!f) return -1;
	long t = 0;
	if (fscanf(f, "%ld", &t) != 1) t = 0;
	fclose(f);
	if (t <= 0) return -1;
	return (long)time(NULL) - t;
}

/* 注意：不能用 bpf_map__set_initial_value()。
 * libbpf 里它只对内部 map（.data/.rodata/.bss/.kconfig）有效，普通 map 的
 * map->mmaped 为 NULL，会直接返回 -EINVAL。所以初始值必须在 load 之后
 * 用 bpf_map_update_elem 写进去。 */
static int cfg_seed(struct bpf_object *obj)
{
	struct bpf_map *m = bpf_object__find_map_by_name(obj, "cfg");
	if (!m) return -1;
	uint32_t k = 0;
	struct cfg_t c = {0};
	c.default_mode = (uint8_t)G.default_mode;
	c.relay_ip4 = inet_addr("127.0.0.1");
	c.relay_port = (uint16_t)G.relay_port;
	c.flags = (uint32_t)G.flags;
	c.armed = 0;                 /* 未就绪：一律直连（fail-open） */
	c.enabled = (uint32_t)G.enabled;
	c.udp_on = (uint32_t)G.udp_on;
	c.relay_udp_port = (uint32_t)G.relay_udp_port;
	c.lo_ifindex = 0;
	c.redir_flags = (uint32_t)G.redir_flags;
	return bpf_map_update_elem(bpf_map__fd(m), &k, &c, BPF_ANY);
}

/* 读-改-写 cfg，只动需要动的字段。
 * armed   -1=保持不变
 * enabled -1=保持不变
 * 这样 CLI 改 default / 切总开关时，绝不会误清掉守护的 armed。 */
static int cfg_patch(int armed, int enabled)
{
	int fd = map_fd("cfg");
	if (fd < 0) return -1;               /* 守护没跑，只落盘即可 */
	uint32_t k = 0;
	struct cfg_t c = {0};
	if (bpf_map_lookup_elem(fd, &k, &c)) {   /* 读不到就按当前内存配置初始化 */
		c.relay_ip4 = inet_addr("127.0.0.1");
		c.relay_port = (uint16_t)G.relay_port;
		c.flags = (uint32_t)G.flags;
		c.armed = 0;
		c.enabled = (uint32_t)G.enabled;
	}
	c.default_mode = (uint8_t)G.default_mode;
	c.relay_port = (uint16_t)G.relay_port;
	c.flags = (uint32_t)G.flags;
	c.udp_on = (uint32_t)G.udp_on;
	c.relay_udp_port = (uint32_t)G.relay_udp_port;
	c.redir_flags = (uint32_t)G.redir_flags;
	if (armed >= 0)   c.armed   = (uint32_t)armed;
	if (enabled >= 0) c.enabled = (uint32_t)enabled;
	int r = bpf_map_update_elem(fd, &k, &c, BPF_ANY);
	close(fd);
	return r;
}

/* 删掉残留的 pin（能拿到单实例锁就说明上个实例确实已经不在了） */
static void cleanup_pins(void)
{
	for (int i = 0; i < NMAPS; i++) {
		char p[128];
		snprintf(p, sizeof(p), "%s/%s", PIN_DIR, MAPNAMES[i]);
		unlink(p);
	}
	rmdir(PIN_DIR);
}

static void detach_links(int n)
{
	for (int i = 0; i < n; i++)
		if (g_link[i]) bpf_link__destroy(g_link[i]);
}

/* ================= TC 挂载（UDP 用） =================
 * 为什么 TC：cgroup/sendmsg4 对 connected UDP（QUIC 用 connect+send）不触发。
 * TC 在 IP 层，一视同仁。
 */
static int g_tc_ifs[MAX_TC_DEV];
static int g_ntc;
static int g_tc_fd = -1;

static int tc_attach_devs(int prog_fd)
{
	DIR *d = opendir("/sys/class/net");
	if (!d) return -1;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.') continue;
		if (!strcmp(e->d_name, "lo")) continue;
		if (g_ntc >= MAX_TC_DEV) break;
		int idx = (int)if_nametoindex(e->d_name);
		if (!idx) continue;
		/* 已经挂过就跳过 */
		int seen = 0;
		for (int i = 0; i < g_ntc; i++) if (g_tc_ifs[i] == idx) seen = 1;
		if (seen) continue;

		struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = idx,
		                            .attach_point = BPF_TC_EGRESS };
		int r = bpf_tc_hook_create(&hook);
		if (r && r != -EEXIST) {
			logmsg("tc[%s]: 建 clsact 失败: %s", e->d_name, strerror(-r));
			continue;
		}
		struct bpf_tc_opts opts = { .sz = sizeof(opts), .prog_fd = prog_fd,
		                            .handle = 1, .priority = 1 };
		r = bpf_tc_attach(&hook, &opts);
		if (r) { logmsg("tc[%s]: 挂载失败: %s", e->d_name, strerror(-r)); continue; }
		g_tc_ifs[g_ntc++] = idx;
		logmsg("tc[%s]: 已挂 egress (ifindex=%d)", e->d_name, idx);
	}
	closedir(d);
	return 0;
}

/* 扫一遍设备，按固定 handle/priority 摘掉我们自己的过滤器。
 * 用固定 handle/prio（1/1）的好处：**任何进程都能干净卸载**，
 * 不依赖内存里的列表 —— 所以崩溃后、卸载脚本里、下次启动前都能清。 */
static int tc_detach_all(int verbose)
{
	DIR *d = opendir("/sys/class/net");
	if (!d) return 0;
	struct dirent *e;
	int n = 0;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.') continue;
		int idx = (int)if_nametoindex(e->d_name);
		if (!idx) continue;
		struct bpf_tc_hook hook = { .sz = sizeof(hook), .ifindex = idx,
		                            .attach_point = BPF_TC_EGRESS };
		struct bpf_tc_opts opts = { .sz = sizeof(opts), .handle = 1, .priority = 1 };
		if (bpf_tc_detach(&hook, &opts) == 0) {
			n++;
			if (verbose) logmsg("tc[%s]: 已卸载我们的过滤器", e->d_name);
		}
	}
	closedir(d);
	g_ntc = 0;
	return n;
}

/* ================= UDP 中继 =================
 * 收：App 的 UDP 被 TC 改写成 127.<slot>:RELAY_UDP —— 用 IP_PKTINFO 拿到目的地址，
 *     解出 slot，从 dtable 还原原目标，走 SOCKS5 UDP ASSOCIATE 转发。
 * 回：出口回包的 SOCKS5 头里带着"真实应答者地址"，把它作为**伪造源地址**发给 App
 *     （QUIC 的 connected socket 只认这个源，否则内核在收包时就把包丢了）。
 *     源端口必须等于原目标端口，所以回包要经由"绑定到 (原目标IP,原目标端口)"的专用 socket。
 */
#define MAX_SLOT 1024
static int g_udp_fd = -1, g_dtable = -1, g_dmap = -1;
static int g_udp_ctrl = -1;
static struct sockaddr_in g_udp_relay;
static int g_slot_fd[MAX_SLOT];
static struct sockaddr_in g_slot_app[MAX_SLOT];

static void cfg_set_lo_index(int idx)
{
	int fd = map_fd("cfg");
	if (fd < 0) return;
	uint32_t k = 0;
	struct cfg_t c;
	if (bpf_map_lookup_elem(fd, &k, &c)) { close(fd); return; }
	c.lo_ifindex = (uint32_t)idx;
	bpf_map_update_elem(fd, &k, &c, BPF_ANY);
	close(fd);
}

static int udp_open(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;
	int on = 1;
	if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)))
		logmsg("udp: IP_TRANSPARENT 设置失败: %s", strerror(errno));
	setsockopt(fd, SOL_IP, IP_PKTINFO, &on, sizeof(on));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)G.relay_udp_port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);      /* 通配，才能收到 127.x.y.z */
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		logmsg("udp: bind 0.0.0.0:%d 失败: %s", G.relay_udp_port, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

/* 建立/重建 SOCKS5 UDP ASSOCIATE */
static int socks_udp_associate(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	struct sockaddr_in sa = {0};
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)G.socks_port);
	if (inet_pton(AF_INET, G.socks_host, &sa.sin_addr) != 1) { close(fd); return -1; }
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }

	struct timeval tv = { 5, 0 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	uint8_t buf[32];
	if (G.socks_user[0]) {
		buf[0]=5; buf[1]=2; buf[2]=0; buf[3]=2;
		if (write(fd, buf, 4) != 4) goto fail;
		if (read(fd, buf, 2) != 2) goto fail;
		if (buf[1] == 2) {
			int u = strlen(G.socks_user), p = strlen(G.socks_pass), o = 0;
			buf[o++]=1; buf[o++]=u; memcpy(buf+o,G.socks_user,u); o+=u;
			buf[o++]=p; memcpy(buf+o,G.socks_pass,p); o+=p;
			if (write(fd, buf, o) != o) goto fail;
			if (read(fd, buf, 2) != 2 || buf[1]) goto fail;
		} else if (buf[1] != 0) goto fail;
	} else {
		buf[0]=5; buf[1]=1; buf[2]=0;
		if (write(fd, buf, 3) != 3) goto fail;
		if (read(fd, buf, 2) != 2 || buf[1] != 0) goto fail;
	}
	/* UDP ASSOCIATE, DST=0.0.0.0:0 */
	buf[0]=5; buf[1]=3; buf[2]=0; buf[3]=1;
	memset(buf+4, 0, 6);
	if (write(fd, buf, 10) != 10) goto fail;
	if (read(fd, buf, 4) != 4 || buf[1] != 0) goto fail;
	{
		int skip;
		switch (buf[3]) {
		case 1: memcpy(&g_udp_relay.sin_addr, buf, 0); /* 下面读 */
			if (read(fd, buf, 6) != 6) goto fail;
			memcpy(&g_udp_relay.sin_addr, buf, 4);
			memcpy(&g_udp_relay.sin_port, buf + 4, 2);
			g_udp_relay.sin_family = AF_INET;
			break;
		case 4:
			if (read(fd, buf, 18) != 18) goto fail;
			memcpy(&g_udp_relay.sin_addr, buf + 12, 4);
			memcpy(&g_udp_relay.sin_port, buf + 16, 2);
			g_udp_relay.sin_family = AF_INET;
			break;
		case 3:
			if (read(fd, buf, 1) != 1) goto fail;
			skip = buf[0] + 2;
			while (skip > 0) { int n = read(fd, buf, skip > 32 ? 32 : skip); if (n <= 0) goto fail; skip -= n; }
			memcpy(&g_udp_relay.sin_addr, &sa.sin_addr, 4);
			g_udp_relay.sin_port = sa.sin_port;
			g_udp_relay.sin_family = AF_INET;
			break;
		default: goto fail;
		}
	}
	if (g_udp_relay.sin_addr.s_addr == 0) g_udp_relay.sin_addr = sa.sin_addr;
	tv.tv_sec = 0; tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	logmsg("udp: 已建立 SOCKS5 UDP 关联，relay=%s:%d",
	       inet_ntoa(g_udp_relay.sin_addr), ntohs(g_udp_relay.sin_port));
	g_udp_ctrl = fd;
	return 0;
fail:
	close(fd);
	return -1;
}

/* 回包专用 socket：绑定到 (原目标IP, 原目标端口)，这样 App 看到的源才正确 */
static int slot_sock(int slot, struct dstkey *k)
{
	if (g_slot_fd[slot] >= 0) return g_slot_fd[slot];
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;
	int on = 1;
	if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &on, sizeof(on)))
		logmsg("udp: slot%d IP_TRANSPARENT 失败: %s", slot, strerror(errno));
	struct sockaddr_in a = {0};
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = k->ip4;
	a.sin_port = k->port;
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		logmsg("udp: slot%d bind %s:%d 失败: %s", slot,
		       inet_ntoa(a.sin_addr), ntohs(a.sin_port), strerror(errno));
		close(fd);
		return -1;
	}
	g_slot_fd[slot] = fd;
	return fd;
}

static void *udp_thread(void *arg)
{
	char *buf = malloc(65536);
	if (!buf) return NULL;
	char cbuf[256];
	for (;;) {
		struct sockaddr_in from = {0};
		struct iovec iov = { buf, 65536 };
		struct msghdr mh = { .msg_name = &from, .msg_namelen = sizeof(from),
		                     .msg_iov = &iov, .msg_iovlen = 1,
		                     .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
		ssize_t n = recvmsg(g_udp_fd, &mh, 0);
		if (n < 0) { if (errno == EINTR) continue; break; }
		if (n <= 0) continue;

		/* 来自出口 relay 的 → 回给 App */
		if (from.sin_addr.s_addr == g_udp_relay.sin_addr.s_addr &&
		    from.sin_port == g_udp_relay.sin_port) {
			if (n < 10) continue;
			uint8_t *p = (uint8_t *)buf;
			if (p[3] != 1) continue;                 /* 只处理 IPv4 应答 */
			uint32_t rip; uint16_t rport;
			memcpy(&rip, p + 4, 4);
			memcpy(&rport, p + 8, 2);
			struct dstkey key = { .ip4 = rip, .port = rport };
			uint32_t slot;
			if (g_dmap < 0 || bpf_map_lookup_elem(g_dmap, &key, &slot)) continue;
			if (slot >= MAX_SLOT) continue;
			uint8_t *payload = p + 10;
			ssize_t plen = n - 10;
			if (plen <= 0) continue;
			int sfd = slot_sock((int)slot, &key);
			if (sfd < 0) continue;
			if (sendto(sfd, payload, plen, 0,
			           (struct sockaddr *)&g_slot_app[slot], sizeof(g_slot_app[slot])) < 0)
				logmsg("udp: 回包给 App 失败: %s", strerror(errno));
			continue;
		}
		/* 来自 App 的 → 转给出口 */
		__u32 daddr = 0;
		for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
			if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo pi;
				memcpy(&pi, CMSG_DATA(c), sizeof(pi));
				daddr = pi.ipi_addr.s_addr;
			}
		if (!daddr) continue;
		__u32 slot = ntohl(daddr) & 0xFFFFFFu;
		if (slot >= MAX_SLOT) continue;
		struct dstkey k;
		if (bpf_map_lookup_elem(g_dtable, &slot, &k)) continue;
		g_slot_app[slot] = from;
		if (g_udp_ctrl < 0 && socks_udp_associate()) { usleep(200000); continue; }

		uint8_t *out = malloc(n + 16);
		if (!out) continue;
		out[0]=0; out[1]=0; out[2]=0; out[3]=1;
		memcpy(out+4, &k.ip4, 4);
		memcpy(out+8, &k.port, 2);
		memcpy(out+10, buf, n);
		ssize_t r = sendto(g_udp_fd, out, n + 10, 0,
		                   (struct sockaddr *)&g_udp_relay, sizeof(g_udp_relay));
		if (r < 0) { g_udp_ctrl >= 0 && (close(g_udp_ctrl), 0); g_udp_ctrl = -1; }
		free(out);
	}
	free(buf);
	return NULL;
}

static void udp_shutdown(void)
{
	for (int i = 0; i < MAX_SLOT; i++)
		if (g_slot_fd[i] >= 0) { close(g_slot_fd[i]); g_slot_fd[i] = -1; }
	if (g_udp_ctrl >= 0) { close(g_udp_ctrl); g_udp_ctrl = -1; }
	if (g_udp_fd >= 0) { close(g_udp_fd); g_udp_fd = -1; }
	g_dtable = -1;
}

/* ---- 运行时接管：需要接管的挂载点清单（目前只有 connect4） ---- */
#define TAKEOVER_F BASE_DIR "/takeover.conf"
static const struct { const char *name; int type; } HOOKS[] = {
	{ "inet4_connect", BPF_CGROUP_INET4_CONNECT },
};
#define NHOOKS ((int)(sizeof(HOOKS) / sizeof(HOOKS[0])))
static int type_by_name(const char *nm);
static int take_over_hook(int cg, const char *name, int type);
static int restore_hooks(int cg, int verbose);

/* 打开并加载 BPF 对象。with_tc=0 时不加载 TC 程序（用于 TC 加载失败后的退回）。 */
static struct bpf_object *open_and_load(int with_tc)
{
	struct bpf_object *o = bpf_object__open_file(BPFOBJ_F, NULL);
	long e = libbpf_get_error(o);
	if (e) { fprintf(stderr, "open %s: %s\n", BPFOBJ_F, strerror(-e)); return NULL; }

	struct bpf_map *m;
	bpf_object__for_each_map(m, o) {
		char pbuf[128];
		snprintf(pbuf, sizeof(pbuf), "%s/%s", PIN_DIR, bpf_map__name(m));
		bpf_map__set_pin_path(m, pbuf);
	}
	if (!with_tc) {
		struct bpf_program *tp = bpf_object__find_program_by_name(o, "steer_tc_egress");
		if (tp) bpf_program__set_autoload(tp, false);
	}
	if (bpf_object__load(o)) {
		logmsg("BPF 加载失败（with_tc=%d）", with_tc);
		bpf_object__close(o);
		return NULL;
	}
	return o;
}

static int cmd_daemon(void)
{
	mkdirs();
	cfg_load();
	raise_fds();
	raise_memlock();
	libbpf_set_print(libbpf_log);

	/* ★ 构建戳校验：二进制与 bpf 对象必须是同一次构建 */
	{
		char want[128] = "(无)";
		FILE *sf = fopen(BASE_DIR "/steer.stamp", "r");
		if (sf) { if (!fgets(want, sizeof(want), sf)) want[0] = 0; fclose(sf); want[strcspn(want, "\r\n")] = 0; }
		if (strcmp(want, STEER_STAMP) != 0) {
			logmsg("!!!! 构建戳不一致：");
			logmsg("     二进制内 = %s", STEER_STAMP);
			logmsg("     对象文件 = %s", want[0] ? want : "(缺失)");
			logmsg("     => 二进制与 .o 不是同一次构建！行为可能异常。请重新安装模块。");
			fprintf(stderr, "!! 构建戳不一致（二进制 vs .o），请重装模块\n");
		}
	}

	/* ---- 单实例：flock 拿不到 = 已有活着的守护，直接退出（不报错）---- */
	int nlink = 0;          /* 必须在这里声明：后面的 goto fail 会跨过它 */
	int cg = -1;

	int lk = open(LOCK_F, O_CREAT | O_RDWR, 0600);
	if (lk < 0) { fprintf(stderr, "open %s: %s\n", LOCK_F, strerror(errno)); return 1; }
	if (flock(lk, LOCK_EX | LOCK_NB) != 0) {
		fprintf(stderr, "steer: 已有实例在运行，本次不启动\n");
		close(lk);
		return 0;
	}
	if (ftruncate(lk, 0) == 0)
		(void)!dprintf(lk, "%d\n", getpid());

	cleanup_pins();          /* 上个实例即使被 SIGKILL，pin 也清掉重建 */

	/* 两遍加载：先带上 TC（UDP）。若 TC 程序被 verifier 拒，**退回只做 TCP**，
	 * 绝不让 UDP 的问题把整个 daemon（连 TCP）一起拖死。 */
	struct bpf_object *obj = open_and_load(G.udp_on ? 1 : 0);
	if (!obj && G.udp_on) {
		logmsg("!! 带 TC 的 BPF 对象加载失败 —— 退回『只做 TCP』（TCP 不受影响）");
		G.udp_on = 0;
		logmsg("   看上面的 verifier 日志定位 TC 程序的问题；`steer cfg set udp 1` 可再试");
		obj = open_and_load(0);
	}
	if (!obj) {
		fprintf(stderr, "load bpf failed\n");
		logmsg("!!! BPF 加载失败（连 TCP 也起不来），常见原因：");
		logmsg("  1) SELinux 拒绝 bpf() —— 需给 su 域补 allow 规则");
		logmsg("  2) 缺 CAP_BPF/CAP_SYS_ADMIN —— 确认用的是 KernelSU 的 root");
		logmsg("  3) RLIMIT_MEMLOCK 太小（上面已尝试抬高）");
		logmsg("  4) 内核未开 CONFIG_BPF_SYSCALL");
		return 1;
	}
	struct bpf_map *m;

	if (cfg_seed(obj)) {
		fprintf(stderr, "写入初始 cfg 失败: %s\n", strerror(errno));
		goto fail;
	}

	mkdir(PIN_DIR, 0700);
	bpf_object__for_each_map(m, obj) {
		int r = bpf_map__pin(m, NULL);
		if (r && r != -EEXIST) logmsg("pin %s: %s", bpf_map__name(m), strerror(-r));
	}

	cg = open(CGROUP_F, O_RDONLY | O_DIRECTORY);
	if (cg < 0) { fprintf(stderr, "open %s: %s\n", CGROUP_F, strerror(errno)); return 1; }

	const char *pn[3] = { "steer_connect4", "steer_getpeername4", "steer_sockops" };

	/* 上次异常退出可能留下"平台程序仍被摘下"的状态 —— 先自愈还原 */
	if (access(TAKEOVER_F, F_OK) == 0) {
		logmsg("检测到上次遗留的接管记录，先还原平台程序");
		restore_hooks(cg, 0);
	}

	/* 把占用该挂载点的平台程序"请走"（仅当它非 MULTI 独占时） */
	if (G.takeover) {
		for (int i = 0; i < NHOOKS; i++)
			take_over_hook(cg, HOOKS[i].name, HOOKS[i].type);
	} else {
		logmsg("takeover=0：不接管平台挂载点（若被独占，attach 必然失败）");
	}

	/* ---- 只用 bpf_link ----
	 * link 随进程退出（含 SIGKILL/OOM）由内核自动解绑 ⇒"守护没了就立刻恢复原状"。
	 * 若内核不支持 cgroup link，我们**宁可整个不工作**，也绝不退回 legacy attach
	 * （legacy attach 会在进程死后残留挂载，把 app 断网到重启）。 */
	for (int i = 0; i < 3; i++) {
		struct bpf_program *p = bpf_object__find_program_by_name(obj, pn[i]);
		if (!p) { fprintf(stderr, "prog %s 不存在\n", pn[i]); goto fail; }
		struct bpf_link *ln = bpf_program__attach_cgroup(p, cg);
		long le = libbpf_get_error(ln);
		if (le == -EPERM) {
			fprintf(stderr, "attach %s 失败: Operation not permitted\n", pn[i]);
			logmsg("attach %s 失败 EPERM：该 cgroup 挂载点很可能已被别的程序"
			       "以「非 BPF_F_ALLOW_MULTI」方式独占（内核 cgroup.c:657/664），"
			       "此时任何新程序都挂不上，子 cgroup 也不行", pn[i]);
			logmsg("  常见占用者：其它 eBPF 转发模块（如 gacboost_steering）。"
			       "请先禁用它们再重启本服务");
			logmsg("  运行 `steer probe` 可看到每个挂载点被谁占用");
			goto fail;
		}
		if (le) {
			fprintf(stderr, "attach %s 失败: %s\n", pn[i], strerror((int)-le));
			logmsg("attach %s 失败(%s)", pn[i], strerror((int)-le));
			goto fail;
		}
		g_link[nlink++] = ln;
		logmsg("attached %s (bpf_link)", pn[i]);
	}
	/* ---- TC 挂载（UDP）---- */
	g_tc_fd = -1;
	if (G.udp_on) {
		struct bpf_program *tp = bpf_object__find_program_by_name(obj, "steer_tc_egress");
		if (!tp) {
			logmsg("找不到 steer_tc_egress，UDP 接管关闭");
		} else {
			int loidx = (int)if_nametoindex("lo");
			if (!loidx) {
				logmsg("取 lo ifindex 失败，UDP 接管关闭");
			} else {
				cfg_set_lo_index(loidx);
				/* 先清掉上次崩溃/卸载残留的过滤器，再挂 */
				{
					int leftover = tc_detach_all(0);
					if (leftover) logmsg("tc: 清掉了 %d 个残留过滤器", leftover);
				}
				g_tc_fd = bpf_program__fd(tp);
				tc_attach_devs(g_tc_fd);
				logmsg("udp: TC 已挂到 %d 个接口（lo=%d redir_flags=%d）",
				       g_ntc, loidx, G.redir_flags);
				g_dmap = map_fd("dmap");
				g_dtable = map_fd("dtable");
				g_udp_fd = udp_open();
				if (g_udp_fd < 0) {
					logmsg("udp: 中继监听失败，UDP 接管关闭");
					G.udp_on = 0;
					cfg_patch(-1, -1);
					tc_detach_all(0);
				} else {
					pthread_t ut;
					if (pthread_create(&ut, NULL, udp_thread, NULL) == 0) pthread_detach(ut);
					else { logmsg("udp: 中继线程创建失败"); G.udp_on = 0; }
				}
			}
		}
	}

	/* 保留 cg 句柄：退出时要用它把平台程序挂回去 */

	/* 关键：必须先把分应用策略读进内存，再下发到内核。
	 * policy_push() 会"清空内核表 → 按内存重建"，内存没读就是清空！ */
	policy_load();
	policy_push();
	logmsg("policy: 已下发 %d 条分应用策略到内核", ELN);

	g_rmap = map_fd("rstats");   /* 中继计数用 */

	int lfd = relay_listen();
	if (lfd < 0) {
		/* 监听失败绝不 arm —— 全部流量保持直连 */
		logmsg("中继监听失败，不 arm，流量保持直连");
		goto fail;
	}
	cfg_patch(1, -1);
	logmsg("ARMED default=%s relay=127.0.0.1:%d socks=%s:%d flags=%d",
	       mode_name(G.default_mode), G.relay_port, G.socks_host, G.socks_port, G.flags);

	for (int i = 0; i < MAX_SLOT; i++) g_slot_fd[i] = -1;

	FILE *pf = fopen(PID_F, "w");
	if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); }

	hb_write();
	g_hb_ts = time(NULL);
	g_alog = open(LOG_F, O_WRONLY | O_CREAT | O_APPEND, 0600);
	logmsg("=== steer %s 启动（pid %d）===", STEER_VERSION, getpid());
	install_sigs();
	relay_loop(lfd);
	unlink(HB_F);

	cfg_patch(0, -1);
	logmsg("DISARMED，正常退出");
	if (G.udp_on) { tc_detach_all(0); udp_shutdown(); }
	detach_links(nlink);
	restore_hooks(cg, 0);     /* 把平台的程序原样装回去 */
	cleanup_pins();
	if (cg >= 0) close(cg);
	unlink(PID_F);
	return 0;

fail:
	cfg_patch(0, -1);
	if (G.udp_on) { tc_detach_all(0); udp_shutdown(); }
	detach_links(nlink);
	restore_hooks(cg, 0);     /* 失败也要把平台的程序装回去 */
	cleanup_pins();
	if (cg >= 0) close(cg);
	unlink(PID_F);
	return 1;
}

/* ---------------------------------------------------------------- CLI */

/* 直接读内核里的策略表 —— 用来确认"下发到底成没成" */
static int cmd_policymap(int json)
{
	int fd = map_fd("policy");
	if (fd < 0) {
		if (json) printf("{\"running\":false}\n");
		else printf("服务未在运行，内核里没有策略表\n");
		return 1;
	}
	uint32_t key, next;
	int n = 0, r;
	if (json) printf("[");
	r = bpf_map_get_next_key(fd, NULL, &key);
	while (r == 0) {
		uint8_t v = 0;
		if (!bpf_map_lookup_elem(fd, &key, &v)) {
			if (json) printf("%s{\"uid\":%u,\"mode\":%d}", n ? "," : "", key, v);
			else printf("%-8u %s\n", key, mode_name(v));
			n++;
		}
		r = bpf_map_get_next_key(fd, &key, &next);
		key = next;
	}
	if (json) printf("]\n");
	close(fd);
	if (!json) printf("内核里共 %d 条\n", n);
	return 0;
}

static int cmd_list(int json)
{
	policy_load();
	if (json) {
		printf("[");
		for (int i = 0; i < ELN; i++)
			printf("%s{\"uid\":%u,\"mode\":%d,\"pkg\":\"%s\"}",
			       i ? "," : "", EL[i].uid, EL[i].mode, EL[i].pkg);
		printf("]\n");
	} else {
		for (int i = 0; i < ELN; i++)
			printf("%-8u %-7s %s\n", EL[i].uid, mode_name(EL[i].mode), EL[i].pkg);
	}
	return 0;
}

static int entry_find(uint32_t uid, const char *pkg)
{
	for (int i = 0; i < ELN; i++)
		if (EL[i].uid == uid || (pkg && pkg[0] && !strcmp(EL[i].pkg, pkg)))
			return i;
	return -1;
}

static int cmd_set(const char *what, const char *mode_s)
{
	int mode = mode_from(mode_s);
	if (mode < 0) { fprintf(stderr, "mode 必须是 direct|proxy|block\n"); return 1; }
	uint32_t uid;
	if (resolve_uid(what, &uid)) { fprintf(stderr, "找不到: %s\n", what); return 1; }

	policy_load();
	int i = entry_find(uid, is_all_digits(what) ? NULL : what);
	if (i < 0) {
		if (ELN >= 1024) { fprintf(stderr, "策略表已满\n"); return 1; }
		i = ELN++;
		EL[i].uid = uid;
		EL[i].pkg[0] = 0;
	}
	EL[i].mode = mode;
	if (!is_all_digits(what)) strncpy(EL[i].pkg, what, 127);
	policy_save();
	policy_push();
	printf("%u -> %s\n", uid, mode_name(mode));
	return 0;
}

static int cmd_del(const char *what)
{
	uint32_t uid;
	if (resolve_uid(what, &uid)) { fprintf(stderr, "找不到: %s\n", what); return 1; }
	policy_load();
	int i = entry_find(uid, is_all_digits(what) ? NULL : what);
	if (i < 0) { fprintf(stderr, "没有这项策略\n"); return 1; }
	for (int j = i; j < ELN - 1; j++) EL[j] = EL[j + 1];
	ELN--;
	policy_save();

	int fd = map_fd("policy");
	if (fd >= 0) { bpf_map_delete_elem(fd, &uid); close(fd); }
	printf("%u deleted\n", uid);   /* 前缀给 uid，便于调用方解析 */
	return 0;
}

static int cmd_default(const char *mode_s)
{
	int mode = mode_from(mode_s);
	if (mode < 0) { fprintf(stderr, "mode 必须是 direct|proxy|block\n"); return 1; }
	cfg_load();
	G.default_mode = mode;
	cfg_save();

	cfg_patch(-1, -1);      /* 只同步 default_mode，armed/enabled 原样保留 */
	printf("default -> %s\n", mode_name(mode));
	return 0;
}

/* 总开关：off = 全部直连（策略表原样保留，随时可切回） */
static int cmd_switch(const char *s)
{
	int on;
	if (!strcmp(s, "on") || !strcmp(s, "1") || !strcmp(s, "enable") || !strcmp(s, "true"))
		on = 1;
	else if (!strcmp(s, "off") || !strcmp(s, "0") || !strcmp(s, "disable") || !strcmp(s, "false"))
		on = 0;
	else { fprintf(stderr, "用法: steer switch on|off\n"); return 1; }

	cfg_load();
	G.enabled = on;
	cfg_save();
	cfg_patch(-1, on);
	printf("steer %s\n", on ? "已开启" : "已关闭（全部直连）");

	/* 打开开关时，若服务没在跑就顺手拉起来 —— 否则用户会以为“开了却没用” */
	if (on && !daemon_running()) {
		printf("检测到服务未运行，正在启动…\n");
		cmd_restart();
	}
	return 0;
}

static int cmd_stats(int json)
{
	int fd = map_fd("stats");
	if (fd < 0) {
		if (json) printf("{\"running\":false}\n");
		else printf("daemon 未运行\n");
		return 1;
	}
	uint32_t k = 0;
	struct stats_t s = {0};
	struct rstats_t r = {0};
	int have_r = 0;
	bpf_map_lookup_elem(fd, &k, &s);
	close(fd);
	int rfd = map_fd("rstats");
	if (rfd >= 0) { have_r = !bpf_map_lookup_elem(rfd, &k, &r); close(rfd); }

	if (json) {
		printf("{\"running\":true,"
		       "\"direct\":%llu,\"proxied\":%llu,\"blocked\":%llu,\"failed\":%llu,"
		       "\"relay\":{\"ok\":%llu,\"miss\":%llu,\"socksfail\":%llu,"
		       "\"active\":%llu,\"bytes_up\":%llu,\"bytes_down\":%llu},"
		       "\"udp\":{\"direct\":%llu,\"proxied\":%llu,\"blocked\":%llu,\"failed\":%llu}}\n",
		       (unsigned long long)s.direct, (unsigned long long)s.proxied,
		       (unsigned long long)s.blocked, (unsigned long long)s.failed,
		       (unsigned long long)r.ok, (unsigned long long)r.miss,
		       (unsigned long long)r.socksfail, (unsigned long long)r.active,
		       (unsigned long long)r.bytes_up, (unsigned long long)r.bytes_down,
		       (unsigned long long)s.udp_direct, (unsigned long long)s.udp_proxied,
		       (unsigned long long)s.udp_blocked, (unsigned long long)s.udp_failed);
	} else {
		printf("kern : direct=%llu proxied=%llu blocked=%llu failed=%llu\n",
		       (unsigned long long)s.direct, (unsigned long long)s.proxied,
		       (unsigned long long)s.blocked, (unsigned long long)s.failed);
		printf("udp  : direct=%llu proxied=%llu blocked=%llu failed=%llu\n",
		       (unsigned long long)s.udp_direct, (unsigned long long)s.udp_proxied,
		       (unsigned long long)s.udp_blocked, (unsigned long long)s.udp_failed);
		if (have_r)
			printf("relay: ok=%llu miss=%llu socksfail=%llu active=%llu "
			       "up=%.1fKB down=%.1fKB\n",
			       (unsigned long long)r.ok, (unsigned long long)r.miss,
			       (unsigned long long)r.socksfail, (unsigned long long)r.active,
			       r.bytes_up / 1024.0, r.bytes_down / 1024.0);
	}
	return 0;
}

static int cmd_status(int json)
{
	cfg_load();
	policy_load();
	int running = map_fd("policy") >= 0;
	if (json)
		printf("{\"running\":%s,\"hb_age\":%ld,\"enabled\":%s,\"default\":\"%s\",\"relay_port\":%d,"
		       "\"socks\":\"%s:%d\",\"entries\":%d,\"flags\":%d}\n",
		       running ? "true" : "false", hb_age(), G.enabled ? "true" : "false",
		       mode_name(G.default_mode),
		       G.relay_port, G.socks_host, G.socks_port, ELN, G.flags);
	else
		printf("running=%s enabled=%s default=%s relay=127.0.0.1:%d socks=%s:%d entries=%d\n",
		       running ? "yes" : "no", G.enabled ? "yes" : "no",
		       mode_name(G.default_mode),
		       G.relay_port, G.socks_host, G.socks_port, ELN);
	return 0;
}

/* ---------------- 运行时接管（摘掉占位者 / 用完装回） ----------------
 *
 * 背景：Android 平台自己的 netd.o 会在开机时把 cgroup/connect4 等挂载点
 * 以 flags=0（非 MULTI = 独占）挂上，导致任何新程序都挂不进去（内核 cgroup.c:657/664）。
 * 而它的 bpfloader 只在 load-bpf-programs 那一次挂载，跑完就不再管。
 *
 * 所以正确做法不是"开机抢位"（抢位会让 bpfloader 失败 → netd/系统崩溃 → 变砖），
 * 而是**开机完成后**把平台那个先摘下来、pin 住，再挂上我们的；停止时原样装回。
 */

static int type_by_name(const char *nm)
{
	for (int i = 0; i < NHOOKS; i++)
		if (!strcmp(HOOKS[i].name, nm)) return HOOKS[i].type;
	return -1;
}

/* 在 /sys/fs/bpf 下找这个 prog 的既有 pin（AOSP 自己会 pin，优先用它，
 * 这样即使我们被强杀，也能靠它把平台程序挂回去） */
static int check_pin(const char *path, __u32 want, char *out, size_t outlen)
{
	int fd = bpf_obj_get(path);
	if (fd < 0) return 0;
	struct bpf_prog_info info;
	__u32 len = sizeof(info);
	memset(&info, 0, sizeof(info));
	int hit = 0;
	if (!bpf_prog_get_info_by_fd(fd, &info, &len) && info.id == want) {
		snprintf(out, outlen, "%.300s", path);
		hit = 1;
	}
	close(fd);
	return hit;
}

/* 在 /sys/fs/bpf 下（含一层子目录）找这个 prog 的既有 pin。
 * AOSP 自己会 pin（bpffs 的 prog_* 条目），优先用它 ——
 * 这样即使我们被强杀，也能靠它把平台程序挂回去。 */
static int find_pin_for_prog(__u32 want, char *out, size_t outlen)
{
	DIR *top = opendir("/sys/fs/bpf");
	if (!top) return -1;
	struct dirent *e;
	int found = -1, scanned = 0;
	while ((e = readdir(top)) && found < 0 && scanned < 4096) {
		if (e->d_name[0] == '.') continue;
		char p1[320];
		snprintf(p1, sizeof(p1), "/sys/fs/bpf/%.120s", e->d_name);
		struct stat sb;
		if (stat(p1, &sb) == 0 && S_ISDIR(sb.st_mode)) {
			DIR *sub = opendir(p1);
			if (!sub) continue;
			struct dirent *sd;
			while ((sd = readdir(sub)) && found < 0 && scanned < 4096) {
				if (sd->d_name[0] == '.') continue;
				char p2[640];
				snprintf(p2, sizeof(p2), "%.300s/%.120s", p1, sd->d_name);
				scanned++;
				if (check_pin(p2, want, out, outlen)) found = 0;
			}
			closedir(sub);
		} else {
			scanned++;
			if (check_pin(p1, want, out, outlen)) found = 0;
		}
	}
	closedir(top);
	return found;
}

/* 摘掉该挂载点上的占位者；成功返回 1（表示需要还原），无需摘返回 0，出错 -1 */
static int take_over_hook(int cg, const char *name, int type)
{
	__u32 cnt = 8, flags = 0, ids[8];
	if (bpf_prog_query(cg, type, 0, &flags, ids, &cnt)) {
		logmsg("takeover[%s]: query 失败(%s)，按空闲处理", name, strerror(errno));
		return 0;
	}
	if (!cnt) return 0;
	if (flags & BPF_F_ALLOW_MULTI) {
		logmsg("takeover[%s]: 现挂载为 ALLOW_MULTI，可共存，无需摘", name);
		return 0;
	}

	int did = 0;
	for (__u32 i = 0; i < cnt; i++) {
		int fd = bpf_prog_get_fd_by_id(ids[i]);
		if (fd < 0) { logmsg("takeover[%s]: 取 prog %u fd 失败: %s", name, ids[i], strerror(errno)); continue; }

		char pin[640];
		if (find_pin_for_prog(ids[i], pin, sizeof(pin))) {
			/* 平台没 pin（少见）：我们自己 pin 一份，保证能还原 */
			snprintf(pin, sizeof(pin), "%s/takeover_%s_%u", PIN_DIR, name, ids[i]);
			if (bpf_obj_pin(fd, pin)) {
				logmsg("takeover[%s]: 自行 pin 也失败(%s)，将只做摘除", name, strerror(errno));
				pin[0] = 0;
			}
		}

		if (bpf_prog_detach2(fd, cg, type)) {
			logmsg("takeover[%s]: 摘除 prog %u 失败: %s", name, ids[i], strerror(errno));
		} else {
			logmsg("takeover[%s]: 已摘下平台程序 prog %u（还原句柄: %s）", name, ids[i], pin[0] ? pin : "(无)");
			FILE *m = fopen(TAKEOVER_F, "a");
			if (m) { fprintf(m, "%s 0x%x %s\n", name, flags, pin[0] ? pin : "-"); fclose(m); }
			did = 1;
		}
		close(fd);
	}
	return did;
}

/* 把之前摘下来的平台程序挂回去 */
static int restore_hooks(int cg, int verbose)
{
	FILE *f = fopen(TAKEOVER_F, "r");
	if (!f) return 0;
	char line[1024];
	int n = 0;
	while (fgets(line, sizeof(line), f)) {
		char hook[64], pin[640];
		unsigned flags = 0;
		if (sscanf(line, "%63s %x %639s", hook, &flags, pin) != 3) continue;
		int type = type_by_name(hook);
		if (type < 0) continue;
		if (!strcmp(pin, "-")) { logmsg("restore[%s]: 当时未能保存句柄，无法还原（下次重启平台会自行挂回）", hook); continue; }

		int fd = bpf_obj_get(pin);
		if (fd < 0) { logmsg("restore[%s]: 打开 %s 失败: %s", hook, pin, strerror(errno)); continue; }
		if (bpf_prog_attach(fd, cg, type, flags))
			logmsg("restore[%s]: 挂回失败: %s", hook, strerror(errno));
		else {
			logmsg("restore[%s]: 已把平台程序挂回（flags=0x%x）", hook, flags);
			if (verbose) printf("  已还原 %s\n", hook);
			n++;
		}
		close(fd);
	}
	fclose(f);
	unlink(TAKEOVER_F);
	return n;
}

static int cmd_tcclean(void)
{
	int n = tc_detach_all(1);
	printf("已卸载 %d 个 TC 过滤器\n", n);
	return 0;
}

static int cmd_restore(void)
{
	int cg = open(CGROUP_F, O_RDONLY | O_DIRECTORY);
	if (cg < 0) { fprintf(stderr, "open %s: %s\n", CGROUP_F, strerror(errno)); return 1; }
	int n = restore_hooks(cg, 1);
	close(cg);
	printf("还原 %d 个挂载点\n", n);
	return 0;
}

/* ---------------- cgroup BPF 占用探查 ----------------
 * attach 返回 EPERM 时（内核 kernel/bpf/cgroup.c:657/664）说明该挂载点
 * 已被别人以「非 BPF_F_ALLOW_MULTI」方式独占 —— 此时谁也别想再挂。
 * 用 bpf_prog_query 把每个挂载点的现状打出来。 */

struct owner { __u32 id; int pid; char cmd[64]; };
static const struct owner *owner_of(__u32 id);

static double uptime_sec(void);

/* prog id -> 名字/tag/加载者 uid/加载时刻：认领占位者的关键 */
static void prog_info(__u32 id)
{
	int fd = bpf_prog_get_fd_by_id(id);
	if (fd < 0) { printf("        prog %-4u : 取 fd 失败 (%s)\n", id, strerror(errno)); return; }
	struct bpf_prog_info info;
	__u32 len = sizeof(info);
	memset(&info, 0, sizeof(info));
	if (bpf_prog_get_info_by_fd(fd, &info, &len)) {
		printf("        prog %-4u : 取信息失败 (%s)\n", id, strerror(errno));
		close(fd);
		return;
	}
	close(fd);

	char nm[17];
	memcpy(nm, info.name, 16);
	nm[16] = 0;
	for (int i = 0; i < 16; i++)
		if (nm[i] && (nm[i] < 32 || nm[i] > 126)) nm[i] = '?';

	char tag[20];
	for (int i = 0; i < 8; i++) snprintf(tag + i * 2, 3, "%02x", info.tag[i]);

	printf("        prog %-4u name=\"%s\" tag=%s type=%u 加载者uid=%u 于 %.0f 秒前\n",
	       id, nm, tag, info.type, info.created_by_uid,
	       info.load_time ? (uptime_sec() - (double)info.load_time / 1e9) : -1.0);
}

static void probe_one(int cg, const char *name, int type)
{
	__u32 cnt = 64, flags = 0, ids[64];
	int r = bpf_prog_query(cg, type, 0, &flags, ids, &cnt);
	if (r) {
		printf("  %-26s : 查询失败 %s\n", name, strerror(errno));
		return;
	}
	if (!cnt && !flags) {
		printf("  %-26s : 空闲\n", name);
		return;
	}
	printf("  %-26s : %u 个 prog, flags=0x%x %s\n", name, cnt, flags,
	       (flags & BPF_F_ALLOW_MULTI) ? "(ALLOW_MULTI)" : "★非MULTI=独占，别人挂不上");
	if (cnt) {
		printf("      prog ids:");
		for (__u32 i = 0; i < cnt && i < 8; i++) printf(" %u", ids[i]);
		printf("\n");
		for (__u32 i = 0; i < cnt && i < 8; i++) {
			const struct owner *o = owner_of(ids[i]);
			if (o) printf("        prog %u ← 现由 pid %d 持有  %s\n", ids[i], o->pid, o->cmd);
			else  printf("        prog %u ← 无进程持有（加载器已退出，程序仍挂着）\n", ids[i]);
			prog_info(ids[i]);
		}
	}
}

/* 扫一遍每个进程的 fdinfo，把 prog_id 映射到进程，用来点名"谁占着挂载点" */
static struct owner g_own[256];
static int g_nowner;

static void scan_prog_owners(void)
{
	DIR *p = opendir("/proc");
	if (!p) return;
	struct dirent *pe;
	while ((pe = readdir(p)) && g_nowner < 256) {
		if (pe->d_name[0] < '0' || pe->d_name[0] > '9') continue;
		char fdd[320];
		snprintf(fdd, sizeof(fdd), "/proc/%s/fdinfo", pe->d_name);
		DIR *f = opendir(fdd);
		if (!f) continue;
		struct dirent *fe;
		while ((fe = readdir(f)) && g_nowner < 256) {
			if (fe->d_name[0] == '.') continue;
			char fp[768];
			snprintf(fp, sizeof(fp), "%s/%s", fdd, fe->d_name);
			int fd2 = open(fp, O_RDONLY | O_CLOEXEC);
			if (fd2 < 0) continue;
			char buf[1024];
			ssize_t n = read(fd2, buf, sizeof(buf) - 1);
			close(fd2);
			if (n <= 0) continue;
			buf[n] = 0;
			char *q = strstr(buf, "prog_id:");
			if (!q) continue;
			unsigned id = 0;
			if (sscanf(q + 8, "%u", &id) != 1 || !id) continue;

			g_own[g_nowner].id = id;
			g_own[g_nowner].pid = atoi(pe->d_name);
			g_own[g_nowner].cmd[0] = 0;
			char cp[320];
			snprintf(cp, sizeof(cp), "/proc/%s/cmdline", pe->d_name);
			int cf = open(cp, O_RDONLY | O_CLOEXEC);
			if (cf >= 0) {
				ssize_t m = read(cf, g_own[g_nowner].cmd, sizeof(g_own[g_nowner].cmd) - 1);
				close(cf);
				if (m > 0) {
					g_own[g_nowner].cmd[m] = 0;
					for (ssize_t k = 0; k < m; k++)
						if (g_own[g_nowner].cmd[k] == 0) g_own[g_nowner].cmd[k] = ' ';
				}
			}
			g_nowner++;
		}
		closedir(f);
	}
	closedir(p);
}

static const struct owner *owner_of(__u32 id)
{
	for (int i = 0; i < g_nowner; i++)
		if (g_own[i].id == id) return &g_own[i];
	return NULL;
}

static double uptime_sec(void)
{
	FILE *f = fopen("/proc/uptime", "r");
	double v = 0;
	if (f) { if (fscanf(f, "%lf", &v) != 1) v = 0; fclose(f); }
	return v;
}

static int cmd_probe(void)
{
	int cg = open(CGROUP_F, O_RDONLY | O_DIRECTORY);
	if (cg < 0) { fprintf(stderr, "open %s: %s\n", CGROUP_F, strerror(errno)); return 1; }

	printf("== cgroup BPF 挂载点占用 (%s) ==\n", CGROUP_F);
	scan_prog_owners();
	static const struct { const char *n; int t; } tab[] = {
		{ "cgroup_inet_ingress",       BPF_CGROUP_INET_INGRESS },
		{ "cgroup_inet_egress",        BPF_CGROUP_INET_EGRESS },
		{ "cgroup_inet_sock_create",   BPF_CGROUP_INET_SOCK_CREATE },
		{ "cgroup_inet_sock_release",  BPF_CGROUP_INET_SOCK_RELEASE },
		{ "cgroup_inet4_bind",         BPF_CGROUP_INET4_BIND },
		{ "cgroup_inet6_bind",         BPF_CGROUP_INET6_BIND },
		{ "cgroup_inet4_connect",      BPF_CGROUP_INET4_CONNECT },
		{ "cgroup_inet6_connect",      BPF_CGROUP_INET6_CONNECT },
		{ "cgroup_inet4_getpeername",  BPF_CGROUP_INET4_GETPEERNAME },
		{ "cgroup_inet6_getpeername",  BPF_CGROUP_INET6_GETPEERNAME },
		{ "cgroup_inet4_getsockname",  BPF_CGROUP_INET4_GETSOCKNAME },
		{ "cgroup_udp4_sendmsg",       BPF_CGROUP_UDP4_SENDMSG },
		{ "cgroup_udp4_recvmsg",       BPF_CGROUP_UDP4_RECVMSG },
		{ "cgroup_sock_ops",           BPF_CGROUP_SOCK_OPS },
	};
	for (unsigned i = 0; i < sizeof(tab) / sizeof(tab[0]); i++)
		probe_one(cg, tab[i].n, tab[i].t);
	close(cg);

	/* 顺便看看 /sys/fs/bpf 下还有谁在 pin —— 其它 eBPF 工具的常见痕迹 */
	printf("\n== /sys/fs/bpf 下的 pin（一层）==\n");
	DIR *d = opendir("/sys/fs/bpf");
	if (d) {
		struct dirent *e;
		int n = 0;
		while ((e = readdir(d))) {
			if (e->d_name[0] == '.') continue;
			printf("  %s\n", e->d_name);
			n++;
		}
		closedir(d);
		if (!n) printf("  (空)\n");
	} else {
		printf("  打不开: %s\n", strerror(errno));
	}
	return 0;
}

/* ---------------- 启停 / 诊断 ---------------- */

static int cmd_stop(void)
{
	FILE *f = fopen(PID_F, "r");
	int pid = 0;
	if (f) { if (fscanf(f, "%d", &pid) != 1) pid = 0; fclose(f); }
	if (pid > 1) { kill(pid, SIGTERM); printf("已请求停止 (pid %d)\n", pid); }
	else printf("服务未在运行\n");
	return 0;
}

static int cmd_start(void)
{
	if (daemon_running()) { printf("服务已在运行\n"); return 0; }
	return cmd_restart();
}

static void tail_file(const char *path, int nlines, const char *title)
{
	printf("\n---- %s (%s) ----\n", title, path);
	FILE *f = fopen(path, "r");
	if (!f) { printf("(无此文件)\n"); return; }
	long cap = 65536;
	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); printf("(读不了)\n"); return; }
	long sz = ftell(f);
	long start = sz > cap ? sz - cap : 0;
	fseek(f, start, SEEK_SET);
	char *buf = malloc(cap + 1);
	if (!buf) { fclose(f); return; }
	size_t got = fread(buf, 1, cap, f);
	buf[got] = 0;
	fclose(f);
	long i; int cnt = 0;
	for (i = (long)got - 1; i >= 0; i--)
		if (buf[i] == '\n' && ++cnt > nlines) break;
	if (got == 0) printf("(空)\n");
	else fputs(buf + (i < 0 ? 0 : i + 1), stdout);
	free(buf);
}

static int cmd_diag(void)
{
	cfg_load();
	struct rlimit rl;
	struct stat sb;

	printf("== steer 诊断 ==\n");
	printf("bin        : %s\n", BASE_DIR "/steer");
	printf("bpf obj    : %s (%s)\n", BPFOBJ_F, stat(BPFOBJ_F, &sb) == 0 ? "存在" : "缺失");
	{
		long hb = hb_age();
		printf("build      : %s\n", STEER_STAMP);
		printf("daemon     : %s\n", daemon_running() ? "running" : "NOT running");
		printf("UDP(TC)    : %s  已挂接口=%d  udp_port=%d  redir_flags=%d\n",
		       G.udp_on ? "开启" : "关闭", g_ntc, G.relay_udp_port, G.redir_flags);
		int dfd = map_fd("dbgmap");
		if (dfd >= 0) {
			uint32_t dk = 0;
			struct dbg_t dv;
			if (!bpf_map_lookup_elem(dfd, &dk, &dv))
				printf("TC 探针    : 进入=%llu  proxy=%llu direct=%llu 无uid=%llu\n"
				       "             最近uid=%llu  最近prio=%llu  最近mark=0x%llx\n"
				       "             最近proxy_uid=%llu  最近direct_uid=%llu\n",
				       (unsigned long long)dv.calls, (unsigned long long)dv.n_proxy,
				       (unsigned long long)dv.n_direct, (unsigned long long)dv.n_nouid,
				       (unsigned long long)dv.last_uid,
				       (unsigned long long)dv.last_prio,
				       (unsigned long long)dv.last_mark,
				       (unsigned long long)dv.last_proxy_uid,
				       (unsigned long long)dv.last_direct_uid);
			/* TC 看到的 uid 分布（遍历 uidtop） */
			printf("             TC 看到的 uid 分布:");
			int ufd = map_fd("uidtop");
			if (ufd >= 0) {
				uint32_t uk, un;
				int shown = 0, r = bpf_map_get_next_key(ufd, NULL, &uk);
				while (r == 0 && shown < 12) {
					uint64_t c = 0;
					if (!bpf_map_lookup_elem(ufd, &uk, &c))
						printf("  %u×%llu", uk, (unsigned long long)c);
					shown++;
					r = bpf_map_get_next_key(ufd, &uk, &un);
					uk = un;
				}
				close(ufd);
			}
			printf("\n");
			{
				struct in_addr a1; a1.s_addr = (in_addr_t)dv.last_daddr;
				struct in_addr a2; a2.s_addr = (in_addr_t)dv.lastp_daddr;
				printf("             退出原因: 回环跳过=%llu 私网跳过=%llu 已改写=%llu\n",
				       (unsigned long long)dv.n_loopback, (unsigned long long)dv.n_privskip,
				       (unsigned long long)dv.n_rewrite);
				printf("             最近目的=%s:%u   最近proxy目的=%s:%u\n",
				       inet_ntoa(a1), ntohs((uint16_t)dv.last_dport),
				       inet_ntoa(a2), ntohs((uint16_t)dv.lastp_dport));
			}
			close(dfd);
		}
		if (hb < 0)        printf("accept 循环 : 无心跳（守护从未起来 / 已退出）\n");
		else if (hb > HB_MAX_AGE) printf("accept 循环 : ★卡住★（%ld 秒无心跳，>%d 秒）\n", hb, HB_MAX_AGE);
		else               printf("accept 循环 : 正常（%ld 秒前心跳）\n", hb);
	}

	if (!getrlimit(RLIMIT_NOFILE, &rl))
		printf("nofile     : %llu / %llu\n",
		       (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);
	if (!getrlimit(RLIMIT_MEMLOCK, &rl))
		printf("memlock    : %llu / %llu\n",
		       (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);

	FILE *st = fopen("/proc/self/status", "r");
	if (st) {
		char l[300];
		while (fgets(l, sizeof(l), st))
			if (!strncmp(l, "CapEff:", 7) || !strncmp(l, "Seccomp:", 8))
				printf("%s", l);
		fclose(st);
	}

	printf("cgroup     : %s\n", stat(CGROUP_F, &sb) == 0 ? CGROUP_F " ok" : "缺失");
	printf("pin dir    : ");
	DIR *d = opendir(PIN_DIR);
	if (d) {
		struct dirent *e; int n = 0;
		while ((e = readdir(d)))
			if (e->d_name[0] != '.') { printf("%s ", e->d_name); n++; }
		closedir(d);
		printf("%s\n", n ? "" : "(空)");
	} else {
		printf("(无: %s)\n", strerror(errno));
	}

	policy_load();
	printf("配置       : socks=%s:%d relay=127.0.0.1:%d enabled=%d default=%s flags=%d 策略=%d条\n",
	       G.socks_host, G.socks_port, G.relay_port, G.enabled,
	       mode_name(G.default_mode), G.flags, ELN);

	cmd_probe();

	tail_file(LOG_F, 30, "steer.log");
	tail_file(BASE_DIR "/daemon.log", 30, "daemon.log");
	return 0;
}

/* ---------------- 设置项（面板用） ---------------- */

static const char *CFG_KEYS[] = {
	"socks_host", "socks_port", "socks_user", "socks_pass", "relay_port", "flags",
	"takeover", "udp", "relay_udp_port", "redirect_flags"
};

static int cmd_cfg(int argc, char **argv, int json)
{
	cfg_load();

	if (argc >= 5 && !strcmp(argv[2], "set")) {
		const char *k = argv[3], *v = argv[4];
		int ok = 0;
		for (unsigned i = 0; i < sizeof(CFG_KEYS) / sizeof(CFG_KEYS[0]); i++)
			if (!strcmp(k, CFG_KEYS[i])) ok = 1;
		if (!ok) { fprintf(stderr, "未知配置项: %s\n", k); return 1; }

		if (!strcmp(k, "socks_host")) {
			struct in_addr a;
			if (inet_pton(AF_INET, v, &a) != 1) {
				fprintf(stderr, "socks_host 必须是 IPv4 字面量（不支持域名）\n");
				return 1;
			}
			snprintf(G.socks_host, sizeof(G.socks_host), "%s", v);
		} else if (!strcmp(k, "socks_port")) {
			int p = atoi(v);
			if (p < 1 || p > 65535) { fprintf(stderr, "端口不合法\n"); return 1; }
			G.socks_port = p;
		} else if (!strcmp(k, "socks_user")) {
			snprintf(G.socks_user, sizeof(G.socks_user), "%s", v);
		} else if (!strcmp(k, "socks_pass")) {
			snprintf(G.socks_pass, sizeof(G.socks_pass), "%s", v);
		} else if (!strcmp(k, "relay_port")) {
			int p = atoi(v);
			if (p < 1024 || p > 65535) { fprintf(stderr, "端口需在 1024-65535\n"); return 1; }
			G.relay_port = p;
		} else if (!strcmp(k, "flags")) {
			G.flags = atoi(v) ? 1 : 0;
		} else if (!strcmp(k, "takeover")) {
			G.takeover = atoi(v) ? 1 : 0;
		} else if (!strcmp(k, "udp")) {
			G.udp_on = atoi(v) ? 1 : 0;
		} else if (!strcmp(k, "relay_udp_port")) {
			int p = atoi(v);
			if (p < 1024 || p > 65535) { fprintf(stderr, "端口需在 1024-65535\n"); return 1; }
			G.relay_udp_port = p;
		} else if (!strcmp(k, "redirect_flags")) {
			G.redir_flags = atoi(v);
		}
		cfg_save();
		cfg_patch(-1, -1);
		printf("%s ok\n", k);
		return 0;
	}

	if (json)
		printf("{\"socks_host\":\"%s\",\"socks_port\":%d,\"socks_user\":\"%s\","
		       "\"socks_pass_set\":%s,\"relay_port\":%d,\"default\":\"%s\","
		       "\"flags\":%d,\"enabled\":%s,\"takeover\":%s,"
		       "\"udp\":%s,\"relay_udp_port\":%d,\"redirect_flags\":%d}\n",
		       G.socks_host, G.socks_port, G.socks_user,
		       G.socks_pass[0] ? "true" : "false",
		       G.relay_port, mode_name(G.default_mode), G.flags,
		       G.enabled ? "true" : "false", G.takeover ? "true" : "false",
		       G.udp_on ? "true" : "false", G.relay_udp_port, G.redir_flags);
	else
		printf("socks_host=%s\nsocks_port=%d\nsocks_user=%s\n"
		       "relay_port=%d\ndefault_mode=%s\nflags=%d\nenabled=%d\n",
		       G.socks_host, G.socks_port, G.socks_user, G.relay_port,
		       mode_name(G.default_mode), G.flags, G.enabled);
	return 0;
}

/* 重启守护：先礼貌停掉旧的，再把自己以 daemon 身份拉起来（脱离当前会话） */
static int cmd_restart(void)
{
	FILE *f = fopen(PID_F, "r");
	if (f) {
		int pid = 0;
		if (fscanf(f, "%d", &pid) == 1 && pid > 1) {
			kill(pid, SIGTERM);
			for (int i = 0; i < 50; i++) {
				if (kill(pid, 0) && errno == ESRCH) break;
				usleep(200000);
			}
		}
		fclose(f);
	}

	const char *self = BASE_DIR "/steer";
	if (access(self, X_OK)) { fprintf(stderr, "找不到 %s\n", self); return 1; }

	pid_t p = fork();
	if (p < 0) { fprintf(stderr, "fork 失败\n"); return 1; }
	if (p == 0) {
		setsid();

		/* 关键：把 stdio 接到 daemon.log，并关掉所有继承来的 fd。
		 * 否则守护进程会一直攥着调用者（KernelSU WebUI 的 exec）的管道写端，
		 * 那边读不到 EOF，回调永不触发 —— 面板就会永远停在"读取中…"。 */
		int lg = open(BASE_DIR "/daemon.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (lg >= 0) { dup2(lg, 1); dup2(lg, 2); if (lg > 2) close(lg); }
		int dn = open("/dev/null", O_RDONLY);
		if (dn >= 0) { dup2(dn, 0); if (dn > 2) close(dn); }
		for (int fd = 3; fd < 1024; fd++) close(fd);

		execl(self, self, "daemon", (char *)NULL);   /* argv[0] 用全路径：pgrep/pkill 才匹配得到 */
		_exit(127);
	}
	usleep(600000);
	printf("已重启\n");
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
		"usage:\n"
		"  steer daemon\n"
		"  steer list   [--json]\n"
		"  steer set    <pkg|uid> <direct|proxy|block>\n"
		"  steer del    <pkg|uid>\n"
		"  steer default <direct|proxy|block>\n"
		"  steer switch on|off        # 总开关\n"
		"  steer version\n"
		"  steer start | stop\n"
		"  steer diag                          # 诊断（含日志尾部 + 挂载点占用）\n"
		"  steer probe                         # 只看 cgroup BPF 挂载点占用\n"
		"  steer restore                       # 把被接管的平台程序挂回去\n"
		"  steer tcclean                       # 摘掉残留的 TC 过滤器\n"
		"  steer policy [--json]               # 看内核里实际生效的策略表\n"
		"  steer cfg    [--json]\n"
		"  steer cfg    set <key> <value>   # socks_host/socks_port/socks_user/socks_pass/relay_port/flags\n"
		"  steer restart\n"
		"  steer stats  [--json]\n"
		"  steer status [--json]\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) { usage(); return 1; }
	const char *c = argv[1];
	int json = (argc > 2 && !strcmp(argv[argc - 1], "--json"));

	if (!strcmp(c, "daemon"))                               return cmd_daemon();
	if (!strcmp(c, "list"))                                 return cmd_list(json);
	if (!strcmp(c, "stats"))                                return cmd_stats(json);
	if (!strcmp(c, "status"))                               return cmd_status(json);
	if (!strcmp(c, "set") && argc > 3)                      return cmd_set(argv[2], argv[3]);
	if (!strcmp(c, "del") && argc > 2)                      return cmd_del(argv[2]);
	if (!strcmp(c, "default") && argc > 2)                  return cmd_default(argv[2]);
	if (!strcmp(c, "switch") && argc > 2)                   return cmd_switch(argv[2]);
	if (!strcmp(c, "cfg"))                                  return cmd_cfg(argc, argv, json);
	if (!strcmp(c, "restart"))                              return cmd_restart();
	if (!strcmp(c, "version")) { printf("%s\n", STEER_VERSION); return 0; }
	if (!strcmp(c, "start"))                                return cmd_start();
	if (!strcmp(c, "stop"))                                 return cmd_stop();
	if (!strcmp(c, "diag"))                                 return cmd_diag();
	if (!strcmp(c, "probe"))                                return cmd_probe();
	if (!strcmp(c, "restore"))                              return cmd_restore();
	if (!strcmp(c, "tcclean"))                              return cmd_tcclean();
	if (!strcmp(c, "policy"))                               return cmd_policymap(json);
	if (!strcmp(c, "enable"))                               return cmd_switch("on");
	if (!strcmp(c, "disable"))                              return cmd_switch("off");
	usage();
	return 1;
}
