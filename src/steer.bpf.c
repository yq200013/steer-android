// SPDX-License-Identifier: GPL-2.0
/*
 * steer.bpf.c —— cgroup eBPF 透明 SOCKS5 重定向（分应用）
 *
 * 思路（不需要 iptables，也不需要任何 ip rule）：
 *   1) cgroup/connect4  : 按 uid 查策略 -> 把目的地址改写成 127.0.0.1:<relay>，
 *                         并把"原目标"存进 pending[cookie]
 *   2) cgroup/sock_ops  : TCP_CONNECT_CB 时源端口已分配 -> by_port[源端口] = 原目标
 *                         （relay 在 accept 后用 getpeername 拿到对端源端口即可查到）
 *   3) cgroup/getpeername4 : 把原目标"还"给 app，令 app 完全无感
 *
 * 因为改写后的目标是 loopback，内核直接按本地连接处理，全程零路由规则。
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 策略模式 */
#define MODE_DIRECT 0
#define MODE_PROXY  1
#define MODE_BLOCK  2

/* cfg.flags */
#define FLAG_SKIP_PRIVATE 1u

enum { MAX_POLICY = 8192, MAX_PENDING = 16384, MAX_BYPORT = 16384 };

/* 原目标（网络字节序） */
struct orig {
	__u32 ip4;
	__u16 port;
	__u16 _pad;
};

struct cfg_t {
	__u8  default_mode;      /* 0 direct / 1 proxy / 2 block */
	__u8  _pad0[3];
	__u32 relay_ip4;         /* 网络字节序，通常 127.0.0.1 */
	__u16 relay_port;        /* 主机字节序，程序内转网络序 */
	__u16 _pad1;
	__u32 flags;
	__u32 armed;             /* 0 = 守护未就绪：一律放行（fail-open 安全阀） */
	__u32 enabled;           /* 0 = 用户关掉了总开关：一律放行（策略表保留） */
	__u32 udp_on;            /* 1 = 接管 UDP（TC 路径） */
	__u32 relay_udp_port;    /* 中继的 UDP 端口 */
	__u32 lo_ifindex;        /* loopback 的 ifindex（用户态填） */
	__u32 redir_flags;       /* bpf_redirect 的 flags（0 或 BPF_F_INGRESS） */
};

struct stats_t {
	__u64 direct;
	__u64 proxied;
	__u64 blocked;
	__u64 failed;
	__u64 udp_direct;
	__u64 udp_proxied;
	__u64 udp_blocked;
	__u64 udp_failed;
};

/* uid -> mode（分应用策略，可运行时增删改，即时生效） */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_POLICY);
	__type(key, __u32);
	__type(value, __u8);
} policy SEC(".maps");

/* 全局配置 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg_t);
} cfg SEC(".maps");

/* socket cookie -> 原目标（供 getpeername 还原） */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_PENDING);
	__type(key, __u64);
	__type(value, struct orig);
} pending SEC(".maps");

/* 客户端源端口（主机序） -> 原目标（供 relay 查询） */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_BYPORT);
	__type(key, __u32);
	__type(value, struct orig);
} by_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct stats_t);
} stats SEC(".maps");

/* 中继侧计数：BPF 不碰，由用户态填写，便于"卡在哪一段"一眼可见 */
struct rstats_t {
	__u64 ok;           /* 成功连上出口 SOCKS5 */
	__u64 miss;         /* 找不到原目标（sock_ops 时序问题） */
	__u64 socksfail;    /* 连不上/握不上出口 */
	__u64 active;       /* 当前在途 */
	__u64 bytes_up;     /* App -> 出口 */
	__u64 bytes_down;   /* 出口 -> App */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rstats_t);
} rstats SEC(".maps");

/* ---- UDP：原目标 <-> slot ---- */
#define MAX_UDP_SLOT 1024

struct dstkey { __u32 ip4; __u16 port; __u16 _pad; };

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_UDP_SLOT);
	__type(key, struct dstkey);
	__type(value, __u32);
} dmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_UDP_SLOT);
	__type(key, __u32);
	__type(value, struct dstkey);
} dtable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} dalloc SEC(".maps");

/* 守护进程的心跳（CLOCK_MONOTONIC 纳秒）。TC 程序据此判断"守护还活着吗"。
 * cgroup 那三个程序用 bpf_link，进程死了内核自动解绑；但 TC 过滤器不会，
 * 所以 TC 必须自己看心跳，否则守护一死、系统 UDP 就被改写到死掉的中继。 */
#define HB_DEAD_NS 10000000000ULL   /* 10 秒没心跳 = 视为死亡，一律放行 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hbmap SEC(".maps");

/* TC 侧探针：把"它到底看到了什么"暴露出来（排查 UDP 用） */
struct dbg_t {
	__u64 calls;            /* 进入 TC 程序的次数 */
	__u64 last_uid;         /* 最近一次看到的 uid（65534 = skb->sk 为空）*/
	__u64 last_direct_uid;  /* 最近一次被判为 direct 的 uid */
	__u64 last_proxy_uid;   /* 最近一次被判为 proxy 的 uid */
	__u64 n_proxy, n_direct, n_nouid;
	__u64 last_prio;        /* skb->priority */
	__u64 last_mark;        /* skb->mark */
	/* ↓ 新增：目的地 + 退出原因，用来定位"进了 proxy 分支却中途退出" */
	__u64 last_daddr, last_dport;        /* 最近一个包的原始目的（网络序）*/
	__u64 lastp_daddr, lastp_dport;      /* 最近一个"进了 proxy 分支"的包的目的 */
	__u64 n_loopback, n_privskip, n_rewrite;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dbg_t);
} dbgmap SEC(".maps");

/* 按 uid 计数（键=uid 的 hash），用来回答"某个 uid 的包到底有没有经过 TC"。
 * 注意：这里**不能用循环** —— BPF 里带 break 的循环没法保证展开，verifier 会拒。 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} uidtop SEC(".maps");

static __always_inline struct cfg_t *get_cfg(void)
{
	__u32 k = 0;
	return bpf_map_lookup_elem(&cfg, &k);
}

static __always_inline void bump(__u64 *field)
{
	__sync_fetch_and_add(field, 1);
}

static __always_inline int is_loopback(__u32 ip4_net)
{
	return (bpf_ntohl(ip4_net) & 0xff000000u) == 0x7f000000u;
}

static __always_inline int is_private(__u32 ip4_net)
{
	__u32 h = bpf_ntohl(ip4_net);
	if ((h & 0xff000000u) == 0x0a000000u) return 1;   /* 10/8     */
	if ((h & 0xfff00000u) == 0xac100000u) return 1;   /* 172.16/12*/
	if ((h & 0xffff0000u) == 0xc0a80000u) return 1;   /* 192.168/16*/
	if ((h & 0xffff0000u) == 0xa9fe0000u) return 1;   /* 169.254/16*/
	return 0;
}

static __always_inline __u8 lookup_mode(__u32 uid)
{
	__u8 *m = bpf_map_lookup_elem(&policy, &uid);
	if (m)
		return *m;
	struct cfg_t *c = get_cfg();
	return c ? c->default_mode : MODE_DIRECT;
}

SEC("cgroup/connect4")
int steer_connect4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;
	struct stats_t *st = bpf_map_lookup_elem(&stats, &zero);
	struct cfg_t *e = get_cfg();
	if (!e || !e->enabled)
		return 1;                                   /* 总开关关闭：全部直连 */

	__u32 uid = (__u32)bpf_get_current_uid_gid();

	/* root 永不代理：
	 * 1) 中继/守护自己就是 root，若连的是非回环 socks5，代理它会直接成环；
	 * 2) 让 root 的系统级流量进代理本来也没有意义。 */
	if (uid == 0)
		return 1;

	__u8 mode = lookup_mode(uid);

	if (mode == MODE_DIRECT) {
		if (st) bump(&st->direct);
		return 1;
	}
	if (mode == MODE_BLOCK) {
		if (st) bump(&st->blocked);
		return 0;   /* 非 0 即拒绝（EPERM） */
	}

	struct cfg_t *c = get_cfg();
	/* 未就绪（守护没起 / 中继没监听 / 端口异常）一律放行，避免把 app 断网 */
	if (!c || !c->armed || !c->relay_port)
		return 1;

	if (is_loopback(ctx->user_ip4))
		return 1;                                   /* 回环永不代理 */
	if ((c->flags & FLAG_SKIP_PRIVATE) && is_private(ctx->user_ip4))
		return 1;

	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct orig o = {
		.ip4 = ctx->user_ip4,
		.port = (__u16)ctx->user_port,           /* 网络序（sockaddr_in.sin_port） */
	};
	if (bpf_map_update_elem(&pending, &cookie, &o, BPF_ANY)) {
		if (st) bump(&st->failed);
		return 1;                                   /* fail-open */
	}

	ctx->user_ip4  = c->relay_ip4;                   /* 127.0.0.1 */
	ctx->user_port = (__u32)bpf_htons(c->relay_port);
	if (st) bump(&st->proxied);
	return 1;
}

/* 把原目标还给 app：app 调 getpeername() 时看到的是真正的对端 */
SEC("cgroup/getpeername4")
int steer_getpeername4(struct bpf_sock_addr *ctx)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct orig *o = bpf_map_lookup_elem(&pending, &cookie);
	if (!o)
		return 1;
	ctx->user_ip4  = o->ip4;
	ctx->user_port = (__u32)o->port;
	return 1;
}

/* TCP_CONNECT_CB 时源端口已分配（inet_hash_connect 已完成），据此建立 by_port */
SEC("sockops")   /* libbpf 的 SEC_DEF 里叫 sockops，不是 cgroup/sock_ops */
int steer_sockops(struct bpf_sock_ops *ctx)
{
	if (ctx->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 0;

	__u64 cookie = bpf_get_socket_cookie(ctx);
	struct orig *o = bpf_map_lookup_elem(&pending, &cookie);
	if (!o)
		return 0;

	__u32 lport = ctx->local_port;                   /* 主机序 */
	if (!lport)
		return 0;
	bpf_map_update_elem(&by_port, &lport, o, BPF_ANY);
	return 0;
}

/* ================= TC（clsact egress）：拦 UDP，塞回本机 =================
 * 为什么用 TC：cgroup/sendmsg4 对 connected UDP（QUIC 用 connect+send）**根本不触发**
 * （net/ipv4/udp.c:1167 `&& !connected`），而 TC 在 IP 层，两者一视同仁。
 */

struct ethh_min { __u8 dst[6]; __u8 src[6]; __u16 proto; } __attribute__((packed));
struct iph_min {
	__u8  vihl; __u8 tos; __u16 tot_len; __u16 id; __u16 frag_off;
	__u8  ttl;  __u8 proto; __u16 check; __u32 saddr; __u32 daddr;
} __attribute__((packed));
struct udph_min { __u16 source; __u16 dest; __u16 len; __u16 check; } __attribute__((packed));

#define ETH_P_IP_   0x0800
#define ETH_P_8021Q_ 0x8100
#define ETH_P_8021AD_ 0x88A8
#define TC_ACT_OK_   0

static __always_inline void bump64(__u64 *f)
{
	__sync_fetch_and_add(f, 1);
}

SEC("tc")
int steer_tc_egress(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct stats_t *st = bpf_map_lookup_elem(&stats, &zero);
	struct cfg_t *c = get_cfg();
	if (!c || !c->enabled || !c->armed || !c->udp_on || !c->relay_udp_port)
		return TC_ACT_OK_;

	/* ★ 死手开关：守护进程停止心跳 -> 立刻放行（fail-open） */
	__u64 *hb = bpf_map_lookup_elem(&hbmap, &zero);
	if (!hb || !*hb || bpf_ktime_get_ns() - *hb > HB_DEAD_NS)
		return TC_ACT_OK_;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + 14 > data_end)
		return TC_ACT_OK_;

	__u16 proto = ((struct ethh_min *)data)->proto;
	__u32 l3off;
	if (proto == bpf_htons(ETH_P_IP_)) {
		l3off = 14;
	} else if (proto == bpf_htons(ETH_P_8021Q_) || proto == bpf_htons(ETH_P_8021AD_)) {
		l3off = 18;                       /* 单层 VLAN */
		if (data + 18 > data_end) return TC_ACT_OK_;
	} else {
		l3off = 0;                        /* raw IP（rmnet 之类） */
	}

	struct iph_min *ip = (void *)data + l3off;
	if ((void *)ip + sizeof(*ip) > data_end)
		return TC_ACT_OK_;
	if ((ip->vihl >> 4) != 4)
		return TC_ACT_OK_;
	__u32 ihl = (__u32)(ip->vihl & 0x0F) * 4;
	if (ihl < 20)
		return TC_ACT_OK_;
	struct udph_min *udp = (void *)ip + ihl;
	if ((void *)udp + sizeof(*udp) > data_end)
		return TC_ACT_OK_;
	if (ip->proto != 17)
		return TC_ACT_OK_;                 /* 只管 UDP */
	if (bpf_ntohs(udp->dest) == 0)
		return TC_ACT_OK_;

	__u32 uid = bpf_get_socket_uid(skb);
	struct dbg_t *d = bpf_map_lookup_elem(&dbgmap, &zero);
	if (d) { d->calls++; d->last_uid = uid; d->last_prio = skb->priority; d->last_mark = skb->mark; }

	if (d) { d->last_daddr = ip->daddr; d->last_dport = (__u64)udp->dest; }
	if (uid == 0 || uid == 65535 || uid == 65534) {
		if (d) d->n_nouid++;               /* 65534 = 内核给的 overflowuid（skb->sk 为空）*/
		return TC_ACT_OK_;
	}

	/* 记一笔 uid -> 次数（查找+自增，无循环）*/
	{
		__u64 *pc = bpf_map_lookup_elem(&uidtop, &uid);
		if (pc) {
			(*pc)++;
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&uidtop, &uid, &one, BPF_NOEXIST);
		}
	}

	__u8 mode = lookup_mode(uid);
	if (mode == MODE_DIRECT) {
		if (st) bump64(&st->udp_direct);
		if (d) { d->n_direct++; d->last_direct_uid = uid; }
		return TC_ACT_OK_;
	}
	if (d) { d->n_proxy++; d->last_proxy_uid = uid;
	         d->lastp_daddr = ip->daddr; d->lastp_dport = (__u64)udp->dest; }
	if (mode == MODE_BLOCK) {
		if (st) bump64(&st->udp_blocked);
		return 2;                          /* TC_ACT_SHOT */
	}

	if (is_loopback(ip->daddr)) {
		if (d) d->n_loopback++;
		return TC_ACT_OK_;
	}
	if ((c->flags & FLAG_SKIP_PRIVATE) && is_private(ip->daddr)) {
		if (d) d->n_privskip++;
		return TC_ACT_OK_;
	}

	/* 原目标 -> slot */
	struct dstkey k = { .ip4 = ip->daddr, .port = udp->dest };
	__u32 slot;
	__u32 *sl = bpf_map_lookup_elem(&dmap, &k);
	if (sl) {
		slot = *sl;
	} else {
		__u32 *ctr = bpf_map_lookup_elem(&dalloc, &zero);
		if (!ctr) { if (st) bump64(&st->udp_failed); return TC_ACT_OK_; }
		/* BPF 后端不允许使用 XADD 的返回值，所以先读后加（极小概率撞 slot，可接受） */
		slot = (*ctr) % MAX_UDP_SLOT;
		__sync_fetch_and_add(ctr, 1);
		if (bpf_map_update_elem(&dtable, &slot, &k, BPF_ANY)) {
			if (st) bump64(&st->udp_failed);
			return TC_ACT_OK_;
		}
		bpf_map_update_elem(&dmap, &k, &slot, BPF_ANY);
	}

	/* 改写：目的 IP -> 127.<slot>，目的端口 -> relay_udp_port
	 *
	 * ★ 关键：任何"可能改动 skb"的 helper（csum_replace / store_bytes）调用之后，
	 *   直接包指针（ip/udp）在 verifier 眼里就失效了。所以**先把所有读出来的值存进标量**，
	 *   之后只用标量调用 helper，绝不再解引用 ip/udp。
	 */
	__u32 oldip   = ip->daddr;
	__u16 oldport = udp->dest;
	__u16 udp_ck  = udp->check;
	__u32 ip_off   = (__u32)((void *)&ip->daddr  - data);
	__u32 csum_off = (__u32)((void *)&ip->check  - data);
	__u32 p_off    = (__u32)((void *)&udp->dest  - data);
	__u32 u_off    = (__u32)((void *)&udp->check - data);
	__u32 lo_idx   = c->lo_ifindex;
	__u32 rflags   = c->redir_flags;

	__u32 newip = bpf_htonl(0x7F000000u | (slot & 0x00FFFFFFu));
	__u16 newport = bpf_htons((__u16)c->relay_udp_port);

	if (bpf_l3_csum_replace(skb, csum_off, oldip, newip, 4))
		return TC_ACT_OK_;
	if (udp_ck) {
		if (bpf_l4_csum_replace(skb, u_off, oldip, newip, 4 | BPF_F_PSEUDO_HDR))
			return TC_ACT_OK_;
		if (bpf_l4_csum_replace(skb, u_off, oldport, newport, 2))
			return TC_ACT_OK_;
	}
	if (bpf_skb_store_bytes(skb, ip_off, &newip, 4, 0))
		return TC_ACT_OK_;
	if (bpf_skb_store_bytes(skb, p_off, &newport, 2, 0))
		return TC_ACT_OK_;

	if (st) bump64(&st->udp_proxied);
	if (d) d->n_rewrite++;

	/* 塞回本机（127/8 是本机地址，redirect 到 lo 后由协议栈本地投递） */
	return bpf_redirect(lo_idx, rflags);
}

char LICENSE[] SEC("license") = "GPL";
