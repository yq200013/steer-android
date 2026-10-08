# Steer —— 分应用透明代理（TCP via cgroup eBPF / UDP via TC eBPF）

让**选中的应用**在完全无感的情况下走本地 SOCKS5（默认 `127.0.0.1:1180`）。
**不占 VpnService、不写 iptables、不写 ip rule。** 带 KernelSU WebUI 面板。

> 本项目在 Android 16 / ColorOS V16 (PLK110) 上开发，SELinux Enforcing，KernelSU root。
>
> 仓库名 `steer-android`，但 **KernelSU 模块 id 固定为 `steer`**（二者不同无妨；
> 改 id 会让已安装用户变成"另一个模块"，升级/卸载都会错乱）。

---

## 拦截层：为什么 TCP 和 UDP 用了两套机制

| 协议 | 拦截层 | 做法 |
|---|---|---|
| **TCP** | cgroup eBPF：`connect4` + `getpeername4` + `sock_ops` | 把目的地址改写为 `127.0.0.1:<relay>`，用户态中继转 SOCKS5；`getpeername` 把原目标"还"给 App |
| **UDP** | **TC egress eBPF** | 内核里 `cgroup/sendmsg4` 只对**非 connected** 的 UDP 触发（`net/ipv4/udp.c:1167 && !connected`），而 QUIC 用的是 `connect()+send()` → 只能改在 IP 层截 |

UDP 侧还有个前提：`cgroup/connect4`/`udp4_sendmsg` 等挂载点被**平台自己的 `netd.o`** 以
`flags=0`（非 MULTI）独占，所以要么接管（先摘平台程序、用完还回去），要么换一层（TC）。

---

## 当前状态（请先读，避免误判）

| 能力 | 状态 |
|---|---|
| TCP 分应用透明代理 | ✅ **端到端验证通过**（TLS 完成 + HTTP/2 200 + 双向计数）|
| WebUI 面板 / CLI / 策略热更新 | ✅ 可用 |
| UDP(TC) 改写 → 中继 → SOCKS5 | ✅ **验证通过**（`已改写>0`、`udp proxied>0`）|
| UDP 的应用识别、公网端到端 | ⚠️ **仍在调**（`skb->uid` 识别正常，但缺"被代理 App + 公网 UDP 目标"的实测样本）|
| IPv6 | ❌ 未做 |
| 失败降级（TC 挂了只做 TCP） | ✅ 已实现并经实测触发过 |

**测试用靶子的教训**：UDP:53(DNS) 和 UDP:443(QUIC) 在实测网络里都被**网络侧封掉**
（ICMP 秒拒），所以它们**不能**用来判断代码对错。判断依据请用 `steer stats` 的
`已改写` / `udp proxied` 计数，以及 `steer diag` 的 TC 探针。

---

## 构建

```sh
sh build.sh          # 产出 dist/steer-<version>.zip（可刷 KernelSU 模块）
```
依赖：`clang`(带 bpf target) `gcc` `libbpf-dev` `libelf-dev` `zlib1g-dev` `libzstd-dev`
`linux-libc-dev` `zip` `python3`。

`build.sh` 会做三件强制检查，任一不过就**中止出包**：
1. `module.prop` 规范（id 正则 / versionCode 整数 / LF）
2. **版本号注入**（二进制自称的版本 == `module.prop`，不可能不一致）
3. **自洽检查** `tools/check_consistency.py`（BPF ↔ 用户态：结构体逐字段 / map 名单 / 程序名双向引用 / 常量）

---

## 许可

GPL-2.0-only（eBPF 程序必须以 GPL 兼容许可发布）。第三方组件见 `NOTICE`。

> ⚠️ 本项目需要 root 并修改内核网络行为。**用于自己的设备**；请先读完
> `使用说明.md` 的「安全与回退」与「关于接管」两节。

---

## 以下为开发过程记录（按时间倒序，含已修 bug 的根因）



---

## 原理（三段式）

```
app(uid) connect("1.2.3.4",443)
  │
  ├─① cgroup/connect4       按 uid 查策略 map
  │     direct → 放行；block → 返回 EPERM
  │     proxy  → pending[cookie] = {1.2.3.4,443}
  │              ctx->user_ip4 = 127.0.0.1, user_port = RELAY
  │              ↓ 目标是 loopback ⇒ 内核不需要任何路由规则
  ├─② cgroup/sock_ops       TCP_CONNECT_CB 时源端口已分配
  │     by_port[源端口] = {1.2.3.4,443}
  │
  └─③ 用户态 relay accept
        getpeername → 对端源端口 → by_port 查回 {1.2.3.4,443}
        → 向 127.0.0.1:1180 发 SOCKS5 CONNECT → 双向 splice

     cgroup/getpeername4   把原目标“还”给 app ⇒ app 完全无感
```

- **分应用**：策略是一张 **`uid → mode`** 的 BPF map，用户态**随时增删改，即时生效**，
  不用重启 app、不用重载程序、不用重建 VPN。
- **"全部 app"** = 把 default 设成 `proxy`，列表可空。所以"全部"和"分应用"是同一套机制。

---

## 模块结构

```
steer/
├── module.prop
├── customize.sh / service.sh / action.sh / uninstall.sh
├── bin/steer            (静态 aarch64 二进制：loader + relay + CLI)
├── bpf/steer.bpf.o      (clang -target bpf 产物)
└── webroot/             (KernelSU WebUI)
    ├── index.html  style.css  app.js
    └── kernelsu.js      (官方 kernelsu npm 包，ESM，直接 import)
```

配置与状态：
```
/data/adb/steer/cfg        # socks_host / socks_port / relay_port / default_mode / flags
/data/adb/steer/policy     # uid mode pkg    ← 文件即真相
/data/adb/steer/steer.log  # 日志
/sys/fs/bpf/steer/*        # pin 的 map      ← 实时状态
```

---

## 安装与使用

1. KernelSU 管理器 → 模块 → 从本地安装 → 选 `dist/steer-v0.3.4.zip` → 重启。
2. 在模块卡片里打开 **WebUI 面板**：
   - **总开关**（最上面）：开 = 按策略接管；关 = **全部直连、策略原样保留**；关闭时下面几块置灰
   - 状态卡：运行状态 / 出口 SOCKS5 / 本地中继 / 连接计数
   - 「默认策略」三态：直连 / 走代理 / 拦截（选"走代理"即全部 app）
   - 应用列表：图标 + 名称 + 包名 + uid，每个应用一个三态分段控件，**点一下即时生效**
   - 支持搜索、显示系统应用
   - 底部「设置」（折叠）：SOCKS5 主机/端口/账号密码、本地中继端口、私网是否代理，**保存并重启**
3. 改动立即写入 BPF map，无需重启。

### CLI（面板之外的等价物）
```sh
STEER=/data/adb/steer/steer
$STEER status --json
$STEER set com.android.chrome proxy     # 也可直接给 uid
$STEER set com.tencent.mm block
$STEER del com.tencent.mm
$STEER default direct                   # 或 proxy = 全部走代理
$STEER switch off                       # 总开关：关 = 全部直连（策略保留）
$STEER start | stop                     # 启动 / 停止守护
$STEER diag                             # 诊断（含两份日志尾部）
$STEER cfg --json                       # 读设置
$STEER cfg set socks_port 1180          # 改设置
$STEER restart                          # 重启守护（改端口/账号后需要）
$STEER list --json
$STEER stats --json
```

---

## 构建

```sh
sh build.sh          # 产出 dist/steer-v0.3.4.zip
```
依赖：`clang`(带 bpf target) `gcc` `libbpf-dev` `libelf-dev` `zlib1g-dev` `libzstd-dev` `linux-libc-dev` `zip`。

---

## 已知限制 / 待验证（重要，请先读）

1. **尚未在真机跑过**。本环境能编译、能静态链接、CLI 能运行，但 eBPF 的运行时行为
   （attach、sock_ops 时序、loopback 改写后的握手）**必须真机验证**。
2. **仅 TCP + IPv4**。UDP（含 QUIC）暂未接管；建议后续阶段补
   `cgroup/udp4_sendmsg` / `udp4_recvmsg`。当前 QUIC 会走直连（因 UDP 不接管）。
3. **排除项**：目标为回环地址永不代理；`flags=1` 时私网地址也不代理。
   注意 `com.oplus.acc.gac`（SOCKS5 提供者）要**保持默认直连**，否则会自环。
4. **SELinux**：若 `avc: denied` 涉及 `bpf`，需给 KernelSU 的 su 域补规则。
5. **static glibc** 二进制在本机验证为可执行；若真机上出现异常，可改用 musl 或 NDK 重编。
6. `sock_ops` 依赖 `TCP_CONNECT_CB` 时源端口已分配（`inet_hash_connect` 之后）。若个别内核时序不同，
   `by_port` 会查不到，表现为该连接被直接关闭 —— 这是**首要排查点**。

## 自检报告（v0.1.8）

### A. KernelSU 3.x 模块规范

| 规范项 | 状态 |
|---|---|
| `module.prop` 在 zip 根目录；`id` 匹配 `^[a-zA-Z][a-zA-Z0-9._-]+$` | ✅ `id=steer`（build.sh 强校验） |
| `versionCode` 为整数 | ✅ `1` |
| `name`/`version`/`author`/`description` 单行非空 | ✅ |
| 换行符为 LF（非 CRLF） | ✅ build.sh 检测 `\r` 并拒绝出包 |
| `customize.sh` 存在且可执行（0755） | ✅ |
| `service.sh`/`action.sh`/`uninstall.sh` 可执行 | ✅ |
| `webroot/index.html` 为 WebUI 入口 | ✅ |
| 不自行设置 `webroot/` 的 SELinux 上下文（交给 KernelSU） | ✅ customize.sh 不碰 |
| 不创建 `system/`、不使用 `REPLACE`/`REMOVE` | ✅ 完全不碰系统分区 |
| 自带 `skip_mount`（显式声明不挂载） | ✅ |
| 不提供 `sepolicy.rule`（不注入 SELinux 策略） | ✅ |

**权限位（上一版是错的，已修）**：`module.prop`、`webroot/*`、`skip_mount`、`bpf/*.o` → `0644`；
脚本与二进制 → `0755`；目录 → `0755`。
（原来 `module.prop`/webroot 是 `0600`、目录 `0700` —— 管理器和 WebView 读不到，UI 会白屏。）

### B. 非破坏性设计（四条线）

**1) 自动脱钩 —— 最关键**
早期版本用 `bpf_prog_attach()`（legacy attach），它**不随进程退出解绑**：
守护被 kill 后 eBPF 仍挂在 root cgroup 上，继续把流量改写到一个已死的中继
⇒ **那些 app 彻底断网，直到重启**。
现改为 **`bpf_link`（`bpf_program__attach_cgroup`）**：进程一旦消失（含 `SIGKILL`/OOM），
**内核自动 detach**，网络立刻恢复原状。

**2) fail-open 安全阀（`armed`）**
`cfg.armed` 初值恒 0，只有**中继监听成功之后**才置 1；退出前先置 0。
BPF 侧任一条件不满足就**直接放行**：
```c
if (!c || !c->armed || !c->relay_port) return 1;   // 放行
if (bpf_map_update_elem(&pending,...)) return 1;   // 放行
if (is_loopback(...) || (flags&1 && is_private(...))) return 1;
```
⇒ 守护没起 / 中继没监听 / map 写失败，**任何异常都退化成"直连"**，绝不黑洞。

另外 **`uid==0` 永不代理**：中继/守护本身就是 root，代理它会成环（尤其当 socks5 不在回环上时）。

**总开关（`cfg.enabled`）与 `armed` 是两个独立字段，互不覆盖**：
`enabled=0` 时内核侧直接放行（**策略表不动**），用户关掉后随时可切回。
CLI 统一走"读-改-写"的 `cfg_patch(armed, enabled)`，`-1` 表示保持原值 ——
改 `default` 或切总开关时**绝不会误清另一个字段**。

**3) 资源有界**
- 中继并发上限 `MAX_CONNS=512`，超出直接拒绝（防 fd/线程耗尽）。
- 日志 1 MiB 轮转（`steer.log`、`daemon.log`），不会撑爆 `/data`。
- BPF map：`pending`/`by_port` 为 LRU 16384 项封顶，`policy` 8192。
- watchdog 连续启动失败 5 次即放弃，不做无限重启。

**4) 卸载可逆、精确**
- `uninstall.sh` 只用 `rm -f` 删 `/sys/fs/bpf/steer/` 下**我们自己的 5 个 pin 文件**，再 `rmdir` 空目录 —— 不用 `rm -rf` 打整棵 `/sys`。
- 停进程用 `pkill -f "$BASE/steer daemon"` 精确匹配自身路径，**不用 `killall`**。
- 另置 `/data/adb/steer/stop` 让 watchdog 自杀，不依赖 pkill 打中。
- **不删用户配置与日志**；彻底清除的命令会打印出来，由用户决定。
- 无 `setenforce`、无 `mount/insmod`、无系统分区写入。
- 二进制里唯一外部调用是 `execl("/system/bin/cmd", ...)`（包名→uid），**无 `system()`/`popen`**。

### C. 单实例与崩溃自愈
- `flock(/data/adb/steer/steer.lock)` 保证单实例；拿不到锁直接退出（不误报错误）。
- 拿到锁即说明旧实例已死 ⇒ 先 `cleanup_pins()` 清残留 pin 再重建。
  （否则旧 pin 会让新实例误判"已在运行"而拒绝启动，模块得等重启才恢复。）

### D. 紧急停止（一条命令）
```sh
su -c 'touch /data/adb/steer/stop; /data/adb/steer/steer default direct; pkill -f "/data/adb/steer/steer daemon"'
```
`default direct` 让内核侧立刻全部放行；进程退出后 `bpf_link` 自动解绑。

### E. 仍未验证（必须真机确认）
1. eBPF **attach 是否成功**（`bpf_link` 需内核支持 cgroup link；不支持会退 legacy 并打警告）。
2. `sock_ops` 的 `TCP_CONNECT_CB` 时机 —— 若源端口尚未分配，`by_port` 查不到，表现为该连接被关。
3. 改写为 loopback 后的握手/回包是否正常。
4. static glibc 二进制在 ColorOS 16 上能否运行。
5. SELinux：`bpf()` 是否需补规则。

### M. v0.3.4：整体自洽梳理（不是修局部）

起因：连续三轮都在"打地鼠"（版本号撒谎 / TC 被 verifier 拒 / TC 加载失败拖死主功能）。
改为**通读全量代码，找"不自洽"而不是"局部错误"**。

#### M.1 先做了机械检查器（R8：能脚本化的绝不靠眼睛）

`tools/check_consistency.py`，已接进 `build.sh`（不一致直接构建失败）：

| 检查项 | 说明 |
|---|---|
| `struct cfg_t / stats_t / rstats_t / dstkey` | BPF 侧与 C 侧**逐字段**（类型+顺序+名字）比对 |
| map 名单 | BPF 的 `SEC(".maps")` vs C 的 `MAPNAMES[]` |
| 程序名 | C 里引用的每个 `steer_*` 与 BPF 里的函数**双向**比对（BPF 有、C 没用 → 也报错）|
| 常量 | `MAX_UDP_SLOT`(BPF) vs `MAX_SLOT`(C) |
| map 引用 | C 里 `map_fd("x")` 的 x 必须真存在 |

> 这个检查器自己第一版**也是坏的**（把 map 声明当结构体、没处理逗号声明、
> 程序名从数组取的没覆盖 → 那项检查是**空转**的）。修完才真正生效 ——
> 正好印证 R14：**自检机制本身必须先被验证**。

#### M.2 通读后找出的"不自洽"及修法

| # | 问题 | 为什么是"不自洽" | 修法 |
|---|---|---|---|
| 1 | **TC 没有死手开关** | cgroup 程序用 `bpf_link`（进程死→内核自动摘），**TC 过滤器不会**。守护被强杀后，`cfg.armed` 仍是 1，TC 继续把系统 UDP 改写到死掉的中继 | 新增 `hbmap`：守护每轮写 CLOCK_MONOTONIC 纳秒；TC 程序里 `ktime_get_ns - hb > 10s` → 放行 |
| 2 | **TC 过滤器会泄漏** | 与 #1 同源 | 新增 `steer tcclean`（扫网卡 + 固定 handle/prio=1 摘除，**任何进程都能做**）；守护启动前先清残留；`uninstall.sh` 也调 |
| 3 | **网络变化后不重挂** | 只在启动时挂一次，切 Wi-Fi↔移动数据后新网卡裸奔 | relay 循环里每 ~20s 重扫一次网卡补齐 |
| 4 | **"二进制与 .o 不是同一次构建"无检测** | 这正是 ETXTBSY 那次事故的形态 | `build.sh` 用 `.o` 的 sha256 生成构建戳，**同时**注入二进制、写成 `bpf/steer.stamp` 随模块发布；启动时两边比对，不一致就大声报错 |
| 5 | **UI 与配置能力不对等** | 后端支持 `udp`，UI 里却没有入口 | 设置面板加「UDP（QUIC 等）也走代理」+「UDP 中继端口」；`cfg --json` 补 `udp/relay_udp_port/redirect_flags` |
| 6 | **TC 加载失败会拖死主功能** | 违反我自己定的 fail-open | 两遍加载：带 TC 失败 → `set_autoload(false)` 重载 → TCP 照常起来 |

#### M.3 现在的自洽约束（写下来，以后照着守）

1. **BPF ↔ C 的任何共享定义（结构体/常量/名字）必须机械校验通过**，否则不出包。
2. **每个 BPF 程序都必须被 C 引用**（否则就是死代码或漏挂）。
3. **凡是"可选功能"（UDP/TC/接管），失败只能是降级，不能影响主功能。**
4. **凡是"不会被内核自动清理"的东西（TC 过滤器、pin、平台程序），必须有显式的、
   任何进程都能执行的清理路径**（固定 handle/prio/路径，不依赖内存状态）。
5. **构建产物之间必须有指纹**（二进制 ↔ .o），避免"版本拼接"。

### L. v0.1.8：修"设了proxy却走直连"（我自己的严重 bug）

真机现象：把 App 设为 `proxy`，该 App 仍然直连；`steer list` 显示策略在，但 `steer stats` 里 `proxied` 不涨。

**根因**：
```c
static int cmd_daemon(void) {
    cfg_load();        /* 读了 cfg */
    ...
    policy_push();     /* 却从没调用 policy_load() */
}
```
而 `policy_push()` 的语义是 **"清空内核策略表 → 按内存里的 `EL[]` 重建"**。
`EL[]`/`ELN` 是全局（零初始化），`cmd_daemon` 没读文件 ⇒ `ELN == 0`
⇒ **每次守护启动都先把表清空，然后一条也不写** ⇒ 所有 App 退回 `default_mode`（direct）。

为什么"设的时候看起来是对的"：`steer set` 自己会 `policy_load() → policy_save() → policy_push()`，
所以**刚设完那一刻表是对的**；但**任何一次守护重启都会把它清空**
（面板上点「启动 / 重启服务」就触发）。

**修复**：`cmd_daemon` 在 `policy_push()` 前显式 `policy_load()`，并打日志 `policy: 已下发 N 条`。

**同时补可观测性**：新增
```sh
steer policy [--json]     # 直接 dump 内核里实际生效的策略表
```
以前 `steer list` 读的是**文件**，内核表空了也看不出来 —— 这正是这个 bug 藏了这么久的原因。

### K. v0.1.7：运行时"接管"平台挂载点（本方案能跑起来的关键）

**结论（真机实测 + 二进制取证）**：`cgroup/connect4` 被 **Android 自己**（`netd.o` 的
`connect4/inet4_connect`）以 `flags=0`（非 MULTI）独占。真机 probe 的认领信息：

```
prog 25 name="connect4_inet4_" tag=57cd311f2e27366b type=18 加载者uid=0 于 342 秒前
```

进一步从 `netd.o` 的 BTF 里解出 `struct bpf_prog_def`（92B/项）并逐条解析 `progs[]`（2484B = 92×27）：

```
 #  optional  section
19  no       ★connect4/inet4_connect        ← 非 optional
17  no        bind4/inet4_bind
23  no        sendmsg4/udp4_sendmsg
21  no        recvmsg4/udp4_recvmsg
 0  YES       cgroupskb/ingress/stats...
```

**⛔ 所以"开机抢位"绝对不能用**：非 optional 程序挂载失败会让 `bpfloader` 失败，
而 `netbpfload.rc` 原文写着会导致 netd / system_server 崩溃循环、**只能整机重启恢复** = 变砖。

**✅ 正确做法（本版实现）**：平台只在 `load-bpf-programs` 那一次挂载，跑完就不管了。
所以**开机完成之后**再接管：

```
服务启动: bpf_prog_query → bpf_prog_get_fd_by_id → 找它的 pin（AOSP 自己 pin 过）
          → 记录到 /data/adb/steer/takeover.conf → bpf_prog_detach2 摘下 → 挂我们自己的
服务停止: detach 我们的 → 按记录 bpf_prog_attach 挂回平台程序（同 flags）→ 删记录
异常退出: bpf_link 自动摘掉我们的；平台程序仍是"被摘下"状态
          → 下次启动自动还原（也能手动 `steer restore`，重启由系统自己挂回）
```

只接管**非 MULTI 且我们确实需要**的挂载点（当前只有 `inet4_connect`；
若平台用的是 ALLOW_MULTI 则直接共存、不摘）。

**代价**：接管期间 Android 在 connect 侧的 socket 打标缺席，流量统计/计费归因可能不准（重启恢复）。
`cfg takeover=0` 可关闭接管（但那样挂不上）。
`steer restore` 手动还原。

### J. v0.1.5：attach 返回 EPERM 的成因与探查

真机日志（用户提供）走到了最后一步：
```
map ... created / pinned  ✅        prog 全部 load 成功 ✅
prog 'steer_connect4': failed to attach to cgroup: Operation not permitted
```

**内核源码定位**（`kernel/bpf/cgroup.c`，v6.12）：
```c
if (!hierarchy_allows_attach(cgrp, atype))
	return -EPERM;                                  /* :657 祖先已独占该 atype */

if (!hlist_empty(progs) && cgrp->bpf.flags[atype] != saved_flags)
	return -EPERM;                                  /* :664 本 cgroup flags 不匹配 */
```
而 link 方式固定用 `BPF_F_ALLOW_MULTI`（`cgroup_bpf_link_attach()`）：
```c
err = cgroup_bpf_attach(cgrp, NULL, NULL, link, link->type, BPF_F_ALLOW_MULTI);
```
再看 `find_attach_entry()`：`allow_multi == false` 且列表非空 → 直接 `-EINVAL`。

**推论**：`cgroup/inet4_connect` 已经被**别的程序以「非 MULTI」方式独占**了。
这种情况下 —— **谁都挂不上**（本 cgroup 不行，子 cgroup 也不行，因为 `hierarchy_allows_attach` 会沿父链检查）。
这是内核语义，不是我们能绕过的。

**常见占用者**：其它 eBPF 转发模块 / 厂商加速栈（例如 `gacboost_steering` 的 sing-box ebpf 入站，
它 README 里就写着"不同时启用其他接管同一应用的模块"）。

**新增 `steer probe`**（`diag` 已内置，模块「操作」按钮也会跑到）：
用 `bpf_prog_query()` 列出每个 cgroup 挂载点的占用情况 + prog id，
再扫每个进程的 fdinfo 把 **prog id 映射回"是哪个 pid/进程"**，直接点名占位者：

```
== cgroup BPF 挂载点占用 (/sys/fs/cgroup) ==
  cgroup_inet4_connect       : 1 个 prog, flags=0x0 ★非MULTI=独占，别人挂不上
      prog ids: 137
        prog 137 ← pid 4213  /data/adb/modules/gacboost_steering/bin/sing-box run ...
```

**处理**：把占位者停掉（禁用相应模块并重启），再启动 steer。二者**只能二选一**。

#### 真机实测结果（用户提供，v0.1.5 probe）

```
cgroup_inet4_connect       : 1 个 prog, flags=0x0 ★非MULTI=独占，别人挂不上
    prog ids: 25          ← 且"无进程持有"
cgroup_inet_ingress/egress/sock_create/sock_release/
inet4|6_bind/connect/udp4_sendmsg/udp4_recvmsg : 同样被独占
cgroup_inet4_getpeername / inet6_getpeername / inet4_getsockname / sock_ops : 空闲
```

**诊断**：一套完整的 eBPF 透明代理 hook 集合（sock_create/release + bind + connect + udp send/recv）
被**非 MULTI** 方式挂在 root cgroup 上，而且**没有任何进程持有这些 prog** ——
说明加载器（守护进程）**挂完就退出了**，程序却仍挂在核心里，**只有重启才会清掉**。

这与 `gacboost_steering` README 里的原话完全吻合：
> "若守护进程异常消失导致**孤立核心**，请重启确认 eBPF 清理"

**只有 `inet4_connect` 能改写 connect 目标**，而它被占 ⇒ 在清掉占位者之前，本方案无法工作。

#### ✅ 最终确认（真机 on/off 对照，用户提供）

| hook | GacBoost Steering v2 **开** | v2 **关** | 本方案需要 |
|---|---|---|---|
| `cgroup_inet4_connect` | prog 240 ← **gacboost v2 的 sing-box (flags=0x0)** | **空闲** | ✅ |
| `cgroup_inet6_connect` | prog 238 ← gacboost v2 (0x0) | 空闲 | — |
| `cgroup_udp4_sendmsg` | prog 241 ← gacboost v2 (0x0) | 空闲 | 二阶段 |
| `cgroup_udp4_recvmsg` | prog 235 ← gacboost v2 (0x0) | 空闲 | 二阶段 |
| `cgroup_inet_sock_release` | prog 239 ← gacboost v2 (**0x2 ALLOW_MULTI**) | 空闲 | — |
| `cgroup_inet4_getpeername` | 空闲 | 空闲 | ✅ |
| `cgroup_sock_ops` | 空闲 | 空闲 | ✅ |

**结论**：`gacboost_steering_v2` 用 **flags=0（独占）** 占用 `connect4/6` 与 `udp4/6_sendmsg|recvmsg`；
它**关闭即释放**。而本方案需要的三个 hook（`inet4_connect` / `inet4_getpeername` / `sock_ops`）
在它关闭时**全部空闲** ⇒ **关掉它，steer 就能挂上**。

> 注意：它与本方案**不能共存**。内核要求同一挂载点的 flags 一致，而 `find_attach_entry()`
> 在 `allow_multi=false` 且列表非空时返回 `-EINVAL` —— **先到者独占，后到者永远挂不上**。
> （gacboost v2 的 `sock_release` 用了 ALLOW_MULTI 所以能共存，但 `connect4` 不是。）

> `cgroup_inet4_bind` / `inet6_bind`（prog 23/24）在开关两种状态下都被占用且无进程持有 ——
> 这一对**本方案不使用**；ROM 的 `/system/etc/bpf`、tethering APEX、`/vendor/etc/bpf`
> 里都没有 bind 类 section，推测来自 odm 或某个系统服务，与本方案无关。

**v0.1.6 新增**：probe 会打印每个 prog 的 `name / tag / type / 加载者uid / 加载于多少秒前`
（`bpf_prog_get_fd_by_id` + `bpf_prog_get_info_by_fd`），并列出 `/sys/fs/bpf` 下的 pin，
用来最终认领占位者。方案：**禁用所有其它 eBPF 转发模块 → 重启 → 再 probe 确认"空闲" → 再启动 steer**。

### I. v0.1.4 修复（真实设备上 daemon 起不来的根因）

真机诊断（用户提供）：
```
CapEff: 000001ffffffffff      ← 权限齐全
Seccomp: 0
map 'cfg': created successfully, fd=9 ; pinned map '/sys/fs/bpf/steer/cfg'   ← bpf() 正常
prog 'steer_sockops': missing BPF prog type, check ELF section name 'cgroup/sock_ops'
prog 'steer_sockops': failed to load: -22
```

**🔴 我把 section 名写错了。** libbpf 的 `sec_defs` 里（v1.3.0 `libbpf.c:8954`）：
```c
SEC_DEF("sockops", SOCK_OPS, BPF_CGROUP_SOCK_OPS, SEC_ATTACHABLE_OPT),
SEC_DEF("cgroup/connect4",     CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT,     SEC_ATTACHABLE),
SEC_DEF("cgroup/getpeername4", CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_GETPEERNAME, SEC_ATTACHABLE),
```
SOCK_OPS 的 section 名是 **`sockops`**，不是 `cgroup/sock_ops` —— 所以 libbpf 认不出程序类型，
`bpf_object__load()` 直接整对象失败。另两个 section 名是对的（真机日志里也确实只有 sockops 报错）。

**修法**：`SEC("cgroup/sock_ops")` → `SEC("sockops")`。

> 顺带确认 attach 路径没问题：libbpf 的 `bpf_program__attach_cgroup()` →
> `bpf_program_attach_fd()` 用的是 `bpf_program__expected_attach_type(prog)`，
> 而 `SEC_DEF("sockops", ...)` 已经把 expected_attach_type 设成 `BPF_CGROUP_SOCK_OPS`，
> 所以 `bpf_link_create(prog_fd, cgroup_fd, BPF_CGROUP_SOCK_OPS, ...)` 能正常建 link（内核 5.7+ 支持）。

验证：改完后重新编译、在沙箱重跑，`missing BPF prog type` 报错消失。

### H. v0.1.3 修复（"面板一打开就显示『读取中…』"的根因）

**🔴 CSS 把 `[hidden]` 覆盖了 —— 弹窗从来没被隐藏过。**

`.modal` 上写了 `display:flex`，而 HTML 靠 `hidden` 属性控制显隐：
```css
.modal{ ... display:flex; ... }      /* 优先级高于 UA 样式表的 [hidden]{display:none} */
```
```html
<div class="modal" id="diagModal" hidden><pre id="diagOut">读取中…</pre></div>
```
于是这个全屏遮罩**从页面加载起就盖在屏幕上**，显示的正是那段写死的占位文字「读取中…」——
看起来像"诊断一直读不出来"，其实是根本没在诊断。

同一个错误还出现在设置面板：`.cfgbody{display:flex}` + `hidden` ⇒ 设置面板永远展开。

**修法**：样式表最前面加一条全局规则
```css
[hidden]{display:none !important}
```
并在 `init()` 里再显式 `hidden = true` 兜底。

> 附带说明：v0.1.2 修的 **fd 继承** 是另一个**真实但不同**的问题
> （点「启动/重启服务」时守护进程攥着管道写端会让那次 exec 永不回调）。
> 已用可控用例复现并验证，保留该修复。

### G. v0.1.2 修复（守护进程继承 fd 导致 exec 不回调）

**🔴 守护进程没关干净继承来的 fd，攥住了 KernelSU 的管道。**

KernelSU 的 `exec` 必须**读到管道 EOF** 才会回调。它的 shell 里，管道写端除了 fd 1/2，
往往还在 **fd 3** 上留了一份（`dup2(p[1],1)` 并不会关掉 `p[1]` 本身）。
我在 `cmd_restart` 里只做了：

```c
int dn = open("/dev/null", O_RDWR);
if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); }   /* 只处理 0/1/2 */
execl(self, "steer", "daemon", NULL);
```

于是守护进程**永久持有 fd 3 = 面板的管道写端** ⇒ 回调永不触发 ⇒ 卡片一直「读取中…」。
又因为 WebUI 的 `exec` 是串行的，这一次不返回，后面点「诊断」也一起排队卡住。

已用可控用例复现并验证修法（`fdtest3.c`）：
```
旧写法（只 dup2 0/1/2，fd3 留着）        -> 卡住（timeout 124）
修好写法（重定向 0/1/2 + 关掉 3..1023）   -> read -> 0  EOF（管道已释放）
```

**修法**：`cmd_restart` 的子进程把 stdio 接到 `daemon.log`，然后 `close(3..1023)`。
**另加**：UI 的 `sh()` 带 15s 超时，超时后直接把"请在终端手动执行"的命令打在面板上，
不会再无声无息地卡住。

**同轮其它修复**

| 级别 | 问题 | 修法 |
|---|---|---|
| 🟠 | `customize.sh` 不在安装时放二进制，**必须重启**面板才可用 | 安装即 `cp bin/steer`、`bpf/steer.bpf.o` 到 `/data/adb/steer` |

### F. v0.1.1 修复（"状态显示未运行"的根因）

**🔴 致命：`bpf_map__set_initial_value()` 用错了。**

libbpf 源码（v1.3.0，`libbpf.c`）：
```c
int bpf_map__set_initial_value(struct bpf_map *map, const void *data, size_t size)
{
	if (!map->mmaped || map->libbpf_type == LIBBPF_MAP_KCONFIG ||
	    size != map->def.value_size || map->fd >= 0)
		return libbpf_err(-EINVAL);
	...
}
```
它**只对内部 map（`.data`/`.rodata`/`.bss`/`.kconfig`）有效** —— 那些 map 由 libbpf 自己 mmap。
我们的 `cfg` 是普通 `BPF_MAP_TYPE_ARRAY`，`map->mmaped == NULL` ⇒ **永远返回 -EINVAL**。
于是 daemon 在 `cmd_daemon()` 开头就 `return 1` 退出，`service.sh` 拉多少次都起不来，
面板永远显示"未运行"。

**修法**：删掉 `set_cfg_map()`，改为 load 之后用 `bpf_map_update_elem()` 写初始值（`cfg_seed()`）。

> 这个 bug 是在沙箱里**真跑一遍**才抓到的 —— 静态审查看不出来。

**同轮其他修复**

| 级别 | 问题 | 修法 |
|---|---|---|
| 🔴 | `nlink` 可能跨 `goto fail` 未初始化 | 声明提到函数开头 |
| 🟠 | Android 默认 `RLIMIT_MEMLOCK` 极小（实测 64 KB），libbpf 建 map 可能失败 | 新增 `raise_memlock()`，root 下抬到 infinity，失败只记日志不致命 |
| 🟠 | libbpf 的报错只进 stderr，用户看不到 | `libbpf_set_print()` 把 libbpf 输出同时写进 `steer.log` |
| 🟠 | 总开关只管"是否接管"，**不负责启动服务** → 用户开了开关仍显示未运行 | `switch on` 时若服务未运行会**自动拉起** |
| 🟡 | 起不来时没有任何可查的东西 | 新增 `steer diag`：进程/权限(caps,seccomp)/资源上限/pin 目录/配置/两份日志尾部；面板加「诊断」按钮 |
| 🟡 | 没有手动启停 | 新增 `steer start` / `steer stop`；面板加「启动 / 重启服务」 |

## 真机验证步骤（建议顺序）

```sh
# 1) 只 attach，不代理：default=direct，确认不影响任何流量
/data/adb/steer/steer default direct
dmesg | grep -i bpf | tail          # 看 attach 是否成功
ls /sys/fs/bpf/steer                # map 是否 pin 上

# 2) 单个 app 试水
/data/adb/steer/steer set <pkg|uid> proxy

# 3) 看内核计数说不说得通
/data/adb/steer/steer stats
#   proxied 增、failed 不增  => 改写成功
#   failed 增               => pending 更新失败
#   proxied 增但连不上        => relay 侧 by_port 查不到 / SOCKS5 握手失败，看 steer.log

# 4) relay 日志
tail -f /data/adb/steer/steer.log
```
