# ADR WINTUN_VERSION_RISK — Wintun 0.14.1 Known Risk 登记

- 状态：**Proposed → Accepted（M0-3.1-4 冻结）**
- 作者：M0-3.1 VNIC Hardening
- 日期：2026-08-30
- 关联：M0-3 Wintun 实装验收（9/9 E2E PASS，26 项验收满足）；M0-3.1 VNIC Hardening；ADR-002 WINTUN_ADAPTER_IDENTITY.md；third_party/NOTICE.md（Prebuilt Binaries License 表述修正）

---

## 1. 背景（Why this ADR）

Wintun 是 meshlink Overlay 平台唯一的 Layer 3 虚拟网卡驱动，承载全部 L3 RX/TX 数据面与
Keepalive/Path Health 探针。M0-3 阶段已将基线**固定在官方预编译 0.14.1 Stable**，采用
动态加载官方签名 wintun.dll 方案。M0-3.1 要求在进入 M0-4（DirectLink ICE PoC UDP P2P）前
把 Wintun 自身的 Known Risks 全部显式登记，避免在 Path Health / Provider 切换决策时
归因错误。

**关键事实（来自官方 git.zx2c4.com 与 WireGuard/wintun GitHub master 外部审计）：**

| 事实 | 值 | 证据 |
| --- | --- | --- |
| 当前采用版本 | **0.14.1**（tagged；Prebuilt Binaries License 分发） | git.zx2c4.com/wintun/refs tag 0.14.1；Age = 5 年（相对于本次 ADR 日期 2026-08-30） |
| 官方 master HEAD 最新关键修复 | `driver: fix missed-wakeup race in ring buffer Alertable signaling` | WireGuard/wintun commit [`ec0a6b98456fe1ba52567bb2add4bbf5f64315a1`](https://github.com/WireGuard/wintun/commit/ec0a6b98456fe1ba52567bb2add4bbf5f64315a1)，日期 = **2026-03-19**，作者 = Simon Rozman（rozmansi） |
| 0.14.1 是否包含上述 race fix | **明确不包含**（证据：tag 0.14.1 发布 ≈2021；fix 合入 master ≈2026-03-19，间隔 5 年，期间官方未发新的 release tag） | git.zx2c4.com/wintun/log/：tag 0.14.1 之后 5 年内无任何中间 tag；race fix 直接落 master。 |
| 第三方下游同步的额外 race | Twingate/wintun fork 同期还合并了 "Fix store-load reordering race causing TCP upload stalls (#6)"（2026-02-27），说明 Wintun 的 ring buffer 并发访问在高压力下存在两处独立 race。 | GitHub/Twingate/wintun Activity 2026-02-27 ~ 2026-04-08。 |
| 0.14.1 是否有官方签名的新预编译 build | **没有**。官方 wintun.net/builds 上最新 Stable 仍指向 0.14.1。 | WebSearch wintun.net + 0.14.1 tag 对应 wintun.zip SHA256 = third_party/wintun/SHA256SUMS 登记值。 |

---

## 2. 决策（Decision）

- M0-3.1 → M0-4 期间 **继续使用 Wintun 0.14.1 official prebuilt binary** 作为唯一基线。
- **禁止**任何未经过独立 ADR 的 Wintun 版本切换（包括：自行编译 master HEAD snapshot、使用第三方 fork 的非官方签名 DLL、切换到 3.1.1 / dev / unstable branch）。
- 本 ADR 显式将 "wintun master 的 missed-wakeup race 修复**尚未纳入当前基线**" 登记为
  **M0-3 Known Risk**，而不是虚假声称已修复。
- 配套在 M0-3.1 阶段执行 **30 分钟 VNIC latency stall stress test**（要求见 §4）：
  - 若实机**稳定复现**连续 >4~5 秒 stall → **立即暂停 M0-4**，单独启动
    `Wintun 版本升级 ADR`（必须三选一：等官方新 stable release / A 正式接入 master snapshot 自编译并签名 / B 在本层加 WAIT_TIMEOUT 守护检测 + 主动重置 ReadWaitEvent）。
  - 若实机 30 分钟内无 >4s stall（或仅偶尔 >1s <3s stall 且不影响 1s 超时阈值 Keepalive）→
    **按 Known Risk 进入 M0-4**，后续 Provider 故障切换架构（M0-7）在 Hard Failure 检测层
    兜底，不因为单个版本 Known Risk 阻塞进度。

---

## 3. 版本 & 哈希指纹（Immutable baseline）

```text
组件:   Wintun 0.14.1 prebuilt binary
版权:   WireGuard LLC
许可:   Prebuilt Binaries License（8 条款；see third_party/wintun/LICENSE.txt）
分发:   官方 ZIP bin/amd64/wintun.dll，动态加载，不写入 System32

官方 ZIP:
  URL:    https://www.wintun.net/builds/wintun-0.14.1.zip
  SHA256: 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

bin/amd64/wintun.dll (实际随包分发文件):
  SHA256: e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce

Git tag:
  tag=0.14.1  https://git.zx2c4.com/wintun/tag/?h=0.14.1
  发布时间线: ~2021，Age ≈ 5 years（本 ADR 日期 2026-08-30 视角）

Git master HEAD 关键修复（当前 0.14.1 不包含）:
  commit = ec0a6b98456fe1ba52567bb2add4bbf5f64315a1
  date   = 2026-03-19
  title  = "driver: fix missed-wakeup race in ring buffer Alertable signaling"
  author = Simon Rozman <simon@rozman.si>
  repo   = https://github.com/WireGuard/wintun
```

---

## 4. 风险详述（Potential Impact）

### 4.1 Missed-wakeup race in ring buffer Alertable signaling — **HIGH impact，标 Known Risk**

#### 根因（来自修复提交的命名语义 + Twingate 同步 PR 名称推断）

Wintun 用户态 API `WintunReceivePacket` 返回 ring 空后，上层调用 `WaitForMultipleObjects`
等待 `ReadWaitEvent`（内核通知事件句柄）。当驱动在 user thread 进入 Wait 前**刚好**完成
一次 ring 写入 → 事件 Set 与线程状态切换存在 store-load 内存重排 / 丢失 wakeup 窗口 →
ReadWaitEvent 保持未 signaled → 上层 RX worker 卡在 `INFINITE` 等待 → 直到**下一次**
新包到达（下一次 SetEvent）才被唤醒。极端情况下如果下一次包到达需要 4~5 秒（或 idle →
burst 切换后第一包之前窗口丢失），RX path 会观测到长达 **4~5 秒 stall**。

#### 对 meshlink 的直接影响链

```
Wintun missed-wakeup race
    ↓
RX worker WaitForMultipleObjects 无 INFINITE 超时 >4s
    ↓
VNIC RX 队列停滞（ring buffer 实际有包但未被 drain → 上层 PacketBuffer 不产出）
    ↓
Path Health Keepalive 对端回包未到达 → 连续超时 ≥3s 触发 QualityDegraded.Critical
    ↓
Circuit Breaker → HALF_OPEN 或 Path Manager 硬切换 Provider（从 DirectLink → N2N）
    ↓
"DirectLink 丢包" 误报，但实际原因是 VNIC ring missed wakeup（非网络质量 / 对端故障）
    ↓
M0-7 Overlay Router 决策被污染；RTT/Jitter 观测产生假毛刺（本应 <1ms 的同机/同 LAN 路径
    报告 4s+，Metrics 被扭曲）
```

#### 与用户规定 Hard Failure 阈值冲突点

- 用户 M0 架构：**Hard Failure P95 ≤ 1s** 即熔断切换；且 Path Health 健康分
  Critical<40 持续 3s = Quality Degradation。
- 如果 Wintun race 稳定产生 4~5 秒 stall：上述两类故障切换机制都会被持续误触发 →
  使得 DirectLink 链路看起来"不可靠"——这是**归因错误**，不是 DirectLink UDP P2P 的错。
- **因此 4-5s stall 是否复现，是决定是否进入 M0-4 的硬 gate**（用户 M0-3.1 §4 明确规定）。

### 4.2 Twingate "store-load reordering race → TCP upload stalls" — **MEDIUM**

与 4.1 独立，但同样影响 TX/RX 并发高压力场景；M0-4 阶段 DirectLink 以 UDP payload 为
主，TCP 压力在 M0-5 Noise + M0-7 才会真正出现。登记 Known Risk，M0-4 30 分钟压力测试
同步观测 TCP ICMP 模式下是否命中。

### 4.3 Minor：官方未在 0.14.1 后打任何 Security Patch（5 年 window）— **LOW**

Wintun 驱动运行在 Ring 0；5 年内无 security backport。但 M0 我们不接受非 Wintun 签名的
包，RX 入口有 classify() 校验 + PacketBuffer owned 拷贝 + 长度限制（≤64K），用户态
攻击面已经被我们自身的 hardening 收缩。登记为 LOW，后续升级时评估。

---

## 5. 30 分钟 VNIC latency stall stress test（M0-3.1-4b gate）

### 5.1 实验环境要求
- IsAdmin = True；Wintun 0.14.1 DLL SHA256 match = confirmed
- Windows ≥10 22H2 / Rust 1.98.0-msvc / M0-3.1 全部新接口（Mutex + Owned Buf + 四分类）
- `MESH_VNIC_E2E=1` + `--test-threads=1`（并发 adapter 同 V-04 全局损坏风险）
- 单机同进程模拟，或 VNIC ping.exe -t -l 1472 10.70.31.1 回环

### 5.2 测试负载
- Phase A 持续高频：2k pps × 64B ICMP echo request 注入 VNIC + 每包 receive 回 TX 环
  形成 ping-pong；
- Phase B idle/burst cycle：sleep 200ms idle → 4k pps × 2s burst 循环（专用于复现
  missed-wakeup 的 idle→burst 切换窗口）；
- Phase C 并发压力：4 独立线程并发 TX queue 注入 256~1400B 随机 PacketBuffer；
- 总时长：**≥30 分钟**（1800 秒）；覆盖白天夜间各种 Windows 后台调度噪声。

### 5.3 测量指标（每包 TX timestamp → RX receive_time diff = delivery latency）
- P50 / P95 / P99 / Max 分位数延迟（单位 µs）
- stall_gt_1s_count：延迟 >1,000,000 µs 次数
- stall_gt_3s_count：>3,000,000 µs 次数
- stall_gt_4s_count：>4,000,000 µs 次数（**决策 gate**）
- Windows 事件日志同步采集：Wintun Adapter TDR、NDIS reset、Memory 异常（用于排除假 stall =
  Windows 自身挂起，不是 Wintun 的 race）。

### 5.4 验收判定
- **Green**：stall_gt_4s_count == 0 → 按 Known Risk 进入 M0-4
- **Yellow**：stall_gt_4s_count 1~2 次，但无法稳定复现 → 追加一轮 30 分钟，若第二
  轮仍 ≤2 → 记录 Known Risk + 在 Path Manager 侧增加 1s 阈值 Keepalive 重试容忍窗口，
  不阻塞 M0-4
- **Red（硬 gate 阻塞 M0-4）**：stall_gt_4s_count ≥ 3 且连续可稳定复现 → 暂停 M0-4，
  单独拉 WINTUN_VERSION_UPGRADE ADR，三选一方案进入（等官方 release / 自编译 master
  snapshot 签名 / mesh-vnic 加 RX WaitForMultipleObjects 轮询超时守护）。

---

## 6. 缓解措施（在 meshlink 层，不等官方 patch）

即使 0.14.1 不包含 race fix，在用户态 mesh-vnic 层已经落地的防御（M0-3.1 + 原 M0-3）：

1. **RX WaitForMultipleObjects INFINITE → 追加可选 500ms timeout 轮询（仅当未来 Yellow）**：
   当前代码保持 INFINITE（省电 + 低延迟）。一旦 30min stress Yellow，用 `cfg(feature =
   "wintun_stall_workaround")` 门控把 INFINITE 改成 500ms `WaitTimeout` → drain
   `receive_packet()` 再 sleep 1ms → 解决 "last packet before idle 被丢失唤醒" 的窗口。
   当前默认 OFF（不做 speculative pessimization）。
2. **Hard Failure 与 Quality Degradation 双机制隔离（M0-2 已冻结）**：DirectLink 真正
   crash 触发 Hard Failure（Fatal 事件）立即 1s 内熔断切换；VNIC stall 属于 Quality
   Degradation（Keepalive timeout 累积，不立即误判为 DirectLink 崩溃）。即使 1-3s
   stall，Path Manager 不产生 False Positive Hard Failure。
3. **Path Switching Matrix 设计（M0-7）**：DirectLink → N2N P2P → Primary SN → Backup SN
   → CF Relay。即使 DirectLink 被 VNIC stall 误降级，仍保证 overlay 总不中断（降速而
   不中断）。
4. **Metrics 细粒度 rx_dropped_malformed 与 _unsupported 分离（M0-3.1-3 已落地）**：不
   会再把 IPv6/组播这种合法 Windows 正常流量算进损坏率，Path Health 指标被污染风险已
   从 V-04 事故版本降为 0。

---

## 7. 未来升级条件（什么时候允许从 0.14.1 移走）

**必须** 以下全部满足，且写独立 `ADR-XXX WINTUN_VERSION_UPGRADE.md` 评审通过：

1. **版本条件**（二选一）：
   - (a) wintun.net/builds 发布了新的 **Stable release ≥ 0.14.2**，且 Prebuilt Binaries
     License 保持 8 条款无额外限制；**OR**
   - (b) 团队对 master 某个 tag/sha（如 ≥ec0a6b9 race fix + TCP store-load fix）自行编译
     Windows 驱动并获得 EV Code Signing 签名（不能 self-signed，必须 WHQL 或合法 EV 签
     名驱动；Windows 11 强制 HVCI 不加载未签名驱动）。
2. **哈希校验**：ZIP + DLL 双 SHA256 存入 `third_party/wintun/SHA256SUMS`，与官方发布
   的 hash 或自编译的二进制哈希一致。
3. **许可合规**：如果用自编译，必须遵守 Wintun source code GPL-2.0 全部义务（不是
   Prebuilt Binaries License）——包括对 meshlink 分发的 copyleft 影响评估（法务 review
   通过）。NOTICE.md 同步更新许可表述。
4. **全量回归**：重跑 M0-3 全部 9/9 E2E 393 秒（9/9 必须 PASS）+ M0-3.1 全部 7 项
   验收（Mutex/Released/Owned/RxDrop/30min Stall/License/BuildTest）全 PASS。
5. **ABI 兼容性**：`wintun.h` 签名与结构体布局变化 → mesh-vnic 的 FFI extern block
   与 repr(C) 结构断言必须全部重新检查（`size_of` / `offset_of` 13 项断言通过）。
6. **30min Stall Test Red：** stall_gt_4s_count 必须 = 0（升级就是为了修这个 race）。

---

## 8. 后果（Consequences of Accepting This Known Risk）

**Good：**
- M0-4 可以按原计划启动 DirectLink ICE PoC，不被单个驱动的已知问题阻塞。
- 所有风险显式登记，后续归因有据可依，Path Health 与 Metrics 模块可以针对性排除
  "wintun stall" 作为直接的 network quality damage 指标。

**Bad（显式告知而不是假装不存在）：**
- 如果 M0-4 真实双机 UDP P2P 场景下观测到 4s 级 RTT 毛刺，无法立即判断是 DirectLink
  NAT 穿透失败、对端 NAT mapping 失效、还是 Wintun stall——必须交叉比对 VNIC
  `stall_gt_4s_count`、Windows 事件日志、PacketBuffer 实际到达时间戳才能归因。
- 如果在 M0-7 合路测试里多次出现 "DirectLink 假超时→ Provider 切换→ 2 秒后恢复" 抖动，
  需要把 §6.1 的 `wintun_stall_workaround` feature 提前启用，并在 M0-7 验收报告中单列
  归因。

---

*本 ADR 在 M0-3.1 30 分钟 VNIC stall stress test 结果填入 §5.4 后正式 Accept。未填
结果前维持 Proposed 状态。*
