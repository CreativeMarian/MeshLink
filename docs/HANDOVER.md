# MeshLink (NtNTier) 交接文档

- 交接时间：2026-08-30
- 交接状态：M0-4R.2 = CODE PASS（用户已验收）；M0-4 = CONDITIONALLY PASSED；ADR-003 = Proposed；M0-5 = 已获准启动（下一步开发目标）
- 工具链：Windows + MSVC（rust-toolchain.toml 固定），`cargo build --release` 全绿，workspace 测试 **95/95 PASS**
- 本文档目的：让任何新会话/新接手者无需回溯历史对话即可继续开发

---

## 1. 项目目标与产品形态

MeshLink：Windows 端 P2P 虚拟局域网产品。普通用户在两台电脑上安装客户端，一方创建连接码、另一方输入，即可自动建立 Noise 加密的 P2P 隧道并获得 Wintun 虚拟 IP，实现互相 Ping / 文件共享等能力。

**MVP Target Gate（产品级验收线）**：

```text
电脑A安装 MeshLink → 创建6位码 → 电脑B输入 → 自动连接 → Noise加密
→ 获得虚拟IP → 能够互相 Ping
```

- P2P 失败时明确显示 `DIRECTLINK_FAILED`，后续由 N2N/Supernode/Relay 兜底
- 不因某些 NAT 组合直连失败阻塞 MVP
- 开发原则：先把第一版完整做出来，真实用户发现问题后针对性修复

**产品路线图（顺序）**：
M0-5 DirectLink Security → Controller MVP → 6位连接码 → Friend Invite → MeshAgentService → Windows Tauri 客户端 → Wintun Overlay IP → 真正双机虚拟局域网 → 文件共享 → MeshTransfer → N2N/Supernode → Cloudflare Relay

---

## 2. 开发纪律（2026-08-30 用户发布，长期有效，最高优先级）

1. **本机可自动完成的测试全部由 AI 自己执行**，不得要求用户操作：单元/集成测试、loopback、VM、模拟网络、故障注入、静态检查、build、cargo test、Controller API、数据库并发、UI 流程、安装/卸载、服务启动、Wintun 生命周期。
2. **真实双机/真实外网测试**仅在满足以下之一时才可要求用户参与：
   - A. 当前问题会阻塞后续开发；
   - B. 两个架构方案必须靠真实数据才能选择；
   - C. 已完成可用版本，需要最终验收。
   除此以外一律标记 `PENDING_REAL_WORLD_VALIDATION` 后继续开发。
3. 禁止为了"补齐测试矩阵"阻塞产品开发。不为覆盖所有 NAT 让用户反复换网络/换设备跑几十轮。
4. 后续真实网络测试策略：遇到真实 Bug → 收集日志 → 定位 → 修复 → **只做针对性复测**。
5. 用户手工测试必须 **≤3 步**（例：①双击程序 ②输入连接码 ③把日志 ZIP 发回来）。禁止让用户跑 cargo 命令、开多终端、改参数、同步目录、跑20轮、手抄日志——这些必须由测试工具自动完成。
6. 每个开发阶段完成后按 **7 项报告**：完成内容 / 修改文件 / 编译 / 单测 / 自动实机验证 / 未解决问题 / 下一步。需要用户参与的验证单列 **MANUAL TEST REQUIRED**；不阻塞开发的只记录、不要求立即执行。

---

## 3. 里程碑状态总表

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0-0/M0-1 | 工程骨架、transport-api、mesh-common | PASSED |
| M0-2 | Circuit Breaker（纯状态机，FakeClock 注入，26 项场景单测，4 Scope 隔离） | PASSED |
| M0-3 | Wintun VNIC 抽象（0.14.1 签名 DLL、SHA256 校验、RAII、RX/TX worker、24 单测 + 9 实机 E2E） | PASSED |
| M0-3.1 | VNIC Hardening（跨进程 Adapter 互斥、RecvPacketGuard 边界、RX Drop 四分类、风险 ADR） | PASSED |
| M0-4 | DirectLink ICE 双轨 PoC（Track A = rtc-ice 0.20.4 封装；Track B = MinimalPunchAgent） | **CONDITIONALLY PASSED**（足够继续主线） |
| M0-4R | 真实网络测试体系（result.json、真重建轮次、run-test.bat 朋友工具） | CODE PASS |
| M0-4R.1 | Test Harness Hardening（统计口径、Session Code v3、候选过滤/优先级、环境快照、结果 ZIP） | PASSED（95/95） |
| M0-4R.2 | 双向 simultaneous punch 修正 + PunchEvidence 时间证据 | **CODE PASS（当前最新交付）** |
| **M0-5** | **DirectLink Security：Noise_IK / X25519 / AEAD / Replay / Rekey** | **← 下一步，已获准启动** |

---

## 4. Workspace 结构

```text
crates/
  mesh-common/       错误/事件/日志基础件（ErrorCode、TransportEvent、logging）
  transport-api/     TransportProvider trait、TransportConfig/PeerHints/Endpoint 等统一接口
  circuit-breaker/   纯状态机熔断器（CLOSED/OPEN/HALF_OPEN，FakeClock，BreakerKey 4 Scope）
  config-manager/    配置管理
  secure-store/      安全存储
  metrics/           指标
  mesh-vnic/         Wintun VNIC 抽象（adapter/api/ip_config/packet/session/vnic + RX/TX worker）
  directlink/        DirectLink P2P 传输（本交接核心）
    src/ice/         agent.rs=Track B MinimalPunchAgent；webrtc_track.rs=Track A rtc-ice 封装；
                     stun.rs=RFC5389/5780 子集+MeshCandidates；candidate.rs=候选+接口元数据；
                     ifinfo.rs=网卡分类(Physical/Virtual)；mtu.rs=MTU 阶梯
    src/transport.rs DirectLinkTransport（dispatcher、双向 punch、会话、PunchEvidence）
    src/bin/directlink_poc.rs  PoC CLI：create/join/matrix/nat-behavior（~2200 行）
    tests/           dual_track_loopback.rs、gate_webrtc_boundary.rs（依赖边界门禁）
  overlay-router/    Overlay 路由（骨架）
  transport-n2n/     N2N Provider（桩，保持 OFF）
  transport-cf-ws/   Cloudflare Relay Provider（桩，保持 OFF）
  mesh-agent/        Agent 骨架
server/controller/    Controller（Go，main.go + controller.exe）
schemas/             api/config/frame/identity schema（frame/directlink_frame_v1.md）
docs/adr/            ADR-001 WINTUN_ADAPTER_IDENTITY / ADR DIRECTLINK_ICE(003) /
                     NOISE_KEY_LIFECYCLE（M0-5 必读）/ WINTUN_VERSION_RISK
MeshLink-PoC/        朋友测试包：directlink-poc.exe + run-test.bat(纯ASCII) + run-test.ps1(UTF-8 BOM)
third_party/wintun/  Wintun 0.14.1 官方签名 DLL（SHA256SUMS 校验）
```

---

## 5. DirectLink 架构要点（Track B 主线）

### 5.1 硬性不变式（违反即事故）

1. **单 socket**：STUN / punch / response / data / keepalive 全部走同一个 UDP socket（base port）。
2. **loopback 候选禁止**：offer/answer 中不得出现 127.0.0.1（曾导致假成功：对端打自己的 socket）。
3. **远端候选是不可信输入**：过滤 loopback/unspecified/multicast/broadcast，保留私网单播（10/8、172.16/12、192.168/16，Same LAN 需要）；记录 `candidate_rejected_reason`。
4. **虚拟接口降权**：Physical(126) > srflx(100) > Virtual(80)；MeshLink 自己的 Wintun/TUN/TAP 一律排除（防递归路由）。
5. **session demux**：probe 的 USERNAME 必须 == `meshlink-poc:{session_id}:{nonce}` 精确匹配才建会话；keepalive（`meshlink-keepalive`）不触发重建；禁止回退全局匹配。
6. **Session Code v3**：`schema_version/session_id/issued_at/expires_at(10min)/nonce/creator_device_id/track/host_candidates/srflx_candidates`；过期返回 `SESSION_CODE_EXPIRED`；非法输入统一 `SESSION_CODE_INVALID`+reason，永不 panic。
7. **N2N/Supernode/CF-Relay/TURN/TCP-Relay 全 OFF**，失败必须显式 FAIL。
8. **测试轮次真重建**：新 socket、新端口、重 STUN、重 exchange、重 punch，轮间 500-3000ms 随机间隔；round 0 = cold，其余 warm。

### 5.2 双向 simultaneous punch（M0-4R.2 交付，当前实现）

- **join 端**（`connect_peer` → `punch_with`）：每个 probe 携带 `MeshCandidates` 属性（本端物理 host + srflx），主动向对端候选出站 probe（阶梯重传）。
- **creator 端**（`start_accepting` → dispatcher）：收到**精确匹配 session tag** 的首个 probe 后：
  1. 立即回 Binding Response（XOR-MAPPED=观察源）；
  2. `ensure_session` 建会话（remote_kind 按对端候选集匹配来源得出，未命中记 prflx）；
  3. `spawn_reverse_probe`：向 [probe 源 + 对端候选集] 主动反向出站，间隔 T+0/100/250/500/1000/1500/2000/2500/3000ms，收到任一 response 即确认 bidirectional reachability 后停止。
- 等待期 `spawn_stun_refresh` 每 20s 向 STUN 发 Binding 刷新本端 NAT 映射（修复 create 静默等待映射过期问题）。
- 设计必然性说明：creator 反向出站以收到 join 候选集为前提（候选集随 join probe 携带），故 creator 的 `first_peer_rx` 必然先于其 `first_punch_tx`；join 端则 `first_punch_tx < first_peer_rx`。两者合并 = 双方都主动出洞。

### 5.3 PunchEvidence 时间证据（M0-4R.2 §三，仅诊断字段）

- 位置：[transport.rs](../crates/directlink/src/transport.rs) `PunchEvidence`；打点：join=connect_peer 锚点→punch_with 首次出站→dispatcher 收到 session probe；creator=start_accepting 锚点→收 probe→spawn_reverse_probe 首次出站。
- 每轮 result-rNN.json：`punch_evidence: {role, anchor_epoch_ms, first_punch_tx_ms, first_peer_rx_ms}`，**成败轮都记录**；控制台每轮打印 `[punch-evidence] role=… first_punch_tx=+Xms first_peer_rx=+Xms`；client.log 有 `PUNCH_EVIDENCE FIRST_PUNCH_TX / FIRST_PEER_RX` 行。
- 两侧时钟不同步：相对毫秒只做同端先后证明，epoch 仅留档。

### 5.4 Track A（对比轨，保留不冻结）

- rtc-ice 0.20.4 **sans-io** Agent 封装（[webrtc_track.rs](../crates/directlink/src/ice/webrtc_track.rs)）：自有 socket + 阻塞驱动循环，单 host candidate 注册、srflx 同 socket gather、对端发往 srflx 的检查走 peer-reflexive 路径。
- 支持 `peer_reflexive_candidates` 记录与 `selected_pair_origin`（host/srflx/prflx）。
- rtc-ice 符号只允许出现在 directlink crate 内（`gate_webrtc_boundary.rs` 用 cargo tree 门禁强制）。

### 5.5 PoC CLI（MeshLink-PoC/directlink-poc.exe）

```text
directlink-poc.exe create --track b|a [--port 42000] [--keepalive-ms 15000] [--mtu-test] [--answer <code>]
directlink-poc.exe join <code> [--port 42000] [--report] [--idle-test 30,60,120] [--roam-test] [--mtu-test] [--test-id <id>] [--profile same-lan|home-mobile|home-home] [--smoke-threshold 95] [--friend]
directlink-poc.exe matrix --track b|a --rounds 20 --exchange <dir> --side a|b [--report] [--test-id <id>] [--profile ...]
directlink-poc.exe nat-behavior        # RFC5780 可选诊断；server 不支持 OTHER-ADDRESS 时输出 UNVERIFIED（预期行为，不阻塞主线）
```

- `--side a` = creator，`--side b` = joiner；exchange 目录自动交换 offer-rN.json / answer-rN.sig|json / punchok-rN.sig / done-rN.sig。
- run-test.bat（纯 ASCII）→ run-test.ps1（UTF-8 BOM）：朋友模式 [UI] 输出、代码保存记事本打开、一键打包 `MeshLink-Test-<test_id>.zip`。

---

## 6. 测试与报告体系

- **统计口径**：`connection_success_rate` 与 `data_smoke_success_rate` 分列；每轮记录 `smoke_packets_expected/tx/rx/lost/loss_percent`；`round_success = connect AND selected_pair confirmed AND smoke rx ≥ threshold`（默认 100%）。
- **result-rNN.json 关键字段**：test_id、round、timestamp、track、engine、session_id、local/remote candidates、selected_pair_type/origin、candidate_attempt_order、candidates_rejected、punch_evidence、error_stage/error_code、start_type(cold/warm)、profile、relay_used=false。
- **summary-a|b.json**：成功率、connect/gather P50/P95、smoke 汇总、cold/warm 分组。
- **network_snapshot.json**：os_version、app_version、git_commit、local_interfaces、default_route、stun_server、firewall、network_profile、vm/vpn detected。
- 已知环境观察：本机经 CGNAT 映射 `112.90.163.244:24675`；朋友侧 `101.75.142.29`；默认 Google STUN（74.125.250.129:19302）**不支持** RFC5780 OTHER-ADDRESS → nat-behavior 输出 UNVERIFIED 属预期。
- 报告纪律：只写 Observed Mapping / Observed Connectivity / Directional Result / Track Result / Failure Stage；**NAT filtering behavior = UNVERIFIED**（除非有 RFC5780 多 endpoint 证据），禁止直接归因 endpoint-dependent filtering。

---

## 7. PENDING_REAL_WORLD_VALIDATION（全部挂起，不阻塞开发）

按新纪律，以下项不再主动要求用户执行；仅当触发纪律条件 A/B/C 时再启用：

1. **四组实验**（环境：112.90.163.244 侧 ↔ 101.75.142.29 侧；N2N/Supernode/CF/TURN/TCP 全 OFF）：
   - A：你 create / 朋友 join，Track B 双向，20 轮
   - B：朋友 create / 你 join，Track B 双向，20 轮
   - C：你 create / 朋友 join，Track A，20 轮
   - D：朋友 create / 你 join，Track A，20 轮
   - 判读：双向修正后成功→归因旧版单边 punch 不足；B 失败 A 成功→Track A 选型证据；都失败→STUN-only 不可达交 Relay 兜底；换角色结果不同→记 Directional Asymmetry Observed。
2. Same LAN 真实双机矩阵（VMware Bridged 样本仅作 Integration Validation，不进正式成功率）。
3. Home↔Mobile / Home↔Home 矩阵、10min Keepalive、漫游切换、MTU 阶梯实测。

若未来恢复执行，命令模板（两端各一窗口，exchange 用双方可实时同步的独立空目录，测试 1 轮先验证 `[punch-evidence]` 输出正常）：

```text
creator: directlink-poc.exe matrix --track b --rounds 20 --exchange <dir> --side a --report --test-id retestA-tb --profile home-home
joiner:  directlink-poc.exe matrix --track b --rounds 20 --exchange <dir> --side b --report --test-id retestA-tb --profile home-home
```

朋友机器**必须使用最新 exe**（旧版一侧 = 单边 punch，数据无效）。

---

## 8. 下一步：M0-5 DirectLink Security（技术要点）

目标：为 Track B 数据面提供密码学安全，与 NAT traversal 正确性解耦。

- **必读**：[NOISE_KEY_LIFECYCLE.md](adr/NOISE_KEY_LIFECYCLE.md)（已有 ADR 草案）、[directlink_frame_v1.md](../schemas/frame/directlink_frame_v1.md)。
- 核心组件：Noise_IK（建议 `snow` crate，`StatelessTransportState` 或 handshake 状态机）、X25519 静态密钥、AEAD（ChaCha20-Poly1305/AES-GCM）、Replay 窗口（sliding window）、Rekey（周期/字节数阈值）。
- 关键设计点（待实施时细化）：
  1. 密钥分发：creator 静态公钥随 Session Code v3 携带（新增字段 + 指纹校验），join 用临时密钥对发起 IK handshake；
  2. 帧复用：dispatcher 需区分 STUN / Noise handshake / 加密数据帧 / MTU probe（新帧 magic，参考 directlink_frame_v1）；
  3. 加密在 punch 成功后、数据面之前建立； handshake 也走同一 UDP socket；
  4. M0-3.1 的 Circuit Breaker Scope 与 transport-api 事件保持一致；
  5. 单测必须覆盖：握手成功/失败、replay 丢弃、乱序窗口、rekey 平滑切换、错误密钥拒绝（loopback 双进程自动验证，不需要真实双机）。

---

## 9. 关键文件索引（最近改动）

| 文件 | 内容 |
|---|---|
| crates/directlink/src/transport.rs | dispatcher、双向 punch（spawn_reverse_probe/spawn_stun_refresh）、PunchEvidence、connect_peer、ensure_session |
| crates/directlink/src/ice/agent.rs | punch_with（含 extra_attrs/MeshCandidates）、Keepalive、NAT mapping 观测 |
| crates/directlink/src/ice/webrtc_track.rs | Track A 封装、selected_pair_origin、prflx 记录 |
| crates/directlink/src/ice/stun.rs | STUN 编解码、OTHER-ADDRESS/CHANGE-REQUEST、MeshCandidates |
| crates/directlink/src/bin/directlink_poc.rs | CLI 全部命令、matrix_round_a/b、Session Code v3 校验、attach_punch_evidence |
| MeshLink-PoC/run-test.ps1 / run-test.bat | 朋友工具（[UI] 输出、ZIP 打包、隐私说明） |
| docs/adr/DIRECTLINK_ICE.md | ADR-003（Proposed；NAT filtering=UNVERIFIED 口径） |
| docs/adr/NOISE_KEY_LIFECYCLE.md | M0-5 输入 |
| server/controller/main.go | Controller 骨架（Go） |

## 10. 构建与验证命令（AI 本机自动执行）

```text
cargo build --release                     # 全 workspace
cargo test --workspace                    # 95/95 PASS（mesh-vnic real_machine 14 项 ignore 属预期）
cargo build --release -p directlink --bin directlink-poc
Copy-Item target\release\directlink-poc.exe MeshLink-PoC\directlink-poc.exe
MeshLink-PoC\directlink-poc.exe nat-behavior   # 快速网络自检（可选）
```

## 11. 经验教训速查

- run-test.bat 必须纯 ASCII；run-test.ps1 必须 UTF-8 with BOM（PowerShell 5.1 按 ANSI 解析会乱码）。
- VMware NAT 模式打洞必败，Same LAN 实验需桥接模式。
- 外来 STUN 包（USERNAME != meshlink-poc）会污染 session——dispatcher 已严格过滤。
- MIB_IFROW ABI：dwDescrLen 在 bDescr 之前，bDescr 是内联 [u8;256] 不是指针（size 860 断言）；OPER_STATUS 4/5 均视为 up。
- 控制台粘贴长连接码会截断——打印长度对比 + 解析失败自动重试。
- matrix 信号文件：.sig（文本信号）与 .json（JSON 校验）后缀不可混用，否则 wait_file 误判半截文件。
- 端口占用（10048）要给出友好报错，不允许 panic。
