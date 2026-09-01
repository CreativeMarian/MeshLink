# ADR-003: DirectLink 连通性引擎选型（Track A Standards-based ICE vs Track B Purpose-built UDP Hole Punch Engine）

- 状态：**Proposed → Final Gate 评审中**（本机验证全绿；真实双机矩阵完成后冻结为 Accepted）
- 日期：2026-08-30（Final 版）
- 决策人：M0-4 里程碑
- 关联任务：M0-4 DirectLink Connectivity PoC；ADR-002 WINTUN_ADAPTER_IDENTITY；技术设计 `docs/TECH_DESIGN_M0.md` §2.5
- 实测工具：`directlink-poc.exe`（create / join / matrix，普通人可操作；工具内**无任何中继兜底**）

---

## 1. 背景（Why）

DirectLink 是五级路径的**首选路径**（DirectLink → N2N P2P → Primary SN → Backup SN → CF Relay），
其连通性建立在 STUN / UDP Hole Punch 之上。M0-4 以**双轨 PoC** 同条件对比：

- **Track A**：`rtc-ice 0.20.4`（webrtc-rs 拆分后的独立 sans-io ICE crate，技术设计冻结版本）
- **Track B**：自研 MinimalPunchAgent（STUN-assisted UDP Hole Punching）

M0-4 范围约束（用户冻结）：**不做 Noise（M0-5）、不做 N2N（M0-6+）、不做 Cloudflare Relay / TURN**；
只验证 STUN/ICE/UDP Hole Punch + Keepalive + NAT Mapping 观测 + MTU 探测。

## 2. 命名准确性决议（Final Gate §二）

对 Track B 逐项核对 RFC 8445 ICE Full Agent 要素：Candidate Pair 打分 / Checklist、Triggered Check、
Controlling/Controlled 角色仲裁、Tie Breaker、Nomination（USE-CANDIDATE）、ICE-CONTROLLING /
ICE-CONTROLLED 属性、USERNAME/MESSAGE-INTEGRITY——**均未实现**。

**结论：Track B 不是 ICE。** 文档与代码一律命名：

- Track B = **MinimalPunchAgent**（代码）/ **Purpose-built UDP Hole Punch Engine**（文档）
- **禁止**称 "Custom ICE" / "精简 ICE" / "ICE 实现"（其完整性由 M0-5 Noise 层取代）
- 本产品不强制使用完整 ICE；MinimalPunchAgent 的 simultaneous open + STUN Binding 子集
  对 direct-first 拓扑已足够（对比见 §4/§8）

## 3. Track A 架构（冻结定义）

- `rtc-ice 0.20.4` **仅使用独立 ICE/STUN 能力**。
- 不引入：完整 rtc、DTLS、SCTP、DataChannel、RTP、SRTP、SDP（rtc-ice 自身内部依赖除外）。
- 其他 crate 禁止依赖 rtc-ice——由 `tests/gate_webrtc_boundary.rs` cargo tree 反向树门禁强制。
- directlink 内部封装：`src/ice/webrtc_track.rs`（320 行）——自有 UDP socket +
  `handle_timeout`/`handle_read`/`poll_write` sans-io 驱动循环 + srflx gathering。

## 4. Track B 架构（MinimalPunchAgent）

`src/ice/{stun,candidate,agent,mtu}.rs`（1250 行，注入式 send/recv 闭包，**零外部依赖**）：

- RFC 5389 客户端子集：Binding Request/Response、XOR-MAPPED-ADDRESS、FINGERPRINT
  （按 RFC 5769 §2.2 官方向量校验）
- **真双向 simultaneous punch（M0-4 修正，§4.1）**：双方都主动出站 probe，非单边打洞
- Keepalive：间隔/miss 可配（miss 超限回调 down → 熔断事件）
- NAT 映射观测：双 STUN server 映射比较，保守二分类 + Observed Mapping 明细（§7）
- MTU 阶梯回显探测（§12）
- 帧分派：单 socket 复用（STUN / MTU echo `[0x4D54][len][payload]` / IPv4 数据帧）

### 4.1 真双向 simultaneous punch（M0-4 架构修正）

**背景**：实测前版本的 punch 流程为 join 单边主动、creator 被动回应——不构成 simultaneous
open，对 filtering 型 NAT 缺少出站打洞动作。已在 M0-4 内修正（不得推迟到 M0-5，M0-5 是
Security Layer，与 NAT traversal 正确性无关）：

1. **Candidate Exchange 逆向通道**：join 侧每个 punch probe 以自定义属性
   `MESH-CANDIDATES`（0x8050，≤8 条 × 7B ip/port/kind）携带本端候选集（物理 host + srflx，
   虚拟接口剔除）；creator 收到首个合法 probe 后据此获得对端可达地址。
2. **双向主动 probe**：join 侧 `punch_with` 持续主动出站；creator 侧 dispatcher 立即回应
   Binding Response 的同时启动 `spawn_reverse_probe`——对 [probe 源地址] + 对端候选集
   按 T+0/100/250/500/1000/1500/2000/2500/3000ms 阶梯主动出站，收到任一有效 response
   即确认 Bidirectional Reachability 后停止。
3. **同一 socket**：STUN / punch / response / data 全部经 transport 唯一 socket
   （§5 硬规则不变，未为双向 punch 开第二个 socket）。
4. **Session demux 严格化**：punch tag = `meshlink-poc:{session_id}:{nonce}`；dispatcher
   **只接受 USERNAME 精确等于本端 accept tag 的 probe** 建会话（不回退全局
   `meshlink-poc` 匹配）；非本 Session 请求仅回应不建会话。
5. **等待期映射保活**：create 端 accept 等待期间周期向 STUN server 发 Binding 刷新本端
   NAT 映射（修复 join 到达前映射过期问题）；首个会话建立后由 keepalive 接管。

## 5. 硬性要求：srflx 与业务 socket 同源（Final Gate §三）

**两条 Track 都满足：创建 UDP socket → bind 0 → 取真实 local port → 同一 socket 发 STUN Binding
得 srflx → 同一 socket connectivity check / punch → 同一 socket P2P payload → 同一 socket Keepalive。**

- Track B：srflx / punch / keepalive / 数据帧共用 transport 的唯一 socket；
  NAT 观测、srflx、打洞、keepalive 全部经 dispatcher 单 socket（`transport.rs`）。
- Track A：`gather_srflx()` 用 Agent 自有 socket（`webrtc_track.rs`），并内嵌
  `debug_assert`（srflx gathering 端口 == local_base 端口，拆 socket 即 fail）。
- 本机实测证据：`[cand] host 192.168.10.147:57677 (base …) / [cand] srflx 112.90.163.244:25402
  (base 192.168.10.147:57677)`——srflx base 与 host base 同端口（同一 socket）。

## 6. 依赖树 / 代码量 / 二进制增量

**Track A 依赖家族**（仅 directlink crate 内可见）：

```text
rtc-ice 0.20.4
├── rtc-mdns 0.20.4 ── rtc-shared 0.20.4
├── rtc-stun 0.20.4 ── rtc-shared / sansio 1.0.1
├── rtc-shared 0.20.4
└── sansio 1.0.1
+ bytes 1.x（调用方驱动 I/O）
```

**Track B**：0 外部依赖（纯 std）。

代码量（directlink crate，`cargo test --workspace 91 绿` 基线）：

| 模块 | 行数 | 归属 |
|---|---|---|
| `ice/agent.rs`（MinimalPunchAgent） | 477 | Track B |
| `ice/stun.rs` | 454 | Track B |
| `ice/candidate.rs` | 170 | Track B |
| `ice/mtu.rs` | 125 | Track B |
| `transport.rs`（TransportProvider 接线） | 710 | 共用 |
| `ice/webrtc_track.rs` | 320 | Track A |
| `bin/directlink_poc.rs`（实测工具） | 735 | 共用 |

二进制增量：`directlink-poc.exe`（release，MSVC）**1.7 MiB**（含 Track A 冻结依赖 + Track B + 工具）。

## 7. NAT 类型观测纪律（Final Gate §五）

仅普通 RFC 8489 STUN Binding **不允许**宣称 Full/Restricted/Port-Restricted/Symmetric cone。
PoC 输出纪律：

- 双 server 可达 → 保守二分类（EndpointIndependent / AddressDependent）+ Observed Mapping 明细；
- 单 server 可达 → **仅记 Observed Mapping**，分类 = UNKNOWN（不做任何行为结论）；
- 需要 RFC 5780 行为发现（区分 ADM/SDM、filtering）→ 留待 M1 部署支持 CHANGE-REQUEST 的 STUN 服务。

本机实测样例（单 server 可达，cloudflare DNS 失败 → 保守 UNKNOWN）：

```text
[NAT] Track B (MinimalPunchAgent): Unknown
[NAT]   Observed Mapping: 74.125.250.129:19302 → 112.90.163.244:25402
```

## 8. 真实测试矩阵（Final Gate §八/§九）

每个场景两条 Track 各 ≥20 轮独立连接重建，输出：Scenario / Track / Success / gather ms /
connect ms / Selected pair / Local / Public / Remote endpoint / RTT P50/P95 / Loss / Jitter / TX/RX。
工具命令（两端各一条）：

```text
A 机: directlink-poc.exe matrix --track b --rounds 20 --exchange <dir> --side a
B 机: directlink-poc.exe matrix --track b --rounds 20 --exchange <dir> --side b
```

| Scenario | Track | 结果 | 20 轮成功率 | connect P50 | Selected pair | 备注 |
|---|---|---|---|---|---|---|
| 本机 loopback（协议闭环） | B | ✅ 20/20 | 100% | 1.2 ms（P95 409.9） | host↔host | gather P50 398.6ms；RTT P50 1.0ms；TX=200 RX=192（尾部轮 20% 抖动） |
| 本机 loopback | A | ✅（harness 3 轮） | — | 2.1 ms | host↔host | `dual_track_loopback.rs` |
| A. Same LAN | A/B | **PENDING_REAL_TEST** | — | — | — | 预期 host↔host |
| B. Home ↔ Mobile Hotspot | A/B | **PENDING_REAL_TEST** | — | — | — | 真实不同公网路径 |
| C. Home ↔ Other Home | A/B | **PENDING_EXTERNAL_ENVIRONMENT** | — | — | — | 最重要的真实 P2P 场景 |
| D. CGNAT | A/B | **UNKNOWN/UNVERIFIED** | — | — | — | 不凭"手机热点"断言；按 Observed Mapping 与运营商环境记录 |
| E. Symmetric / EDM | A/B | **Not available in current lab** | — | — | — | 非阻塞项；ADR 如实记录 |

> loopback 数据只证明协议闭环正确，不代表真实 NAT 成功率。Accepted 前置条件 = 上表真实行完成。
> 决策优先级（用户冻结）：①真实 NAT 成功率 ②稳定性 ③协议正确性/安全边界 ④复杂网络恢复
> ⑤维护成本 ⑥依赖/二进制 ⑦连接耗时 ⑧CPU。**loopback 0.5ms vs 2.1ms 无决策意义。**

### 8.1 公网失败观察纪律（禁止未证实归因）

当前真实公网环境（家庭宽带 ↔ 朋友家庭宽带）曾出现 Track B punch_timeout。可确认事实：

1. Same LAN host↔host 双机链路成功（VMware Bridged，Integration Validation 性质）；
2. 公网环境 Track B 失败于 punch_timeout（修正前单边 punch 版本）；
3. 双方 STUN 均成功获得 srflx；
4. 无任何 Relay 参与；
5. 双方最终未建立可用 UDP 数据通道。

**不可确认（未做 RFC 5780 Behavior Discovery / 多 Endpoint 实验）**：
creator 一侧是 endpoint-dependent filtering；该 CGNAT 只允许 STUN server 来源入站。

Mapping Behavior 与 Filtering Behavior 是两件不同的事。在完成行为发现实验前，ADR 统一表述：

```text
NAT filtering behavior = UNVERIFIED
Observed symptom: remote srflx connectivity check timed out.
```

后续报告只允许记录：Observed Mapping / Observed Connectivity / Directional Result /
Track Result / Failure Stage；**仅在有充分实验证据时**才给 NAT Behavior 分类。
「手机热点通常更友好」一类预设一律删除——移动网络同样常见 CGNAT / endpoint-dependent
行为 / 运营商 UDP 限制，Home↔Mobile 只是另一种高价值真实样本，以结果为准。

### 8.2 失败环境四组实验（M0-4 当前 Gate，完成前不进入 M0-5）

同一组两台真实电脑、同样网络、同样 STUN server、同样 timeout、各 20 轮：

| Exp | create | join | Track | punch 模式 | 状态 |
|---|---|---|---|---|---|
| A | 本机 | 朋友 | B | 双向 simultaneous | **PENDING** |
| B | 朋友 | 本机 | B | 双向 simultaneous | **PENDING** |
| C | 本机 | 朋友 | A (rtc-ice) | 标准 ICE checks | **PENDING** |
| D | 朋友 | 本机 | A (rtc-ice) | 标准 ICE checks | **PENDING** |

全部无兜底（N2N/SN/CF Relay/TURN/TCP Relay = OFF）。结果解读规则：

- B 双向修正后成功 → 此前限制来自单边 punch 算法，**不得**归因 NAT 无法 P2P；
- B 双向仍失败 + A 成功 → 标准 ICE 在该 NAT 组合显著优，Primary = Track A；
- A/B 都失败 → 当前两端 NAT 组合在 STUN-only P2P 下无路径，未来交 N2N/SN/Relay 兜底，
  **不得**写 "endpoint-dependent filtering confirmed"；
- 正反角色结果不同 → 记 Directional Asymmetry Observed，需 Behavior Discovery 才能分类。

## 9. Keepalive 10 分钟保活（Final Gate §十）

- 工具支持：`join <code> --hold-min 10`（期间仅 Keepalive，第 10 分钟 smoke packets 复验）。
- 记录项：keepalive interval / 10min session survived / mapping before / mapping after。
- 间隔扫描：5s / 15s / 30s 三档实测（`--keepalive-ms`），ADR 依结果定默认值（当前代码默认 15s，
  **不因单次测试写死**）。
- 状态：**PENDING_REAL_TEST**（本机 hold 冒烟通过）。

## 10. 网络切换（漫游）恢复（Final Gate §十一）

- 场景：B 端 Wi-Fi → P2P 建立后 → 切换手机热点 → 旧 mapping 失效。
- DirectLink 行为：检测 path lost → 旧 candidate invalid → 重新 gather（新 srflx）→ 重新 punch → 恢复；
  M0-4 **不要求 seamless migration**，但必须记录恢复时间。
- 工具支持：`join <code> --roam-test`；create 端 accept 模式自动跟随对端重连（首个打洞请求即接入）。
- 状态：**PENDING_REAL_TEST**。

## 11. 无兜底纪律（Final Gate §七）

真实测试期间：N2N=OFF / Supernode=OFF / CF Relay=OFF / TURN=OFF / TCP Relay=OFF。
`directlink-poc` 只含 DirectLink/UDP 直连路径，启动即打印兜底声明，P2P 失败**显式 FAIL**
（matrix 有失败轮次即 `exit(1)`），无任何中继兜底路径。

## 12. MTU 探测（Final Gate §十二）

- 阶梯（用户指定）：1200 / 1280 / 1300 / 1350 / 1400 / 1450（UDP payload，不含 IP/UDP 头 28B）。
- 工具支持：`join <code> --mtu-test`；最终 Overlay MTU 在 M0-7 决定，**不因一次测试写死**。
- 本机实测：`[(1200,T),(1280,T),(1300,T),(1350,T),(1400,T),(1450,T)] → payload_max=1450,
  path_mtu=1478`（loopback 无 PMTU 限制；真实路径数据 PENDING_REAL_TEST）。
- 已修复缺陷：dispatcher 曾缺回显逻辑（对端收 echo 请求被静默丢弃 → 全档超时 FAIL）→
  现按"有 waiter 投响应 / 无 waiter 整帧回显"双角色处理。

## 13. 已知失败 NAT

- 当前 lab 无法构造 Symmetric / Endpoint-Dependent Mapping 环境 → **Not available in current lab**。
- 双 NAT 打洞失败模式（ADM×ADM 组合）的实测结论依赖 §8 场景 B/C 数据。

## 14. 安全边界

- M0-4 数据帧**无加密**（明确 PoC 边界）；M0-5 Noise_IK（snow + StatelessTransportState，
  nonce=seq 从 0，prologue 绑定 `protocol_version‖network_id‖双方 device_id`）接管后的帧分派规则需重审。
- STUN/FINGERPRINT 防非 STUN 流量混淆；echo/punch 帧校验 txid/长度/来源。
- MinimalPunchAgent 无 MESSAGE-INTEGRITY——完整性由 M0-5 Noise 层取代（命名决议 §2 的组成部分）。
- rtc 系符号不越 directlink crate（门禁常设）。

## 15. 决策（What）——以真实数据终裁

当前倾向（按 §8 决策优先级，loopback 数据不构成决策依据）：

1. **若 Track B 在所有可测真实 NAT 场景成功率与 Track A 差距 ≤5% 且代码可维护 → Primary = Track B**
   （零依赖、1250 行全可审计、M0-5 Noise 定时器可精确接管）。
2. **若 Track A 明显提高真实 NAT 成功率 → Primary = Track A**（依赖多也接受）。
3. 若不同环境各有优势 → Primary/Fallback 分层（**不双轨常跑**）。

Track A 不论结果**冻结保留**于 `ice/webrtc_track.rs`（互操作交叉验证 + 未来 TCP candidate/TURN 升级参照），
不进生产调用路径；门禁常设。

**Rejected Alternative**：
- C 双轨长期并行（违背「Overlay Router 禁止 if n2n/webrtc」单一抽象纪律）；
- 完整 ICE 全家桶（rtc 全栈/DTLS/SCTP/DataChannel——M0-4 范围外，且审计面爆炸）；
- 以 loopback P50 选型（违反决策优先级）。

**Fallback 方案**：若 Track B 真实 NAT 成功率不达标且 Track A 提升有限 → M1 引入 TURN/中继兜底
（走 Cloudflare Relay 独立 Provider，不混入 DirectLink）。

## 16. M0-4 Final Gate 清单

| Gate 项 | 状态 |
|---|---|
| Track A 冻结定义（§3） | ✅ |
| Track B 改名 MinimalPunchAgent + 非 ICE 结论（§2） | ✅ |
| srflx 与业务 socket 同源 + 断言（§5） | ✅ |
| Candidate / Selected pair 完整证据输出（§8 样例） | ✅ |
| NAT 观测纪律：Observed Mapping，不宣称 cone（§7） | ✅ |
| `directlink-poc.exe` create/join Code + matrix 20 轮（§8） | ✅ 工具就绪，本机 20/20 |
| 本机 20 轮独立重建汇总 | ✅ 20/20, connect P50 1.2ms, RTT P50 1.0ms |
| MTU 阶梯 1200–1450（§12） | ✅ 本机全档通过；真实路径 PENDING |
| Keepalive 10min（§9） | 工具就绪；**PENDING_REAL_TEST** |
| 网络切换恢复（§10） | 工具就绪；**PENDING_REAL_TEST** |
| Same LAN / Home↔Mobile / Home↔Home（§8） | **PENDING_REAL_TEST / PENDING_EXTERNAL_ENVIRONMENT** |
| 无任何 Relay（§11） | ✅ |
| cargo build PASS / cargo test PASS（91 绿，MSVC） | ✅ |
| ADR 状态 Accepted | ⏳ 真实双机矩阵完成后冻结 |

## 17. 参考

- RFC 5389/8489（STUN）、RFC 8445（ICE，Track B **不满足**其 Full Agent 要素，见 §2）、
  RFC 4787（NAT 行为分类——仅保守二分类依据）、RFC 5780（行为发现，M1）、RFC 8899（PLPMTUD，M1）
- rtc-ice 0.20.4（sans-io Agent：`handle_timeout` / `handle_read` / `poll_write`）
- 实测代码：`crates/directlink/tests/dual_track_loopback.rs`、`crates/directlink/tests/gate_webrtc_boundary.rs`、
  `crates/directlink/src/bin/directlink_poc.rs`
- 技术设计：`docs/TECH_DESIGN_M0.md` §2.5（M0-4 冻结版本 rtc-ice 0.20.x）
