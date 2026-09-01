# meshlink M0 技术设计（v1.1 已确认）

> 状态：架构已经三轮确认冻结。本文为 M0 执行的唯一技术依据。
> 修订：v1.1 合并用户 4 项底层修正（Nonce/anti-replay、overlay_mac、zeroize 语义、Hard Failure vs Quality Degradation）。

## 1. 冻结的总体架构

- **单 Wintun** 唯一主虚拟网卡，MeshAgentService 独占持有；N2N/SN/CF/Controller 任一故障不影响 Wintun 与虚拟 IP。
- 三 Provider 统一 `transport-api::TransportProvider`（九方法），Overlay Router 零实现分支。
- **N2N Headless 优先**：A（库嵌入）/ B（帧通道进程）并行 PoC → ADR `N2N_INTEGRATION_ARCHITECTURE.md`；C（双 TAP）仅兜底。
- N2N 版本锁定 **3.0 Stable**（tag+commit 留档，禁止跟随 dev / 3.1.1 pre）。
- Cloudflare：Tunnel 只做控制面入口；WSS Relay 仅最终灾备。
- 五级路径默认：DirectLink → N2N P2P → Primary SN → Backup SN → CF Relay；策略可配置（DirectFirst 默认）。
- 熔断四类对象独立：`directlink.peer.*` / `n2n.provider` / `n2n.supernode.*` / `cloudflare.relay`。

## 2. 底层设计（合并修正后）

### 2.1 DirectLink 会话帧与 Nonce（修正一）

- 帧布局、prologue 绑定、replay 流程：**唯一权威 = `schemas/frame/directlink_frame_v1.md`**。
- 要点：snow `StatelessTransportState`；nonce = seq 从 0 开始（无随机偏移）；
  每方向独立 `send_seq`/`replay_window`；先预检查后解密后提交窗口；2048 位窗口。

### 2.2 overlay_mac（修正二）

- 唯一权威 = `schemas/identity/overlay_mac.md`。
- Controller 在 Device 创建时分配，hash(network_id||device_id)+counter 防冲突，
  locally administered + unicast，生命周期稳定、与虚拟 IP 无关。

### 2.3 密钥生命周期与 zeroize（修正三）

- 自持密钥：`zeroize` / `Zeroizing<T>` / `secrecy` 显式清理。
- snow 内部状态是否可靠 zeroize：M0-5 对实际版本评估；不可确认时按方案 A
  （最小 security fork 加 ZeroizeOnDrop）/ B（可控 CryptoResolver）/ C
  （ADR 记录 Known Security Risk）处理。
- 权威记录 = `docs/adr/NOISE_KEY_LIFECYCLE.md`（M0-5 产出）。

### 2.4 故障切换双触发机制（修正四）

| 触发类别 | 检测方式 | 动作 | 目标 |
|---|---|---|---|
| **Hard Failure** | Fatal 事件（进程崩溃/引擎不可恢复） | 对应 Circuit **立即 OPEN** → Path Manager **不等 3s 健康窗口** → 立即切换 | 本机明确 Provider Crash 场景 **P95 Failover ≤ 1s** |
| **Quality Degradation** | 健康评分（Critical <40 持续 3s 等） | 走文档 9.4/9.5 评分+防抖流程 | 防抖：新路径稳定 10s / 质量 +20% / 切换间隔 ≥15s / 回切 3 次探测 |

场景语义区分：

- **场景 A（Active = DirectLink）**：kill N2N / kill SN / 断 N2N Provider →
  DirectLink 业务流 0 中断、Wintun 0 中断、虚拟 IP 0 变化（N2N 非当前路径）。
- **场景 B（Active = N2N，DirectLink = READY 热备）**：kill N2N →
  N2N Provider Fatal → Circuit 立即 OPEN → 立即切 DirectLink。
  **不承诺绝对 0 packet loss**；必须记录：切换耗时、ICMP 丢包数、UDP 丢包数、
  TCP 会话是否保持、TCP 断开时恢复耗时。

### 2.5 M0 任务与依赖

| # | 任务 | 产出 |
|---|---|---|
| M0-1 | mono-repo 骨架（本任务） | workspace + 12 crates + controller + schemas + docs |
| M0-2 | transport-api 完善 + circuit-breaker 完整状态机 | 单测 100% |
| M0-3 | mesh-vnic：Wintun 生命周期/收发/MTU 压测 | 基线数据 |
| M0-4 | DirectLink ICE 双轨对比（A: webrtc-rs 0.20.x 封装 / B: 自研精简） | ADR `DIRECTLINK_ICE.md` |
| M0-5 | Noise_IK 会话加密 + 防重放 + 重握手 + zeroize 评估 | 测试报告 + ADR `NOISE_KEY_LIFECYCLE.md` |
| M0-6 | N2N 3.0 Stable 构建 + mgmt API 采集 | 版本档案 |
| M0-6A | N2N Headless A/B 对比 PoC | **ADR `N2N_INTEGRATION_ARCHITECTURE.md`（M1 硬性 gate）** |
| M0-7 | overlay-router + PathPolicy + 健康分 + 防抖 | crate |
| M0-8 | 故障注入（含熔断隔离、双场景切换） | 脚本 + 日志 |
| M0-9 | transport-cf-ws + relay + cloudflared | 基线报告（含断开 100 次恢复率） |
| M0-10 | 路径切换会话影响报告 | ADR |

### 2.6 M0 验收标准（12 项）

1. Wintun 创建/销毁 ≥100 次无残留；回环 iperf3 吞吐基线。
2. 双 NAT 打洞成功 + NAT 类型矩阵；同 LAN 秒连。
3. edge + 自建 SN 24h 稳定；mgmt JSON 可解析上报。
4. 强杀 edge ×10：DirectLink 流量零中断，Supervisor 2s 内重启，熔断 OPEN→HALF_OPEN→CLOSED 全程事件。
5. WSS ≥1h 承载加密帧：帧上限/空闲超时/重连/吞吐基线。
6. 路径切换影响矩阵成文。
7. ADR `N2N_INTEGRATION_ARCHITECTURE.md` 定稿（A/B 均有数据 + overlay_mac 五场景稳定性验证）。
8. ADR `DIRECTLINK_ICE.md` 定稿 + webrtc 符号不越过 directlink 边界（cargo tree 门禁）。
9. 加密验收：错误公钥拒绝 / 重放 100% 丢弃 / 重握手零丢包 / 密钥不落盘。
10. 熔断隔离：OPEN sn_hk_01 不影响 sn_sg_01 与 N2N P2P。
11. 策略生效：改配置即改路径选择。
12. Wintun 存活：N2N headless 崩溃 / 断 Controller / 断 Tunnel 三场景下 Wintun 与虚拟 IP 不变。
    （补充：场景 B failover P95 ≤ 1s。）

## 3. 构建环境（Windows，M0 已固化）

| 项 | 值 |
|---|---|
| Rust | 1.98.0 `stable-x86_64-pc-windows-gnu`（rustup，TUNA 镜像安装；`rust-toolchain.toml` 项目内锁定） |
| MinGW/binutils | w64devkit 2.9.1（`E:\tools\w64devkit`）——仅取 dlltool/as 生成导入库 |
| dlltool shim | `E:\tools\rust-dlltool-shim`（w64devkit 的 dlltool.exe + as.exe 副本） |
| 构建命令 PATH 顺序 | `E:\tools\rust-dlltool-shim` → rustup `lib\rustlib\x86_64-pc-windows-gnu\bin\self-contained` → `%USERPROFILE%\.cargo\bin` → 系统（顺序不可换：链接必须用 rustup 自带 gcc/libgcc_eh；dlltool 必须用 shim 版） |
| crates.io 镜像 | USTC sparse（`.cargo/config.toml`） |
| Go | 1.27.0 |
| MSVC Build Tools | 未安装；M1（Tauri/MSVC）阶段前必须安装 |

## 4. 每子任务汇报格式（用户要求，硬性）

每个 M0 子任务完成后输出：

1. 完成内容
2. 新增/修改文件
3. 编译结果
4. 单元测试结果
5. 实机验证结果
6. 当前未解决问题
7. 下一步

禁止无验证证据的"已完成"。
