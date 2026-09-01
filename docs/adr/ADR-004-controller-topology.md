# ADR-004: Controller 拓扑设计（单 Controller 共享 / LAN 明文 / 未来公网）

- 状态：Accepted（真实双机 Release Bug 修复后定稿）
- 日期：2026-09-01
- 决策人：用户 + 助手（真实双机联机修复）
- 关联任务：M1-1.5 之后的双机联机；真实双机 `SESSION_NOT_FOUND / SESSION_CODE_INVALID (HTTP 404)`
- 实现位置：`server/controller/cmd/controller/main.go`（`-allow-lan-plaintext`）、
  `crates/controller-client/src/lib.rs`（`parse_base_url` 白名单）、
  `apps/meshlink-ui/src/ipc.rs` + `apps/meshlink-ui/ui/app.js`（UI 白名单与状态展示）、
  `dist/README.md`（双机部署说明）

## 背景（Why）

真实双机 Release 联机失败：

- 机器 A 与机器 B 都使用默认 `http://127.0.0.1:18080`，各自 spawn **独立的本机
  Controller 进程 + 独立 SQLite DB**。
- A 创建 6 位码 → 写入 A 的 `connection_sessions` 表；B 输入同码 → 查询 B 自己的
  Controller DB → 必然查不到 → `SESSION_CODE_INVALID (HTTP 404) / 连接码对应的会话不存在`。
- 双机日志均显示 `controller=http://127.0.0.1:18080` + Agent READY，误导排查方向。

结论：**不是 session 创建代码缺陷，而是拓扑错误**——6 位码、设备注册、好友关系、
Supernode Registry 等所有 Controller 状态都必须落在**同一个** Controller 上，
两端 Agent 才能看到同一份数据。

## 候选方案

| 方案 | 描述 |
|---|---|
| A | 双机各跑各的 Controller（现状）——数据隔离，必然互不可见 |
| B | 一台机器跑共享 Controller，双机 Agent 都指向它（局域网明文） |
| C | 公网/异地双机：共享 Controller 走 HTTPS（自签 CA / TLS 终结层） |
| D | 每台机器内嵌只读对账（把 A 的 DB 同步到 B）——复杂度高、实时性差 |

## 对比数据（必须实测，不接受拍脑袋）

| 维度 | A 各自 Controller | B 共享 Controller（LAN 明文） | C 共享 Controller（HTTPS） |
|---|---|---|---|
| 6 位码跨机可见 | ❌（实测 404） | ✅ | ✅ |
| 设备注册/好友/最近连接一致 | ❌ | ✅ | ✅ |
| 需要改动 | 无（默认行为） | Controller 加 `-allow-lan-plaintext`；UI/客户端白名单放行 RFC1918 | 证书配置 / TLS 终结层 |
| 安全边界 | loopback 明文 | RFC1918 私网明文（显式开关） | 全链路 TLS |
| 测试 | release_two_machine_smoke 复现 404 | 同一 Controller 下同码 PeerFound | 需 HTTPS 环境 |

## 决策（What）

1. **双机必须共享同一个 Controller**：6 位码、设备注册、好友、Supernode Registry、
   IPAM、recent_connections 全部以该 Controller 为准。禁止双机各自跑独立 Controller
   再期望互通。
2. **局域网双机（推荐第一版）**：一台机器以
   `controller.exe -addr <私网IP>:18080 -allow-lan-plaintext -db shared.db` 启动共享
   Controller，A/B 两台 MeshLink 的「设置 → 网络服务 → Controller 地址」都填
   `http://<私网IP>:18080`。
3. **`-allow-lan-plaintext` 仅放行 RFC1918 私网**（10/8、172.16/12、192.168/16）：
   公网明文无论是否加开关一律拒绝启动（安全红线不变，防误配公网明文信令）。
4. **客户端白名单同步放行私网 http**：`controller-client::parse_base_url` 与
   MeshLink UI（Rust `validate_controller_url` / JS `isProdHttpRejected`）三处一致——
   `http://` 仅 localhost / 127.0.0.1 / RFC1918 私网；公网 `http://` 拒绝、禁止自动降级。
5. **拓扑对客户端透明**：客户端只配置 Controller URL；不感知 Controller 后面是否有
   Tunnel / 反代 / 公网入口。DEV 本机调试仍用默认 `http://127.0.0.1:18080`。

## 理由与权衡

- 选择 B/C 而非 D（对账同步）：Controller 是唯一事实来源（单一写入点），对账方案需要
  冲突解决、实时性、ACL 复杂度，远超第一版收益。
- `-allow-lan-plaintext` 是显式开关：默认行为（loopback 明文 / HTTPS 任意地址）不变，
  只对明确声明的私网监听放行；公网明文被结构上拒绝，避免用户误把 Controller 暴露到公网。
- 双机共享 Controller 的代价：一台机器要一直跑 controller.exe（本机调试时 MeshLink
  会自动拉起；双机场景由用户手动以私网地址启动）。这不是 MeshLink 的常态路径——第一版
  目标就是打通"GUI → Agent → Controller → 直连/中继 → Overlay"，跨机由共享 Controller 承载。

## 影响与后续

- **UI 用户体验**：
  - 首页未连接 Controller 时明确显示「未连接 Controller」（不再模糊「连接失败」）；
  - 设置页显示「当前 Controller 地址」（实时刷新，进入设置页与 ControllerConnected 均更新）；
  - 局域网 Controller 地址（RFC1918）可在设置页保存/测试（与后端白名单一致）。
- **未来公网 Controller 规划**：
  1. 自签/私有 CA：`--tls-cert/--tls-key` 原生 HTTPS，客户端「设置 → 网络服务」填 CA PEM；
  2. TLS 终结层：Cloudflare Tunnel / Nginx 反代终结 TLS，本进程明文只绑内网 +
     `--trust-proxy`；客户端仍访问 `https://control.example.com`；
  3. 多 Controller / 高可用：当前 `-addr` 单实例；未来可引入 Controller 集群 + 共享存储
     （SQLite → Postgres 等），以 IPAM/设备注册/会话状态为中心。
- **验证**：`release_two_machine_smoke`（真实 dist 二进制）覆盖「独立 Controller → 404
  复现；共享 Controller → 同码 PeerFound；公网明文拒绝」；Go/Rust 单测锁定白名单与
  `-allow-lan-plaintext` 策略。

## 参考

- `dist/README.md`「双机联机」章节（部署步骤）
- 用户真实双机 Release 复现：`SESSION_NOT_FOUND / SESSION_CODE_INVALID (HTTP 404)`
- ADR-001（Noise 密钥生命周期）、ADR-002（Wintun 适配器）、ADR-003（DirectLink 引擎选型）
