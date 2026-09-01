# ADR-004: Controller 拓扑设计（单 Controller 共享 / LAN 明文 / 未来公网）

- 状态：Accepted（真实双机 Release Bug 修复 + 双机 Controller 生命周期设计后定稿）
- 日期：2026-09-01
- 决策人：用户 + 助手（真实双机联机修复 + 生命周期配置设计）
- 关联任务：M1-1.5 之后的双机联机；真实双机 `SESSION_NOT_FOUND / SESSION_CODE_INVALID (HTTP 404)`；
  双机 Controller 生命周期（未配置 / 本机 / 已有地址三态）
- 实现位置：`server/controller/cmd/controller/main.go`（`-allow-lan-plaintext`）、
  `crates/controller-client/src/lib.rs`（`parse_base_url` 白名单）、
  `apps/meshlink-ui/src/ipc.rs`（`controller_mode` / `effective_controller_url` /
  `agent_connect` 生命周期）+ `apps/meshlink-ui/ui/app.js`（设置页模式选择与状态展示）、
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

## 补充决策：Controller 生命周期三态（MeshLink.exe 不静默默认拉起本机 Controller）

真实双机修复后进一步收敛：MeshLink.exe 不再无条件把「没有配置」当作「连本机 127.0.0.1」，
否则双机仍各自拉起独立 Controller，根因复现。正式落地：

1. **三态**：
   - `未配置`（无 controller_mode / controller_url）→ 首页显示「未配置 Controller」，
     **不拉起** controller.exe / mesh-agent.exe，引导去设置页；不再默认 127.0.0.1。
   - `local`（使用本机 Controller）→ 仅此模式 MeshLink 负责 spawn controller.exe
     （地址固定单一默认 127.0.0.1:18080）。
   - `remote`（使用已有 Controller 地址）→ 绝不自动拉起本机 controller；双机联机必须此项，
     双方指向同一共享 Controller。
2. **环境变量 `MESHLINK_CONTROLLER_URL` = 显式既有地址**（remote 语义，不自动拉起本机），
   优先级最高（测试 / 运维覆盖）。`agent_connect` 对 `local` 且 dev loopback 才走
   `spawn_dev_controller` 健康检查拉起。
3. **配置归属**：模式 + 地址存 `%LOCALAPPDATA%\MeshLink\ui\config.json`（普通配置）；
   credential / 私钥仍只归 Agent secure-store（DPAPI）。旧配置（仅 controller_url、无 mode）
   兼容为 remote 语义（不自动拉起本机）。
4. **UI**：设置页「Controller 模式」二选一（本机 / 已有地址）+ 地址输入 + 测试连接 +
   保存并应用；首页未配置横幅「去配置」直达设置页；设置页实时显示当前生效 Controller
   地址 / 状态 / 延迟 / 服务器 / 设备 ID。
5. **自动化**：JS contract 覆盖 NOT_CONFIGURED 渲染与模式切换；`release_gui_smoke` 不经过
   MeshLink.exe `agent_connect`（直接 spawn 二进制），因此不受生命周期改动影响。

## 补充决策：三模式生命周期 + LAN 自动监听（MeshLink.exe 启动参数策略）

控制器监听方式由 MeshLink.exe 依据用户选择的模式决定（**不重构 Controller 架构**，仅生命周期
与启动参数）：

1. **三种模式**：
   - **LOCAL（创建连接 / 本机）**：MeshLink 自动拉起 `controller.exe`；本机存在 RFC1918
     局域网地址时监听 `<私网IP>:18080` 并带 `-allow-lan-plaintext`（同一局域网其他设备可加入），
     无则监听 `127.0.0.1:18080`。
   - **LAN（局域网）**：显式监听本机 RFC1918 IPv4 + `-allow-lan-plaintext`（多设备共享一个
     Controller 的家庭/朋友场景）。
   - **REMOTE（加入连接 / 已有地址）**：只连接用户填写的服务器地址，**绝不**拉起本机
     controller.exe（双机联机必须此项）。
2. **自动探测局域网地址**：`detect_lan_ipv4()` 枚举 RFC1918 非回环 IPv4 取第一个
   （`local-ip-address` crate，与测试同源）；多网卡选卡问题记录为已知限制。
3. **启动日志**：`[Controller Start] Mode: LOCAL|LAN|REMOTE Listen: <addr>`。
4. **安全红线不变**：LAN 明文仅放行 RFC1918 私网；公网明文无论是否加开关一律拒绝启动。
5. **UI 用户化**：普通用户界面不出现 Controller/监听地址/端口/Agent/节点 等术语——
   首页两入口【创建连接/加入连接】；设置页【连接设置】○创建连接（我的电脑作为连接发起方）
   /○加入连接（我的电脑加入别人创建的网络）；服务器地址收进「高级设置」默认隐藏；
   状态文案「网络服务未启动 / 等待创建连接」。
6. **验证**：单测 `controller_listen_spec` 锁定启动参数策略；release 冒烟
   `release_lan_controller_shared_topology` 用真实 dist 二进制验证 Controller 监听本机
   RFC1918 + `-allow-lan-plaintext`、双 Agent 指向 `http://<LAN_IP>:port` → 同一 code 双端
   PeerFound；公网明文拒启。

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
