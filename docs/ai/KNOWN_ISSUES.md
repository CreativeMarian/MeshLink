# Known Issues


## Pending


- Real world public network validation

- Wintun physical machine validation

- NAT compatibility improvement

- Fast reconnect optimization


## M1-2 N2N + Supernode（2026-09-01）


- 自动回退为单向（DirectLink 失败 → N2N Relay）；双向自动选路与运行中实时切换属 M1-3 Path Manager。
- N2N 每 Supernode 熔断阈值当前为 3（`N2NParams.failure_threshold`）；快速回退竞态下（joiner 早于
  creator 注册到 SN 之前就开始 QueryPeer 重试）短暂超时会计入熔断，但 Supernode 重启/恢复后 HALF_OPEN
  探测自动复位，链路可自愈；如需更宽松可调高阈值或延长 `request_timeout_ms`。
- 本机 DEV Supernode 自动拉起/注册当前为固定参数（127.0.0.1:7654 / priority 100），尚未做成可配置；
  远程 Supernode 由 Controller Supernode Registry 下发（priority 排序）。
- DirectLink 数据面测试在机器高负载时偶发打洞抖动（自动化测试的 Controller 启动轮询超时已由 10s 放宽
  至 30s；真实 DirectLink 建立本身由 30s punch_timeout 兜底，属可接受抖动）。
- 若 `dist\` 下的 MeshLink.exe / controller.exe / mesh-agent.exe 正在运行，会因文件锁阻止 dist 重新打包，
  需先关闭 MeshLink 客户端（MeshLink 退出会完整回收其拉起的 agent/controller）。


## Session 生命周期日志（2026-09-01）


- 修复：`JoinQuickSession` 之前把所有 join 失败都硬编码为 `SESSION_NOT_FOUND`，掩盖了 Controller 真实
  业务码（如无效码实际返回 `SESSION_CODE_INVALID`）。现改为透传 `ApiError.code`（传输层错误保留
  `TRANSPORT`），配合 `[SESSION NOT FOUND]` 日志记录 `input_code` + `reason`，可直接区分
  `SESSION_CODE_INVALID` / `SESSION_EXPIRED` / `SESSION_STATE_INVALID` / `SESSION_RATE_LIMITED`。
- 新增 Agent 侧 Session 生命周期日志（tracing，RUST_LOG=info 可见）：
  `[SESSION CREATE]`（session_id/code/device_id/expires_at）、`[SESSION JOIN]`（input_code/found_session/
  session_id）、`[SESSION NOT FOUND]`（input_code/reason）、`[SESSION CLOSE]`（session_id/reason）。
- Controller 侧（Go slog）同步统一为同前缀生命周期日志；create 仍写入 `connection_sessions` 表
  （6 位码唯一来源 = Controller `POST /v1/sessions` 响应，前端/Agent 均不自行生成）。
- creator 轮询 `get_session` 失败记录为 `[SESSION NOT FOUND] poll`（debug 级，避免轮询期刷屏）。


## 双机联机（真实双机 Release，2026-09-01）

- 根因已定位并修复：两台机器默认 `http://127.0.0.1:18080` 时各自拉起**独立的本机
  Controller + 独立 SQLite DB**，A 创建的 6 位码只存在于 A 的 DB，B 输入同码查询 B 的
  Controller → `SESSION_CODE_INVALID (404) / 连接码对应的会话不存在`。这是**拓扑问题**，
  不是 session 创建代码缺陷——双机必须共享**同一个** Controller。
- 修复：Controller 新增 `-allow-lan-plaintext`（仅 RFC1918 私网明文；公网明文即使加开关也
  拒绝启动）；controller-client / MeshLink UI 白名单放行 RFC1918 私网 http（公网 http 仍拒）。
  推荐部署：一台机器 `controller.exe -addr <私网IP>:18080 -allow-lan-plaintext`，双机
  MeshLink 设置页都指向同一私网地址（详见 dist/README.md「双机联机」）。
- 验证：新增 `release_two_machine_smoke`（真实 dist 二进制）：独立 Controller-B 上 join A 的
  code → `SESSION_CODE_INVALID`（复现根因）；与 A 同一 Controller 上 join 同 code → PeerFound
  （证明 code 存在于 Controller-A）；公网明文监听被拒绝（安全约束仍生效）。
- 物理双机实机流程仍标 `PENDING_REAL_WORLD_VALIDATION`（本环境无第二台物理机）；已用
  release 二进制等价覆盖 Controller/Agent/UI bridge 全链路。
- 自动化集成测试在高负载并行运行时偶发启动轮询超时（free_port TOCTOU 加剧），单测/顺序跑
  全部 PASS；属测试基建抖动，不影响产品逻辑。


## 双机部署用户体验优化（2026-09-01）

- 首页首次启动未连接 Controller 时，状态文案由模糊「连接失败」改为明确「未连接 Controller」
  （`renderStatus` 对 FAILED/STOPPED 且无 device_id 或 `S.ctlErr` 置位时覆盖；`CONTROLLER_UNREACHABLE`
  事件路径同步，横幅标题同步改为「未连接 Controller」）。
- 设置页「当前 Controller 地址」实时显示（进入设置页 / ControllerConnected / 启动初始化均刷新）；
  UI 侧 `isProdHttpRejected` 与 Rust controller-client / Tauri validate_controller_url 三处对齐，
  放行 RFC1918 私网 http（公网 http 仍拒绝），消除「后端放行但 UI 拒绝保存局域网地址」不一致。
- 新增 `docs/adr/ADR-004-controller-topology.md`：单 Controller 共享架构、LAN 明文场景、
  未来公网规划（自签/私有 CA HTTPS、TLS 终结层 / Cloudflare Tunnel、多 Controller）。
- 物理双机实机 UI 展示仍标 `PENDING_REAL_WORLD_VALIDATION`；JS 契约测试（ui_error_contract 46 项）
  已覆盖文案与 URL 白名单，release_gui_smoke / release_two_machine_smoke 均 PASS。


## 双机 Controller 生命周期设计（2026-09-01）

- 根因收敛：修复 404 拓扑后仍残留「MeshLink.exe 无条件把无配置当成本机 127.0.0.1」的默认行为——
  双机仍会各自拉起独立 Controller。现正式引入三态：`未配置` / `本机 Controller` / `已有 Controller 地址`。
- 改动：
  - MeshLink.exe 首次启动无任何 Controller 配置时**不再静默默认连 127.0.0.1**，不拉起
    controller.exe / mesh-agent.exe；首页显示「未配置 Controller」+「去配置」按钮。
  - 设置页新增「Controller 模式」二选一：本机 Controller（MeshLink 自动拉起 controller.exe，
    地址固定 127.0.0.1:18080）/ 已有 Controller 地址（绝不自动拉起本机；双机联机必须此项，
    双方指向同一共享 Controller）。地址输入 + 测试连接 + 保存并应用。
  - 环境变量 `MESHLINK_CONTROLLER_URL` = 显式既有地址（remote 语义，最高优先级，不自动拉起本机）。
  - 配置存 `%LOCALAPPDATA%\MeshLink\ui\config.json`（controller_mode + controller_url）；旧配置
    （仅 controller_url）兼容为 remote 语义。credential/私钥仍只归 Agent secure-store。
  - 设置页实时显示当前生效 Controller 地址 / 状态 / 延迟 / 服务器 / 设备 ID；首页未连接时
    横幅明确显示「未连接 Controller」+ 当前地址 + [重新连接]/[修改 Controller 地址]。
- 验证：JS 契约测试新增 NOT_CONFIGURED 渲染（46 项全 PASS）与 Controller 模式切换；release_gui_smoke
  PASS；MeshLink.exe 内嵌 app.js/HTML 经 brotli 反解确认含新模式字段。物理双机实机流程仍标
  `PENDING_REAL_WORLD_VALIDATION`。
- 注意：双机联机时**两台都不能选「使用本机 Controller」**（会各自拉起独立 Controller，码对不上）；
  必须都选「已有 Controller 地址」指向同一共享 Controller（ADR-004 / dist README 双机联机章节）。


## Development Notes


Known problems should be recorded here.

Do not hide bugs.
