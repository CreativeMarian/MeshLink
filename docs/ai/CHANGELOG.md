# MeshLink Changelog


## v0.1.0

Added:

- DirectLink P2P
- Noise encryption
- Controller system
- Friend management
- Recent connections
- Runtime lifecycle
- N2N + Supernode backup path（M1-2）


## M1-2 N2N + Supernode（2026-09-01）

Added:

- DirectLink 建链失败（Auto 路径）自动回退 N2N Supernode Relay：
  creator Noise 握手超时 / joiner 打洞失败 / Noise 握手失败 → 自动切换 N2N；
  Force DirectLink / Force N2N 保持不回退语义。
- Connected 事件携带实际路径 `path`（directlink | n2n）；普通 UI 显示
  DirectLink / N2N Relay，高级诊断显示 `current_path` + N2N 状态。
- GetStatus.current_path 记录当前连接实际路径；recent_connection.last_path
  按实际路径记录（Auto + 实际 N2N 不再误标 directlink）。
- MeshLink 监督者生命周期扩展：DEV 模式自动拉起本机 n2n-supernode.exe、
  经 Agent IPC 注册到 Controller Supernode Registry、退出正确关闭。
- mesh-ipc 新增 `RegisterLocalSupernode` 命令；controller-client 新增
  `register_supernode`。
- 自动集成测试：auto_fallback_n2n（DirectLink 失败 → N2N Relay → 加密
  overlay ping 64/512/1200/1400B）、force_directlink_success 保持 directlink。


## Session 生命周期日志（2026-09-01）

Fixed:

- `JoinQuickSession` join 失败不再硬编码 `SESSION_NOT_FOUND`：透传 Controller 真实
  业务码（无效码 → `SESSION_CODE_INVALID` 等），可直接区分过期/状态/限流错误。

Added:

- Agent 侧 Session 生命周期日志：`[SESSION CREATE]`（session_id/code/device_id/
  expires_at）、`[SESSION JOIN]`（input_code/found_session/session_id）、
  `[SESSION NOT FOUND]`（input_code/reason）、`[SESSION CLOSE]`（session_id/reason）；
  creator 轮询 `get_session` 失败 → `[SESSION NOT FOUND] poll`（debug 级）。
- Controller（Go slog）同步统一生命周期日志前缀；`[SESSION CLOSE]` 覆盖好友直连
  拒绝与好友删除时关闭的会话。
- 确认 6 位码唯一来源 = Controller `POST /v1/sessions` 响应（`connection_sessions`
  表写入 + 原子分配）；前端 `app.js` 仅校验/展示 `data.code`，不自行生成。
- 集成测试：session_lifecycle_test（Create 响应来自 Controller → 无效码 join 透传
  `SESSION_CODE_INVALID` → 正确码 join 双端 Connected）。


## 双机联机修复（真实双机 Release，2026-09-01）

Fixed:

- 真实双机 `SESSION_NOT_FOUND / SESSION_CODE_INVALID (HTTP 404) / 连接码对应的会话不存在`
  根因：双机各自 spawn 独立 controller.exe + 独立 SQLite DB → A 的 code 只在 A 的 DB，
  B 查询自己的 DB 必然 404。属拓扑问题，非 session 创建缺陷。
- 修复方案：双机共享同一个 Controller。
  - Controller `-allow-lan-plaintext`（env `CONTROLLER_ALLOW_LAN_PLAINTEXT=1`）：
    放行 RFC1918 私网明文监听；公网明文无论是否加开关一律拒绝启动（安全红线不变）。
  - controller-client `parse_base_url` + MeshLink UI `validate_controller_url` 白名单
    放行 RFC1918 私网 http（10/8、172.16/12、192.168/16）；公网 http 仍拒绝、无降级。
  - 新增 `isPrivate()`（Go）与 `is_private_host()`（Rust UI）RFC1918 判定助手。
  - dist/README.md 新增「双机联机」部署说明（共享 Controller + 私网明文 + 步骤）。

Added:

- 集成测试 `release_two_machine_smoke`（真实 dist 二进制，默认 #[ignore]）：
  独立 Controller-B join A 的 code → `SESSION_CODE_INVALID`（复现根因）；
  同一 Controller-A join 同 code → PeerFound/Connected（code 存在于 Controller-A）；
  公网明文监听被拒绝（安全约束）。单测 `TestPlaintextListenPolicy`（Go）+
  `dev_mode_allows_only_loopback_and_private_http`（Rust）防默认值/白名单漂移。
- MeshLink UI 设置页 / agent 现在可保存并连接 RFC1918 私网 Controller（局域网双机联机）。


## 双机部署用户体验优化（2026-09-01）

Changed:

- 首次启动未连接 Controller 时，首页状态不再显示模糊「连接失败」：
  明确显示「未连接 Controller」（`renderStatus` 对 FAILED/STOPPED 且无 device_id
  或 `S.ctlErr` 置位时覆盖文案；`CONTROLLER_UNREACHABLE` 事件路径同步）。
- 设置页「当前生效地址」改名为「当前 Controller 地址」并实时刷新：进入设置页、
  ControllerConnected 事件、启动初始化均调用 `loadControllerStatus`。
- UI 侧 `isProdHttpRejected` 增加 RFC1918 私网放行（与 Rust controller-client /
  Tauri validate_controller_url 三处对齐），修复「后端已放行但 UI 拒绝保存局域网
  Controller」的不一致。

Added:

- `docs/adr/ADR-004-controller-topology.md`：记录 Controller 拓扑设计（为什么双机不能
  各自跑独立 Controller、共享 Controller 架构、LAN Controller 使用场景、未来公网
  Controller 规划：自签/私有 CA HTTPS、TLS 终结层 / Cloudflare Tunnel、多 Controller）。
- JS 契约测试扩展：`ui_error_contract.test.js` 新增 isProdHttpRejected（https/
  loopback/私网放行、公网拒绝）与 renderStatus「未连接 Controller」文案断言（40 项全 PASS）。


## Future

M1-3:

Path Manager（自动选路 + 实时路径切换）


M1-4:

HFS 文件共享


M1-5:

MeshTransfer 高速传输


M2:

File transfer


M3:

Remote desktop
