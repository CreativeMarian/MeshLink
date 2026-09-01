# MeshLink Changelog


## 客户端正式版架构 + 公网 Controller（2026-09-01）

Changed:

- **正式版禁止客户端自动启动 controller.exe**（Controller 是服务端组件，不是用户电脑
  组件）：仅 `--local-controller` CLI flag / `MESHLINK_LOCAL_CONTROLLER=1` env（开发模式）
  放行；普通用户双击 MeshLink.exe 不再每台机器拉起独立 Controller。
- **Controller 地址优先级**：`MESHLINK_CONTROLLER_URL` env > 用户保存配置 > 默认公网
  `https://controller.bpbpanel.cc.cd` > 本地（仅开发模式）。`effective_controller_url`
  恒有值、永不回退 127.0.0.1 / 192.168.x.x；用户保存的地址原样保留为权威配置。
- **双击 MeshLink.exe 自动拉起 mesh-agent.exe**（最多 3 次重试：先探测管道 → 失败 spawn
  → 等 15s 未就绪则回收重试）；连接服务失败时首页显示「连接服务启动失败 查看诊断」+ 重连按钮。
- **子进程隐藏启动**：`spawn_managed` 加 Windows `CREATE_NO_WINDOW`，controller/agent/
  supernode 不再弹黑框（`--debug` 开发模式保留日志窗口）。
- **实时连接状态机**：STARTING/CONNECTING/CONNECTED/DISCONNECTED/ERROR；首页顶部显示
  服务器 + 延迟；3 秒心跳轮询 GetStatus；AGENT_STOPPED / GetStatus 失败 → 显示断开 +
  「重新连接」按钮 + 自动重连；恢复自动清除断开态。
- **Session 全局保存**：创建后写入 `data_dir/session_persist.json`（data_dir，非 runtime）；
  软件重启后 READY 时经 Controller `get_session` 验证未过期 → 恢复 6 位码展示
  （GetStatus.active_session），过期/失效自动清理；正常退出/取消即清除。
- **创建/加入流程用户化**：创建页显示「连接服务器: https://…」+ 连接码（不再显示本机
  局域网地址——公网跨网无意义）；「我的电脑地址」局域网卡从设置页移除。
- **诊断中心（三层）**：健康状态（连接服务/服务器连接/网络）→ 详细信息（设备ID/当前
  服务器/延迟/路径）→ 日志查看（分类：全部/连接/网络/错误/Agent/服务端）。
- **日志系统**：`%LOCALAPPDATA%\MeshLink\logs\` 下 app.log（应用启动）/ agent.log
  （连接组件）/ controller.log / supernode.log（原始子进程日志）+ connection/network/
  error 视图（agent.log 按关键词过滤）。Tauri 新增 `read_log_files(category, limit)`。
- **启动失败自动恢复**：Agent 启动失败自动重试最多 3 次；仍失败显示「连接服务启动失败
  查看诊断」，不阻塞 UI，可手动重连。
- 设置页「连接设置」保留创建连接/加入连接二选一；「服务器地址」收进高级设置；普通 UI
  不暴露 Controller/Agent/端口/监听地址等术语，错误码只进诊断日志。

Added:

- 集成测试/契约测试同步更新：ui_error_contract 第 8 节改为验证「局域网地址卡已移除」
  （创建/加入模式均不展示我的电脑地址），47 项全 PASS；JS 三测试全 PASS。
- Agent 侧 `[SESSION CREATE]` 持久化 + `restore_session`（P1-1 重启恢复）。


## Public Controller 架构设计（2026-09-01，设计文档，未大规模编码）

Added:

- 新增 `docs/adr/ADR-005-public-controller-mode.md`：基于真实网络环境（运营商 CGNAT，
  公网出口 112.91.163.213、无公网入口）确定跨公网联机方案——部署**双方都能访问的
  Public Controller**，只做注册/Session/信令；数据面仍 Agent↔Agent P2P 直连。
- 明确 Local Controller 仅用于开发测试；Public Controller 支持原生 HTTPS
  （--tls-cert/--tls-key）或 TLS 终结层（Cloudflare Tunnel/Nginx + --trust-proxy）。
- UI 保持用户化：首页只有【创建连接】/【加入连接】，不暴露 Controller 技术细节。
- `dist/README.md` 增加「公网 Controller 部署」章节（部署方式/客户端配置/架构说明）。
- 不改变：Device Identity / Noise IK / Friend System / Recent Connection / P2P 数据面。


## v0.1.0

Added:

- DirectLink P2P
- Noise encryption
- Controller system
- Friend management
- Recent connections
- Runtime lifecycle
- N2N + Supernode backup path（M1-2）


## Controller 生命周期三模式 + UI 用户化（2026-09-01）

Changed:

- Controller 生命周期扩展为**三种模式**（不重构 Controller 架构，仅 MeshLink 启动参数策略）：
  - **LOCAL（创建连接 / 本机）**：自动拉起 controller.exe；有 RFC1918 局域网地址时监听
    `<私网IP>:18080` + `-allow-lan-plaintext`（同一局域网其他设备可加入），无则 `127.0.0.1:18080`。
  - **LAN（局域网）**：监听本机 RFC1918 IPv4 + `-allow-lan-plaintext`（显式局域网共享）。
  - **REMOTE（加入连接 / 已有地址）**：只连接「高级设置 → 服务器地址」填写的地址，
    **绝不**自动拉起本机 controller.exe（双机联机必须此项，双方指向同一共享 Controller）。
- Controller 启动日志：`[Controller Start] Mode: LOCAL|LAN|REMOTE Listen: <addr>`。
- 新增 `detect_lan_ipv4()`（枚举 RFC1918 非回环 IPv4，取第一个）；`local-ip-address` 依赖。
- `save_controller_config` 支持 lan 模式（落盘 lan_controller_url）；`get_controller_config`
  返回 `lan_ip` 字段；`effective_controller_url` 三态。
- **UI 用户化（普通用户不暴露技术术语）**：
  - 首页只保留两大入口：【创建连接】（"让其他设备加入你的网络"）+【加入连接】
    （"输入连接码，加入其他设备的网络"）；邀请好友移到好友页。
  - 设置页更名【连接设置】：○创建连接（我的电脑作为连接发起方）/○加入连接
    （我的电脑加入别人创建的网络）；服务器地址输入框收进「高级设置」折叠区默认隐藏。
  - 状态文案用户化：「网络服务未启动 / 等待创建连接」替代「未连接 Controller」；
    首页横幅与错误提示不再出现 Controller/SESSION/PeerFound 等术语。
- 单元测试：`controller_listen_spec`（LAN 必带 allow-lan-plaintext；local 自动局域网；端口固定 18080）。
- Release 冒烟新增 `release_lan_controller_shared_topology`：Controller 监听本机 RFC1918 +
  `-allow-lan-plaintext`，双 Agent 指向 `http://<LAN_IP>:port` → 同一 code 双端 PeerFound；公网明文拒启。

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


## 双机 Controller 生命周期设计（2026-09-01）

Changed:

- MeshLink.exe 首次启动无 Controller 配置时**不再静默默认连 127.0.0.1**：不拉起
  controller.exe / mesh-agent.exe，首页显示「未配置 Controller」+「去配置」按钮。
- 设置页新增「Controller 模式」二选一：
  - 使用本机 Controller：MeshLink 自动拉起 controller.exe（地址固定 127.0.0.1:18080）；
  - 使用已有 Controller 地址：绝不自动拉起本机 controller（双机联机必须此项，共享同一 Controller）。
  支持地址输入 + 测试连接 + 保存并应用。
- 环境变量 `MESHLINK_CONTROLLER_URL` = 显式既有地址（remote 语义，最高优先级，不自动拉起本机）。
- 配置存 `%LOCALAPPDATA%\MeshLink\ui\config.json`（controller_mode + controller_url）；
  旧配置（仅 controller_url）兼容为 remote 语义；credential/私钥仍只归 Agent secure-store。
- 设置页实时显示当前生效 Controller 地址 / 状态 / 延迟 / 服务器 / 设备 ID；首页未连接横幅
  明确显示「未连接 Controller」+ 当前地址 + [重新连接]/[修改 Controller 地址]。
- Tauri 新增命令 `save_controller_config` / `get_controller_config`；
  `effective_controller_url` 改为 Option 语义（None = 未配置）。
- JS 契约测试：新增 NOT_CONFIGURED 渲染与 Controller 模式切换（ui_error_contract → 46 项）。


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
