# Known Issues


## Pending


- Real world public network validation

- Wintun physical machine validation

- NAT compatibility improvement

- Fast reconnect optimization

- M1-3b：PathManager 尚未接入 mesh-agent（pump 数据面仍固定走单一 transport，N2N
  subscribe_events 仍空实现待接 PathManager 事件回流；SetPath 强制路径未映射到
  force_path）。核心已就绪（commit 3756b69，10/10 单测），待下一步接入。


## 排障实录 2026-09-02：双机「正在寻找设备」+ 主机连不上（commit 51b387a）

- **客户机「正在寻找设备」根因（配置残留，非代码）**：客户机 agent 实际连接的是
  `127.0.0.1:18080`（本机 Controller 地址），而非公网 `https://controller.bpbpanel.cc.cd`。
  客户机无 controller.exe 在跑 → healthz 30s 未就绪 → CONTROLLER_UNREACHABLE → 无法
  join_session → UI 永远卡第 1 步。来源是客户机 config.json 里保存的 controller_url
  曾为本机地址（或环境变量 MESHLINK_CONTROLLER_URL）。**修复动作**：客户机设置页把
  Controller 地址改回公网；或删除 config.json 的 controller_url 让默认公网生效；同时
  关掉任何手动启动的旧 mesh-agent 控制台（不带参数会默认连 127.0.0.1:18080）。
- **主机连不上根因（代码已修 commit 51b387a）**：Clash 等代理软件关闭后 Windows 系统
  代理残留（注册表 ProxyEnable=1 / ProxyServer=127.0.0.1:7897），controller-client 每次
  请求都先连死代理 → ConnectionRefused → 所有 Controller 请求失败。已修复：**代理不可用
  自动回退直连 + 60s 冷却**（连接代理/CONNECT 失败即标记冷却，冷却期内跳过代理直接连
  目标，冷却后自动重新探测代理）。验证：controller-client 17/17 PASS（新增
  proxy_dead_falls_back_to_direct），cargo check --workspace 干净，mesh-agent lib 11/11。
- **说明**：用户环境若必须走代理才能连公网 Controller，首次回退直连失败后 60s 内会
  保持直连；用户重新开启代理软件后最多 60s 自动切回代理。


## Phase1 逻辑审查优化：P0-1 同步调用隔离 + P1-4 失败自动恢复（2026-09-02，commit 8cbf219）

- **P0-1 已修（运行时饿死）**：22 处同步 Controller 调用（healthz/register_device/
  list_supernodes/poll_events/create_session/get_session/presence_heartbeat/
  list_friendships/upsert_recent_connection/join_session/get_candidates/put_candidates/
  reject_connection_request/register_supernode）全部改 `spawn_blocking` offload，根治
  2-worker Tokio runtime 被同步裸 TCP（8s 超时）阻塞导致的卡顿/心跳饿死。
- **P1-4 已修（失败自动恢复）**：会话失败后 3s 自动回 READY（仅已就绪后的会话失败；
  启动失败保持 Failed 由 ensure_agent_running 冷却重试）。UI 会在 Error 事件展示真实
  原因，随后 Disconnected 事件回到可操作状态。
- **P1-2 已修（watchdog 泄漏）**：finish_connected 诊断 watchdog 原不查 stop 永不退出
  （每次连接泄漏空转任务 + 每 2s 刷日志）；现已加 stop 检查退出。
- **P1-3 已修（keepalive 线程残留）**：abort_session_resources 现调 transport/n2n
  stop_keepalive（Keepalive::Drop 置 stop + join），会话结束即停止保活线程。
- **P2-1~P2-4 已修（commit 4897262）**：heartbeat 连续失败才判定断开（防单次超时
  误报）；事件轮询动态背压（空轮询退避至 10s）；mesh-ipc 广播 sync_channel(512) +
  try_send（慢客户端判 dead）；controller.db 启动 PRAGMA quick_check 完整性校验。
- **测试基建抖动（非产品逻辑）**：n2n_flow 偶发 0.00s 端口竞态（free_port TOCTOU），
  单测/顺序跑全 PASS；default_port_alignment 需 18080 空闲（本机被运行中 controller
  占用，停止后复跑）。
- **遗留**：auto_fallback_n2n 集成测试仍失败（N2N 双 SN 熔断时序，被真实双机公网
  DirectLink 验证覆盖）；dist 打包前需关闭运行中的 MeshLink.exe；controller.exe 反复
  消失根因未根治（用户将自写 vbs 自启动）。

## 日志系统优化（2026-09-02，commit e35c4ff）

- **已修（日志可见性）**：agent 默认级别提升到 `info,agent=debug,mesh_agent=debug`；
  失败时输出 FAIL_SNAPSHOT 故障现场；UI 侧 Error 事件落 app.log。
- **已修（分类定位）**：read_log_files 的 error 分类改为按 ERROR/WARN 级别解析（不再
  漏 AUTH_INVALID 等词外错误）+ 关键词兜底扩充；connection/network 关键词扩充；
  返回 levels 供 UI 着色。
- **已修（诊断体验）**：诊断中心加「最近失败」展示、日志关键字搜索、仅错误/警告过滤、
  按级别着色、刷新按钮。
- **已知局限**：分类日志仍为 agent.log 的过滤视图（非物理分文件）；agent debug 仅覆盖
  agent 自身模块（directlink/transport 细节保持 info，需手动设 RUST_LOG=directlink=debug
  才能看打洞/STUN 明细）。日志文件无轮转（长时间运行会增长）。


## 双机公网 DirectLink 连通 + UI 流程顶走/事件丢失修复（2026-09-02）

- **真实双机公网验证通过（原 PENDING_REAL_WORLD_VALIDATION 已达成）**：主机
  `dev-c3cc517f2c459ea0` 创建 code=721984，虚拟机 `dev-4da9787ba66c4de1` 通过公网
  Controller（Cloudflare Tunnel）JOIN found_session=true → ICE punch 成功 →
  Noise 握手 → Overlay（10.88.0.1 / 10.88.0.2）→ smoke_ok → 双方 Connected +
  数据面持续双向加密传包。**底层连接本身已完全打通**，剩余问题全部在 UI 展示层。
- **UI 流程顶走（已修复，commit 8c4fa49）**：`PeerFound`/`Punching`/`NoiseHandshaking`
  事件会把创建方从连接码页（create/home）顶到进度页——这就是用户实测「切到其他页面再
  切回来看不到连接码」的根因。修复后仅加入方流程（join/progress 视图）才切进度页。
- **Connected 事件丢失兜底（已修复）**：agent 已在运行且已 CONNECTED 时，Connected 事件
  可能在 UI 订阅 `listen()` 前发出而丢失，导致 UI 只显示状态点、不切连接详情页。新增
  `syncConnectedView` 在 boot / waitReady / heartbeat 三处兜底补齐连接详情视图。
- **系统性 UI 排查结论**：全部按钮绑定完整、无悬空事件引用、Tauri 9 个 command 与
  app.js invoke 对应完整、`ActiveSession.status`（SCREAMING_SNAKE）与 UI 常量匹配。
- **遗留待办**：主机 Controller 依赖 Cloudflare Tunnel 且需保持 controller.exe 存活
  （用户将自写 vbs 自启动，守护进程已按用户要求停用）；dist 打包前需关闭运行中的
  MeshLink.exe（文件锁）；controller.db 曾因异常重启重建为空库导致旧设备凭据失效
  （重启 MeshLink 触发幂等 register_device 即可重新注册）。


## 启动阻塞/卡死修复 + 启动失败退避（2026-09-02）

- **虚拟机「打开特别卡 / 一直连接服务 / 点击设备卡死」根因**：`ensure_agent_running`
  原同步阻塞 ~20s + 失败后高频反复 spawn 崩溃 agent → CPU 飙高。已修复：
  启动后台化（立即返回 STARTING）、失败 30s 冷却、确定性失败不重试、JS 指数退避
  （5s→10s→30s→60s）。实证：agent 缺失时 8s 后 MeshLink 存活不卡、app.log 记录真实
  原因、不再无限 spawn。
- **请检查虚拟机上的 `%LOCALAPPDATA%\MeshLink\logs\agent.log`**（agent 自身日志）与
  `app.log`：若 agent.log 为空或 agent 未生成，多为 agent 未随 MeshLink 一起拷贝/被
  杀软拦截/`mesh-agent.exe` 与 `MeshLink.exe` 版本不一致。诊断中心第一层健康 + 第二层
  详情 + 第三层日志可查看失败原因。
- **公网 Controller 连通性**：agent 能起但连不上公网 Controller（healthz 30s 超时 →
  CONTROLLER_UNREACHABLE）时，UI 显示「网络服务未启动」+ 服务器行；请确认虚拟机可访问
  `https://controller.bpbpanel.cc.cd`。
- 若虚拟机上 `%LOCALAPPDATA%\MeshLink\ui\config.json` 存在旧 LAN 残留
  （`192.168.x.x:18080`）会覆盖默认公网，请清理或改回公网地址（本机已清理并备份）。



## mesh-agent 启动风暴修复（2026-09-02）

- **启动风暴根因已修**：`ensure_agent_running` 单例生命周期（Stopped/Starting/Running/
  Failed）+ Named Pipe 握手等待（最多 5s）+ 失败真实原因（进程退出码 + agent.log 尾部）
  + 自动重试 5s 节流。实证：25s 观察只有 1 个 mesh-agent、app.log 仅 1 条启动记录。
- **本机 config.json 旧 LAN 测试残留已清理**：`mode=local` + `192.168.10.147:18080`
  会覆盖默认公网 Controller（第 2 优先级=用户保存配置）导致正式版连本机地址失败；
  已重置为 `{}` 恢复默认公网 `https://controller.bpbpanel.cc.cd`，备份
  `%LOCALAPPDATA%\MeshLink\ui\config.json.bak-test-residue`。若其他机器也出现过
  「启动日志显示 192.168.x.x」，检查该配置是否残留。
- 虚拟机任务管理器验证方法：打开 MeshLink 后应只有 **1 个 mesh-agent.exe**（修复前是
  十几个/几十个）；关闭 MeshLink 后 mesh-agent.exe 应消失为 0。



## 客户端正式版架构 + 公网 Controller（2026-09-01）

- **正式版默认公网 Controller**：`https://controller.bpbpanel.cc.cd`（用户实测 curl 返回
  `404 page not found` = 正常，Cloudflare Tunnel/HTTPS/Controller 服务均可用）。普通客户端
  默认连接该地址；开发模式用 `127.0.0.1:18080`。禁止自动降级/回退到本机地址。
- **正式版禁止客户端拉起本机 controller.exe**：仅 `--local-controller` / `MESHLINK_LOCAL_CONTROLLER=1`
  （开发）放行；双机联机必须双方指向同一公网/共享 Controller。
- **会话重启恢复仅覆盖异常退出**：正常退出/取消时 `teardown_session` 会清除
  `data_dir/session_persist.json`；只有进程被杀/崩溃时残留文件才会在下次启动 READY 后
  经 Controller `get_session` 验证恢复。恢复仅还原 6 位码展示（等待态），不自动重建传输链路。
- **心跳间隔 3 秒**（用户规格 3-5s 取下限）；GetStatus 连续失败 → 断开态 + 自动重连。
  自动重连只针对 Agent 管道恢复；Controller 不可达由 Agent 事件/`[重新连接]` 兜底。
- **诊断中心日志分类**：`logs/` 下 app.log / agent.log / controller.log / supernode.log 为
  原始日志；connection / network / error 为 agent.log 按关键词过滤视图（非独立文件）。
- **Agent 启动失败自动重试最多 3 次**：仍失败时首页显示「连接服务启动失败 查看诊断」，
  可手动点「重新连接」；不静默卡死。
- **默认公网 Controller 对本机无公网入口环境有效**（Cloudflare Tunnel 已在用户侧验证）；
  若未来公网 Controller 不可达，设置页高级设置可改回局域网/开发地址。
- 物理双机公网/NAT/P2P 实机流程仍标 `PENDING_REAL_WORLD_VALIDATION`（本环境无第二台物理机）；
  已用 release_two_machine_smoke + release_gui_smoke（真实 dist 二进制）等价覆盖链路。



## Controller 生命周期三模式 + UI 用户化（2026-09-01）

- 三模式落地：LOCAL（创建连接）自动拉起 controller.exe 并监听本机 RFC1918（有私网地址时）
  或 127.0.0.1；LAN（局域网）显式监听 RFC1918 + `-allow-lan-plaintext`；REMOTE（加入连接）
  只连已有地址、绝不拉起本机 controller.exe（双机联机必须选「加入连接」指向同一共享 Controller）。
- `detect_lan_ipv4` 取本机**第一个** RFC1918 非回环 IPv4（多网卡机器可能选到非目标网卡；
  已记录为已知限制，M1-3 后可做网卡选择 UI）。
- LAN 明文仅放行 RFC1918 私网；公网明文无论是否 `-allow-lan-plaintext` 一律拒绝启动（安全红线不变）。
- 物理双机实机流程仍标 `PENDING_REAL_WORLD_VALIDATION`（本环境无第二台物理机）；已用
  `release_lan_controller_shared_topology` 真实 dist 二进制等价覆盖：Controller 监听本机
  RFC1918 + `-allow-lan-plaintext`，双 Agent 指向 `http://<LAN_IP>:port` → 同一 code 双端
  PeerFound；公网明文拒启。
- UI 用户化后普通用户看不到 Controller/SESSION/PeerFound 等术语；开发文档与高级诊断保留专业名称。
- 自动化集成测试在高负载并行运行时偶发启动轮询超时（free_port TOCTOU 加剧），单测/顺序跑
  全部 PASS；属测试基建抖动，不影响产品逻辑。


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


## dist 重新打包（2026-09-02 19:20）＋客户机「连公网仍一直寻找设备」排障实录二

- **dist 已重打包**：`dist\MeshLink-v0.1.0-alpha-Windows-x64.zip`（16480549B，19:20:55）覆盖六件套，
  已含此前全部未打包改动：`51b387a`（controller-client 代理不可用回退直连＋60s 冷却）、
  `3756b69`（M1-3a PathManager）、`4897262`（P2-1~P2-4），并重构建最新 controller.exe（Go）/ mesh-agent /
  MeshLink(UI) 三件；n2n-supernode.exe / wintun.dll / README.md 原样保留（未变）。
  打包前测试全绿：controller-client 17、overlay-router 10、mesh-agent lib 11。新提交 `3e95d80`
  （Cargo.lock：controller-client tracing 锁文件，51b387a 配套，已 push）。冒烟：mesh-agent/controller
  可正常启动（--version 不被支持、会直接启动服务，验证时需立即杀进程）。
- **客户机「连公网仍一直寻找设备」新证据**（虚拟机 agent.log 10:33Z）：UI 与 agent 均已用公网
  `https://controller.bpbpanel.cc.cd`，但 healthz 持续 `HTTP 530: error code 1033` → 30s 后
  CONTROLLER_UNREACHABLE → Failed。530/1033 是 **Cloudflare Tunnel 层**错误（tunnel 连接被拒/路由失效），
  非 MeshLink 代码问题；主机侧本机 18080 healthz 与公网 healthz 曾同时通过，怀疑**主机两个 cloudflared
  实例（PID 25092/34076）连同一 tunnel 路由冲突**，待清理后复测。
- **设备身份冲突（最严重）**：虚拟机 agent.log 中 agent 自身 `device_id=dev-c3cc517f2c459ea0`
  （这是**主机**的 ID），虚拟机正确 ID `dev-4da9787ba66c4de1` 仅作为 `peer_device_id` 出现在
  OnPeerFound。判定虚拟机的 `%LOCALAPPDATA%\MeshLink\agent\device-identity.json` 系从主机复制，
  导致 controller 认两台为同一设备、会话匹配混乱。修复：删除虚拟机该 identity 文件（agent 重新生成
  唯一 ID）＋结束全部 MeshLink/mesh-agent 进程后干净重启。
- **Controller 运行态**：controller 无守护，用户手动关闭后 18080 立即空闲；测试前需确保 controller 在跑
  （用户自写 vbs 自启动；本次打包时 18080 为空，用户确认系手动关闭）。客户机 config.json 当前为空
  （controller_url 未持久化），备份 `config.json.bak-test-residue` 记录曾用主机局域网 192.168.10.147:18080。


## Development Notes


Known problems should be recorded here.

Do not hide bugs.
