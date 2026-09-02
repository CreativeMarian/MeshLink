# MeshLink Changelog


## M1-3a Path Manager 核心：多路径选路/熔断/防抖/强制路径（2026-09-02，commit 3756b69）

Added:

- **overlay-router 从占位符升级为 Path Manager（M1-3 前半段）**：新增
  `crates/overlay-router/src/path_manager.rs`，只面向 `transport-api::TransportProvider`，
  禁止任何具体实现类型/分支。
- **多 Provider 注册**：`register(name, provider, kind, breaker_scope)` 返回槽位索引，
  每个 provider 独立健康/熔断/退化计时；`set_policy()` 初始策略（默认 DirectFirst）。
- **强制路径与自动路径共存**：`force_path(Some(slot))` 锁定指定路径（agent SetPath
  auto/directlink/n2n 映射入口）；强制路径熔断时自动让出给最佳候选（不死锁在坏路径）。
- **事件驱动的 Hard Failure**：`handle_event` 消费 `Fatal` / `PeerUnreachable` 事件 →
  立即熔断对应 BreakerScope（DirectLinkPeer / N2NProvider）→ 下一次 `evaluate` 即切换；
  `HealthChanged` 事件实时更新健康缓存。
- **健康分驱动的 Quality Degradation**：score < 40（Critical）持续 3s → 切换到最佳
  候选；两套触发机制分离（确认版 §4）。
- **防抖回切**：更高 rank 路径（P2P 恢复）须连续稳定 10s（healthy_threshold=70）
  才回切，避免 P2P/N2N 抖动来回切换。
- **选路决策同步可测**：`evaluate(now)` 纯同步；内部先快照健康/熔断/退化/稳定到本地
  Vec 再决策，**决策期不嵌套持锁**（修复同线程二次加锁死锁——首版死锁导致测试挂起）。
- **切换事件 + 诊断快照**：`PathSwitchRecord{from,to,reason,score,at_ms}`（文档 9.5）
  经 event_sink 上抛；`snapshot()` 返回 active/paths（score/rtt/breaker）供诊断页。
- **run() wrapper**：tokio interval 定时驱动 drain_events + evaluate（agent 侧
  M1-3b 再 spawn）。

Changed:

- `crates/overlay-router/Cargo.toml`：补 tokio(sync/time)、tracing、config-manager
  （RuntimeParams 作熔断参数来源）、async-trait/serde；dev-deps tokio(macros/rt) 供测试。
- `crates/overlay-router/src/lib.rs`：导出 PathManager 及类型。

Verified:

- overlay-router 单测 **10/10 PASS**（initial_select / selects_n2n_when_down /
  forced_path_locks / degraded_switches_after_window / fatal_breaks_immediately /
  switchback_requires_stability / forced_path_failed_falls_back / snapshot_reflects /
  send_packet_routes_to_active / event_sink_emits_switch_record），0.00s 无挂起。
- cargo check --workspace 干净（仅 mesh-vnic-test-helper 历史遗留 unused `sn` warning，
  非本次改动）。


## 审查后续项 P2-1~P2-4：心跳防误报 + 轮询背压 + 广播有界化 + DB 完整性（2026-09-02，commit 4897262）

Changed / Fixed:

- **P2-1 UI heartbeat 连续失败才判定断开（app.js）**：`heartbeat()` 原 GetStatus 单次
  失败即 `setConnState(DISCONNECTED)` + `autoRetryAgent()`——agent 忙于建链 / Controller
  偶发超时也会误报「连接服务启动失败」并反复拉起。新增 `S.statusFailStreak`：失败连续
  ≥3 次（约 9s）才切断开态 + 自动重试；成功任意一次清零。
- **P2-2 agent 事件轮询动态背压（agent.rs）**：`background_loop` 原固定每 2s `poll_events`，
  空闲期对 Controller 无意义轮询。改为空轮询指数退避 2s→4s→8s→10s（上限 5 tick），
  有事件或轮询失败恢复 1 tick。心跳（30s）/在线状态刷新（30s）不受影响。
- **P2-3 mesh-ipc 广播有界化（server.rs）**：每连接写出通道 `unbounded mpsc::channel`
  → `sync_channel(512)`，`ClientRegistry` 存 `SyncSender`；广播线程 `send` → `try_send`
  非阻塞，队列满（慢客户端跟不上）或已断开判 dead 移除——不再让一个慢客户端拖累全体
  广播线程、也不让事件无限堆积撑爆内存。
- **P2-4 controller.db 启动完整性校验（store.go）**：`OpenWithOverlayPool` 迁移后加
  `PRAGMA quick_check`，损坏/被截断的 db 文件启动即明确报错（含 db 路径），不再静默
  重建空库导致设备身份/会话数据「凭空消失」。内存库（isMemory）跳过。

Verified:

- cargo check 干净；mesh-ipc 19 / mesh-agent lib 11 / JS 契约 4（quick_code/ui_error/
  recent/boot_heartbeat）/ Go controller 4 包全 PASS。
- n2n_flow 单跑 3 次全过（3.59/3.48/3.50s）；全跑偶发 486/565 失败为**已知 free_port
  TOCTOU UDP bind 竞态**（KNOWN_ISSUES），非本次改动引入。


## 日志系统优化：更多日志 + 更清晰定位（2026-09-02，commit e35c4ff）

Changed:

- **agent 默认日志级别提升**：`info` → `info,agent=debug,mesh_agent=debug`。agent.rs 内
  debug 仅 4 处（不刷屏），状态切换/会话建链/候选处理/重试等中间步骤现在全部可见。
- **故障现场快照 FAIL_SNAPSHOT**：`fail()` 失败时一行输出完整现场——event 标记 /
  state / 错误码 / 完整错误消息 / controller / device_id / 会话(session_id/role/code6) /
  对端 / 当前路径。诊断中心 error 分类可 grep `fail_snapshot` 直接抓到失败现场，
  无需翻几十行前文拼上下文。
- **UI 侧错误落盘**：MeshLink 收到 agent 的 Error 事件（如 AUTH_INVALID /
  CONTROLLER_UNREACHABLE）同步写 app.log，app 分类可见 UI 视角错误时间线。
- **分类日志真解析**：`read_log_files` error 分类改为按 ERROR/WARN 级别解析（不再依赖
  关键词而漏掉 AUTH_INVALID 这类词外错误），并补关键词兜底（invalid/401/403/502/
  refused/panic 等）；connection/network 关键词扩充（握手/noise/smoke/fail_snapshot/
  srflx/gather/supernode 等）。返回 `levels[]` 与 `lines[]` 一一对应。
- **诊断中心 UI**：健康区加「最近失败」；日志区加关键字搜索（提示如 fail_snapshot、
  握手、502）、「仅错误/警告」过滤、刷新按钮；日志行按级别着色（ERROR 红/WARN 黄/
  DEBUG 灰）。

Verified:

- cargo check 干净；lib 11 / JS 契约 4（quick_code/ui_error/recent/boot_heartbeat）/
  n2n_flow(3, --test-threads=1) / session_lifecycle 全 PASS。
- FAIL_SNAPSHOT 实际输出确认：
  `ERROR agent: 会话流程失败（故障现场） event="FAIL_SNAPSHOT" state=Ready
  code="SESSION_CODE_INVALID" error=... controller=... device_id=... session_id=...
  role=... code6=... peer_device=... path=...`


## Phase2 逻辑审查优化：P1-2 watchdog 退出 + P1-3 keepalive 清理（2026-09-02，commit a8842b2）

Fixed:

- **P1-2 watchdog 泄漏/刷屏**：`finish_connected` 的诊断 watchdog
  `loop { sleep 500ms; n++; if n<=4 || n%4==0 { 打日志 } }` 原**不查 stop 标志、永不
  退出**——每次连接泄漏一个空转任务 + 每 2s 刷一条「watchdog: runtime 调度心跳」。
  修复：每轮先查 `stop.load()`，会话结束即 break 退出，不再泄漏/刷屏。
- **P1-3 keepalive 线程残留**：`abort_session_resources` 原只拆 Overlay + 置 stop，
  **不调 transport.stop_keepalive**——会话结束后 DirectLink/N2N 的 keepalive 线程仍
  继续每 15s 刷新 NAT 映射发包，直至 transport drop（dispatcher_stop）。修复：abort
  时对 `s.peer.peer_id` 调用 `transport.stop_keepalive` + `n2n.stop_keepalive`
  （Keepalive::Drop 置 stop 标志并 join 线程），会话结束即停止保活线程。

Verified:

- `cargo check` 干净（无新增 warning）；mesh-agent lib 11 / friend_flow /
  n2n_flow(--test-threads=1, 3) 全 PASS。
- 注：n2n_flow 默认并行跑时偶发 `N2NSupernode::bind` 端口竞态（free_port TCP 探测 →
  UDP bind 的 TOCTOU，SERIAL 锁 poisoned 连锁），`--test-threads=1` / 单测 / 顺序跑
  全 PASS；属测试基建已知抖动，非产品逻辑。


## Phase1 逻辑审查优化：P0-1 同步调用隔离 + P1-4 失败自动恢复（2026-09-02，commit 8cbf219）

Fixed:

- **P0-1 运行时饿死（架构级）**：agent.rs Tokio runtime 仅 `worker_threads(2)`，而
  controller-client 为**同步裸 TCP**（IO_TIMEOUT=8s）。`startup` / `background_loop`
  （每 2s `poll_events`）/ `handle_command` / `finish_connected` 全同步调用 Controller，
  Controller 慢时一次最多阻塞 worker 8s，其它 async 任务（心跳、IPC、会话流程）可能
  饿死 → 卡顿 / 心跳延迟。修复：新增 `AgentCore::controller_call`（`spawn_blocking`
  包装，`tokio::task::spawn_blocking(f).await`），22 处同步 Controller 调用
  （healthz / register_device / list_supernodes / poll_events / create_session /
  get_session / presence_heartbeat / list_friendships / upsert_recent_connection /
  join_session / get_candidates / put_candidates / reject_connection_request /
  register_supernode）全部 offload；`refresh_presence` 转 async fn。
- **P1-4 会话失败后自动恢复**：`fail()` 置 Failed 后原需手动重连；新增 `failed_at`
  时间戳 + `background_loop` 自动恢复（失败展示 3s 后若仍 Failed 且无活动会话 →
  自动回 READY 并发 Disconnected 事件让 UI 回到可操作状态）。仅**已就绪后的会话
  失败**恢复；启动阶段失败（Controller 不可达等）保持 Failed，由
  `ensure_agent_running` 冷却重试。`set_state(Ready)` 清空 failed_at。

Verified:

- `cargo check` 干净（无新增 warning）；mesh-agent lib 11 测试 / mvp_gate / friend_flow /
  n2n_flow(3) / service_identity / session_lifecycle_test / recent_connection_test 全 PASS。
- `default_port_alignment` 因本机 18080 被运行中 controller（PID 17076）占用未跑（环境
  冲突，非回归；停止 controller 后可复跑）。n2n_flow 偶发 0.00s 端口竞态为测试基建
  free_port TOCTOU 已知抖动（单测/顺序跑全 PASS）。


## UI 启动冻结修复（2026-09-02，commit ddee880，补记）

Fixed:

- **boot 被 listen 异常中断 → 心跳永不启动**：`boot()` 中 `startStatusPoll()` 原在
  `listen()` 之后；`listen()` 抛异常会中断 boot，导致心跳轮询从未启动，UI 永远停在
  初始状态（「正在连接服务...」）。修复：`startStatusPoll()` 前置 + 两个 `listen()`
  各自 try/catch 包裹。
- 新增 `apps/meshlink-ui/tests/boot_heartbeat_contract.test.js`（8 项）覆盖：boot
  异常时心跳仍启动、listen 失败不中断启动流程。


## 双机公网 DirectLink 连通 + UI 流程顶走/事件丢失修复（2026-09-02，commit 8c4fa49）

Fixed:

- **UI 流程顶走根因（真实双机公网验证）**：`PeerFound`/`Punching`/`NoiseHandshaking` 事件
  原为 `if (S.view !== "create"/"progress") show("progress")`——创建方在**连接码页（create）或
  首页（home）**查看时，对端一加入就会被强制顶到进度页，连接码页消失（用户实测
  「切到其他页面再切回来看不到连接码」）。修复：四个事件统一为仅 `join/progress`（加入方
  流程）视图才切进度页，创建方连接码页一律不被顶走。
- **Connected 事件丢失兜底**：当 agent 已在运行且已 CONNECTED（UI 重启 / 事件在
  `listen()` 订阅前发出）时，事件丢失导致 UI 只显示状态点、不切连接详情页。新增
  `syncConnectedView(snap)`：GetStatus 为 CONNECTED 且处于 create/progress/join/home
  视图时填充连接详情并切到连接页；boot（agent 已就绪分支）、waitReady（CONNECTED 分支）、
  heartbeat（状态刚进入 CONNECTED）三处调用，绝不打扰 settings/friends/devices/diag 浏览。
- **系统性 UI 排查结论**：静态核对 index.html 全部 115 个 id vs app.js 引用/事件绑定——
  所有 `<button>` 均有绑定、无悬空 addEventListener / 悬空 `$()` 引用；Tauri bridge
  9 个 command（agent_connect/ensure_agent_running/ipc_request/get_controller_default/
  load_ui_config/save_controller_config/save_controller_url/get_controller_config/
  read_log_files）与 app.js `invoke` 全部对应；`ActiveSession.status` 用 `wire()`（serde
  SCREAMING_SNAKE）与 UI 英文常量匹配无误。

Verified（真实双机公网，2026-09-02 实测）：

- 主机（dev-c3cc517f2c459ea0）`[SESSION CREATE] code=721984` → 虚拟机
  （dev-4da9787ba66c4de1）`[SESSION JOIN] found_session=true` → 双方
  `PUNCH_EVIDENCE`（ICE punch 成功 rtt≈4.7ms）→ Noise 握手（initiator/responder）
  → Overlay 配置（主机 10.88.0.1 / 虚拟机 10.88.0.2）→ 冒烟 smoke_ok →
  **双方 `state=Connected` + `event=Connected` 广播** → 数据面持续双向加密传包 +
  ICMP 经 Overlay 往返（iter 上万无错误）。公网 Controller
  `https://controller.bpbpanel.cc.cd`（Cloudflare Tunnel）跨 NAT 全流程打通。
- JS 契约测试（quick_code 39 / ui_error 47 / recent）全 PASS；`node --check` 通过；
  dist\MeshLink.exe 重新编译打包（SHA256 F5052F7E...，10758144B）。


## 启动阻塞/卡死修复 + 启动失败退避（2026-09-02）


Fixed:

- **UI 卡死根因（虚拟机实测）**：`ensure_agent_running` 原为同步 Tauri command，agent
  起不来时 `do_agent_connect` 阻塞约 20+s（3 次 × spawn+等 pipe 5s）；`boot()` 的
  `await invoke("ensure_agent_running")` 挂起阻塞，且失败后心跳每 5s 反复触发重启，
  反复 spawn 崩溃的 agent → CPU 飙高 → 整个 UI 卡死（点击设备等操作无响应）。
- **启动流程后台化**：`ensure_agent_running` 改为单例 gate 后**立即返回 STARTING**，
  真正启动放到独立后台线程执行（`app.state::<IpcState>()` 重新获取状态，无 lifetime
  依赖）；启动成功经 IPC 线程建立 + ControllerConnected 事件感知，失败经
  `AGENT_START_FAILED` 事件携带真实原因（进程退出码 + agent.log 尾部）。
- **启动失败 30s 冷却**：`IpcState.next_spawn_at` 记录冷却截止；agent 反复起不来时
  `do_agent_connect` 在冷却期内直接返回「后台服务启动失败，约 N 秒后自动重试（请查看
  诊断中心 agent.log）」，不再高频 spawn 崩溃进程。
- **确定性失败不重试**：`spawn_agent_process` 返回 Err（未找到 agent / exe 路径错误）
  直接 break（重试无意义），只有「spawn 成功但 pipe 未就绪」才在本轮重试；失败原因
  补记 app.log（此前 agent 缺失时 spawn_agent_process 在写日志前返回，诊断中心空白）。
- **JS 自动重试指数退避**：`AGENT_RETRY_BACKOFF = [5s,10s,30s,60s]`，成功归零；心跳
  失败分支走 `autoRetryAgent`，不再每 5s 高频触发。
- **UI 失败文案与诊断**：`handleErrorEvent` 新增 `AGENT_START_FAILED` 分支——显示
  「连接服务启动失败」+ 真实原因（含 agent.log 尾部）+ [重新连接]。

Added:

- 实证验证（本机真实 dist 二进制）：
  - agent 缺失路径：8s 后 MeshLink 存活不卡死，app.log 记录「mesh-agent 启动失败：未找到
    后台服务」；不再无限 spawn。
  - 正常路径：1 个 mesh-agent、1 条启动日志、默认公网 Controller、关闭后清理为 0。
- meshlink-ui 单测 9 项、JS 契约（47/39/recent）全 PASS。


## mesh-agent 启动风暴修复（2026-09-02）

Fixed:

- **mesh-agent 启动风暴根因**：`agent_connect` 是同步 Tauri command，首页加载 / 设置页 /
  诊断页 / 心跳**并发**调用时无单例锁，每个调用者各自跑 3 次 spawn 循环 → 日志反复
  「启动 mesh-agent」几十次；且 spawn 后等 15s 未就绪就 kill 重试，agent 启动慢时被反复
  杀掉重启。
- **单例生命周期**：新增 `AgentLifecycle`（Stopped/Starting/Running/Failed）状态机，
  统一入口 `ensure_agent_running()`（首页/设置/诊断/心跳全部走它，`agent_connect` 变为
  等价别名）。`Starting` 状态禁止再次 spawn（返回「正在准备连接...」）；并发调用者
  直接返回，只有第一个进入真正启动流程。单测 `agent_lifecycle_singleton_starts_only_once`
  覆盖 Stopped→Starting（禁止重复）→Running（不启动）/Failed（允许重启）。
- **握手等待**：spawn 后必须等待 Named Pipe 就绪（`wait_pipe_ready`，轮询最多 5s）才认为
  启动成功，禁止 spawn 后立即返回成功。
- **失败显示真实原因**：启动未就绪时 `child_exit_reason` 收集进程退出码 + `agent.log`
  尾部，替代笼统「后端服务启动失败」；诊断中心可据此定位。
- **自动重试节流**：心跳/恢复共用 `autoRetryAgent()`（5s 节流），统一走
  `ensure_agent_running` 单例入口。
- **文案用户化**：「正在准备连接...」替代「正在连接服务...」；「连接服务启动失败
  [自动重试] [查看诊断]」替代「后端服务启动失败」。
- **实证验证**（本机真实 dist 二进制）：25s 观察始终只有 1 个 mesh-agent 进程、
  app.log 仅 1 条「启动 mesh-agent」（修复前几十次）；关闭 MeshLink 后 agent 清理为 0。
- 清理本机 `%LOCALAPPDATA%\MeshLink\ui\config.json` 中旧 LAN 测试残留
  （`mode=local` + `192.168.10.147:18080`，会覆盖默认公网 Controller），恢复默认公网
  `https://controller.bpbpanel.cc.cd`（备份为 `config.json.bak-test-residue`）。

Added:

- ipc.rs 单元测试 +1（agent_lifecycle_singleton_starts_only_once），meshlink-ui 单测 8→9。
- 全部验证 PASS：meshlink-ui 9 单测、JS 三契约（47/39/recent）、workspace 全量、
  release smoke 四文件 5 用例（binary/gui/lifecycle/two_machine）。


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
