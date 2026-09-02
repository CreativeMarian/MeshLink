# MeshLink Current Status


## Current Version

v0.1.0


## Completed Milestones

[x] Project architecture

[x] DirectLink P2P

[x] Noise IK encryption

[x] Controller MVP

[x] Device identity

[x] Friend system

[x] Six digit invite code

[x] Recent connection

[x] Process lifecycle

[x] M1-2 N2N + Supernode（含 DirectLink 失败自动回退 N2N Relay）

[x] Session 生命周期日志（CREATE / JOIN / NOT FOUND / CLOSE + join 错误码透传）

[x] 双机联机修复（共享 Controller 拓扑；局域网 RFC1918 明文显式放行）

[x] 双机部署用户体验优化（未连接 Controller 明确提示；设置页当前 Controller 地址；ADR-004）

[x] 双机 Controller 生命周期设计（首次启动未配置不再默认连 127.0.0.1；设置页本机/已有地址二选一；
    仅「本机 Controller」模式才自动拉起 controller.exe；双机联机必须选「已有 Controller 地址」共享同一 Controller）

[x] Controller 生命周期与双机部署修复（三模式：LOCAL=本机 / LAN=局域网 RFC1918 自动监听 + -allow-lan-plaintext /
    REMOTE=已有地址不拉起本机；启动日志 [Controller Start] Mode/Listen；UI 用户化：首页【创建连接/加入连接】、
    设置页【连接设置】创建/加入二选一、服务器地址进高级设置隐藏；术语清理 Controller/SESSION/PeerFound）

[x] Public Controller 架构设计（ADR-005：CGNAT 环境下跨公网联机改用公网 Controller；Local 仅开发测试；
    Controller 只做注册/Session/信令，数据面仍 Agent↔Agent P2P；UI 保持创建/加入两入口；
    dist README 增加公网部署架构说明）

[x] 客户端正式版架构 + 公网 Controller（综合修复 P0/P1/P2）：
    正式版禁止客户端自动启动 controller.exe（仅 --local-controller dev 放行）；Controller 地址
    优先级 MESHLINK_CONTROLLER_URL env > 用户保存 > 默认公网 https://controller.bpbpanel.cc.cd >
    本地(dev)，永不回退 127.0.0.1；双击 MeshLink.exe 自动拉起 mesh-agent（3 次重试）；
    CREATE_NO_WINDOW 隐藏子进程；实时连接状态 STARTING/CONNECTING/CONNECTED/DISCONNECTED/ERROR +
    3s 心跳 + 自动重连；Session 全局保存 + 重启恢复 6 位码（Controller get_session 验证）；
    创建页显示连接服务器（不显示本机局域网地址）；诊断中心三层（健康/详情/日志查看）；
    logs/ 六类日志（app/agent/connection/controller/network/error）；启动失败自动恢复最多 3 次。

[x] mesh-agent 启动风暴修复（单例生命周期 + 握手等待 + 真实错误原因）：
    新增 AgentLifecycle 单例状态机（Stopped/Starting/Running/Failed）；统一入口
    ensure_agent_running()（首页/设置/诊断/心跳全部走同一入口），Starting 禁止重复 spawn；
    spawn 后必须等待 Named Pipe 握手（最多 5s）才认为启动成功；启动失败显示真实原因
    （进程退出码 + agent.log 尾部）；自动重试节流 5s；文案用户化
    （正在准备连接... / 连接服务启动失败 [自动重试] [查看诊断]）。
    实证：25s 观察只有 1 个 mesh-agent 进程、app.log 仅 1 条「启动 mesh-agent」；关闭后 agent 清理干净。

[x] 启动阻塞/卡死修复 + 启动失败退避（虚拟机实测）：
    ensure_agent_running 后台化（立即返回 STARTING，不再同步阻塞 ~20s 导致 UI 卡死）；
    启动失败 30s 冷却（next_spawn_at）+ 确定性失败（agent 缺失等）不重试 + 失败原因补记
    app.log；JS 自动重试指数退避 5s→10s→30s→60s；AGENT_START_FAILED 事件携带真实原因。
    实证：agent 缺失时 MeshLink 存活不卡、app.log 记录真实原因、不再无限 spawn。

[x] 双机公网 DirectLink 连通（真实双机 + 公网 Controller 实测，2026-09-02）：
    主机创建 code=721984 → 虚拟机 JOIN found_session=true → ICE punch 成功 → Noise 握手 →
    Overlay（主机 10.88.0.1 / 虚拟机 10.88.0.2）→ smoke_ok → 双方 Connected + 数据面
    双向加密传包（ICMP 往返）。公网 Controller（Cloudflare Tunnel）跨 NAT 全流程打通。

[x] UI 流程顶走/事件丢失修复（commit 8c4fa49）：
    PeerFound/Punching/NoiseHandshaking 不再顶走创建方连接码页（仅加入方 join/progress
    视图切进度页）；新增 syncConnectedView 兜底（Connected 事件丢失时自动补连接详情页，
    boot/waitReady/heartbeat 三处调用）。系统性 UI 排查：全部按钮绑定完整、Tauri 9 个
    command 对应完整、ActiveSession.status（SCREAMING_SNAKE）与 UI 匹配无误。

[x] UI 启动冻结修复（commit ddee880）：
    boot() 中 startStatusPoll() 原在 listen() 之后，listen 抛异常中断 boot → 心跳永不
    启动 → UI 永远停在初始态（已修复：startStatusPoll 前置 + 两个 listen 各自 try/catch +
    boot_heartbeat_contract.test.js 8 项全 PASS）。

[x] 全项目逻辑审查 + Phase1 优化（commit 8cbf219）：
    审查定位两类问题并修复——P0-1：agent.rs 2-worker Tokio runtime 被 controller-client
    同步裸 TCP 阻塞（IO_TIMEOUT=8s，startup/background_loop/handle_command/finish_connected
    全同步调用），Controller 慢时阻塞 worker 8s、其它 async 任务饿死 → 卡顿/心跳延迟；
    22 处同步 Controller 调用全部改 `AgentCore::controller_call`（spawn_blocking offload），
    refresh_presence 转 async。P1-4：fail() 置 Failed 后卡死需手动重连；新增 failed_at +
    background_loop 自动恢复（3s 展示真实原因后回 READY，仅已就绪的会话失败恢复，启动失败
    保持 Failed 由 ensure_agent_running 冷却重试）。验证：cargo check 干净、lib 11 /
    mvp_gate / friend_flow / n2n_flow(3) / service_identity / session_lifecycle /
    recent_connection_test 全 PASS。

[x] 日志系统优化（commit e35c4ff）：
    ① agent 默认日志级别 `info` → `info,agent=debug,mesh_agent=debug`（agent.rs 仅 4 处
    debug 不刷屏；状态切换/会话建链/候选处理/重试等中间步骤全部可见）。
    ② fail() 输出**故障现场快照** `FAIL_SNAPSHOT`（一行含 event 标记/状态/错误码/完整
    消息/controller/device_id/会话/对端/路径，诊断中心 error 分类可直接 grep）。
    ③ read_log_files 分类增强：error 分类改为**按 ERROR/WARN 级别真解析**（不再漏
    AUTH_INVALID 等关键词外错误）+ 关键词兜底（invalid/401/403/502/refused/panic 等扩充）；
    connection/network 关键词扩充（握手/noise/smoke/fail_snapshot/srflx/gather 等）；
    返回 levels 数组供 UI 着色。
    ④ 诊断中心 UI：健康区加「最近失败」展示；日志区加**关键字搜索 + 仅错误/警告过滤 +
    刷新按钮**；日志行按级别着色（ERROR 红/WARN 黄/DEBUG 灰）。
    ⑤ UI 侧收到 agent 的 Error 事件同步落 app.log（UI 视角错误时间线）。
    验证：cargo check 干净；lib 11 / JS 契约 4 / n2n_flow(3, --test-threads=1) /
    session_lifecycle(含 FAIL_SNAPSHOT 输出确认) 全 PASS。

[x] Phase2 逻辑审查优化（commit a8842b2）：
    P1-2：finish_connected 诊断 watchdog `loop { sleep 500ms; 打日志 }` 原不查 stop
    标志、永不退出（每次连接泄漏空转任务 + 每 2s 刷日志）；加 stop 检查退出。
    P1-3：abort_session_resources 原只拆 overlay+置 stop，不调 transport.stop_keepalive
    （keepalive 线程继续刷新 NAT 映射发包直至 transport drop）；补 stop_keepalive
    （Keepalive::Drop 置 stop + join 线程）清理 DirectLink/N2N peer keepalive。
    验证：cargo check 干净、lib 11 / friend_flow / n2n_flow(--test-threads=1, 3) 全 PASS。

[x] 审查后续项 P2-1~P2-4（commit 4897262）：
    P2-1：UI heartbeat 连续失败才判定断开——GetStatus 单次偶发超时不再误报
    「连接服务启动失败」/误触发 autoRetryAgent；连续 ≥3 次(约 9s)才切断开态，
    成功任意一次即清零（app.js statusFailStreak）。
    P2-2：agent 事件轮询动态背压——空轮询指数退避 2s→4s→8s→10s(上限 5 tick)，
    有事件或失败恢复 1 tick，减少空闲期对 Controller 无意义轮询（agent.rs）。
    P2-3：mesh-ipc 广播有界化——连接写出通道 unbounded→sync_channel(512)，
    广播 try_send 非阻塞，慢客户端(队列满/断开)判 dead 移除，防内存膨胀拖累
    全体（server.rs SyncSender）。
    P2-4：controller.db 启动完整性校验——OpenWithOverlayPool 加 PRAGMA quick_check，
    文件损坏时明确报错(含 db 路径)而非静默重建空库导致设备身份丢失（store.go，
    内存库 isMemory 跳过）。
    验证：cargo check 干净；mesh-ipc 19 / mesh-agent lib 11 / JS 契约 4 / Go
    controller 4 包全 PASS；n2n_flow 单跑 3 次全过（全跑 486/565 为已知 free_port
    TOCTOU UDP bind 竞态，非本次回归）。

[x] M1-3a Path Manager 核心（commit 3756b69）：
    overlay-router 从占位符升级为可用的多路径选路管理器（M1-3 前半段）：
    ① 只面向 transport-api::TransportProvider，禁止任何具体实现类型/分支（确认版 §4）；
    ② register()/set_policy()/force_path()：多 Provider 注册 + 自动/强制双模式，
       强制路径(SetPath 映射)与自动路径共存；
    ③ attach_peer()：统一 subscribe_events + connect_peer（事件先于连接订阅，
       回流窗口不丢 Fatal/Reachable）；
    ④ evaluate()：同步可测的选路决策入口——健康采样 + 本地快照决策（锁纪律：
       先快照后决策，决策期不嵌套持锁，修复同线程二次加锁死锁）；
    ⑤ Hard Failure（Fatal/PeerUnreachable 事件）→ 立即熔断并切换；
       Quality Degradation（Critical<40 持续 3s）→ 驱动切换；两套机制分离；
    ⑥ 回切更高 rank 路径（P2P 恢复）须稳定 10s 防抖（switchback_stable）；
    ⑦ PathSwitchRecord 切换事件（文档 9.5 from/to/reason/score）+ snapshot 诊断
       （active/paths/score/rtt/breaker）；
    ⑧ run() tokio 定时驱动 wrapper（agent 接入在 M1-3b）。
    验证：overlay-router 10/10 单测 PASS（initial/down/forced/degraded/fatal/
    switchback_stable/forced_failed/snapshot/send_routes/event_emit，0.00s 无挂起）；
    cargo check --workspace 干净。


## Current Development

M1-3b 把 PathManager 接入 mesh-agent（pump 转发走 active path + SetPath/status 上抛）


## Next Milestones

M1-3b Path Manager 接入 agent

M1-4 HFS 文件共享

M1-5 MeshTransfer 高速传输

M2 File Transfer

M3 Remote Desktop

M4 Productization


## Last Update

2026-09-02
