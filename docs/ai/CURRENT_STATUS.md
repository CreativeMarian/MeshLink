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


## Current Development

M1-3 Path Manager（DirectLink ↔ N2N 自动选路）


## Next Milestones

M1-3 Path Manager

M1-4 HFS 文件共享

M1-5 MeshTransfer 高速传输

M2 File Transfer

M3 Remote Desktop

M4 Productization


## Last Update

2026-09-02
