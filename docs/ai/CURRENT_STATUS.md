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
