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

2026-09-01
