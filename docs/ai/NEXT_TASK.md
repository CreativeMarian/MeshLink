# Next Task


## Current Milestone

双机公网连接收尾（UI 修复验证 + 公网 P2P 全流程复测）→ M1-3 Path Manager


## 当前焦点（双机公网连接 UI 收尾）

- 底层公网 DirectLink 已打通（commit 8c4fa49 前已验证：code=721984、主机 10.88.0.1 /
  虚拟机 10.88.0.2、双方 Connected）。下一轮用**最新 dist 包**（SHA256 F5052F7E...）
  双机复测，确认：
  1. 创建方连接码页不被 PeerFound/Punching/NoiseHandshaking 顶走；
  2. 切页再切回仍能看到连接码（active_session 恢复）；
  3. 连接成功 UI 一定切到「已连接」详情页（Connected 事件 + syncConnectedView 兜底）；
  4. 两台机器都必须用新 MeshLink.exe + mesh-agent.exe（版本一致）。
- 双机复测通过后，再验证：Overlay 虚拟 IP ping（10.88.0.1 ↔ 10.88.0.2）与真实数据面。
- 主机 Controller 需保持存活（用户自写 vbs 自启动）；公网 Controller 可达性前置检查。

## M1-3 Path Manager（后续）

## Goal

实现 DirectLink ↔ N2N/Supernode 的自动实时选路与切换（M1-2 已完成「DirectLink 失败 → N2N 回退」的单向自动回退；M1-3 在两者都可用时自动选最优路径，并在运行中按 RTT/丢包切换，不中断数据面）。


## Requirements

- 多路径健康度量（DirectLink RTT/Loss + N2N Relay RTT/Loss）
- 自动选路策略（初始 + 运行中切换）
- 路径切换不中断 Overlay 数据面（recent_connection 保留实际路径记录）
- Path Manager 状态与切换事件上抛 UI（高级诊断展示）
- 强制路径（SetPath auto/directlink/n2n）与自动路径共存


## After Completion

Update:

- CURRENT_STATUS.md
- CHANGELOG.md
- KNOWN_ISSUES.md
- NEXT_TASK.md


Then:

- 项目已建立 git（remote：git@github.com:CreativeMarian/MeshLink.git，branch main）：
  每个功能阶段 git add/commit/push，提交信息清晰（如 "Fix quick session creation flow"）；
  完成后更新 CURRENT_STATUS.md / CHANGELOG.md / NEXT_TASK.md 再提交。


Finally report:

Development completed, notify ChatGPT to review repository.
