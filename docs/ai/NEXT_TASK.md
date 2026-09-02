# Next Task


## Current Milestone

打包最新 dist + 双机复测（验证 UI 已连接展示 / 失败自动恢复）→ 后续审查项 P2-1~P2-4 → M1-3 Path Manager


## 当前焦点（打包 + 双机复测）

- Phase1（commit 8cbf219）、Phase2（commit a8842b2）、日志优化（commit e35c4ff：
  agent debug 默认 + FAIL_SNAPSHOT 故障现场 + 分类日志级别解析 + 诊断中心搜索/着色）
  均已完成并推送，相关测试全 PASS。
- **下一步：重新打包 dist + 双机复测**（MeshLink.exe 需重新编译，UI 有改动）：
  1. 首页/连接码页/加入进度页在底层 Connected 后正确展示已连接（不再卡「正在寻找设备」/
     「等待好友加入」）；
  2. 会话失败后 UI 显示真实原因并在 ~3s 后自动回可操作状态（P1-4）；
  3. 日志可见性：失败时 agent.log 出现 FAIL_SNAPSHOT 故障现场、诊断中心 error 分类按
     级别着色 + 搜索 fail_snapshot 能定位；长时间运行无 watchdog/keepalive 残留。
  前提：两台都用新包、虚拟机无残留手动旧 mesh-agent、虚拟机 config 无旧 LAN 残留。
- 之后可做 P2-1~P2-4（低优先）：heartbeat 连续失败才切换 / 事件轮询背压 /
  广播 channel 限流 / controller.db 空库校验。

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
