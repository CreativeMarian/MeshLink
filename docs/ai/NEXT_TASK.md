# Next Task


## Current Milestone

双机复测最新包（验证 UI 已连接展示 / 失败自动恢复 / 日志可见性）→ M1-3 Path Manager


## 当前焦点（双机复测 + 后续优化）

- Phase1（8cbf219）、Phase2（a8842b2）、日志优化（e35c4ff）、审查后续项 P2-1~P2-4
  （4897262：heartbeat 连续失败才断开 / 事件轮询背压 / mesh-ipc 广播有界化 /
  controller.db quick_check 完整性）均已完成并推送，相关测试全 PASS。
- **待办：双机复测最新包**（用户暂没时间，一版先敲定；等用户方便时再测）：
  1. 首页/连接码页/加入进度页在底层 Connected 后正确展示已连接（不再卡「正在寻找设备」/
     「等待好友加入」）；
  2. 会话失败后 UI 显示真实原因并在 ~3s 后自动回可操作状态（P1-4）；
  3. 日志可见性：失败时 agent.log 出现 FAIL_SNAPSHOT、诊断中心 error 分类着色 +
     搜索 fail_snapshot 定位；
  4. 断连不再单次误报（P2-1：连续 9s 失败才判定断开）。
  前提：两台都用新包（MeshLink.exe 需重编译嵌入最新 UI）、虚拟机无残留手动旧
  mesh-agent、虚拟机 config 无旧 LAN 残留。
- 打包流程（用户下次要测时执行）：`cargo build -p mesh-agent --release` +
  `cargo build -p meshlink-ui --release`（build.rs 自动嵌入 ui/）→ 覆盖 dist\ →
  Compress-Archive 六件套；打包前关 MeshLink.exe/controller.exe（文件锁，但用户
  controller PID 17076 运行中需保留时跳过 controller）。

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
