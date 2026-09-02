# Next Task


## Current Milestone

Phase2 逻辑审查优化（P1-2 watchdog / P1-3 transport 清理）→ 打包双机复测 → M1-3 Path Manager


## 当前焦点（Phase2：P1-2 / P1-3）

- Phase1（commit 8cbf219）已完成：P0-1 同步 Controller 调用全 offload（spawn_blocking，
  根治 2-worker runtime 饿死）+ P1-4 失败后自动回 READY（3s 展示真实原因）。全部相关
  测试 PASS。
- **Phase2 待实施**：
  1. **P1-2**：`finish_connected` watchdog `loop { sleep 500ms; 打日志 }` 不查 stop
     标志、永不退出 → 每次连接泄漏一个空转任务 + 刷屏。加退出条件（stop 标志 / 会话
     结束 / 连接断开）。
  2. **P1-3**：`abort_session_resources` 只拆 overlay+置 stop，不调
     transport.stop_keepalive / 清 Noise 状态；`spawn_stun_refresh` /
     `spawn_reverse_probe` 线程无会话级退出 → 多次会话后线程残留。加会话级退出 + 清理。
- Phase2 完成后：cargo build + cargo test + commit+push + 更新 docs/ai 四份文档。
- 随后**重新打包 dist + 双机复测**（新包）：验证 ① 首页/连接码页/加入进度页在底层
  Connected 后正确展示已连接（不再卡"正在寻找设备"/"等待好友加入"）；② 会话失败后
  UI 显示真实原因并在 ~3s 后自动回可操作状态。前提：两台都用新包、虚拟机无残留手动旧
  mesh-agent、虚拟机 config 无旧 LAN 残留。

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
