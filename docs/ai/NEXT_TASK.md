# Next Task


## Current Milestone

M1-3b：把 PathManager 接入 mesh-agent（M1-3a 核心已交付，commit 3756b69）


## 当前焦点（M1-3b PathManager 接入 agent）

- M1-3a 已完成（commit 3756b69，已 push）：overlay-router 从占位符升级为可用
  PathManager——多 Provider 注册 / attach_peer（subscribe_events+connect_peer）/
  evaluate() 同步可测选路决策（健康采样+本地快照，锁纪律防死锁）/ 强制路径与自动
  共存 / Hard Failure(Fatal 事件)立即熔断切换 + Quality Degradation(Critical<40 持续
  3s)驱动切换 / 回切高 rank 路径须稳定 10s 防抖 / PathSwitchRecord 切换事件 +
  snapshot 诊断 / run() tokio 定时 wrapper。单测 10/10 PASS，cargo check --workspace
  干净。
- **M1-3b 待做（下一步）**：
  1. agent.rs AgentCore 内建 `PathManager`，注册 DirectLink + N2N 两个 provider；
  2. N2NTransport::subscribe_events 空实现 → 接 PathManager 事件回流（M1-3 预留点，
     当前 N2N 事件走 mesh-ipc Event）；
  3. pump() 数据面改为经 PathManager::send_packet 转发 active path（不中断 Overlay）；
  4. finish_connected 接入（active path 冒烟 + PathKind 上抛）；
  5. SetPath 命令映射到 force_path（auto/directlink/n2n）；
  6. n2n_status_json / status 上抛 active_path + PathSwitchRecord（诊断页展示）。
- 验证：`cargo test -p overlay-router`（10）+ `cargo test -p mesh-agent --lib` +
  `cargo test -p mesh-agent --test n2n_flow -- --test-threads=1` + JS 契约 4。
- 双机复测最新包（用户暂没时间，一版先敲定；等用户方便时再测）：
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

## M1-3 Path Manager（完成度：a 已交付，b 进行中）

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
