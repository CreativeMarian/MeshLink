# Known Issues


## Pending


- Real world public network validation

- Wintun physical machine validation

- NAT compatibility improvement

- Fast reconnect optimization


## M1-2 N2N + Supernode（2026-09-01）


- 自动回退为单向（DirectLink 失败 → N2N Relay）；双向自动选路与运行中实时切换属 M1-3 Path Manager。
- N2N 每 Supernode 熔断阈值当前为 3（`N2NParams.failure_threshold`）；快速回退竞态下（joiner 早于
  creator 注册到 SN 之前就开始 QueryPeer 重试）短暂超时会计入熔断，但 Supernode 重启/恢复后 HALF_OPEN
  探测自动复位，链路可自愈；如需更宽松可调高阈值或延长 `request_timeout_ms`。
- 本机 DEV Supernode 自动拉起/注册当前为固定参数（127.0.0.1:7654 / priority 100），尚未做成可配置；
  远程 Supernode 由 Controller Supernode Registry 下发（priority 排序）。
- DirectLink 数据面测试在机器高负载时偶发打洞抖动（自动化测试的 Controller 启动轮询超时已由 10s 放宽
  至 30s；真实 DirectLink 建立本身由 30s punch_timeout 兜底，属可接受抖动）。
- 若 `dist\` 下的 MeshLink.exe / controller.exe / mesh-agent.exe 正在运行，会因文件锁阻止 dist 重新打包，
  需先关闭 MeshLink 客户端（MeshLink 退出会完整回收其拉起的 agent/controller）。


## Session 生命周期日志（2026-09-01）


- 修复：`JoinQuickSession` 之前把所有 join 失败都硬编码为 `SESSION_NOT_FOUND`，掩盖了 Controller 真实
  业务码（如无效码实际返回 `SESSION_CODE_INVALID`）。现改为透传 `ApiError.code`（传输层错误保留
  `TRANSPORT`），配合 `[SESSION NOT FOUND]` 日志记录 `input_code` + `reason`，可直接区分
  `SESSION_CODE_INVALID` / `SESSION_EXPIRED` / `SESSION_STATE_INVALID` / `SESSION_RATE_LIMITED`。
- 新增 Agent 侧 Session 生命周期日志（tracing，RUST_LOG=info 可见）：
  `[SESSION CREATE]`（session_id/code/device_id/expires_at）、`[SESSION JOIN]`（input_code/found_session/
  session_id）、`[SESSION NOT FOUND]`（input_code/reason）、`[SESSION CLOSE]`（session_id/reason）。
- Controller 侧（Go slog）同步统一为同前缀生命周期日志；create 仍写入 `connection_sessions` 表
  （6 位码唯一来源 = Controller `POST /v1/sessions` 响应，前端/Agent 均不自行生成）。
- creator 轮询 `get_session` 失败记录为 `[SESSION NOT FOUND] poll`（debug 级，避免轮询期刷屏）。


## Development Notes


Known problems should be recorded here.

Do not hide bugs.
