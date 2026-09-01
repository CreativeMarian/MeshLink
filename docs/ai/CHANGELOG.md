# MeshLink Changelog


## v0.1.0

Added:

- DirectLink P2P
- Noise encryption
- Controller system
- Friend management
- Recent connections
- Runtime lifecycle
- N2N + Supernode backup path（M1-2）


## M1-2 N2N + Supernode（2026-09-01）

Added:

- DirectLink 建链失败（Auto 路径）自动回退 N2N Supernode Relay：
  creator Noise 握手超时 / joiner 打洞失败 / Noise 握手失败 → 自动切换 N2N；
  Force DirectLink / Force N2N 保持不回退语义。
- Connected 事件携带实际路径 `path`（directlink | n2n）；普通 UI 显示
  DirectLink / N2N Relay，高级诊断显示 `current_path` + N2N 状态。
- GetStatus.current_path 记录当前连接实际路径；recent_connection.last_path
  按实际路径记录（Auto + 实际 N2N 不再误标 directlink）。
- MeshLink 监督者生命周期扩展：DEV 模式自动拉起本机 n2n-supernode.exe、
  经 Agent IPC 注册到 Controller Supernode Registry、退出正确关闭。
- mesh-ipc 新增 `RegisterLocalSupernode` 命令；controller-client 新增
  `register_supernode`。
- 自动集成测试：auto_fallback_n2n（DirectLink 失败 → N2N Relay → 加密
  overlay ping 64/512/1200/1400B）、force_directlink_success 保持 directlink。


## Session 生命周期日志（2026-09-01）

Fixed:

- `JoinQuickSession` join 失败不再硬编码 `SESSION_NOT_FOUND`：透传 Controller 真实
  业务码（无效码 → `SESSION_CODE_INVALID` 等），可直接区分过期/状态/限流错误。

Added:

- Agent 侧 Session 生命周期日志：`[SESSION CREATE]`（session_id/code/device_id/
  expires_at）、`[SESSION JOIN]`（input_code/found_session/session_id）、
  `[SESSION NOT FOUND]`（input_code/reason）、`[SESSION CLOSE]`（session_id/reason）；
  creator 轮询 `get_session` 失败 → `[SESSION NOT FOUND] poll`（debug 级）。
- Controller（Go slog）同步统一生命周期日志前缀；`[SESSION CLOSE]` 覆盖好友直连
  拒绝与好友删除时关闭的会话。
- 确认 6 位码唯一来源 = Controller `POST /v1/sessions` 响应（`connection_sessions`
  表写入 + 原子分配）；前端 `app.js` 仅校验/展示 `data.code`，不自行生成。
- 集成测试：session_lifecycle_test（Create 响应来自 Controller → 无效码 join 透传
  `SESSION_CODE_INVALID` → 正确码 join 双端 Connected）。


## Future

M1-3:

Path Manager（自动选路 + 实时路径切换）


M1-4:

HFS 文件共享


M1-5:

MeshTransfer 高速传输


M2:

File transfer


M3:

Remote desktop
