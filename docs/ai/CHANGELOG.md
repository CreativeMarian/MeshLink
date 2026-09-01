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
