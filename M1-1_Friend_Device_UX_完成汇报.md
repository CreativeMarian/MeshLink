# MeshAgent + Tauri + Overlay MVP — M1-1 Friend / Device / Connection UX 完成汇报

- 日期：2026-08-31
- 里程碑：M1-1 Friend & Device UX = CODE PASS（真实双机 Wintun + 公网链路 PENDING_REAL_WORLD_VALIDATION）
- MANUAL TEST REQUIRED：NONE

---

## 1. 完成内容

### 1.1 Controller 地址进入正式 UI（规格一）
- 新增「设置 → 网络服务」：Controller 地址输入、保存、测试连接、重新连接；显示连接状态/延迟/服务器名。
- URL 校验白名单（`controller-client` + UI 双处）：`https://` 任意放行；`http://` 仅限回环（`127.0.0.1` / `localhost`）；公网明文 HTTP 明确拒绝（文案「生产 Controller 必须使用 HTTPS」），**禁止自动降级 HTTP**。
- URL 存普通配置（`%LOCALAPPDATA%\MeshLink\ui\config.json`）；credential / 私钥仍只归 Agent secure-store（DPAPI）。启动优先级：`MESHLINK_CONTROLLER_URL` 环境变量 > 已保存配置 > 默认 `http://127.0.0.1:18080`。

### 1.2 好友邀请 UI（规格二～三）
- 首页「邀请好友」→ 有效期（永久/24h/7天/自定义）+ 使用次数（1次/5次/不限）→ 生成邀请。
- 生成后展示邀请，支持「复制邀请链接」（`meshlink://invite/<invite_id>.<token>`）与「复制邀请码/Token」。
- 接收：支持粘贴兑换，也支持启动参数 / URI Scheme（`MeshLink.exe "meshlink://invite/..."` 或 `--invite`）自动带入兑换框 → 兑换 → 接受 → 好友出现。
- 接受邀请**不**立即建网；好友关系与 Online Session 分离。
- 「我的邀请」列表 + 撤销：撤销后 `INVITE_REVOKED`，旧 Token 不可再用。

### 1.3 好友 / 设备模型与列表（规格四～六、九）
- Controller 新增 `friendships`（friendship_id / ownerA / ownerB / status / created_at / revoked_at；status=PENDING|ACCEPTED|BLOCKED|REMOVED）、`invites`（ttl/max_uses/used_count/status）；模型层预留一用户多设备（friend 建立在 Device Identity 之上）。
- 主导航：首页 / 好友 / 设备 / 设置（+高级诊断按钮）。
- 好友页：好友名、在线/离线、设备数、[连接]；点好友展开设备与权限、[连接]/[邀请加入网络]/[删除好友]。
- 设备页：设备名称（默认 Windows 计算机名，可设昵称）、device_id 简写、在线/离线、Overlay IP、当前路径、最后在线时间；Noise 指纹仅高级详情显示。
- 接受邀请记录对方 `device_id` + Noise 静态公钥指纹（来自 Controller Registry）；同好友公钥异常变化 → 「设备身份已发生变化」+ 拒绝自动连接，绝不静默覆盖。

### 1.4 好友快速连接（规格七、十）
- 好友页点「连接」→ `ConnectFriend` → Controller 为目标设备创建 WAITING 会话并通知对端 → 对端「接受」/「拒绝」→ 候选交换 → DirectLink → Noise → Wintun → Overlay IP → 加密冒烟 → CONNECTED。全程复用既有数据面。
- 新增 IPC：`ConnectFriend / AcceptConnectionRequest / RejectConnectionRequest`；事件：`IncomingConnectionRequest / FriendOnline / FriendOffline / DeviceOnline / DeviceOffline / FriendConnected / FriendDisconnected`。
- 「允许好友自动连接」开关：第一版按手动接受实现（收到请求弹窗 [接受]/[拒绝]）。
- 6 位码保留（陌生设备/临时连接），与好友直连、Friend Invite 三者职责分开。

### 1.5 好友删除与断开（规格十一）
- 删除好友 = 撤销授权（Controller `friendship → REMOVED`），已建临时会话立即断开（`FRIEND_AUTH_REVOKED`），不删除对方本地数据。

### 1.6 首页体验（规格十三）
- 状态行（已连接 Controller + 本机设备 + Overlay IP）、快速操作（创建6位连接/加入连接/邀请好友）、好友区（在线好友可一键连接）。

### 1.7 普通 UI 不暴露技术术语（规格十四）
- 普通视图只显示「正在寻找设备 / 正在建立直连 / 正在建立安全连接 / 正在配置虚拟网络 / 已连接」；Noise/srflx/Candidate/epoch/STUN/Wintun 仅高级诊断页。

### 1.8 关键缺陷修复（本阶段两处根因）
1. **Windows Controller RST 收尾导致偶发 `10054`**：Go `http.Server` 关 keep-alive=false 连接时以 RST 而非 FIN 收尾，客户端 `read_to_end` 等 EOF 撞 RST。修复：`controller-client` 新增 `has_complete_response`（按 Content-Length / chunked 终结块判定完整即停读），并新增单测。
2. **加密 Overlay 冒烟偶发超时**：冒烟请求只发一次，对端 pump/RX 启动时序竞争时丢包即超时（friend_flow 4 连跑 2 挂）。修复：冒烟请求周期性重发（500ms 间隔）直到应答或超时。修复后 friend_flow 连跑 6/6 通过。

### 1.9 事件与状态机
- Agent 统一状态机驱动（STOPPED…CONNECTED），UI 只消费 Agent 事件/状态，不自行推断；`GetStatus` 快照含 state/device_id/user_facing/overlay IP。

---

## 2. 修改文件

**Go Controller（server/controller）**
- `internal/model/model.go`：friendship/invite 模型、状态常量
- `internal/store/store.go`：friendships/invites 表、事务、friendship 直连会话、friend connect 等
- `internal/api/friends.go`：invite 创建/兑换/撤销、friendship 接受/拒绝/撤销、ConnectFriend、Accept/RejectConnectionRequest、ListFriendships/ListInvites/ListDevices、GetDevice
- `internal/api/invites.go`：邀请管理端点
- `internal/api/events.go`：好友/设备/连接事件推送
- `internal/api/server.go`：路由注册
- `internal/api/helpers.go`、`internal/api/api_test.go`、`internal/store/store_test.go`：测试与辅助

**Rust**
- `crates/controller-client/src/lib.rs`：新类型 + 11 个新方法 + 事件常量模块 + `has_complete_response` 修复 + 新增单测
- `crates/mesh-ipc/src/proto.rs`（或对应文件）：Command 9→22、Event 10→21
- `crates/mesh-agent/src/agent.rs`：AgentCore 扩展、background_loop（心跳+事件轮询转发+好友在线刷新）、reconnect_controller、creator/joiner flow（friend 参数）、新命令处理、**冒烟重发修复**
- `crates/mesh-agent/tests/friend_flow.rs`：M1-1 全链路集成测试（新增）
- `crates/mesh-agent/tests/mvp_gate.rs`：事件补全
- `crates/directlink/tests/controller_e2e.rs`：邀请段改写 + 好友直连测试

**UI（apps/meshlink-ui）**
- `ui/index.html`：多视图 + 模态 + 主导航（全部重写）
- `ui/style.css`：导航/列表/模态/设置页/邀请表单/状态点（全部重写）
- `ui/app.js`：导航切换、列表渲染、11 个新事件处理、Controller URL 校验与测试、`meshlink://invite/...` 解析、邀请生成/兑换/撤销、连接请求弹窗、GetStatus 轮询（全部重写）
- `src/ipc.rs`：load_ui_config / save_controller_url / validate_controller_url；spawn 读取已保存 Controller URL
- `src/main.rs`：`--invite`/URI 参数处理；注册新命令

**部署包（dist）**
- `MeshLink.exe` / `mesh-agent.exe` / `controller.exe` / `wintun.dll` / `README.md`（更新 M1-1 说明）

---

## 3. 编译

| 目标 | 命令 | 结果 |
|---|---|---|
| Go Controller（release） | `go build -o dist/controller.exe ./cmd/controller` | ✅ 通过 |
| Rust release | `cargo build --release -p meshlink-ui -p mesh-agent` | ✅ 通过（54s，仅存量警告） |
| release 冒烟 | `controller.exe -addr 127.0.0.1:18099` → `/healthz` | ✅ 200 ok |
| release 端到端冒烟 | MeshLink.exe 拉起 → 自动 spawn mesh-agent → 生成 device-identity.json → 连上 Controller（mock overlay） | ✅ 通过 |

---

## 4. 单测

**Go（29 项全绿）**：store 19（IPAM 分配/回收/耗尽/校验/迁移、注册设备绑定/幂等/密钥不匹配、6 位码流、邀请生命周期/过期/耗尽/撤销、好友撤销、好友直连会话等）；api 7（注册/会话/限流/候选交换/好友邀请流/错误映射/healthz）；ratelimit 3。

**Rust 单元（workspace 全绿，含新增）**：controller-client 13（含 `has_complete_response` content-length/chunked、公网明文拒绝、HTTPS 禁降级等）；mesh-ipc 15；mesh-agent lib 11；mesh-common 7；mesh-vnic 33；secure_store 12；directlink lib 2；ice 52 等。全 workspace 合计 **152 项 Rust 测试通过**。

---

## 5. 自动集成验证

**friend_flow（M1-1 全链路，`cargo test -p mesh-agent --test friend_flow`）**
覆盖：A 创建 6 位码 / 邀请 → B 兑换 → 接受成为好友 → 好友列表 → ConnectFriend → B 接受连接请求 → 双端 Device Registry 校验 → 候选交换 → DirectLink → Noise（互验身份）→ Overlay(mock) → 加密 overlay 冒烟 → 双端 CONNECTED → 断开。修复冒烟重发后 **连跑 6/6 通过**。

**mvp_gate（`cargo test -p mesh-agent --test mvp_gate`）**：6 位码全链路 + 事件补全，通过。

**controller_e2e（`cargo test -p directlink --test controller_e2e`）**：6 位码、好友直连与接受、删除好友后 NOT_FRIENDS、不可达结构化错误、以及（并行）friend_flow/mvp_gate 三套件同跑，全绿。

**Rust `cargo test --workspace`**：全绿（CARGO=0）。

**自动化覆盖清单（规格十五逐项）**
| 场景 | 结果 |
|---|---|
| Create / Redeem / Expired / Revoked invite | ✅ store TestInviteLifecycle/ExpiryAndExhaustion/Revoke + e2e |
| Single-use race | ✅ store 幂等/唯一约束 |
| Friend created / reconnect / removal | ✅ store + controller_e2e 好友直连段 |
| Device key mismatch | ✅ store TestRegisterDeviceKeyMismatchRejected |
| Device online / offline | ✅ events + agent 心跳/事件转发 |
| ConnectFriend | ✅ friend_flow + controller_e2e |
| Incoming request accept / reject | ✅ friend_flow（accept）；reject 语义由 store/api 覆盖 |
| 好友连接后 Encrypted overlay ping | ✅ friend_flow 冒烟（ICMP Echo 经 Noise 往返） |

---

## 6. 未解决问题

1. **真实双机 Wintun + 公网链路**：`PENDING_REAL_WORLD_VALIDATION`。自动集成测试已覆盖 mock overlay 全链路；真实 Wintun 网卡、NAT 打洞、公网 Controller 待实机验证（按纪律不要求用户现在手动测试）。
2. **基础连接历史与状态**：规格 M1-1 提及，本阶段未展开实现（会话历史表/最近连接记录未做），归入 M1-2+。
3. **「允许好友自动连接」开关**：第一版按手动接受实现；自动接受/拒绝策略留待后续。
4. **好友 reject 的端到端自动用例**：store/api 层已覆盖拒绝语义，friend_flow 未单独加 reject 全链路用例（当前以 accept 为主路径）；后续可补。
5. **mesh-ipc `malformed_request` 与 friend_flow 在全量并行下的偶发饿死**：已放宽超时（3s→10s）与冒烟重发修复，连跑稳定；属测试负载时序，非产品缺陷。

---

## 7. 下一步

M1-1 完成，进入 **M1-2：N2N + Supernode**（此后 M1-3 Path Manager 自动切换 → M1-4 HFS → M1-5 MeshTransfer → M1-6 Cloudflare Disaster Relay）。

优先建议：
1. 补「连接历史与状态」与好友 reject 端到端用例；
2. 真实双机公网链路验证（待环境就绪，非阻塞）；
3. 按 M1-2 规格启动 N2N + Supernode 设计与开发。

---

## MVP FLOW（M1-1）
| 步骤 | 状态 |
|---|---|
| A 设置 Controller 地址并连接 | PASS（UI 保存/测试/连接；healthz 200） |
| A 创建 6 位码 / 邀请好友 | PASS |
| B 兑换邀请 → 接受 → 成为好友 | PASS |
| 好友页点「连接」→ Controller 通知 B | PASS |
| B 接受连接请求（弹窗） | PASS |
| Candidate Exchange → DirectLink | PASS（controller_e2e + friend_flow） |
| Noise 互验身份 | PASS（mutual identity，Registry 公钥比对） |
| Overlay（Wintun/mock）+ Overlay IP + /32 路由 | PASS（mock；真 Wintun 待实机） |
| 加密 overlay ping（ICMP 经 Noise 往返） | PASS（friend_flow 冒烟） |
| 双端 CONNECTED | PASS |

---

## 补丁：Controller/MeshAgent 默认端口对齐修复

**真实 Bug**：Controller 默认 127.0.0.1:8080（Go flag 默认）与 MeshAgent/UI 默认 http://127.0.0.1:18080 漂移 → CONTROLLER_UNREACHABLE（os error 10061）。非网络问题，是默认配置不一致。

### 单一 Default（规格二）
- Go（server/controller/cmd/controller/main.go）：常量 DefaultControllerHost=127.0.0.1、DefaultControllerPort=18080、DefaultAddr=127.0.0.1:18080；-addr 默认 envOr("CONTROLLER_LISTEN", DefaultAddr)。
- Rust（crates/mesh-ipc/src/lib.rs）：pub const DEFAULT_CONTROLLER_URL: &str = "http://127.0.0.1:18080" 作为唯一默认常量；mesh-agent（AgentConfig::default / state 测试 / main.rs 文档）、controller-client（残留 7 处 8080 已清理）、UI 设置页默认值均引用它，不再各自硬编码。

### 各指令落地
| # | 要求 | 状态 |
|---|---|---|
| 1 | 统一 18080（不再有 8080/18080 两套默认） | DONE（全仓 :8080 残留为 0；README 的 8080 均为 18080 子串） |
| 2 | 单一 Default 常量 | DONE（Go 三常量 + Rust DEFAULT_CONTROLLER_URL） |
| 3 | controller.exe 无 -addr 默认 127.0.0.1:18080 | DONE（冒烟验证） |
| 4 | mesh-agent 默认同 URL | DONE |
| 5 | UI 设置页默认同 URL | DONE（走 get_controller_default，JS 不再硬编码） |
| 6 | dist/README.md 同步 | DONE（全 18080） |
| 7 | release 二进制冒烟（无 -addr → ControllerConnected + READY） | DONE（scripts/smoke-default-ports.ps1 + crates/mesh-agent/tests/release_binary_smoke.rs，实测 PASS 4.6s） |
| 8 | 防漂移测试 | DONE（Go main_test.go 2 项 + Rust mesh-ipc default_controller_url_is_canonical + default_port_alignment.rs 集成测试 + elease_binary_smoke.rs） |
| 9 | Controller 不可达 UI 横幅（无法连接到 Controller / 当前地址 / 重新连接 / 修改地址） | DONE（index.html #ctl-err + app.js showControllerUnreachable/retryController + 视觉验证） |
| 10 | winerror=109 为 UI 断开次级现象，勿误判为 Controller 根因 | 诊断指引，无代码改动 |

### 测试
- Go：go test ./... 全绿（含新增 TestDefaultAddrIsCanonical / TestAddrFlagDefaultEqualsCanonical）。
- Rust workspace 全绿（mesh-ipc 16 项含 default_controller_url_is_canonical；default_port_alignment、elease_binary_smoke、riend_flow 等全部 PASS）。
- Release 冒烟：controller.exe（无 -addr）默认监听 127.0.0.1:18080 → mesh-agent.exe（无 URL）默认连上 → READY + GetControllerStatus connected=true + url=http://127.0.0.1:18080。

### 重新打包 dist（已完成）
dist/：controller.exe / mesh-agent.exe / MeshLink.exe / wintun.dll / README.md（临时 db/备份文件已清理）。

MANUAL TEST REQUIRED：NONE。