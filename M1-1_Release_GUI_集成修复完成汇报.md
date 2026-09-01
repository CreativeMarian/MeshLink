# M1-1 Release GUI 集成修复完成汇报

标题：M1-1 Release GUI 集成修复完成汇报
状态：Release GUI 集成修复 = CODE PASS + 自动验证 PASS（真实 dist 三件套）
MANUAL TEST REQUIRED = NONE
（真实双机 Wintun + 公网链路仍标 PENDING_REAL_WORLD_VALIDATION，不阻塞；完成后才继续 M1-2 N2N）

---

## 一、完成内容

### 1. 找到真实底层根因（不是只修 UI 文案）
实机录屏三个症状（邀请「生成失败：undefined」、设备页「设备列表加载失败」无内容、
诊断「诊断加载失败：undefined」）的**同一个根因**：

- Tauri GUI 桥接 `ipc_request` 用 `{"cmd": <name>, ...payload}` 直接反序列化 `Request`，
  而 `Request.id: u64` 无 `#[serde(default)]` —— 缺 `id` → serde 拒绝
  → 命令返回 `Err("命令非法：missing field id")` → `invoke` 以**字符串**拒绝
  → 前端 catch 读 `e.code / e.message` 双双 undefined → 显示 `undefined`。
- 这正是「friend_flow PASS（直连 AgentCore）但 GUI 失败（走 bridge）」的覆盖缺口：
  测试从未经过 GUI 桥的 wire 构造路径。

**修复**：`mesh_ipc::build_request(next_id, cmd, payload)` 单独反序列化内部标签
`Command`（`{"cmd":...}` 无 id 也可解析），再补生成 id 构造 `Request`。
Tauri `ipc_request` 与新增的 GUI Bridge 集成测试**共用同一函数**，杜绝再次漂移；
同时给 `Request.id` 加 `#[serde(default)]` 作为协议层兜底。

### 2. 空错误横幅（粉红空白区）
- 实机另发现：首页 `<div id="home-error">` 是**空 div、无 `.error-text` 子节点**；
  原 `showError` 先 `classList.remove("hidden")`（横幅变可见）再
  `querySelector(".error-text").textContent`（null 抛 TypeError）→ **可见空白红色区常驻**。
- 修复：`showError` 遇缺失子节点自动创建；空横幅默认隐藏、成功后 `hideError` 清除。
  静态渲染确认首页空闲时无任何红色横幅。

### 3. 统一 formatError（用户规格二）
新增 `formatError(err)` 覆盖：string / `err.message` / `err.error` / `err.code`
（`${code}: ${message}`）/ JSON.stringify 兜底 / String 兜底；
`{}`、`[object Object]`、空串一律归一为 `ERROR_UNKNOWN`。**全前端 10+ 个 catch 位置**
（生成邀请 / 设备列表 / 好友列表 / 诊断 / 创建6位码 / 加入连接 / Controller测试 /
ConnectFriend / 邀请兑换 / 邀请撤销 / 连接请求接受）统一改用 `formatError` / `errorCode`。
`send()` 对 `invoke` 拒绝（string / Error / 对象）归一化为 `{code,message}`，
message 永不为 undefined。

### 4. 弃用 window.alert（用户规格九）
所有 `alert(...)` 改为应用内 **Toast**（新增 `.toast` 样式，4.2s 自动消失）；
保留 `confirm(...)` 仅用于删除/撤销等破坏性二次确认。

### 5. 设置页「当前生效地址」（用户规格十）
确认 `https://control.example.com/` 仅为输入框 **placeholder**（非 value，非 Bug）；
新增「当前生效地址」行（来自 `GetControllerStatus.url`，即 Agent 实际使用地址），
与已保存地址在视觉上区分。Agent 生效地址 = `http://127.0.0.1:18080` 时如实显示。

### 6. CreateFriendInvite 返回 schema（用户规格五）
- 前端「7天 + 不限」→ `ttl:"7d"` + `max_uses:0`（明确值，非 "7d"/"infinite"/undefined）；
- agent 响应补齐 `expires_at` / `created_at` / `status`，与 UI 读取的
  `invite_id` / `invite_token` 字段名一致（invite_token 前缀 `mli_`）。

### 7. 诊断页（用户规格七）
`GetDiagnostics` 无 Peer 时本就走 ok:true（`selected_pair:null`），
新增「暂无连接数据（当前未连接 Peer，仅显示基础状态）」提示，与「诊断接口失败」
严格分开；仍显示 state / device_id / controller。

### 8. 五层一致性核查（用户规格三）
JS 命令名 ↔ mesh-ipc `Command` enum ↔ `ipc_request`（统一入口）↔ agent handler 逐条核对：
GetStatus / ListDevices / GetDiagnostics / CreateFriendInvite / ListInvites /
ListFriends / RedeemFriendInvite / RevokeInvite / ConnectFriend /
AcceptFriendship / RejectFriendship / AcceptConnectionRequest /
RejectConnectionRequest / GetControllerStatus / SetControllerUrl —— **全部一致**；
无「JS 名 ≠ Tauri 命令 / 未注册 / bridge 未序列化 / 旧 schema」缺口。

---

## 二、修改文件

| 文件 | 改动 |
|---|---|
| `crates/mesh-ipc/src/lib.rs` | 新增 `build_request()`（GUI 桥与测试共用）；`Request.id` 容忍缺省 |
| `crates/mesh-ipc/src/proto.rs` | 测试 `gui_bridge_wire_missing_id_tolerated`（防回归） |
| `apps/meshlink-ui/src/ipc.rs` | `ipc_request` 改用 `mesh_ipc::build_request`（修根因） |
| `crates/mesh-agent/src/agent.rs` | CreateFriendInvite 响应补 `expires_at/created_at/status` |
| `apps/meshlink-ui/ui/app.js` | `formatError`/`errorCode`/Toast；`send()` 拒绝归一化；健壮 `showError`；全部 catch 去 undefined；诊断「暂无连接数据」提示；设置页生效地址 |
| `apps/meshlink-ui/ui/index.html` | 设置页新增「当前生效地址」行 |
| `apps/meshlink-ui/ui/style.css` | 新增 `.toast` / `.toast-error` / `.toast.show` |
| `crates/mesh-agent/tests/gui_bridge_integration.rs` | **新增**：GUI Bridge 集成测试（普通 cargo test 运行） |
| `crates/mesh-agent/tests/release_gui_smoke.rs` | **新增**：Release GUI Bridge Smoke（`#[ignore]`，真实 dist 三件套；不操作真实 WebView） |
| `apps/meshlink-ui/tests/ui_error_contract.test.js` | **新增**：JS 错误契约测试（27 断言） |
| `dist/README.md` | 补 Release GUI 集成修复说明 + 自动验证方式；controller 无 -addr 默认 18080 |

---

## 三、编译

- `cargo build --release -p meshlink-ui -p mesh-agent` → Finished（release profile）
- `go build -o dist/controller.exe ./cmd/controller` → 成功
- dist 已重新打包 5 件套：`controller.exe / mesh-agent.exe / MeshLink.exe / wintun.dll / README.md`（无临时 db 残留）

---

## 四、单测

- `cargo test --workspace`：**全绿**（含 mesh-ipc `gui_bridge_wire_missing_id_tolerated`）
- `go test -count=1 -vet=off -timeout 180s ./...`：**全绿**
- `node --check apps/meshlink-ui/ui/app.js`：PASS
- `node apps/meshlink-ui/tests/ui_error_contract.test.js`：**27 passed, 0 failed**（UI ERROR CONTRACT TESTS PASS）
  - formatError 对 string/{message}/{error}/{code}/{} /null/undefined/0 全返回非 undefined，最终兜底 ERROR_UNKNOWN；
  - send() 对 invoke 字符串拒绝/对象拒绝/undefined 拒绝/agent 错误响应全部归一化 {code,message}，message 非空；
  - showError 在空横幅上不抛错、自动补子节点、hideError 生效；
  - toast 替代 alert 生效。

---

## 五、自动集成测试

- `m1_1_gui_bridge_integration`（PASS，~2.7s，普通 `cargo test` 运行）：
  真实 Go Controller + mesh-agent（Mock Overlay），**全部命令经 `mesh_ipc::build_request`
  （= Tauri `ipc_request` 的 bridge 构造路径）** 驱动，不直连 AgentCore。覆盖：
  - GetStatus → READY；GetControllerStatus → connected=true、url 正确；
  - ListDevices → 真实返回本机 device（device_id/device_name/online/overlay_ip/last_seen）；
  - GetDiagnostics → 无 Peer 时 ok:true、state/device_id/controller 齐全、selected_pair=null；
  - CreateFriendInvite：**7天+不限 / 永久+1次 / 24小时+5次 三种组合全部成功**，
    invite_id/invite_token(mli_)/expires_at/max_uses 字段齐全；
  - ListInvites=3；ListFriendships=[]；
  - 非法 ttl → ok:false + `INVITE_TTL_INVALID` + message 非空（无 undefined 语义）；
  - 未知命令 / payload 类型错误 → bridge 构造拒绝「命令非法」。
- **Release GUI Bridge Smoke** `release_gui_bridge_smoke`（PASS，~3.7s，`-- --ignored` 显式运行；命名校准：本测试**不**操作真实 WebView，刻意不称 "Full GUI Automated E2E"，真实 app.js 由 JS contract tests 覆盖）：
  真实 `dist/controller.exe`（无 -addr → 默认 18080）+ `dist/mesh-agent.exe` +
  bridge wire 驱动 GetStatus/GetControllerStatus/ListDevices/GetDiagnostics/
  CreateFriendInvite/ListInvites/ListFriends → 全部 ok:true、字段齐全、事件流无 Error。
- `m1_1_friend_invite_to_encrypted_overlay_ping`（PASS）：M1-1 既有好友→加密 overlay ping 全链路。

**Gate 逐项确认（用户规格十二）**：
| 项 | 结果 |
|---|---|
| 邀请 7天+不限 / 永久+1次 / 24小时+5次 → 成功 | PASS（gui_bridge_integration） |
| 设备页真实返回本机设备 | PASS（ListDevices schema 断言） |
| 诊断页 READY/Controller/Device + 无 Peer 不报错 | PASS（GetDiagnostics ok:true） |
| 错误情况显示真实 error code | PASS（INVITE_TTL_INVALID / 命令非法 message 非空） |
| 不再出现任何 undefined | PASS（formatError 27 断言 + 根因修复） |
| 不再出现空白 error banner | PASS（showError 修复 + 首页静态渲染无横幅） |
| cargo test --workspace / Go tests / cargo build --release | 全 PASS |
| 重新打包 dist | 完成（5 件套） |

---

## 六、未解决问题

- **真实双机 Wintun + 公网链路**：仍标 `PENDING_REAL_WORLD_VALIDATION`，不要求用户测试，不阻塞开发。
- **MeshLink.exe 的 Tauri webview 可视化验证**：本环境桌面 GUI 自动化不可用（返回 mac 限制），
  无法对真实窗口逐屏截图；改用等价三层覆盖：① release_gui_smoke 驱动真实 agent/controller +
  与 Tauri 完全相同的 bridge wire（根因修复点的直接验证）；② JS 错误契约测试直接加载真实
  app.js 验证 formatError/send/showError/toast；③ artifact-preview 静态渲染确认首页无空白红色横幅。
  若用户需要，可在本机运行 `dist\controller.exe` + `dist\MeshLink.exe` 直观确认。

---

## 七、下一步

M1-2：N2N + Supernode（按既定顺序，仅在本轮 Gate 确认后开始）。
