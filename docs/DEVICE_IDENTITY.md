# DEVICE_IDENTITY.md — 设备静态身份（Controller MVP）

状态：**Accepted（M0 Controller MVP）**　crate：`crates/secure-store`
关联：`docs/adr/NOISE_KEY_LIFECYCLE.md`（密钥生命周期）、`server/controller`（Device Registry）

## 1. 身份是什么

| 字段 | 值 | 说明 |
|---|---|---|
| `device_id` | `dev-` + 公钥前 8 字节 hex（共 20 字符） | 首次生成时从公钥派生；**持久化后与公钥解耦**（key rotation 不改变 device_id） |
| identity key | X25519 静态密钥对（`Noise_IK_25519_ChaChaPoly_BLAKE2s`，snow 0.10 CSPRNG） | 数据面 Noise 身份；**公钥即指纹**（完整 hex 64，PoC/Controller 早期零依赖比对） |
| `controller_credential` | `mlk_` + 32 字节 CSPRNG hex | Controller API 认证（注册响应一次性下发）；**与 Noise 私钥完全独立** |

硬性规则：

- 设备**第一次运行**生成一次，之后**稳定保存**；重启后公钥/device_id 不变（Controller 注册绑定不漂移）。
- **私钥禁止明文落盘**。
- **6 位连接码绝不作为认证 token、绝不派生任何密钥**——它只是会话索引。
- Joiner 信任的 Creator 公钥唯一来源 = **Controller Device Registry**（join 响应），Session Code v4 的 `k` 字段仅 `--legacy-code` 测试兼容。

## 2. 存储

| 项 | 实现 |
|---|---|
| 位置 | `%LOCALAPPDATA%\MeshLink\device-identity.json`（用户级目录） |
| 私钥 | **DPAPI `CryptProtectData`（CurrentUser scope）** 密文 → base64 |
| credential | 同上，DPAPI(CurrentUser) 密文 → base64 |
| 公钥 / device_id | 明文（本就注册到 Controller 公开） |
| 写入 | 临时文件 + `rename` 原子替换（防半写） |
| 文件版本 | `version: 1`（将来演进按版本迁移） |

### 2.1 ACL

文件 DACL 收敛为「**当前用户 + SYSTEM 全权，PROTECTED（切断目录继承）**」：

- `InitializeAcl(ACL_REVISION=2)` + 2 × `AddAccessAllowedAce(FILE_ALL_ACCESS)`；
- `SetNamedSecurityInfoW(..., DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION)`；
- 临时文件与最终文件都收紧（rename 携带 ACL）。

**ABI 教训（同 MIB_IFROW 一类，已写入 acl.rs 头注释）**：`SE_OBJECT_TYPE` 枚举首位是
`SE_UNKNOWN_OBJECT_TYPE = 0`，`SE_FILE_OBJECT = 1`——传 0 会得到
`ERROR_INVALID_PARAMETER(87)`。定位方法：.NET P/Invoke 对照实验（同样传 0 → 同样 87，
证明与 Rust FFI 声明无关）。

### 2.2 DPAPI scope 决策（Overlay MVP 已冻结）

**冻结结论（MeshAgentService 运行身份已确定）**：MeshAgentService 以**当前登录
用户**身份运行（Tauri 客户端拉起的用户态后台进程，非 LocalSystem 服务）。据此：

| 项 | 决策 | 理由 |
|---|---|---|
| DPAPI scope | **CurrentUser**（`CRYPTPROTECT_UI_FORBIDDEN`） | 服务运行身份 = 当前用户，CurrentUser 即为该身份的加密边界；密文可解集合恰好 = 服务身份本身 |
| 文件 ACL | 当前用户 + SYSTEM 全权（PROTECTED，切断继承） | 仅服务运行身份 + 系统管理员级账户可访问 |
| 密钥目录 | `%LOCALAPPDATA%\MeshLink\agent`（用户 profile，天然用户级） | 用户态服务对应的用户级目录，无跨用户共享 |

- **禁止**随意改用 machine-wide scope（`CRYPTPROTECT_LOCAL_MACHINE`）——那等于对
  本机所有用户可解密。已明确排除"改成 LocalMachine 就算安全"的捷径；
- Tauri UI 进程**不直接读取私钥文件**：结构上 mesh-ipc 协议（9 命令/10 事件）无
  密钥字段，且 `ui_process_does_not_receive_private_key` 以真实私钥 hex 对全部
  IPC 面做字节级泄漏扫描锁定；
- 损坏/跨用户复制导致解密失败 → **报错，绝不静默重建**（重建 = 新公钥 =
  Controller `DEVICE_KEY_MISMATCH`，必须显式走 re-enrollment）；
- **变更触发条件**：若 MeshAgentService 未来切换为 Windows 服务
  （LocalSystem / 特定服务账户）运行，必须重开本节决策（服务身份 ≠ 用户身份，
  CurrentUser 密文将无法被服务解密；届时评估 DPAPI scope + 服务账户文件 ACL +
  密钥目录三要素，并同步更新本文档与 `NOISE_KEY_LIFECYCLE.md`）。

## 3. 生成与加载流程（`DeviceIdentityStore`）

```
首次运行                重启
──────────────          ──────────────
create_or_load()        create_or_load()
  load() → None           load() → Some(identity)
  snow CSPRNG 生成          （DPAPI 解密）
  device_id = dev-<hex8>    返回同一身份
  save()（DPAPI+ACL）
  返回 (identity, first=true)
```

注册完成后 `update_credential()` 只回填 credential，其余字段不变。

## 4. Controller 侧公钥绑定规则

1. **第一次合法注册**：建立 `device_id → noise_static_public_key` 绑定（SQLite
   `devices` 表，事务内原子插入）。
2. 之后同一 device_id 再连接：
   - 公钥相同 → 允许（幂等，`status=existing`，不重复下发 credential）；
   - 公钥变化 → **`DEVICE_KEY_MISMATCH`（HTTP 409）**，Controller 绝不静默覆盖。
3. Credential 只存 SHA-256 hash（`device_credentials` 表）；明文仅注册响应出现一次。

Rust E2E 断言（`crates/directlink/tests/controller_e2e.rs`）：同 device_id 换公钥
必须 409，且原 credential 仍可用（绑定未被破坏）。

## 5. Rotation（规划，MVP 未实现）

```
设备侧                          Controller 侧
────────                        ────────────
生成新密钥对
POST /v1/devices/rotate（待实现）→ 校验旧公钥签名/credential
  提交 old_pub + new_pub        → devices.status = ROTATING
新身份落盘（DPAPI）              → 绑定切换 new_pub
                                → 旧公钥进入宽限期（在途会话仍可完成）
```

约束：rotation 只由**设备本端**发起（私钥持有方）；Controller 侧永不接受无凭证的
公钥替换；进行中会话用**成员表公钥快照**（`session_members.noise_public_key`）完成，
不受轮换影响。

## 6. Revocation

- Controller 将 `devices.status = REVOKED`：该设备 credential 立即失效（auth 查询
  拒绝），其公钥不再进入新会话的成员快照；
- 在途会话按快照完成或到期自然终止；
- 设备侧对应操作 = 删除 `%LOCALAPPDATA%\MeshLink\device-identity.json`
  （等于本端放弃身份）。

## 7. Re-enrollment（身份丢失/损坏恢复）

触发条件：身份文件损坏、DPAPI 解密失败（换用户/系统重装）、用户主动删除、
device 被 revoke。

流程：新 device_id（新密钥对）注册为**全新设备**；原设备如仍持有旧 credential
可在 Controller 侧走「旧设备身份认证 + 新设备绑定」的迁移流程（规划）。
**不存在**「同 device_id 恢复旧公钥」的路径——公钥与 device_id 的绑定一旦更换，
旧绑定只能通过 rotation 流程显式切换。

## 8. 自动化测试覆盖

| 测试 | 位置 | 断言 |
|---|---|---|
| `save_load_roundtrip_and_stable_identity` | secure-store | 保存/重启加载 = 同一身份 |
| `private_key_never_plaintext_on_disk` | secure-store | 私钥/credential 明文不出现在落盘文件 |
| `tampered_file_rejected_not_regenerated` | secure-store | 篡改密文 → 报错（DPAPI 失败），不静默重建 |
| `update_credential_keeps_identity` | secure-store | 回填 credential 不改变密钥身份 |
| `create_or_load_generates_once_and_is_stable` | secure-store | 首次生成 + 重启稳定 + device_id 格式 |
| `restrict_acl_on_temp_file` | secure-store | ACL 收敛生效（回读 DACL 恰好 2 ACE） |
| `unauthorized_user_cannot_read_identity` | secure-store | DACL 受托人穷举 = 当前用户 + SYSTEM；Everyone / Authenticated Users / BUILTIN\Users 零授权（用户规格五） |
| `service_identity_restart_stable` | mesh-agent | MeshAgentService 进程重启 → device_id/公钥/私钥逐字节稳定 |
| `ui_process_does_not_receive_private_key` | mesh-agent | 9 命令响应 + 事件流对真实私钥 hex/字节零泄漏 |
| `controller_e2e_six_digit_code_encrypted_directlink` | directlink | 重启语义 + 幂等注册 + DEVICE_KEY_MISMATCH |

## 9. 已知限制 / 后续

- **PENDING_REAL_WORLD_VALIDATION**：DPAPI/ACL 仅在本机（Win11 x64）自动验证；
  跨 Windows 版本（DPAPI 行为差异极小）待后续 CI 覆盖。
- **PENDING_REAL_WORLD_VALIDATION**：`unauthorized_user_cannot_read_identity`
  以 DACL 受托人穷举为自动化等价验证；真实第二用户账户进程打开身份文件
  需双账户环境（非阻塞，标记待实测）。
- DPAPI scope 已冻结（§2.2）；Windows 服务化（LocalSystem）时重开决策。
- Rotation / Revocation API 为规划项（§5/§6），MVP 仅实现绑定不变量与拒绝路径。
