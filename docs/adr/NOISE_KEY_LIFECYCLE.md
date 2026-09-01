# ADR-001: Noise 会话密钥生命周期与 zeroize 语义

* 状态：Accepted（M0-5 代码实现 + snow 0.10.0 源码审计完成；决策=方案 C）

* 日期：2026-08-29（创建）／ 2026-08-30（M0-5 回填定稿）

* 决策人：用户 + 助手（M0-5）

* 关联任务：M0-5（用户修正三）

* 实现位置：`crates/directlink/src/crypto/{mod,keys,frame,replay}.rs`

## 背景

用户修正三明确：

1. 不承诺 "snow TransportState drop 后自动 zeroize 内部 session key"——必须对
   **实际使用的 snow 版本** 做安全评估。
2. 自持密钥必须显式清理：设备静态私钥 / 临时 X25519 私钥 / Invite secret /
   Controller token / 缓存 credential → `zeroize` / `Zeroizing<T>` / `secrecy`。
3. snow 内部（HandshakeState / StatelessTransportState / CipherState）评估后按：

   * 方案 A：最小 snow security fork，增加 ZeroizeOnDrop；

   * 方案 B：可控 CryptoResolver / cipher backend，关键材料用 zeroize 类型；

   * 方案 C：M0 无法安全修改时，**在本 ADR 明确记录为 Known Security Risk**。

## 密钥清单登记表（Overlay MVP 实际状态）

| 密钥                             | 级别  | 存储位置                                                                                                | 创建时机                | 轮换方式                           | 销毁方式                                | zeroize 可验证?                      |
| ------------------------------ | --- | --------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------ | ----------------------------------- | --------------------------------- |
| 设备静态 X25519 私钥                 | 长期  | 进程内存 `Zeroizing<[u8;32]>`（`StaticIdentity`，Agent 进程独占持有）；落盘 DPAPI(CurrentUser) 密文 @ `%LOCALAPPDATA%\MeshLink\agent\device-identity.json`（ACL=用户+SYSTEM） | 首次运行生成一次，重启加载（Overlay MVP 已持久化）  | 不轮换（rekey 复用做 IK 认证；吊销替代留待注册表） | 进程退出 Drop 自动擦除；文件由用户删除/重装走 re-enrollment | ✅ 单测 `private_key_zeroed_on_drop`；DPAPI/ACL 由 `service_identity_restart_stable` / `unauthorized_user_cannot_read_identity` 锁定 |
| 握手 X25519 私钥（静态副本 + ephemeral） | 握手级 | snow 内部 `Dh25519.privkey: [u8;32]`（普通数组）                                                            | 每次握手/rekey          | 每次新握手                          | HandshakeState 消费后 Drop（**无擦除**）    | ❌ 方案 C 风险                         |
| 会话对称密钥链                        | 会话级 | snow `StatelessCipherState` → `CipherChaChaPoly.key: [u8;32]`（普通数组，堆上 `Box<dyn Cipher>`）            | IK 握手派生（每 epoch 一对） | 10min/1GB 重握手 epoch+1          | 旧 epoch 宽限 5s 后 Drop（**释放堆内存但不擦除**） | ❌ 方案 C 风险                         |
| Invite secret（兑换 token）        | 中期  | Controller SQLite + 兑换时经 IPC/UI 手工传递（一次性使用；非 Noise 密钥材料）                                                  | Controller 生成（FriendInvite MVP 已落地） | 不轮换（max_uses 用尽即失效）                 | 一次性兑换 / 到期清理（`invite_redemptions` 过期回收） | 结构性：单次使用后失效 |
| Controller 侧 credential 摘要    | 中期  | Go Controller SQLite `device_credentials`（**仅 SHA-256 hash，永不存明文**）                                                    | 设备注册时下发一次 | 不可轮换（revoke 即失效）                 | revoke / 设备删除                        | 结构性：仅哈希落库 |
| 缓存 credential                  | 短期  | `%LOCALAPPDATA%\MeshLink\agent\device-identity.json` DPAPI(CurrentUser) 密文（与身份同文件）；进程内存 `Mutex<String>`（Agent 独占，UI 经 IPC 不可见） | 注册响应一次性下发 | 不可轮换（revoke 即失效）                 | revoke / re-enrollment；`ui_process_does_not_receive_private_key` 锁定 IPC 零泄漏 | ✅ DPAPI + ACL + IPC 泄漏扫描 |

补充（M0-5 实现，Overlay MVP 仍然成立）：

* `StaticIdentity` 私钥以 `Arc` 在会话存续期间共享给 rekey 监视线程（重握手需要
  静态私钥参与 IK），生命周期 = 加密会话生命周期 + 进程生命周期，Drop 擦除。

* epoch 退役路径：`NoiseChannel::apply_new_epoch` 将旧 epoch 移入 `previous`（仅
  接收，宽限 `rekey_grace_ms` ≤5s），宽限过期 `expire_previous_if_due` 置
  `None` → 旧 `StatelessTransportState`（含其 CipherState）Drop → 堆内存归还
  分配器，**字节内容不擦除**。

## snow 版本安全评估（已完成）

* 评估对象版本：`snow = 0.10.0`（Cargo.lock 锁定；`crates/directlink` 直接依赖）

* 审计方式：registry 源码逐文件阅读（`~/.cargo/registry/src/…/snow-0.10.0/src/`）

### 检查项与结论

1. **`CipherState`** **内部 key 字段类型**（`src/cipherstate.rs`）：

   * `CipherState { cipher: Box<dyn Cipher>, n: u64, has_key: bool }`——
     结构体本身无 `Drop` impl、无 zeroize；

   * 默认 resolver（`src/resolvers/default.rs`）中密钥落地为
     `CipherChaChaPoly { key: [u8; CIPHERKEYLEN] }` **普通字节数组**，
     `set()` 直接 `copy_slices` 覆盖，无 ZeroizeOnDrop。
2. **`into_stateless_transport_mode()`** **转换路径**（`src/stateless_transportstate.rs`

   * `cipherstate.rs`）：

   - `From<CipherState> for StatelessCipherState` 把 `Box<dyn Cipher>`（含密钥）
     **移动**进传输态——密钥延续使用（预期行为）；

   - `HandshakeState` 其余字段（SymmetricState、`Dh25519` 含静态/ephemeral 私钥
     普通数组）随消费 Drop，**无擦除**。
3. **`rekey()`** **后旧 key 是否清理**（`src/types.rs` `Cipher::rekey` 默认实现）：

   * 新 key 通过 `set()` 覆盖旧 `key` 字段（覆盖 ≠ 擦除语义，但同位置覆盖使旧值
     不可恢复——仅限 cipher 对象内部那份）；

   * 派生过程中的栈局部 `key`/`ciphertext` 缓冲（`[0u8; 32]` 等）用后**不擦除**。

   * 注：MeshLink M0-5 未用 snow 的 `rekey()`——重握手走完整 IK（新
     StatelessTransportState 对象），因此每轮旧密钥对象整体 Drop 释放。

### 结论（勾选）

* [ ] 方案 A：fork（未采用）

* [ ] 方案 B：resolver/backend 替换（未采用，见下节可行性记录）

* [x] 方案 C：Known Security Risk 记录（本 ADR 生效）

## 方案 B 可行性记录（供复审时参考，M0-5 未实施）

snow 的 `CryptoResolver` 允许注入自定义 `Cipher`/`Dh` trait 实现：
两个适配器（`ZeroizingCipher` 包装 ChaChaPoly、`ZeroizingDh` 包装 Dh25519，
内部用 `Zeroizing<[u8;32]>` 存 key/privkey）即可在不 fork snow 的前提下获得
Drop-擦除保证，估算 \~150 行 + 各自单测。**触发条件见「决策-复审」**。

## 验证方法论（M0-5 执行结果）

* 自持密钥：✅ 单测 `private_key_zeroed_on_drop`
  （`crates/directlink/src/crypto/keys.rs`）——`Box` 固定地址 + Drop 前后
  `unsafe` 读断言全零，已通过。

* snow 内部：✅ 以源码审计为准（上节证据），**未做**任何运行时内存扫描声称
  （不可靠、不承诺）。

## 决策

**M0-5 采用方案 C：snow 0.10.0 内部密钥材料无 zeroize 保障，记录为 Known
Security Risk。**

* 风险描述：进程内存转储、冷启动攻击、Windows 页面文件（pagefile）等物理内存
  取证手段，可从已退役 epoch 的堆内存与已 Drop 的握手私钥中恢复会话对称密钥
  与 X25519 私钥材料。

* 威胁模型边界：MeshLink MVP 阶段的对手 = 网络路径上的窃听/篡改/重放者
  （IK + AEAD + 防重放已完整覆盖），**不含**能读取本机进程内存的本地攻击者
  ——后者拥有内存读取能力时，可直接读取存活密钥，zeroize 无增益。

* 缓解措施：

  1. 密钥暴露窗口有界：每 epoch 10 分钟 / 1GB 流量即重握手换钥（帧规范阈值），
     退役密钥可解密的流量上限随之冻结；
  2. 自持静态私钥（`StaticIdentity`）已 `Zeroizing`，有单测锁定；
  3. 退役 epoch 的堆内存在宽限期后立即 Drop 归还分配器（复用概率随时间上升，
     但不做定量声称）；
  4. ~~PoC 形态进程短生命周期（退出即整体释放）~~（已失效）——MeshAgentService
     现为**常驻用户态进程**，密钥常驻期 = 进程运行期；由下述复审结论接管。

* **复审记录（Overlay MVP，触发条件 1 已满足）**：身份私钥已 DPAPI 持久化 +
  Agent 常驻化。复审结论（用户规格五"DPAPI Scope 冻结"）：

  1. MeshAgentService 以**当前登录用户**身份运行（Tauri 子进程，非 LocalSystem）→
     DPAPI 维持 **CurrentUser**，文件 ACL 维持「当前用户 + SYSTEM」，密钥目录
     `%LOCALAPPDATA%\MeshLink\agent`（详见 `DEVICE_IDENTITY.md` §2.2 冻结表）；
     **未**切换 LocalMachine scope（对所有本机用户可解密，明确排除）；
  2. 常驻化的新增暴露面由三个测试锁定：`service_identity_restart_stable`（重启
     身份稳定）、`unauthorized_user_cannot_read_identity`（DACL 受托人穷举）、
     `ui_process_does_not_receive_private_key`（9 命令 + 事件流私钥零泄漏）；
  3. 方案 C 风险本身**维持不变**（snow 内部无 zeroize；见上）；
  4. 若服务化切换 LocalSystem（Windows Service 里程碑），DPAPI/ACL/目录三要素
     必须重开决策——与 `DEVICE_IDENTITY.md` §2.2 变更触发条件联动。

* 复审触发条件（满足任一即重开本 ADR，优先方案 B）：

  1. ~~Controller/注册表落地、身份私钥持久化（DPAPI）时~~（已触发并完成复审，
     见上「复审记录」）；
  2. MeshAgentService 切换为 Windows 服务（LocalSystem / 服务账户）运行时——
     运行身份与 DPAPI 边界改变；
  3. snow 上游版本合入 zeroize 支持并升级依赖时；
  4. 威胁模型升级（如企业部署要求内存取证抗性）时。

## 参考

* snow 0.10.0 源码：`src/cipherstate.rs`、`src/stateless_transportstate.rs`、
  `src/resolvers/default.rs`、`src/types.rs`

* Noise Protocol Framework spec (rev34) §4.2 Rekey、§5.1 CipherState

* 用户修正三原文（M0-5 任务说明）

* 关联文档：`schemas/frame/directlink_frame_v1.md`（帧格式与 epoch/宽限语义）

