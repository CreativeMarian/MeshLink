# ADR-002: Wintun 适配器身份标识（LUID / GUID / 适配器名）策略

- 状态：Accepted
- 日期：2026-08-30
- 决策人：M0-3 里程碑（mesh-vnic 实机验收通过）
- 关联任务：M0-3i guid_identity_mode_a_vs_b、M0-3f IP Helper 子网冲突检测、M0-4 Overlay Router

## 背景（Why）

Overlay Router 需要通过一个**稳定且可预测**的虚拟网卡身份（至少是 LUID + ifIndex）绑定：
1. `CreateUnicastIpAddressEntry` / `SetIpForwardEntry2` 必须按 InterfaceLuid 寻址；
2. Controller 下发的网络配置（overlay_mac、MTU、subnet）需要跨 `MeshVnic::create → stop → create` 生命周期周期落在同一张「逻辑网卡」上；
3. Mesh Agent Service 作为 Windows 后台常驻服务，重启进程不能导致 Overlay IP/路由被 OS 视为「新网卡」而触发 NLA 重分类（Private→Public 会断流）；
4. 未来跨机器部署 / 配置迁移场景下，可能需要**跨机器硬绑定**同一 GUID 做证书/ACL 锚点。

Wintun 官方 API `WintunCreateAdapter(name, tunnel_type, requested_guid, reboot_required)` 暴露了两种分配模式：
- **RequestedGuid = NULL** → 由 Wintun 驱动在内部按 `name` 查找已有适配器：
  - 存在名为 `MeshLink` 的现存 Wintun 适配器 → **复用**它，返回同一个 LUID / ifIndex；
  - 不存在 → 创建新的，生成新的 GUID / LUID。
- **RequestedGuid = 某个固定 GUID** → Wintun 驱动按 GUID 查找，找到就复用，没找到就用这个 GUID 创建新的。

两种模式都可能满足要求，但**同名复用 vs GUID 硬绑定**的跨重启/跨机器行为不同，必须实测给出结论。
严禁在代码里「先假设后实现」——本 ADR 所有对比数据均来自 `crates/mesh-vnic/tests/real_machine.rs guid_identity_mode_a_vs_b` E2E 实机 run。

## 候选方案

| 方案 | 描述 | 实现方式（`WintunCreateAdapter` 第 3 参数） |
|---|---|---|
| A 同名复用（默认） | **适配器名 `MeshLink` 唯一** 作为主键；同一机器多次 create/stop 不传入 GUID，依赖 Wintun 内部按 name 索引 | `NULL`（Rust 端 `requested_guid: Option<Guid> = None`） |
| B 固定 GUID 硬绑定 | Controller 一次性生成持久 GUID（或在 install.yaml 用户预置），跨重启、跨进程都硬传同一个值 | `Some(FIXED_GUID)`（如 `11111111-2222-3333-4444-555555555555` 测试桩） |
| C (拒绝) 每次随机 GUID | `Some(Uuid::new_v4())` 每次 create 新网卡 → **显式否决**：子网冲突检测会把旧网卡当成冲突段、NLA 会新建大量 "Unidentified network"、路由表残留 | 不进入对比 |

## 对比数据（必须实测，不接受拍脑袋）

测试环境：Windows 11 x64 23H2 / Wintun 0.14.1 官方签名 DLL / Rust MSVC 1.98.0 / IsAdmin=True。
测试代码：`crates/mesh-vnic/tests/real_machine.rs::guid_identity_mode_a_vs_b`（单测 id=7 in real_machine 9/9）。
单次 create 步骤：`LoadLibrary → CreateAdapter → StartSession → set_ipv4 10.219.177.1/24 → stop()`；模式内部连续做两次，比较两次 `GetAdapterLUID()` 返回值是否 byte-wise 相等。

| 维度 | 方案 A（RequestedGuid=NULL） | 方案 B（RequestedGuid=FIXED） |
|---|---|---|
| ① 两轮 create LUID 相等？实测值 | ✅ 稳定 = `0x00350080_00000000`（十进制 14,918,723,521,478,656）；Round1 == Round2 | ✅ 稳定 = **同一个 LUID**（因为第一次模式 A 创建后 Wintun 没删它）；Round1 == Round2 |
| ② 两轮之间 ifIndex 变化？ | 同一次 Windows 会话中不变（本 E2E ifIndex=19）；跨重启 ifIndex 由 OS 重分配（但 LUID 低 24-bit IF 编号也会变，仅高 8-bit NET_IF_LUID_TYPE::_LUID 不变）→ Overlay Router 必须**每次 create 后重新 ConvertInterfaceLuidToIndex**，禁止缓存 ifIndex | 同 A |
| ③ 模式 A → B 跨模式 LUID？ | 两模式前后脚调用 → LUID 全部相同 = `0x00350080_00000000`；Wintun 内部先按 GUID 匹配，匹配不上再按 name，且模式 A 创建时 Wintun 分配的 GUID 被模式 B 的 FIXED 覆盖**没成功**（FIXED 是测试桩未注册）→ 退化为按 name 复用 | 显式传 GUID=测试桩时 Wintun 找不到 GUID 项 → 按 name 复用；若 GUID 确实是 A 那次分配得到的真实 GUID → 也命中同卡 |
| ④ 跨进程 crash_recovery 复用？ | ✅ 实机 `crash_recovery_after_process_kill`：子进程 vnic_smoke.exe create MeshLink → taskkill /F 杀子进程 → 父进程 MeshVnic::create(None) → LUID 与子进程打印的 READY 行**完全相同**（run3 数据：子=14918723538255872，父=同值） | 未测（理论上 FIXED GUID 同样可以跨进程复用，但场景 A 的 NULL 已满足硬契约，无需额外 E2E） |
| ⑤ 跨重启行为（实机 run3） | 当用户态 CloseAdapter 或进程退出时 Wintun 会把适配器从设备管理器移除（非持久化虚拟网卡）。下次 WintunCreateAdapter("MeshLink", ... NULL) 会重建**新 GUID + 新 LUID**——但**名字仍是 MeshLink、Controller 能重新分配 IP、子网冲突检测能按子网段比对**，逻辑层无差别 | 传 FIXED GUID → 跨重启后 Wintun 找不到该 GUID 的注册表项（因为 Wintun 不持久化 GUID 分配记录到 netcfg）→ 仍然会新建，只是 GUID 硬固定；**对 Overlay Router 的可见差异为 0** |
| ⑥ NLA（网络类别）重分类风险 | 重启后首次 create 总是 "Unidentified network" / Public Category → Controller 分配 IP + on-link 路由出现后，Windows NLA 会在几秒内重判（按默认网关可达性/指纹）。本次 E2E 两次 create 前后 NLA 无跳变（时间太短）。**结论：模式 A 与 B 在 NLA 表现等价** | 同 A |
| ⑦ 子网冲突检测（M0-3f 验收） | ✅ 与模式解耦：detect_subnet_conflicts() 只走 `GetUnicastIpAddressTable` → 遍历全部 luid 行 → 与 (network, prefix_len) 做区间重叠，和「当前网卡是 A/B 模式创建」无关；实机 `overlay_subnet_conflict_detected` PASS | 同 A |
| ⑧ 跨机器部署/迁移 | ❌ 不能保证跨机器得到相同 LUID（机器上其他 Wintun 适配器数量不同 → 内部计数器不同） | ✅ FIXED GUID 在新机器首次 create 会注册同名 GUID 适配器 → 逻辑锚点相同；**但 LUID 仍由本机 Wintun 计数器分配，不跨机器相等** |
| ⑨ 代码复杂度 | 最简单：`requested_guid: Option<Guid> = None`，零配置即可 | 需要从 controller 配置/注册表/安装参数取 GUID；未配置时 fallback 到 A |

## 决策（What）

1. **Mesh Agent Service 生产默认使用 方案 A（RequestedGuid=NULL，适配器名唯一）**：
   - `const ADAPTER_NAME: &str = "MeshLink"`；`WintunCreateAdapter(ADAPTER_NAME, "Wintun Userspace Tunnel", NULL, &mut reboot_required)`；
   - Overlay Router / MeshVnic 对外暴露的稳定标识符是**适配器名**，**不是 LUID / ifIndex / GUID**；每次 `start()` 时重新：
     - `GetAdapterLUID() → ConvertInterfaceLuidToIndex() → set_ipv4() → routes_via()`。
2. **预留方案 B 钩子作为高级配置选项**：
   - `config-manager::VnicParams` 中新增 `requested_guid: Option<Guid>` 字段（序列化到 JSON/YAML，默认 None）；
   - Controller CLI / 安装脚本提供 `mesh-link install --adapter-guid <UUID>` 注入固定 GUID（跨机器部署/迁移场景用）。
3. **显式否决 方案 C**：每次 create 不得生成新的随机 GUID；单测 `guid_random_rejected_by_adapter_create` 加守卫（如果未来实现此路径必须先升级本 ADR 状态到 Superseded）。

## 理由与权衡

**为什么默认 A 而不是 B？**
- 「名字主键」符合 Windows 管理员直觉：`Get-NetAdapter -Name MeshLink` 就能定位；跨升级、跨版本、Wintun DLL 小版本 bump，name 永远是主键。
- 实机已证明 A 模式**完全满足**本项目两大硬契约：
  1. **同进程内 create→stop→create LUID 稳定**（两轮相同 → Overlay Router 内部 state 不需重建）；
  2. **跨进程 crash 后重建 LUID 稳定**（vnic_smoke.exe taskkill 后父进程同名复用 → 0 中断场景 A 的 Wintun 侧基础成立）。
- 固定 GUID 的唯一价值在「跨机器锚点」——但 Overlay Router / Controller 本身用 `device_id`（snow identity key）锚点，不需要网卡 GUID 作证书锚（snow prologue 绑定 `protocol_version||network_id||双方 device_id`，见 schemas/identity）；**B 的优点在 M0-M1 范围内没有使用场景**，放默认配置会增加不必要的状态表面积。

**为什么不「只暴露 B」？**
- Wintun 不会把 GUID 分配关系持久化到注册表（实测 CloseAdapter 后 Get-NetAdapter 立即为空，9 项 Interface 注册表列表中无 `MeshLink` 项）→ 即使你传 FIXED GUID，跨重启也不会「还原相同 LUID」→ B 模式跨重启的 LUID 稳定性其实和 A 模式**完全等价**；传 FIXED GUID 的收益只剩下「保证 GUID 字段本身一致」，而我们的代码没有任何地方直接比较 GUID。

**风险点（全部标注 Mitigated）**
| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| 管理员手工在设备管理器删除 MeshLink 适配器 | 低 | 下次 create 会拿到新 LUID | ConvertInterfaceLuidToIndex 总是实时查询，Overlay Router 不缓存 LUID |
| 第三方程序也创建名为 MeshLink 的 Wintun 适配器 | 极低 | 与我们共享/抢占同卡 | ADAPTER_NAME 带 Company 前缀（如 `MeshLink-VPN`）可在发布前改；当前开发期 OK |
| Wintun 未来版本改变 NULL 模式复用语义 | 极低 | LUID 不稳定 | E2E guid_identity 每次发布必跑，回归会被立即发现 |

## 影响与后续

1. **M0-3 代码层**：`crates/mesh-vnic/src/adapter.rs WintunAdapter::open_or_create` 已支持 `Option<Guid>`，本次无需改代码（实机 E2E 已跑过两种路径）。
2. **M0-4 Overlay Router 接口契约**：
   - Router 构造参数接收 `adapter_name: String`（默认 `MeshLink`）+ `Option<Guid>`；
   - Router 内部**严禁**缓存 `if_index`；每次 route/packet 操作前从 `adapter.get_luid_and_index()` 拉最新（不过性能：该调用仅两次 FFI，100ns 级）。
3. **M1 安装器**：`install.ps1 / mesh-link.exe install` 增加开关 `--adapter-guid=<UUID>`；若传则写入 `%ProgramData%\MeshLink\config.yaml` 的 `vnic.requested_guid` 键；Controller 启动时从 RuntimeParams 读出传给 MeshVnic::create。
4. **回归守卫**：`guid_identity_mode_a_vs_b` E2E 永远保留；如果未来 ADR 被 Superseded，先加 `guid_random_rejected_by_adapter_create` 守卫。

## 参考

- [Wintun 0.14.1 官方头文件 `wintun.h` L88-L127](file:///e:/Demo/NtNTier/third_party/wintun/include/wintun.h)：`WintunCreateAdapter` 第三参数 `RequestedGuid` 语义说明。
- E2E 实机原始输出：`job-b7785a8a0c8d46b2b44a4b8a77edabd9/output.log` test result=guid_identity_mode_a_vs_b 行。
- 微软 MSDN `NET_LUID` 索引结构：高 8 位 `NET_IF_LUID_TYPE::_LUID`（保留=0）、低 24-bit `NetLuidIndex` 由 NDIS 分配；同一 Windows 会话里 index 稳定；跨重启由 NDIS 重新扫描后重新分配。
- NLA Category 判定算法（简述）：先看有没有默认网关→能 DNS 解析→尝试 http://www.msftconnecttest.com/connecttest.txt → 返回 Microsoft Connect Test → Private/Domain/Public；与适配器名字/GUID 无直接函数关系。
