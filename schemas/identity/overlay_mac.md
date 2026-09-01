# overlay_mac 规范（v1）

> 状态：已确认（用户修正二）。实现归属：Controller（分配与唯一性保证）+ overlay-router（使用）。

## 定义

`overlay_mac` 是 Controller 在 **Device 创建时** 分配的 6 字节以太网地址，用于 N2N Headless 的本机 MAC 与远端 Ethernet Frame 目的 MAC。

## 硬性要求

| 要求 | 说明 |
|---|---|
| 6 bytes | 标准 MAC 长度 |
| locally administered | mac[0] bit1 = 1 |
| unicast | mac[0] bit0 = 0 |
| Network 内唯一 | Controller 分配时查重，冲突则换盐重算 |
| 设备生命周期稳定 | 持久化在 `devices.overlay_mac`，任何重启/重连不变 |
| IP 无关 | 虚拟 IP 变化/重新分配时 MAC **不变**；禁止运行时按 IP 推导 |

## 推荐算法（确定性 + 冲突可重试）

```
seed      = SHA-256( network_id_utf8 || 0x00 || device_id_utf8 || counter_u32_LE )
mac[0..5] = seed[0..5]
mac[0]    = (mac[0] | 0x02) & 0xFE
```

- `counter` 从 0 起，仅当同网络内出现 MAC 冲突时递增重算。
- Controller 计算并持久化；冲突检测在同一 network_id 范围内进行。

## 数据面使用

1. Overlay Router 收到 wintun L3 IP 包 → 查 PeerInfo 得对端 overlay_mac → 合成 Ethernet 帧头（dst = 对端 overlay_mac，src = 本机 overlay_mac，ethertype 0x0800）→ 注入 N2N Headless。
2. N2N Headless 解封装得到帧 → 校验 dst == 本机 overlay_mac 或广播 → 剥帧头 → L3 包写回 wintun。
3. 广播/组播帧（dst bit0=1）：v1 默认丢弃（L3 wintun 无真实 ARP/mDNS，见技术风险表）。

## 禁止事项

- ❌ 运行时根据虚拟 IP 临时推导 MAC（如 `02:4D:<IP后3字节>`，已废弃）。
- ❌ 客户端自行生成 MAC 上报（必须 Controller 统一分配保证唯一性）。

## M0-6A 稳定性验证清单（必须全部通过）

| # | 场景 | 断言 |
|---|---|---|
| 1 | 设备注册 | MAC 生成并持久化，格式合法（locally administered + unicast） |
| 2 | P2P 直连 | 双端帧收发使用分配的 MAC |
| 3 | Supernode Relay | 中继路径下帧地址不变 |
| 4 | edge 重启 | MAC 不变 |
| 5 | 虚拟 IP 重新分配 | MAC 不变 |
