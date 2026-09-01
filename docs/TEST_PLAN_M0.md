# meshlink M0 测试计划（v1.1）

> 状态：随架构确认冻结。执行载体：`tests/poc/`（脚本+用例）。
> 汇报要求：每项测试必须留下可复查的原始数据（日志/pcap/耗时表）。

## 1. 网络环境矩阵（文档 22.1 裁剪到 M0 相关项）

| 场景 | 必测内容 |
|---|---|
| 同一 LAN | DirectLink 局域网直连秒连 |
| 两端家庭 NAT | UDP 打洞成功率 |
| 一端 CGNAT / 对称 NAT | 打洞失败时的 Relay 兜底 |
| UDP 被阻断 | CF WSS Relay 可用性 |
| Controller 断网 | 已有连接继续 |
| N2N edge 强杀 | 场景 A/B 语义（见 §3） |
| Primary SN 强杀 | 切 Backup + 恢复回切 |
| 高丢包/高延迟 | 熔断与防抖 |
| Cloudflare Tunnel 断开 | 已有 P2P/N2N 不受影响 |

## 2. DirectLink 会话层测试（M0-5）

| # | 用例 | 断言 |
|---|---|---|
| C-1 | 正常握手（双方注册公钥匹配） | 会话建立，双向收发 |
| C-2 | 对端静态公钥与注册表不符 | 握手拒绝，`CryptoKeyMismatch` |
| C-3 | 重放旧帧（相同 seq） | 预检查丢弃，不解密，replay window 不被污染 |
| C-4 | 乱序帧（窗口内） | 正常解密提交 |
| C-5 | 过旧帧（窗口外） | 拒绝并计数 |
| C-6 | 伪造帧（随机 ciphertext） | AEAD 校验失败丢弃，window 不变 |
| C-7 | 周期重握手（10min/1GB 触发条件加速模拟） | epoch +1，切换期零丢包 |
| C-8 | prologue 上下文绑定（改 network_id/device_id 重放握手包） | 握手失败 |
| C-9 | nonce 单调性（send_seq 永不复用同一 epoch+方向） | 审计断言 |
| C-10 | zeroize 验证 | 方法论见 `docs/adr/NOISE_KEY_LIFECYCLE.md`（自持密钥强制验证；snow 内部按评估结论记录） |

## 3. 故障切换双机制测试（M0-8，修正四）

### 场景 A：Active Path = DirectLink

| # | 注入 | 断言 |
|---|---|---|
| F-A1 | kill N2N（headless/进程） | DirectLink 业务 0 中断、Wintun 0 中断、虚拟 IP 0 变化 |
| F-A2 | kill Supernode 进程 | 同上 + sn 熔断器 OPEN 事件 |
| F-A3 | 断 N2N Provider（模拟 Fatal） | 同上 |

### 场景 B：Active Path = N2N（DirectLink READY 热备）

| # | 注入 | 断言 |
|---|---|---|
| F-B1 | 本机 N2N Provider 明确崩溃（Fatal 事件） | Circuit 立即 OPEN；**不等 3s 健康窗口**；立即切 READY DirectLink；**P95 failover ≤ 1s** |
| F-B2 | F-B1 度量记录 | 切换耗时 / ICMP 丢包数 / UDP 丢包数 / TCP 存活 / TCP 恢复耗时 全部落表 |
| F-B3 | Quality Degradation（注入高丢包，非 Fatal） | 走健康评分路径：Critical<40 持续 3s 才切换（证明两套机制分离） |
| F-B4 | Primary SN 强杀 | 切 Backup；SN 熔断独立：其他 SN 与 N2N P2P 不受影响 |

## 4. overlay_mac 稳定性测试（M0-6A，修正二）

| # | 场景 | 断言 |
|---|---|---|
| M-1 | 注册 | MAC 生成持久化，locally administered + unicast |
| M-2 | P2P 直连 | 双端帧地址 = 分配值 |
| M-3 | SN Relay | 中继下地址不变 |
| M-4 | edge 重启 | 地址不变 |
| M-5 | IP 重新分配 | 地址不变 |

## 5. Cloudflare WSS 测试（M0-9，修正六）

| # | 用例 | 断言 |
|---|---|---|
| W-1 | ≥1h 加密帧承载 | 帧大小上限/空闲超时/吞吐基线成文 |
| W-2 | **主动断开 WSS ×100** | 自动恢复率 100%（heartbeat + 指数退避 + 最大重连时间内恢复） |
| W-3 | 重连后 session resume / peer rebind | sequence 连续性处理正确，无重复/丢失交付 |
| W-4 | Tunnel 断开时存量 P2P/N2N | 不受影响 |
| W-5 | 限速/限包 | Relay 永不成为默认主路径（策略断言） |

## 6. 环境与门禁

- `cargo test` 全绿；`go build ./...` + controller 冒烟。
- `cargo tree` 门禁：webrtc 系符号不出现在 directlink 之外；
  n2n FFI 符号不出现在 transport-n2n 之外。
- 每项测试原始数据归档 `tests/poc/results/`（gitignore 大文件，保留汇总表）。
