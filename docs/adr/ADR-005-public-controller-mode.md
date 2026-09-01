# ADR-005: Public Controller 模式（CGNAT 环境下跨公网联机的信令中枢）

- 状态：Proposed（设计文档阶段，未大规模编码）
- 日期：2026-09-01
- 决策人：用户 + 助手（基于真实网络环境确认：运营商 CGNAT）
- 关联任务：M1-2 之后；ADR-004（Controller 拓扑）的跨公网延伸
- 前置事实：用户本机公网出口 `112.91.163.213`，但 `tracert` 显示
  `192.168.10.1 → 192.168.1.1 → 10.161.160.1`——运营商级 CGNAT，
  **本机无法把 Controller 直接暴露给公网**。

## 背景（Why）

1. **局域网（LAN）Controller 方案在跨公网场景不可用**：
   ADR-004 的「一台机器跑共享 Controller（RFC1918 + `-allow-lan-plaintext`）」
   只覆盖同一局域网 / 家庭网络。本机位于 CGNAT 之后，出口 IP 是运营商共享的
   112.91.163.213，没有可被远程朋友直接访问的公网入口——**创建机不能承担
   跨公网联机的 Controller 角色**。

2. **但 P2P 数据面不受 CGNAT 阻碍**：
   DirectLink 基于 STUN 辅助 UDP 打洞（simultaneous open）；CGNAT 下双方都主动
   出站时，同一运营商 NAT 上仍可打洞成功（尤其 10.x 大 NAT）。即使打洞失败，
   N2N Supernode 中继 / 未来 Cloudflare Relay 可作为兜底。**数据面从来不是问题，
   问题只在"谁提供双方都能访问到的信令中心"**。

3. **结论**：需要一个**双方都能访问**的 Controller——即 **Public Controller**。
   它只做信令，不转发数据；数据面仍走 Agent ↔ Agent 的 P2P 直连。

## 候选方案

| 方案 | 描述 |
|---|---|
| A | **Public Controller**：客户端连接公网 Controller；创建/加入 session 都请求同一个 Controller；Controller 只做注册/会话/信令；数据面 P2P 直连 |
| B | 把 Controller 部署在创建机本机（现状 LAN 思路）→ 受 CGNAT 限制，远程朋友无法访问 |
| C | 每台机器跑独立 Controller → 状态隔离，6 位码互不可见（ADR-004 已否决） |
| D | 客户端间不经 Controller、直接相互信令 → 需要发现机制与公网可达点，复杂度高，且仍绕不开 NAT 发现问题 |

## 对比数据（依据真实环境，非拍脑袋）

| 维度 | A Public Controller | B 本机 Controller（CGNAT） | D 无中心信令 |
|---|---|---|---|
| 远程朋友可达 | ✅（公网可达） | ❌（CGNAT 无公网入口） | 依赖公网发现点，本质仍需要中心 |
| 6 位码跨机可见 | ✅（同一 Controller） | ❌ | ❌ |
| 数据面 | P2P 直连（不经过 Controller） | P2P | P2P |
| 现有代码改动 | Controller 部署方式 + 客户端仅 URL；信令/会话逻辑复用 | 无（但不可用） | 大改 |
| 安全 | HTTPS/WSS + TLS 终结层（Controller 已有 --tls-cert/--trust-proxy 能力） | 明文/RFC1918 | 复杂 |

## 决策（What）

### 1. 保留 Local Controller（仅开发测试）
- `Local Controller` 继续存在：`http://127.0.0.1:18080`，MeshLink 自动拉起，
  用于本机联调、单元测试、release 冒烟。**不作为跨公网联机方案**。

### 2. 新增 Public Controller 模式
- 客户端通过「设置 → 连接设置 → 加入连接（高级设置 → 服务器地址）」填写
  公网 Controller 地址（如 `https://control.example.com`）。
- **创建连接**：客户端请求**公网 Controller** 创建 session（6 位码）；
- **加入连接**：客户端请求**同一个公网 Controller** 加入 session。
- Controller 只负责：
  - 用户 / 设备注册（Device Identity / device_id → noise_static_public_key）
  - Session（创建 / 查询 / 过期）
  - 信令交换（Candidate Exchange：STUN srflx 候选互换；好友/邀请元数据）
- **数据面不变**：两端 Agent 拿到对端候选后，DirectLink P2P 直连（或 N2N 中继）；
  Controller 不转发任何数据面字节。

### 3. UI 保持用户化（不暴露 Controller 细节）
- 首页仍只有：【创建连接】/【加入连接】两个入口。
- 不显示 Controller / 端口 / 信令等术语。
- Public Controller 与 Local Controller 的区别只体现在「连接设置 → 高级设置」
  的服务器地址上——用户无需理解底层。

### 4. 安全要求
- **公网 Controller 必须 HTTPS/WSS**（或置于 TLS 终结层后，如 Cloudflare Tunnel /
  Nginx 反代）。公网明文 HTTP 继续禁止（Controller 启动即拒绝，客户端白名单同步拒绝）。
- Controller 只持有信令；Noise 私钥 / credential 仍只归 Agent secure-store。
- 双向身份验证（A 验证 B / B 验证 A，基于 Controller Device Registry 的
  device_id → noise_static_public_key）保持现有实现，不重新设计。

### 5. 部署形态（第一版）
- 一台有公网 IP 的服务器（或云主机 / 家庭公网 IP 机器）跑
  `controller.exe --tls-cert cert.pem --tls-key key.pem --db ctrl.db`（原生 HTTPS）；
- 或 Controller 明文只绑内网，前端 Cloudflare Tunnel / Nginx 终结 TLS
  （`--trust-proxy`）。
- 公网 IPAM：Controller `--overlay-pool` 继续作为唯一 Overlay IPAM。

## 理由与权衡

- 选 A 而非 B/C/D：Controller 仍是唯一事实来源（单一写入点），P2P 数据面
  不变；改动最小（Controller 已支持 TLS/trust-proxy，客户端只是填一个公网地址）。
- CGNAT 下「创建机开放本机 Controller」被明确排除：无公网入口，路由不可达。
- Public Controller 是共享基础设施：为朋友/多机提供服务；本机自测仍用 Local。
- 数据面 P2P 直连保证：即使公网 Controller 被压垮，已建立的 P2P 数据面不受影响；
  只有新建会话 / 信令需要 Controller 在线。

## 影响与后续

- **改动范围（后续实现，不在本文档内编码）**：
  - 客户端：无协议改动；仅配置项「服务器地址」可填公网 HTTPS 地址。
  - Controller：已具备 --tls-cert/--tls-key/--trust-proxy；可能需要公网部署脚本 /
    文档（systemd / Docker / Cloudflare Tunnel 配置示例）。
  - 文档：`dist/README.md` 增加「公网 Controller 部署」章节。
- **验证**：release 冒烟扩展——用本地起 HTTPS（自签 CA）Controller 模拟公网，
  验证 create/join → PeerFound 全链路；真实公网标记 `PENDING_REAL_WORLD_VALIDATION`。
- **未来**：M1-6 Cloudflare Disaster Relay（数据面兜底中继）与 Public Controller
  正交；N2N Supernode 同理可部署在公网作为中继路径。

## 参考

- ADR-004（Controller 拓扑：单 Controller 共享 / LAN 明文 / 未来公网）
- `server/controller/cmd/controller/main.go`（--tls-cert/--tls-key/--trust-proxy）
- `docs/adr/DIRECTLINK_ICE.md`（P2P 打洞能力；数据面不经 Controller）
- 用户真实网络确认：公网出口 112.91.163.213 + CGNAT（192.168.10.1 → 192.168.1.1 → 10.161.160.1）
