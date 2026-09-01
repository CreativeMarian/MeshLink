# third_party NOTICE — 第三方组件分发记录

本目录记录 meshlink 随安装包分发 / 动态加载的第三方组件及其许可证与分发方式。
任何组件进入安装包前，必须先在本文件登记（组件 / 版本 / 来源 / 校验 / 许可证 / 分发方式）。

## 1. Wintun（M0-3 起使用，M0-3.1 许可表述修正）

| 项 | 内容 |
| --- | --- |
| 组件 | Wintun — Layer 3 TUN Driver for Windows |
| 版本 | 0.14.1（锁定，M0 baseline；升级需独立 ADR + 全量重新验收） |
| 官网 | https://www.wintun.net/ |
| 来源 | 官方 ZIP：https://www.wintun.net/builds/wintun-0.14.1.zip |
| ZIP SHA2-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| DLL SHA2-256（bin/amd64/wintun.dll） | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| 版权所有者 | **WireGuard LLC**（注意：不是笼统 "Jason A. Donenfeld / WireGuard 项目"——预编译二进制许可第 2/3/5/6 条版权实体是 WireGuard LLC） |
| 实际分发内容 | Wintun 0.14.1 **prebuilt binary**（bin/amd64/wintun.dll，官方签名，动态加载） |
| 预编译二进制许可 | 官方 ZIP 自带 [third_party/wintun/LICENSE.txt](wintun/LICENSE.txt)，标题为 **「Prebuilt Binaries License」**（共 8 条：Definitions / License Grant / Restrictions / Limited Warranty / Limitation of Liability / Termination / Severability / Reservation of Rights）。本安装包随附该文件原文，不做任何概括、改写或缩略。 |
| 源码许可（与本安装包分发**无直接关系**） | Wintun 源码在 https://git.zx2c4.com/wintun 以 GPL-2.0 发布。**注意：meshlink 不重编、不修改、不随安装包分发 Wintun 源码或自建驱动，因此不受 GPL-2.0 义务约束。** 此处仅做信息完整登记。 |
| 分发方式 | **仅允许分发官方预编译签名 DLL**（bin/amd64/wintun.dll）——Wintun 官方明确这是唯一受支持的生产分发方式（Prebuilt Binaries License §3 Restrictions d 项：仅当通过 wintun.h 的 Permitted API 使用时，允许与其它软件一并分发）。 |

### meshlink 的使用方式（硬性约定，M0-3.1 未变更）

1. **禁止自行编译驱动**：不 clone 源码自建，不修改 Wintun 代码，不使用 master HEAD 非官方签名构建。
2. **官方签名 DLL + 运行时动态加载**：`mesh-vnic` crate 通过 `LoadLibraryW(wintun.dll)` 动态解析
   `WintunCreateAdapter / WintunStartSession / WintunReceivePacket` 等 API（对应官方 `wintun.h`
   0.14.1 签名），不静态链接、不做 import lib 绑定，DLL 加载路径禁止相对路径（DLL Hijacking
   防御见 M0-3 ABI 验收）。
3. DLL 随 meshlink 安装包释放到应用安装目录，不写入系统目录、不注册驱动服务；加载前校验
   SHA2-256 与版本签名（M0-3 BuildTools 验收已经过）。
4. 不得对 `wintun.dll` 重命名、修改或重打包；分发时必须原样保留官方签名。
5. 每次升级 Wintun 版本：
   - 必须先写独立 ADR（引用 WINTUN_VERSION_RISK.md 第 7 节升级条件）；
   - 从官网下载 ZIP → 校验 ZIP 与 DLL 双 SHA2-256 → 更新本 NOTICE 的版本与哈希 →
     在安装部署文档中记录变更 → 重跑 M0-3 全部 393 秒 E2E + M0-3.1 全部 6 项验收。
6. 随安装包分发的许可义务：**一字不改附官方 ZIP 内 `third_party/wintun/LICENSE.txt`
   （Prebuilt Binaries License 原文）**，并在"关于 / 开源致谢"页面列出 Wintun 及其
   Copyright=WireGuard LLC。

---
*登记日期：2026-08-30（M0-2）；许可表述修正：2026-08-30（M0-3.1-5）*
