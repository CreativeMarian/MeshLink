# third_party/wintun — 官方 Wintun 0.14.1 存档

meshlink 的虚拟网卡 (mesh-vnic) 唯一驱动来源。**官方签名 DLL 是唯一受支持的分发方式。**

| 文件 | 说明 |
| --- | --- |
| `VERSION` | 锁定版本 0.14.1 |
| `SHA256SUMS` | 官方 ZIP + 各架构 DLL 的 SHA2-256 |
| `SOURCE.txt` | 下载来源、校验值、分发规则 |
| `LICENSE.txt` | 官方许可（预编译 DLL 专用许可，随包分发义务） |
| `OFFICIAL_README.md` | Wintun 官方 README 原文 |
| `include/wintun.h` | 官方 C 头文件（mesh-vnic FFI 声明的对照基准） |
| `bin/amd64/wintun.dll` | 运行时唯一分发 DLL（Windows x64） |

## 构建集成

- `crates/mesh-vnic` 通过 `LoadLibraryExW` 从应用程序目录加载（`LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`），DLL 劫持防护见 mesh-vnic 安全测试。
- 构建 / 测试前把 `bin/amd64/wintun.dll` 复制到目标可执行文件同目录（开发机：`target/debug/` 或 `target/release/`）。
- Windows x64 之外架构的 DLL 已删除，仅 SHA256SUMS 留档哈希。
