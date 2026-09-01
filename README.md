# \# MeshLink

# 

# \## 私有点对点 Mesh 网络平台

# 

# MeshLink 是一个面向个人和小团队使用的安全 P2P 网络工具。

# 

# 目标：

# 

# \- 简单连接好友设备

# \- 自动建立加密隧道

# \- 创建私有虚拟局域网

# \- 支持远程访问和文件传输

# 

# 

# \---

# 

# \# ✨ 当前功能

# 

# \## 已完成

# 

# ✅ DirectLink P2P 直连

# 

# ✅ NAT 穿透

# 

# ✅ STUN 候选交换

# 

# ✅ Noise IK 加密通信

# 

# ✅ Controller 身份管理

# 

# ✅ 6位数字连接码

# 

# ✅ 好友系统

# 

# ✅ 最近连接记录

# 

# ✅ Wintun 虚拟网络接口

# 

# ✅ Overlay 虚拟 IP

# 

# 

# \---

# 

# \# 🏗 项目架构

# 

# 

# 

# MeshLink

# 

# &#x20;   ┌──────────────┐

# &#x20;   │ Controller   │

# &#x20;   │ Go Server    │

# &#x20;   └──────┬───────┘

# &#x20;          │

# &#x20;   Identity / Session

# 

# ┌──────────────┐ ┌──────────────┐

# │ Mesh Agent A │◄─────►│ Mesh Agent B │

# │ Rust │ P2P │ Rust │

# └──────┬───────┘ └──────┬───────┘

# 

# &#x20;  │                      │

# 

# Wintun VPN Wintun VPN

# 

# &#x20;  │                      │

# 

# &#x20;  └──── Virtual Network ┘

# 

# 

# \---

# 

# \# 🔐 安全设计

# 

# \- Device Identity

# \- X25519 密钥交换

# \- Noise IK 加密

# \- 会话隔离

# \- 防重放保护

# 

# 

# \---

# 

# \# 📦 项目结构

# 

# 

# 

# apps/

# MeshLink 用户界面

# 

# crates/

# Rust 核心模块

# 

# server/

# Controller 服务

# 

# schemas/

# 协议定义

# 

# docs/

# 项目文档

# 

# 

# 

# \---

# 

# \# 🚀 开发状态

# 

# 当前版本：

# 

# 

# M1-1.5

# 

# 

# 已完成：

# 

# \- 基础 P2P 网络

# \- 加密传输

# \- 用户连接流程

# \- 好友管理

# \- 生命周期管理

# 

# 

# 开发路线：

# 

# \- N2N + Supernode

# \- Path Manager

# \- 自动线路切换

# \- 文件传输

# \- 远程桌面

# 

# 

# \---

# 

# \# 🤖 AI 协作开发

# 

# 本项目采用：

# 

# \- 豆包 AI 编程

# \- ChatGPT 架构审核

# 

# 开发规范：

# 

# 

# docs/ai/

# 

# 

# AI 开发流程：

# 

# 1\. 阅读项目状态

# 2\. 完成功能开发

# 3\. 更新文档

# 4\. Git 提交

# 5\. 推送仓库

# 6\. 等待代码审核

# 

# 

# \---

# 

# \# 📄 文档

# 

# AI 管理：

# 

# 

# docs/ai

# 

# 

# 项目规划：

# 

# 

# docs/

# 

# 

# \---

# 

# \# 📌 项目定位

# 

# MeshLink 当前用于：

# 

# \- 个人设备连接

# \- 好友之间组网

# \- 私有网络访问

# 

# 不是商业 VPN 服务。

# 

# \---

# 

# \# License

# 

# Private Project

# 

# 保存。

# 

# 然后：

# 

# git add README.md

# git commit -m "Update README in Chinese"

# git push

# 

# 完成后 GitHub 首页会变成：

# 

# MeshLink

# 

# 私有点对点 Mesh 网络平台

# 

# ✨ 当前功能

# 🏗 项目架构

# 🔐 安全设计

# 📦 项目结构

# 🚀 开发状态

# 🤖 AI协作开发

