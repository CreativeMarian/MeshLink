# MeshLink

> 私有点对点 Mesh 网络平台

MeshLink 是一个面向个人和小团队使用的安全 P2P Mesh 网络工具。

支持设备之间建立加密连接，并提供类似局域网的虚拟网络环境。


## 当前功能

- ✅ DirectLink P2P 直连
- ✅ NAT 穿透
- ✅ STUN 候选交换
- ✅ Noise IK 加密通信
- ✅ Controller 身份管理
- ✅ 6 位连接码
- ✅ 好友系统
- ✅ 最近连接记录
- ✅ Wintun 虚拟网络接口
- ✅ Overlay 虚拟 IP


## 项目架构


    Controller
         |
         |
    MeshAgent A <====> MeshAgent B

       P2P Encrypted Tunnel

              |
       Virtual Network


## 安全设计

- X25519 密钥交换
- Noise IK 加密协议
- 防重放保护
- Device Identity
- 会话隔离


## 项目结构


    apps/
        用户界面

    crates/
        Rust 核心模块

    server/
        Controller 服务

    schemas/
        协议定义

    docs/
        项目文档


## 开发状态

当前版本：

M1-1.5


已完成：

- P2P 基础连接
- 加密传输
- Controller
- 好友系统
- 最近连接
- 生命周期管理


开发计划：

- N2N + Supernode
- Path Manager
- 自动线路切换
- 文件传输
- 远程桌面
- Relay 服务


## AI 协作开发

本项目采用：

- 豆包 AI 编程开发
- ChatGPT 架构审核


AI 开发文档：

    docs/ai/


开发流程：

1. AI 阅读项目状态
2. 完成功能开发
3. 更新项目文档
4. Git 提交
5. 代码审核


## 项目定位

MeshLink 当前用于：

- 个人设备连接
- 好友之间组网
- 私有网络访问


## License

Private Project
