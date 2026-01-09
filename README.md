# Mimic-Node

> **拟态节点 (Mimic Node)**
> 一个基于 Arch Linux + systemd 的隐形 sing-box 节点管理器， Reality 协议。

Mimic-Node 专为 **Arch Linux** 服务器设计，采用自动化、“部署即忘”的理念，为您维护一个高可用的 Reality 节点。

## 核心特性

<details>
<summary>核心特性（展开查看）</summary>

- **Systemless 架构 (无系统侵入)**：使用 **OverlayFS** 技术管理配置。您的所有修改（用户、密钥、SNI）都存储在 `/var/lib/mimic-node` 中，保持系统原始配置纯净。卸载时可彻底清除，不留垃圾。
- **自动维护**：每日自动轮换 SNI 目标域名，避免因长期伪装单一域名而被主动探测识别。
- **反探测机制**：自动扫描并切换至高质量的 Reality 目标域名（如 Microsoft, Amazon, Google 等），优先选择支持 H2/TLS1.3 的大站。
- **便捷管理**：内置强大的 `mimictl` 命令行工具，轻松管理用户、密钥和订阅链接。

</details>


## 环境要求

<details>
<summary>环境要求（展开查看）</summary>

- **网络环境**： 需要公网ip
- **操作系统**: Arch Linux (或 Manjaro/EndeavourOS 等衍生版)
- **Init 系统**: systemd
- **内核**: 必须支持 **OverlayFS** (现代内核几乎默认支持)
- **AUR 助手**: `paru` (推荐) 或 `yay` 

</details>


## 安装

<details>
<summary>安装（展开查看）</summary>

Mimic-Node 已发布至 AUR。

```bash
# 使用 yay 安装
yay -S mimic-node-git

# 或者使用 paru 安装
paru -S mimic-node-git
```

特别注意⚠️：
1. 小内存机器建议修改/etc/makepkg.conf
将默认的构建模块从/tmp（内存里的tmpfs）移动到更大空间的硬盘上去！ 

2. 如果存储空间也紧张，建议安装后清理：CARGO_TARGET_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/cargo-target"
缺点是更新的时候不能加速，浪费时间重新编译

3. mimic-node-bin, 暂时不提供.

</details>



## 快速开始

<details>
<summary>快速开始（展开查看）</summary>

安装完成后，请按顺序初始化节点：

```bash
# 1. 启用配置覆盖层 (至关重要！否则修改无法保存)
sudo systemctl enable --now mimic-node-mount.service
# 如果报错，最终解决方法是删除/var/lib/mimic-node文件夹，使用mimicctl reset命令重置为默认配置
# 2. 生成 Reality 密钥对并自动探测最佳 SNI
sudo mimictl gen-keys
sudo mimictl sni

# 3. 添加第一个用户
sudo mimictl add my_email@example.com

# 4. 启用后台自动维护服务
sudo systemctl enable --now mimic-node.timer
sudo systemctl enable --now mimic-node.path

# 5. 启动 sing-box
sudo systemctl enable --now sing-box
```

</details>


## 管理工具 (mimictl)

<details>
<summary>管理工具 (mimictl)（展开查看）</summary>

`mimictl` 是您的控制中心。它会强制检查 OverlayFS 挂载状态，确保所有写入操作都发生在虚拟层，保护物理磁盘配置不被污染。

</details>

## 默认配置

<details>
<summary>默认配置（展开查看）</summary>

可以通过以下命令恢复默认
```bash
sudo mimictl reset
sudo mimictl apply
```
注意！默认配置里面的私钥是虚假的，为什么一定要留着占位
因为mimictl apply会调用sing-box检查，检查通过才能应用，所以默认配置必须得通过检查才行

</details>

### 用户管理

<details>
<summary>用户管理（展开查看）</summary>

```bash
# 添加用户 (返回 UUID 和 ShortID)
sudo mimictl add alice@example.com

# 删除用户
sudo mimictl del alice@example.com

# 重置用户的 UUID 和 ShortID (当用户被封锁时)
sudo mimictl reset alice@example.com

# 列出所有用户
sudo mimictl list
```

</details>

### 客户端链接

<details>
<summary>客户端链接（展开查看）</summary>

为用户生成 VLESS+Reality+Vision 订阅链接：

```bash
# 自动探测服务器 IP 并生成链接
mimictl link alice@example.com

# 指定 IP 生成链接 (如果服务器在 NAT 后或使用 CDN)
mimictl link alice@example.com 1.2.3.4
```

</details>

### 高级操作

<details>
<summary>高级操作（展开查看）</summary>

```bash
# 手动扫描新的 Reality 目标域名
sudo mimictl sni

# 强制设置特定的目标域名
sudo mimictl sni www.microsoft.com

# 查看当前配置和公钥 (PUBKEY)
sudo mimictl show

# 自定义config.json更新后的动作 (默认是检查)
systemctl edit mimic-node-deploy.service

```

</details>

## 架构说明

<details>
<summary>架构说明（展开查看）</summary>

Mimic-Node 使用 **OverlayFS** 将读写层 (`/var/lib/mimic-node/upper`) 挂载在只读的默认配置层 (`/usr/share/mimic-node/default`) 之上。合并后的视图挂载在 `/etc/sing-box`。

- **持久化**: 您的所有配置更改都位于 `/var/lib/mimic-node`。
- **安全性**: 重新安装或升级软件包 **不会** 覆盖您的密钥或用户数据。
- **纯净性**: 如果想彻底重置配置，只需停止服务并删除 `/var/lib/mimic-node` 目录即可。

</details>

### 举个栗子：深入理解 OverlayFS 的“墓碑”机制

<details>
<summary>举个栗子：OverlayFS 的白障机制（展开查看）</summary>

当你发现 `/var/lib/mimic-node/upper` 目录下出现奇怪的 `c--------- 0, 0` 文件时，请不要惊慌，这是 OverlayFS 的正常行为。

**场景**：
假设默认配置中存在文件 `/etc/sing-box/PUBKEY.new`。当你执行操作删除了这个文件时，OverlayFS 不能去修改只读的底层（Lower Layer)，也不能仅仅是从读写层（Upper Layer）删除它（因为底层还有）。

**机制**：
OverlayFS 会在 Upper 层创建一个同名的 **Whiteout（白障/墓碑）文件**。这是一个特殊的字符设备，设备号为 `0,0`。

```bash
# 查看 upper 层
ls -l /var/lib/mimic-node/upper/PUBKEY.new
# 输出: c--------- 1 root root 0, 0 ... PUBKEY.new
```

当系统读取 `/etc/sing-box` 时，OverlayFS 看到这个墓碑，就会在合并视图中隐藏该文件。这证明了您的 Systemless 架构正在完美工作！

</details>

## 许可证

GPL-3.0-or-later
