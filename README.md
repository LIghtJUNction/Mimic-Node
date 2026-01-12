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

# 半自动安装脚本



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
# 推荐：一键生成命令补全并应用，推荐使用fish
mimictl completions -s fish -a
# 1. 启用配置覆盖层 (至关重要！否则修改无法保存)
sudo systemctl enable --now mimic-node-mount.service
# 如果报错，最终解决方法是删除/var/lib/mimic-node文件夹，使用mimicctl reset命令重置为默认配置
# 2. 生成 Reality 密钥对并自动探测最佳 SNI
sudo mimictl gen-keys
sudo mimictl sni
# 如果实在是无法联网，很有可能是sni配置错误，sni需要是国外网站，但是国内也能访问，比如微软的域名.
# mimictl sni url 应用自定义的sni

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
# 添加用户 (返回 UUID 和 ShortID)。支持批量：可以同时添加多个邮箱
sudo mimictl add alice@example.com bob@example.com

# 删除用户。支持批量与通配模式，例如删除某个域内所有用户；使用 --dry-run 预览，使用 --apply 立即应用
sudo mimictl del alice@example.com
sudo mimictl del '*@example.com' --dry-run
sudo mimictl del '*@example.com' --apply

# 重置用户的 UUID 和 ShortID (当用户被封锁时)。支持批量与通配模式，使用 --dry-run 预览/--apply 立即应用
sudo mimictl reset-user alice@example.com
sudo mimictl reset-user '*@example.com' --dry-run
sudo mimictl reset-user '*@example.com' --apply

# 修改用户 (支持批量)
# - 批量设置 level
mimictl update '*@example.com' --level 1
# - 重命名单个用户邮箱（仅当精确匹配一个用户时允许）
mimictl update alice@example.com --email alice+new@example.com --apply
# - 批量替换邮箱片段（字符串替换）；使用 --regex 可把 FROM 当作正则
mimictl update '*@old.com' --email-replace '@old.com' '@new.com' --dry-run
mimictl update 'user@domain.com' --email-replace '^(.*)@old\\.com$' '$1@new.com' --regex --apply

# 列出所有用户
sudo mimictl list
```

</details>

### 客户端链接

<details>
<summary>客户端链接（展开查看）</summary>

为用户生成 VLESS+Reality+Vision 订阅链接，并可将这些链接转换为 sing-box 客户端配置。`mimictl link` 支持以下与 IP 探测/生成相关的选项（常见场景：一个 IPv4，很多 IPv6）：

- `--v4`：仅尝试 IPv4 探测/使用（优先 IPv4）
- `--v6`：仅尝试 IPv6 探测/使用（优先 IPv6）
- `--num N`：希望生成的地址数量（默认 1）
- `--interface IFACE`：优先使用指定接口的地址或在该接口上分配地址
- `--assign`：允许（IPv6）在接口前缀内自动分配 IPv6 地址（需要 root）
- `--assign-v4`：实验性：允许在接口的 IPv4 子网内尝试自动分配 IPv4 地址（需要 root，谨慎使用）

示例：

```bash
# 默认：自动探测并生成一个地址（JSON 数组）
mimictl link alice@example.com

# 指定 IP 生成链接 (当服务器在 NAT 后或使用 CDN)
mimictl link alice@example.com 1.2.3.4

# 请求 5 个地址，优先 IPv6：若不足会尝试从接口枚举或分配 IPv6（需要 --interface + --assign）
mimictl link alice@example.com --num 5 --v6 --interface eth0 --assign

# 实验性：请求 3 个 IPv4（若接口可分配且为 root 会尝试分配）
mimictl link alice@example.com --num 3 --v4 --interface eth0 --assign-v4

# 混合常用场景（通常为 1 IPv4 + 多个 IPv6）
mimictl link alice@example.com --num 6 --interface eth0 --assign

# 将 link 输出直接转换成 sing-box 客户端配置
mimictl link alice@example.com | mimictl from-link -o client.json
```

行为说明（简化与鲁棒性）：
- 针对常见场景（“一个 v4，超级多 v6”）：命令会尽量拿到 1 个 v4（公网检测或接口上已有），并使用 IPv6（公网/API、接口枚举或自动分配）填充到 `--num` 的数量。
- 自动分配（IPv6、IPv4 实验性）均为**尽力而为**（best-effort），当无法探测或分配到足够的地址时，命令会输出 WARN 日志提示（例如找不到公网 IP，或分配失败），但不会因为找不到而直接中断（以便在尽可能多的场景下仍产出可用链接）。
分配后，不能直接用，你需要认领这些IP，最便捷的方法是下载一个ndppd。

- IPv4 自动分配是实验性的：可能导致网络冲突或需要管理员策略，请在受控环境下使用并确认你有权限。

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
# 你会看到一堆systemd自动生成的注释，按注释的说明来修改，这个服务将在config.json发生变化时执行

# 命令补全
mimictl completions -s fish -a # 为fish生成补全并立即应用

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
