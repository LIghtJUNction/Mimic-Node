# Mimic-Node

> **拟态节点 (Mimic Node)**
> 一个基于 Arch Linux + systemd 的隐形 sing-box 节点管理器，支持 Reality、Hysteria2、TUIC 等多种协议。

Mimic-Node 专为 **Arch Linux** 服务器设计，采用自动化、"部署即忘"的理念，为您维护一个高可用的代理节点。

部署完成后可在daed添加（最简单）

---

## 🤖 AI 助手部署 (推荐!)

**现在支持 Claude Code AI 助手！** 安装 Skill 后，只需说一句"帮我部署 Mimic-Node"，AI 就会自动完成全部配置工作。

```bash
# 安装后，在 Claude Code 中直接说这句话即可：
/mimic-node

# 或者在终端用 mimictl 安装 Skill:
sudo mimictl skill install
```

**AI 可以帮你做的事：**
- ✅ 自动部署完整节点
- ✅ 安装 AUR 包并初始化配置
- ✅ 管理用户 (添加/删除/更新/重置)
- ✅ 配置各种协议 (Reality, Hysteria2, TUIC, AnyTLS...)
- ✅ 诊断并修复问题
- ✅ 升级配置到最新版本
- ✅ 生成客户端订阅链接

**零学习成本，会说话就会用！**

---

## 核心特性

- **Systemless 架构 (无系统侵入)**：使用 **OverlayFS** 技术管理配置。您的所有修改（用户、密钥、SNI）都存储在 `/var/lib/mimic-node` 中，保持系统原始配置纯净。卸载时可彻底清除，不留垃圾。
- **自动维护**：每日自动轮换 SNI 目标域名，避免因长期伪装单一域名而被主动探测识别。
- **反探测机制**：自动扫描并切换至高质量的 Reality 目标域名（如 Microsoft, Amazon, Google 等），优先选择支持 H2/TLS1.3 的大站。
- **便捷管理**：内置强大的 `mimictl` 命令行工具，轻松管理用户、密钥和订阅链接。
- **多协议支持**：VLESS+Reality, VLESS+WebSocket, Hysteria2, TUIC, AnyTLS, Cloudflared, SSH, TUN
- **AI 助手集成**：Claude Code Skill 支持，说话就能部署和维护

## 环境要求

- **网络环境**：需要公网 IP
- **操作系统**: Arch Linux (或 Manjaro/EndeavourOS 等衍生版)
- **Init 系统**: systemd
- **内核**: 必须支持 **OverlayFS** (现代内核几乎默认支持)
- **AUR 助手**: `paru` (推荐) 或 `yay`

## 快速部署

### 🤖 AI 部署 (最简单)

```bash
# 1. 在 Claude Code 中输入:
/mimic-node

# 2. 然后说: "帮我部署 Mimic-Node"

// AI 会自动完成以下所有步骤，无需手动输入任何命令!
```

### 📦 手动部署

```bash
# 1. 安装 AUR 助手 (如果没有)
# yay 或 paru

# 2. 安装 mimic-node-git
paru -S mimic-node-git

# 3. 启用 OverlayFS 挂载 (关键！否则无法写入配置)
sudo systemctl enable --now mimic-node-mount.service

# 4. 运行交互式初始化向导
sudo mimictl setup
# 或手动：
sudo mimictl gen-keys          # 生成 Reality 密钥对并自动探测最佳 SNI
sudo mimictl add my@email.com  # 添加用户
sudo mimictl verify           # 验证配置
sudo mimictl apply            # 应用配置

# 5. 启动服务
sudo systemctl enable --now sing-box
sudo systemctl enable --now mimic-node.timer
sudo systemctl enable --now mimic-node.path
```

## 支持的协议

| 协议 | 端口 | 特性 |
|------|------|------|
| VLESS+Reality | 443 | TCP+UDP over TCP, Multiplex, Brutal |
| VLESS+WebSocket | 8080 | HTTP/2, 路径 /vless-ws |
| Hysteria2 | 443 | QUIC, OBFS, BBR |
| TUIC | 8443 | QUIC, BBR |
| AnyTLS | 8444 | Padding scheme |
| Cloudflared | - | H2, 后量子 |
| SSH | 22 | Direct |
| TUN | - | VPN 模式, auto_route |

## 默认路径

| 路径 | 说明 |
|------|------|
| `/etc/sing-box/config.json` | 主配置 (OverlayFS 合并视图) |
| `/var/lib/mimic-node/` | 持久化存储 (upper layer) |
| `/var/lib/mimic-node/staging/` | 应用前的暂存配置 |
| `/usr/share/mimic-node/default/` | 默认配置 (lower layer) |
| `/usr/share/mimic-node/sni.txt` | SNI 域名列表 |

## mimictl 命令行工具

`mimictl` 是 Mimic-Node 的控制中心。它会强制检查 OverlayFS 挂载状态，确保所有写入操作都发生在虚拟层，保护物理磁盘配置不被污染。

### 用户管理

```bash
# 添加用户 (支持批量)
sudo mimictl add alice@example.com
sudo mimictl add user1@example.com user2@example.com user3@example.com

# 列出所有用户
sudo mimictl list

# 用户详情
sudo mimictl info user@example.com

# 更新用户 (支持批量)
sudo mimictl update user@example.com --level 2

# 重命名用户邮箱 (仅精确匹配单个用户时允许)
sudo mimictl update alice@example.com --email alice+new@example.com --apply

# 批量替换邮箱部分内容
sudo mimictl update '*@old.com' --email-replace '@old.com' '@new.com' --dry-run

# 正则替换邮箱
sudo mimictl update 'user@domain.com' --email-replace '^(.*)@old\.com$' '$1@new.com' --regex --apply

# 重置用户 UUID 和 ShortID (用户被封锁时使用)
sudo mimictl reset-user alice@example.com
sudo mimictl reset-user '*@example.com' --dry-run

# 删除用户 (支持批量和通配符)
sudo mimictl del alice@example.com
sudo mimictl del '*@example.com' --dry-run
sudo mimictl del '*@example.com' --apply

# 生成 VLESS 订阅链接
sudo mimictl link alice@example.com
```

### 链接生成选项

`mimictl link` 支持 IP 检测和生成：

| 参数 | 说明 |
|------|------|
| `--v4` | 仅使用 IPv4 (优先 IPv4) |
| `--v6` | 仅使用 IPv6 (优先 IPv6) |
| `--num N` | 生成 N 个地址 (默认: 1) |
| `--interface IFACE` | 使用指定网卡的地址 |
| `--assign` | 在网卡前缀内自动分配 IPv6 地址 (需要 root) |
| `--assign-v4` | **实验性** - 在网卡 IPv4 子网内自动分配 (需要 root) |
| `--strict` | 检测/分配失败时直接报错而非警告 |

```bash
# 自动检测并生成一个地址
mimictl link alice@example.com

# 手动指定 IP (用于 NAT/CDN 环境)
mimictl link alice@example.com 1.2.3.4

# 生成 5 个地址，优先 IPv6
mimictl link alice@example.com --num 5 --v6 --interface eth0 --assign

# 混合场景 (通常为 1 个 IPv4 + 多个 IPv6)
mimictl link alice@example.com --num 6 --interface eth0 --assign

# 将链接转换为 sing-box 客户端配置
mimictl link alice@example.com | mimictl from-link -o client.json
```

### 配置管理

```bash
# 查看当前配置和公钥
sudo mimictl show

# 对比当前配置与默认配置
sudo mimictl diff

# 验证配置完整性
sudo mimictl verify --verbose

# 丢弃暂存的更改
sudo mimictl discard --item config --force
sudo mimictl discard --item pubkey --force

# 升级配置到最新默认
sudo mimictl upgrade --dry-run
sudo mimictl upgrade --auto

# 重置为默认配置 (保留指定用户)
sudo mimictl reset --keep-user alice@example.com
sudo mimictl apply
```

### 诊断检查

```bash
# 完整诊断
sudo mimictl diagnose --verbose

# 检查项目：
#   - OverlayFS 挂载状态
#   - 配置文件存在性
#   - sing-box 安装状态
#   - 端口 443 监听状态
#   - 防火墙规则
#   - 协议探测配置
#   - TLS 证书
#   - Reality 密钥
#   - 废弃功能检测
#   - DNS 配置
#   - 权限设置
#   - 内核 TLS / BBR 支持
```

### Hysteria2 管理

```bash
# 设置 Hysteria2 入站
sudo mimictl hysteria2 setup --port 443 --masquerade microsoft.com --up 100 --down 200

# 添加 Hysteria2 用户
sudo mimictl hysteria2 add-user --name alice
```

### DNS 管理

```bash
# 设置 DoH3 (DNS over HTTP3)
sudo mimictl dns setup-do-h3

# 添加 DNS 服务器
sudo mimictl dns add-server --tag google --server dns.google --type h3 --path /dns-query
```

### Claude Code Skill

Mimic-Node 包含 Claude Code Skill，可直接在 Claude Code 中使用 `/mimic-node` 命令：

```bash
# 安装 Skill 到全局 (让 AI 助手学习 Mimic-Node 部署知识)
sudo mimictl skill install

# 安装到项目 (只在本项目可用)
sudo mimictl skill install --project

# 查看安装状态
mimictl skill status

# 卸载
mimictl skill uninstall
```

**在 Claude Code 中使用：**
```bash
# 输入 /mimic-node 即可激活 AI 助手
# 然后用自然语言描述你的需求：

/mimic-node

# "帮我部署 Mimic-Node 到新服务器"
# "添加一个新用户 alice@example.com"
# "帮我检查为什么服务启动不了"
# "升级配置到最新版本"
# "生成一个链接给用户 alice"
```

### Shell 补全

```bash
# 生成并应用补全
mimictl completions --shell bash --apply
mimictl completions --shell zsh --apply
mimictl completions --shell fish --apply
```

## 架构说明

Mimic-Node 使用 **OverlayFS** 将读写层 (`/var/lib/mimic-node/upper`) 挂载在只读的默认配置层 (`/usr/share/mimic-node/default`) 之上。合并后的视图挂载在 `/etc/sing-box`。

- **持久化**: 您的所有配置更改都位于 `/var/lib/mimic-node`
- **安全性**: 重新安装或升级软件包 **不会** 覆盖您的密钥或用户数据
- **纯净性**: 如果想彻底重置配置，只需停止服务并删除 `/var/lib/mimic-node` 目录即可

### OverlayFS 白障 (Whiteout) 文件

当你发现 `/var/lib/mimic-node/upper` 目录下出现奇怪的 `c--------- 0, 0` 文件时，请不要惊慌，这是 OverlayFS 的正常行为。

**机制**：
当删除一个底层存在的文件时，OverlayFS 会在 Upper 层创建一个同名的 **Whiteout (白障/墓碑) 文件**。这是一个特殊的字符设备，设备号为 `0, 0`。

```bash
# 查看 upper 层
ls -l /var/lib/mimic-node/upper/PUBKEY.new
# 输出: c--------- 1 root root 0, 0 ... PUBKEY.new
```

当系统读取 `/etc/sing-box` 时，OverlayFS 看到这个墓碑，就会在合并视图中隐藏该文件。这证明了 Systemless 架构正在完美工作！

## 环境变量

| 变量 | 说明 |
|------|------|
| `SINGBOX_JSON` | 覆盖配置文件路径 |
| `MIMIC_OVERLAY` | 覆盖 Overlay 挂载点 |

## 安全建议

- Reality SNI 应指向合法域名 (如 microsoft.com)
- 启用协议探测以获得更好的路由
- 使用 `prefer_ipv4` DNS 策略以提高稳定性
- 启用 BBR 拥塞控制: `sudo sysctl -w net.ipv4.tcp_congestion_control=bbr`
- 保持 `mimictl diagnose --verbose` 无警告

## 故障排除

1. **服务无法启动**: `sudo journalctl -u sing-box -xe`
2. **端口冲突**: `sudo ss -tlnp | grep 443`
3. **配置错误**: `mimictl verify --verbose`
4. **缺少 Reality 密钥**: `mimictl gen-keys`
5. **SNI 问题**: `mimictl sni --file /usr/share/mimic-node/sni.txt`
6. **Overlay 挂载失败**: 检查 `mountpoint /etc/sing-box`; 尝试 `sudo systemctl restart mimic-node-mount`

## 许可证

GPL-3.0-or-later
