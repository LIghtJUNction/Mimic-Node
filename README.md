<div align="center">
  <h1>Mimic Node</h1>
  <p><strong>在 Arch Linux 上部署和维护 sing-box 节点，不让软件包升级覆盖用户、密钥与配置。</strong></p>
  <p>VLESS + Reality · Hysteria2 · staged configuration · OverlayFS persistence</p>

  [![Version](https://img.shields.io/badge/version-0.2.0-111111?style=flat-square)](Cargo.toml)
  [![sing-box](https://img.shields.io/badge/sing--box-1.14%2B-111111?style=flat-square)](https://sing-box.sagernet.org/)
  [![Rust](https://img.shields.io/badge/Rust-1.88%2B-111111?style=flat-square&logo=rust)](Cargo.toml)
  [![License](https://img.shields.io/badge/license-GPL--3.0--or--later-111111?style=flat-square)](LICENSE)
</div>

## 本质上是什么

Mimic Node 是一个 `mimictl` 命令行工具，加上一组 systemd 与 OverlayFS 规则。

```text
包内默认配置 ─┐
              ├─ OverlayFS 合并 → /etc/sing-box/config.json → sing-box
持久化上层 ───┘
      /var/lib/mimic-node

mimictl 修改 → config.new → sing-box check → apply → 当前配置
```

所以升级软件包时，包内文件可以被替换，但用户、Reality 密钥和自定义配置仍保存在 `/var/lib/mimic-node`。配置修改也不会直接打到运行文件：它先进入暂存区，只有真实的 `sing-box check` 通过后才会激活。

## 适用范围

| 项目 | 要求 |
| --- | --- |
| 系统 | Arch Linux + systemd |
| 网络 | 公网地址；对应 TCP/UDP 端口可达 |
| 内核 | 支持 OverlayFS |
| sing-box | 1.14 或更新版本 |
| 默认协议 | VLESS + Reality |
| 可选协议 | Hysteria2，自备 TLS 证书与私钥 |

TLS 目标可达、服务成功启动，都不等于任意地区的公网客户端一定能连通。最终仍需用真实客户端验证。

## 快速安装

```bash
paru -S mimic-node
sudo systemctl enable --now mimic-node-mount.service
sudo mimictl setup
sudo mimictl apply
sudo systemctl enable --now sing-box.service
```

`setup` 会生成 Reality 密钥和初始用户、验证并暂存配置；`apply` 才会将已验证配置激活。

也可以从本仓库构建完整 Arch 软件包：

```bash
git clone https://github.com/LIghtJUNction/Mimic-Node.git
cd Mimic-Node
bash install.sh install
```

请以普通用户运行安装脚本。脚本通过 `makepkg` 构建，再调用 `pacman` 安装。卸载软件包不会删除 `/var/lib/mimic-node` 中的节点数据。

## 手动创建 Reality 节点

```bash
sudo mimictl gen-keys
sudo mimictl sni www.microsoft.com
sudo mimictl add alice@example.com
sudo mimictl check
sudo mimictl apply
sudo systemctl enable --now sing-box.service
sudo mimictl link alice@example.com YOUR_PUBLIC_IP
```

默认模板故意保留空密钥和空用户，必须先初始化。生成密钥后，应把 SNI 改成适合服务器网络环境的真实可达目标。

## Hysteria2

Hysteria2 不会自动申请证书。准备好域名、完整证书链和私钥后：

```bash
sudo mimictl hysteria2 setup \
  --port 8443 \
  --domain node.example.com \
  --cert-path /path/to/fullchain.pem \
  --key-path /path/to/privkey.pem

sudo mimictl hysteria2 add-user --name alice
sudo mimictl check
sudo mimictl apply
sudo mimictl hysteria2 link --name alice
```

Reality 通常使用 TCP；Hysteria2 使用 UDP。防火墙与云平台安全组需要开放对应协议和端口。

## 日常管理

```bash
sudo mimictl list --json
sudo mimictl info alice@example.com
sudo mimictl add alice@example.com bob@example.com
sudo mimictl update alice@example.com --email alice+new@example.com
sudo mimictl reset-user alice@example.com --dry-run
sudo mimictl del '*@example.com' --dry-run
sudo mimictl discard --item config --force
sudo mimictl apply
sudo mimictl diagnose --verbose
```

管理命令只会定位启用了 Reality 的 VLESS 入站；如果存在多个候选，它会停止并报错，而不是猜测要修改哪个入站。

客户端链接也可以离线转换，无需 root 或 OverlayFS：

```bash
printf '%s\n' 'vless://YOUR_LINK' | mimictl from-link -o client.json
sing-box check -c client.json
```

完整参数见 `mimictl --help` 和各子命令的 `--help`。可选 Claude Code skill 由普通用户安装：

```bash
mimictl skill install
```

## 升级已有节点

```bash
paru -S mimic-node
sudo mimictl upgrade --dry-run
sudo mimictl upgrade --auto
sudo mimictl check
sudo mimictl apply
```

升级会暂存旧字段迁移，并保留用户、密钥和自定义配置。先审阅 dry-run，再检查并应用。

以前手动写入的 `/usr/local/bin/mimictl` 或 `/etc/systemd/system/mimic-node*` 可能遮蔽软件包文件。迁移前检查：

```bash
command -v mimictl
systemctl cat mimic-node-mount.service
```

确认迁移完成前，不要删除 `/var/lib/mimic-node`。旧 AUR 包 `mimic-node-git` 由其他维护者管理；当前维护发布使用 `mimic-node`，两者互斥。

## 文件和服务

| 路径 / 服务 | 作用 |
| --- | --- |
| `/etc/sing-box/config.json` | OverlayFS 合并后的当前配置 |
| `/etc/sing-box/config.new` | 待校验、待应用配置 |
| `/var/lib/mimic-node/upper` | 持久化用户、密钥和配置 |
| `/usr/share/mimic-node/default/config.json` | 包内未初始化模板 |
| `mimic-node-mount.service` | 挂载配置层 |
| `mimic-node.timer` | 可选每日配置检查 |
| `mimic-node.path` | 可选自动应用暂存配置 |

自动维护和自动应用默认关闭。只有明确需要“暂存即自动应用”时再启用：

```bash
sudo systemctl enable --now mimic-node.timer
sudo systemctl enable --now mimic-node.path
```

## 验证与发布

需要 Rust 1.88+、sing-box 1.14+、Python 3、OpenSSL、curl 和 ShellCheck：

```bash
bash scripts/check.sh
cargo build --locked --release --all-features
```

检查覆盖格式、Clippy、两轮 Rust 测试、离线脚本与打包测试，以及只监听本机的真实 sing-box 传输验证。测试使用隔离目录，不会修改系统节点或启停本机服务。

- `check.yml`：手动执行完整检查；普通 push 不触发重型 CI。
- `release.yml`：版本标签触发正式构建、验证和 GitHub Release。
- `aur.yml`：手动构建 AUR 包；发布需要专用密钥、已验证的 known-hosts 和目标包所有权。

测试环境可用 `MIMIC_NODE_ROOT` 指定隔离根目录，用 `SING_BOX_BIN` 指定校验程序。隔离测试不能替代真实系统挂载与公网连通性验证。

## 排错

```bash
sudo mimictl check
sudo journalctl -u sing-box -u mimic-node-mount -n 100 --no-pager
findmnt /etc/sing-box
sudo ss -tulpn
```

按顺序确认：配置能通过检查、OverlayFS 已挂载、服务没有启动错误、端口正在监听、防火墙允许对应协议，最后再用外部网络上的真实客户端测试。

## License

[GPL-3.0-or-later](LICENSE)
