# Mimic-Node

Arch Linux 上的 sing-box 节点管理工具。`mimictl` 管理用户、Reality 密钥和客户端链接；OverlayFS 将配置改动保存在 `/var/lib/mimic-node`，升级软件包不会覆盖节点数据。

0.2.0 针对 **sing-box 1.14** 修复了配置、初始化和打包流程。默认部署 VLESS + Reality，也可通过向导或子命令配置 Hysteria2。需要 Arch Linux、systemd、公网地址，以及支持 OverlayFS 的内核。

## 安装

```bash
paru -S mimic-node
sudo systemctl enable --now mimic-node-mount.service
sudo mimictl setup
sudo mimictl apply
sudo systemctl enable --now sing-box.service
```

`setup` 会生成密钥和用户、验证并暂存配置，随后用 `apply` 激活。Hysteria2 需要你已有的 TLS 证书和私钥；它不会自动申请证书。

也可逐步初始化默认的 Reality 节点：

```bash
sudo mimictl gen-keys
sudo mimictl sni www.microsoft.com
sudo mimictl add alice@example.com
sudo mimictl check
sudo mimictl apply
sudo systemctl enable --now sing-box.service
sudo mimictl link alice@example.com YOUR_PUBLIC_IP
```

默认模板保留空密钥和空用户，必须先初始化。`gen-keys` 后请设置适合服务器网络的 SNI；TLS 目标可达并不保证任意地区都能连接。

从仓库使用安装入口：

```bash
git clone https://github.com/LIghtJUNction/Mimic-Node.git
cd Mimic-Node
bash install.sh install
```

安装脚本通过 `makepkg` 和 `pacman` 安装完整软件包，使用普通用户执行。卸载软件包保留 `/var/lib/mimic-node` 中的节点数据。

## 升级已有节点

```bash
paru -S mimic-node
sudo mimictl upgrade --dry-run
sudo mimictl upgrade --auto
sudo mimictl check
sudo mimictl apply
```

升级命令暂存旧字段迁移，保留用户、密钥和自定义配置；`check` 通过后再应用。以前手动安装的 `/usr/local/bin/mimictl` 和 `/etc/systemd/system/mimic-node*` 可能覆盖新包：先用 `command -v mimictl` 和 `systemctl cat` 检查，确认迁移后再处理旧文件。迁移前保存已有配置，别直接删除 `/var/lib/mimic-node`。

旧 AUR 包 `mimic-node-git` 由另一位维护者管理。本仓库保留其修复后的构建配方，当前维护发布使用 `mimic-node`；两者互斥。

## 常用命令

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

修改默认写入 `config.new`，`apply` 用真实的 `sing-box check` 验证后激活。管理命令定位启用 Reality 的 VLESS 入站，遇到多个候选会报错，避免改错入站。

生成客户端配置不需要 root，也不需要挂载 OverlayFS：

```bash
printf '%s\n' 'vless://YOUR_LINK' | mimictl from-link -o client.json
sing-box check -c client.json
```

Hysteria2 示例（UDP 8443）：

```bash
sudo mimictl hysteria2 setup --port 8443 --domain node.example.com \
  --cert-path /path/to/fullchain.pem --key-path /path/to/privkey.pem
sudo mimictl hysteria2 add-user --name alice
sudo mimictl check
sudo mimictl apply
sudo mimictl hysteria2 link --name alice
```

其他参数用 `mimictl --help` 和各子命令 `--help` 查看。可选 Claude Code skill 通过普通用户运行 `mimictl skill install` 安装；无需 `sudo`。

## 服务与文件

| 路径 / 服务 | 用途 |
| --- | --- |
| `/etc/sing-box/config.json` | OverlayFS 合并后的当前配置 |
| `/etc/sing-box/config.new` | 待验证、待应用配置 |
| `/var/lib/mimic-node/upper` | 持久化用户、密钥和配置 |
| `/usr/share/mimic-node/default/config.json` | 包内未初始化模板 |
| `mimic-node-mount.service` | 挂载配置层 |
| `mimic-node.timer` | 可选每日配置检查 |
| `mimic-node.path` | 可选自动应用暂存配置 |

自动维护和自动应用默认不启用。开启 `mimic-node.path` 后，暂存修改会被自动应用，适合明确需要该行为的部署：

```bash
sudo systemctl enable --now mimic-node.timer
sudo systemctl enable --now mimic-node.path
```

## 本地验证与发布

需要 Rust 1.88+、sing-box 1.14+、Python 3、OpenSSL、curl 和 ShellCheck：

```bash
bash scripts/check.sh
cargo build --locked --release --all-features
```

检查包括格式、Clippy、两轮 Rust 测试、离线脚本/打包测试，以及仅监听本机的真实 sing-box 传输验证。测试使用隔离目录，不修改系统节点或启停本机服务。

- `check.yml`：手动执行同样的检查，普通推送不触发 CI。
- `release.yml`：版本 tag 触发正式构建、验证和 GitHub Release 发布。
- `aur.yml`：手动构建 AUR 包；勾选发布时需要专用 `AUR_SSH_PRIVATE_KEY` 和已验证的 `AUR_KNOWN_HOSTS` secrets，且该 AUR 账号必须拥有目标包。未配置 secrets 时仍可构建和下载产物。

测试用 `MIMIC_NODE_ROOT` 指定隔离根目录，`SING_BOX_BIN` 指定校验程序。不要用测试根目录代替实际系统挂载验证。

## 排错

```bash
sudo mimictl check
sudo journalctl -u sing-box -u mimic-node-mount -n 100 --no-pager
findmnt /etc/sing-box
sudo ss -tulpn
```

Reality 使用 TCP，Hysteria2 使用 UDP；确认对应端口已开放。服务启动成功不代表公网客户端已连通，需要在实际客户端验证。

GPL-3.0-or-later。
