#!/usr/bin/env bash
#####################################################################################
# Mimic-Node Installer
# 基于 Arch Linux + systemd + OverlayFS 的 sing-box Reality 节点管理器
#####################################################################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
B_RED='\033[1;31m'
B_GREEN='\033[1;32m'
B_YELLOW='\033[1;33m'
B_BLUE='\033[1;34m'
NC='\033[0m'

STY_BOLD='\033[1m'
STY_UNDERLINE='\033[4m'
STY_RST='\033[0m'

# 消息函数
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
success() { echo -e "${B_GREEN}[SUCCESS]${NC} $1"; }

#####################################################################################
# 防止 root 运行
#####################################################################################
prevent_root() {
    if [[ $EUID -eq 0 ]]; then
        error "请勿使用 root 运行此脚本！"
        error "请使用普通用户登录后，使用 sudo 或以 wheel 组用户运行。"
        exit 1
    fi
}

#####################################################################################
# 检查 Arch Linux
#####################################################################################
check_arch() {
    if [[ ! -f /etc/arch-release ]]; then
        warn "此脚本专为 Arch Linux 设计，其他发行版可能无法正常工作。"
        confirm "继续安装？" || exit 0
    fi
}

#####################################################################################
# 确认提示 (Y/n)
#####################################################################################
confirm() {
    read -p "[确认] ${1:-继续?} [Y/n]: " i
    [[ "$i" != [Nn]* ]]
}

#####################################################################################
# 确保提示 (N/y)
#####################################################################################
ensure() {
    read -p "[确认] $1 (y/N): " i
    [[ "$i" == [Yy]* ]]
}

#####################################################################################
# 暂停继续
#####################################################################################
pause() {
    read -p "按 Enter 继续..."
}

#####################################################################################
# 检查命令是否存在
#####################################################################################
command_exists() {
    command -v "$1" &>/dev/null
}

#####################################################################################
# 检查并安装依赖
#####################################################################################
install_deps() {
    info "检查依赖..."

    local missing_deps=()

    # 核心依赖
    for dep in sing-box rust cargo git; do
        if ! command_exists "$dep"; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "缺少以下依赖: ${missing_deps[*]}"
        if command_exists yay; then
            info "使用 yay 安装依赖..."
            sudo yay -S --noconfirm "${missing_deps[@]}"
        elif command_exists paru; then
            info "使用 paru 安装依赖..."
            sudo paru -S --noconfirm "${missing_deps[@]}"
        else
            error "需要 yay 或 paru 作为 AUR 助手，请先安装！"
            exit 1
        fi
    else
        info "所有依赖已安装"
    fi
}

#####################################################################################
# 编译 mimictl
#####################################################################################
build_mimictl() {
    info "编译 mimictl..."

    # 检查 CARGO_TARGET_DIR，如果用户有设置且空间不足则警告
    if [[ -n "${CARGO_TARGET_DIR}" ]]; then
        warn "检测到 CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    fi

    cargo build --release

    # 安装 mimictl
    sudo install -Dm755 "target/release/mimictl" /usr/local/bin/mimictl

    success "mimictl 安装完成！"
}

#####################################################################################
# 创建 OverlayFS 目录结构
#####################################################################################
setup_overlay() {
    info "设置 OverlayFS 目录结构..."

    # 创建目录
    sudo mkdir -p /var/lib/mimic-node/upper
    sudo mkdir -p /var/lib/mimic-node/work
    sudo mkdir -p /usr/share/mimic-node/default

    # 复制默认配置
    if [[ -d "TEST/etc/sing-box" ]]; then
        sudo cp -r TEST/etc/sing-box/* /usr/share/mimic-node/default/
    fi

    # 设置权限
    sudo chown -R root:root /var/lib/mimic-node
    sudo chmod -R 755 /var/lib/mimic-node

    success "OverlayFS 目录结构创建完成！"
}

#####################################################################################
# 创建 systemd 服务文件
#####################################################################################
create_services() {
    info "创建 systemd 服务文件..."

    # mimic-node-mount.service
    sudo tee /etc/systemd/system/mimic-node-mount.service > /dev/null <<'EOF'
[Unit]
Description=Mimic-Node OverlayFS Mount
Requires=local-fs-pre.target
After=local-fs-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/mount -t overlay overlay -o lowerdir=/usr/share/mimic-node/default,upperdir=/var/lib/mimic-node/upper,workdir=/var/lib/mimic-node/work /etc/sing-box
ExecStop=/usr/bin/umount /etc/sing-box
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF

    # mimic-node timer 和 path (自动维护)
    sudo tee /etc/systemd/system/mimic-node.timer > /dev/null <<'EOF'
[Unit]
Description=Mimic-Node Daily Maintenance Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo tee /etc/systemd/system/mimic-node.path > /dev/null <<'EOF'
[Unit]
Description=Mimic-Node Path Unit (watch config changes)

[Path]
DirectoryNotEmpty=/var/lib/mimic-node/upper
Unit=mimic-node-deploy.service

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/mimic-node-deploy.service > /dev/null <<'EOF'
[Unit]
Description=Mimic-Node Deploy Service
Requires=sing-box.service
After=sing-box.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mimictl apply
EOF

    success "systemd 服务文件创建完成！"
}

#####################################################################################
# 启用服务
#####################################################################################
enable_services() {
    info "启用服务..."

    sudo systemctl daemon-reload
    sudo systemctl enable --now mimic-node-mount.service
    sudo systemctl enable --now sing-box

    success "服务启用完成！"
}

#####################################################################################
# 显示帮助
#####################################################################################
showhelp_global() {
    printf "${STY_BOLD}${STY_CYAN}Mimic-Node 安装脚本${STY_RST}

${STY_BOLD}用法:${STY_RST}
  $0 <子命令> [选项]...

${STY_BOLD}子命令:${STY_RST}
  install        (重新)安装 Mimic-Node
  uninstall      卸载 Mimic-Node
  check          检查系统环境
  help           显示此帮助信息

${STY_BOLD}示例:${STY_RST}
  $0 install      # 开始安装
  $0 check        # 检查依赖

${STY_BOLD}快速开始:${STY_RST}
  1. sudo $0 install
  2. sudo mimictl gen-keys && sudo mimictl sni
  3. sudo mimictl add your@email.com
  4. sudo systemctl enable --now mimic-node.timer
  5. sudo systemctl enable --now mimic-node.path
  6. sudo systemctl enable --now sing-box

"
}

#####################################################################################
# 卸载
#####################################################################################
uninstall() {
    info "卸载 Mimic-Node..."

    if ! ensure "确定要卸载 Mimic-Node 吗？"; then
        info "取消卸载"
        exit 0
    fi

    # 停止服务
    sudo systemctl disable --now sing-box 2>/dev/null || true
    sudo systemctl disable --now mimic-node-mount.service 2>/dev/null || true
    sudo systemctl disable --now mimic-node.timer 2>/dev/null || true
    sudo systemctl disable --now mimic-node.path 2>/dev/null || true

    # 卸载 OverlayFS
    sudo umount /etc/sing-box 2>/dev/null || true

    # 删除目录
    sudo rm -rf /var/lib/mimic-node
    sudo rm -rf /usr/share/mimic-node

    # 删除服务文件
    sudo rm -f /etc/systemd/system/mimic-node-mount.service
    sudo rm -f /etc/systemd/system/mimic-node.timer
    sudo rm -f /etc/systemd/system/mimic-node.path
    sudo rm -f /etc/systemd/system/mimic-node-deploy.service
    sudo rm -f /etc/systemd/system/sing-box.service

    # 删除 mimictl
    sudo rm -f /usr/local/bin/mimictl

    sudo systemctl daemon-reload

    success "Mimic-Node 已卸载！"
}

#####################################################################################
# 检查系统
#####################################################################################
check() {
    info "检查系统环境..."

    local issues=0

    # 检查 root
    if [[ $EUID -eq 0 ]]; then
        warn "以 root 运行此检查...请使用普通用户"
    fi

    # 检查 Arch Linux
    if [[ -f /etc/arch-release ]]; then
        success "Arch Linux: OK"
    else
        warn "非 Arch Linux 系统"
        ((issues++))
    fi

    # 检查 AUR 助手
    if command_exists yay; then
        success "yay: OK"
    elif command_exists paru; then
        success "paru: OK"
    else
        warn "缺少 AUR 助手 (yay 或 paru)"
        ((issues++))
    fi

    # 检查 sing-box
    if command_exists sing-box; then
        success "sing-box: OK"
    else
        warn "缺少 sing-box"
        ((issues++))
    fi

    # 检查 rust/cargo
    if command_exists cargo; then
        success "cargo: OK"
    else
        warn "缺少 cargo"
        ((issues++))
    fi

    # 检查 OverlayFS 支持
    if grep -q overlay /proc/filesystems; then
        success "OverlayFS: OK"
    else
        warn "内核不支持 OverlayFS"
        ((issues++))
    fi

    if [[ $issues -eq 0 ]]; then
        success "所有检查通过！"
    else
        warn "有 ${issues} 个问题需要解决"
    fi

    return $issues
}

#####################################################################################
# 主安装流程
#####################################################################################
do_install() {
    info "${STY_BOLD}${STY_CYAN}开始安装 Mimic-Node${STY_RST}"
    echo ""

    # 1. 欢迎和确认
    echo "=============================================="
    info "Mimic-Node 是一个基于 Arch Linux + systemd 的"
    info "sing-box Reality 节点管理器"
    echo "=============================================="
    echo ""

    if ! confirm "继续安装?"; then
        info "安装取消"
        exit 0
    fi

    # 2. 检查依赖
    echo ""
    info "=== 第 1 步: 检查依赖 ==="
    pause
    install_deps

    # 3. 编译 mimictl
    echo ""
    info "=== 第 2 步: 编译 mimictl ==="
    pause
    build_mimictl

    # 4. 设置 OverlayFS
    echo ""
    info "=== 第 3 步: 设置 OverlayFS ==="
    pause
    setup_overlay

    # 5. 创建服务
    echo ""
    info "=== 第 4 步: 创建 systemd 服务 ==="
    pause
    create_services

    # 6. 启用服务
    echo ""
    info "=== 第 5 步: 启用服务 ==="
    pause
    enable_services

    echo ""
    echo "=============================================="
    success "Mimic-Node 安装完成！"
    echo "=============================================="
    echo ""
    info "后续步骤:"
    echo "  1. sudo mimictl gen-keys    # 生成密钥"
    echo "  2. sudo mimictl sni         # 自动探测 SNI"
    echo "  3. sudo mimictl add you@ex.com  # 添加用户"
    echo "  4. sudo mimictl link you@ex.com  # 生成链接"
    echo ""
}

#####################################################################################
# 主入口
#####################################################################################
main() {
    cd "$(dirname "$0")"

    case "${1:-}" in
        "" | "install")
            prevent_root
            do_install
            ;;
        "uninstall")
            prevent_root
            uninstall
            ;;
        "check")
            check
            ;;
        "help" | "--help" | "-h")
            showhelp_global
            ;;
        *)
            error "未知子命令: $1"
            echo ""
            showhelp_global
            exit 1
            ;;
    esac
}

main "$@"
