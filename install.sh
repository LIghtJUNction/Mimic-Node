#!/bin/bash

RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[0;33m' BLUE='\033[0;34m' PURPLE='\033[0;35m' CYAN='\033[0;36m' WHITE='\033[0;37m' B_RED='\033[1;31m' B_GREEN='\033[1;32m' B_YELLOW='\033[1;33m' B_BLUE='\033[1;34m' NC='\033[0m'

# 成功消息
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# 错误消息
error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2 # 错误重定向到 stderr
}

# 警告消息
warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

run_as() { sudo -u "$1" -i bash -c "$2"; }

# Y/n
confirm() { read -p "[确认] ${1:-继续?} [Y/n]: " i; [[ "$i" != [Nn]* ]]; }
# N/y
ensure() {
    read -p "[确认] $1 (y/N): " i; [[ "$i" == [Yy]* ]]
}


confirm "我已了解这是一个半自动脚本，接下来每个步骤，我都会仔细阅读" || {
  warn "你没有好好阅读!"
  exit 0
}

info "第一步，检查系统是否满足要求，如果不满足要求，比如你的系统不是arch，建议手动部署"

ensure "你需要配置新用户、设置默认 Shell (Fish) 并安装 AUR 助手吗？如果你决定自己配置，直接回车即可" && {
    info "开始配置用户环境..."

    info "正在刷新 Arch Linux 密钥..."
    pacman -Sy archlinux-keyring --noconfirm
    pacman-key --init && pacman-key --populate archlinux

    info "正在安装 Fish, Git 和基础编译工具 (base-devel)..."
    pacman -S --needed base-devel git fish --noconfirm
    read -p "请输入要创建的用户名: " username
    if id "$username" &>/dev/null; then
        warn "用户 $username 已存在。"
    else
        useradd -m -G wheel -s /usr/bin/fish "$username"
        info "用户 $username 已创建，默认 Shell 已设为 Fish。"
        info "请为新用户设置密码："
        passwd "$username"
        echo "%wheel ALL=(ALL:ALL) ALL" > /etc/sudoers.d/10-wheel
    fi

    confirm "是否安装 paru (推荐)？[n 则安装 yay]" && {
        info "正在安装 paru-bin..."
        sudo -u "$username" bash -c "cd ~ && git clone aur.archlinux.org && cd paru-bin && makepkg -si --noconfirm"
    } || {
        info "正在安装 yay-bin..."
        sudo -u "$username" bash -c "cd ~ && git clone aur.archlinux.org && cd yay-bin && makepkg -si --noconfirm"
    }

    info "用户配置完成！现在你可以切换到新用户了。"
}

ensure "推荐启用cachyos的软件仓库，想启用嘛？直接回车跳过。" && {
    info "https://github.com/CachyOS/linux-cachyos#cachyos-repositories"
    # Download and extract the installer
    curl -O https://mirror.cachyos.org/cachyos-repo.tar.xz

    tar xvf cachyos-repo.tar.xz && cd cachyos-repo

    # Run the automated installer
    sudo ./cachyos-repo.sh && { 
        cd -
        rm -rf ./cachyos-repo
    }
}

ensure "需要安装一个简单易用的编辑器：micro吗？直接跳过（熟悉vim或者nano）" && {
    

}