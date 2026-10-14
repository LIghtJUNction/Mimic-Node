#!/usr/bin/env bash
# Install through pacman so upgrades and removal use the same owned files.
set -euo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./install.sh {install|uninstall|check|help}

install     Install the stable mimic-node AUR package with paru or yay.
uninstall   Remove the package; preserve /var/lib/mimic-node and system config.
check       Check Arch Linux, build tools, and runtime dependencies.

Run as your normal user; the package manager requests sudo when needed.
For the development package: MIMIC_NODE_PACKAGE=mimic-node-git ./install.sh install

After installing:
  sudo systemctl enable --now mimic-node-mount.service
  sudo mimictl setup
  sudo mimictl check && sudo mimictl apply
  sudo systemctl enable --now sing-box.service

Optional automation, after configuration is working:
  sudo systemctl enable --now mimic-node.timer mimic-node.path
EOF
}

check_arch() {
    [[ -f /etc/arch-release ]] || die 'This installer requires Arch Linux.'
}

normal_user() {
    (( EUID != 0 )) || die 'Run as a normal user, without sudo.'
}

check() {
    local issues=0 command
    if [[ -f /etc/arch-release ]]; then
        printf 'Arch Linux: OK\n'
    else
        printf 'Arch Linux: missing\n'
        issues=$((issues + 1))
    fi
    for command in makepkg cargo git sing-box systemctl findmnt flock modprobe openssl; do
        if command -v "$command" >/dev/null 2>&1; then
            printf '%s: OK\n' "$command"
        else
            printf '%s: missing\n' "$command"
            issues=$((issues + 1))
        fi
    done
    if command -v paru >/dev/null 2>&1 || command -v yay >/dev/null 2>&1; then
        printf 'AUR helper: OK\n'
    else
        printf 'AUR helper: missing (use makepkg manually)\n'
        issues=$((issues + 1))
    fi
    (( issues == 0 ))
}

main() {
    local package="${MIMIC_NODE_PACKAGE:-mimic-node}" helper
    case "$package" in
        mimic-node|mimic-node-git) ;;
        *) die 'MIMIC_NODE_PACKAGE must be mimic-node or mimic-node-git.' ;;
    esac
    case "${1:-help}" in
        install)
            normal_user
            check_arch
            if command -v paru >/dev/null 2>&1; then
                helper=paru
            elif command -v yay >/dev/null 2>&1; then
                helper=yay
            else
                die 'Install paru or yay, or build packaging/aur/mimic-node/PKGBUILD with makepkg -si.'
            fi
            "$helper" -S --needed "$package"
            if [[ -x /usr/local/bin/mimictl ]]; then
                printf 'Review /usr/local/bin/mimictl from the old installer; it may shadow /usr/bin/mimictl.\n'
            fi
            printf '\nInstalled. Initialize the node before starting sing-box:\n'
            printf '  sudo systemctl enable --now mimic-node-mount.service\n  sudo mimictl setup\n'
            ;;
        uninstall)
            normal_user
            check_arch
            # The package pre_remove hook stops its units before files disappear.
            # Never delete keys, users, original sing-box config, or sing-box itself.
            sudo pacman -R "$package"
            ;;
        check) check ;;
        help|--help|-h) usage ;;
        *) usage >&2; exit 2 ;;
    esac
}

main "$@"
