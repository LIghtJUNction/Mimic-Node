#!/bin/bash
# Install the skill embedded in mimictl; no separate source copy is required.
# Usage: bash scripts/install-skill.sh [--global|--project] [--force]

set -euo pipefail

install_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --global)
            install_args=()
            ;;
        --project)
            install_args=(--project)
            ;;
        --force)
            force=true
            ;;
        --help|-h)
            echo "Usage: $0 [--global|--project] [--force]"
            echo "  --global   Install to ~/.claude/skills/ (default)"
            echo "  --project  Install to .claude/skills/ in the current directory"
            echo "  --force    Replace an existing installation"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
    shift
done

if ! command -v mimictl >/dev/null 2>&1; then
    echo "mimictl is required. Install Mimic-Node before installing its skill." >&2
    exit 127
fi

if [[ "${force:-false}" == true ]]; then
    install_args+=(--force)
fi
exec mimictl skill install "${install_args[@]}"
