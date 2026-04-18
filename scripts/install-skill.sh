#!/bin/bash
#
# Mimic-Node Skill Installer for Claude Code
# Usage: bash scripts/install-skill.sh [--global|--project]
#

set -e

SKILL_DIR="$HOME/.claude/skills/mimic-node"
PROJECT_SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.claude/skills/mimic-node"
INSTALL_TYPE="global"

while [[ $# -gt 0 ]]; do
    case $1 in
        --global)
            INSTALL_TYPE="global"
            shift
            ;;
        --project)
            INSTALL_TYPE="project"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--global|--project]"
            echo "  --global   Install skill to ~/.claude/skills/ (all projects)"
            echo "  --project  Install skill to .claude/skills/ (current project only)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ "$INSTALL_TYPE" = "global" ]; then
    TARGET_DIR="$SKILL_DIR"
    echo "Installing mimic-node skill to: $TARGET_DIR"
else
    TARGET_DIR="$PROJECT_SKILL_DIR"
    echo "Installing mimic-node skill to project: $TARGET_DIR"
fi

# Create directory
mkdir -p "$TARGET_DIR"

# Copy skill file
cp "$PROJECT_SKILL_DIR/SKILL.md" "$TARGET_DIR/SKILL.md"

echo ""
echo "✓ Skill installed successfully!"
echo ""
echo "Usage in Claude Code:"
echo "  /mimic-node"
echo ""
echo "The skill provides commands for:"
echo "  - Installing Mimic-Node (AUR, source)"
echo "  - Initial setup and configuration"
echo "  - User management (add, list, update, delete)"
echo "  - Service management (systemctl)"
echo "  - Diagnostics and troubleshooting"
echo "  - Protocol-specific commands (Hysteria2, DNS, etc.)"
