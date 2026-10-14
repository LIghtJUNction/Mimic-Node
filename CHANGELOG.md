# 0.2.0

- Restore compatibility with sing-box 1.14 and repair default, wizard, DNS, Hysteria2 and client configuration generation.
- Generate valid Reality key pairs, preserve private configuration permissions and reject invalid staged changes before activation.
- Locate managed VLESS inbounds by protocol instead of position; preserve other protocols during user management.
- Repair selective configuration migration and keep-user reset without dropping Reality credentials.
- Provide AUR stable and Git package recipes, complete systemd units and an installer that preserves node state.
- Replace machine-specific tests with isolated CLI lifecycle tests and real local sing-box traffic checks.
- Add manual verification, version-tag release and optional AUR publishing workflows.
