"""Exercise installation and mount safety without touching host mounts/services."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MOCK = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

state_path = Path(os.environ["MOUNT_MOCK_STATE"])
state = json.loads(state_path.read_text())
command, args = Path(sys.argv[0]).name, sys.argv[1:]
state["calls"].append([command, *args])
code = 0
if command == "id":
    print("0")
elif command == "findmnt":
    target = args[args.index("-M") + 1]
    mount = state["mounts"].get(target)
    if mount is None:
        code = 1
    elif "-o" in args:
        print(mount[args[args.index("-o") + 1]])
elif command == "stat":
    print(state.get("inodes", {}).get(args[-1], "1:100"))
elif command == "mount":
    if "--bind" in args:
        state["mounts"][args[-1]] = {"FSTYPE": "ext4", "SOURCE": "/dev/mock", "OPTIONS": "rw"}
    elif args[:2] == ["-t", "overlay"]:
        if state.get("fail") == "overlay":
            code = 1
        else:
            state["mounts"][args[-1]] = {"FSTYPE": "overlay", "SOURCE": args[2], "OPTIONS": args[4]}
    elif state.get("fail") == "remount":
        code = 1
elif command == "umount":
    state["mounts"].pop(args[-1], None)
state_path.write_text(json.dumps(state))
sys.exit(code)
'''


class MountSafety(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".maintenance"
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="mount-test-", dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.target = str(self.base / "etc/sing-box")
        self.state_dir = str(self.base / "var/lib/mimic-node")
        self.runtime = str(self.base / "run/mimic-node")
        self.lower = self.runtime + "/lower"
        self.defaults = str(self.base / "usr/share/mimic-node/default")
        Path(self.target).mkdir(parents=True)
        Path(self.defaults).mkdir(parents=True)
        script = (ROOT / "overlay/usr/bin/mimic-mount").read_text()
        for original, replacement in [
            ("/etc/sing-box", self.target),
            ("/var/lib/mimic-node", self.state_dir),
            ("/run/mimic-node", self.runtime),
            ("/usr/share/mimic-node/default", self.defaults),
        ]:
            script = script.replace(original, replacement)
        self.script = self.base / "mimic-mount"
        self.script.write_text(script)
        self.state_path = self.base / "state.json"
        self.state = {"calls": [], "mounts": {}}
        for command in ("id", "findmnt", "mount", "umount", "stat", "modprobe"):
            executable = self.bin / command
            executable.write_text(MOCK)
            executable.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin", MOUNT_MOCK_STATE=str(self.state_path))

    def run_mount(self, action):
        self.state_path.write_text(json.dumps(self.state))
        result = subprocess.run(["/usr/bin/bash", str(self.script), action], env=self.env,
                                text=True, capture_output=True)
        self.state = json.loads(self.state_path.read_text())
        return result

    def own_overlay(self, source="mimic-node"):
        return {"FSTYPE": "overlay", "SOURCE": source,
                "OPTIONS": f"rw,upperdir={self.state_dir}/upper,workdir={self.state_dir}/work"}

    def mutations(self):
        return [call for call in self.state["calls"] if call[0] in ("mount", "umount")]

    def test_start_refuses_unrelated_mount(self):
        self.state["mounts"][self.target] = {"FSTYPE": "tmpfs", "SOURCE": "tmpfs", "OPTIONS": "rw"}
        result = self.run_mount("start")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated mount", result.stderr)
        self.assertEqual(self.mutations(), [])

    def test_stop_refuses_foreign_overlay(self):
        overlay = self.own_overlay()
        overlay["OPTIONS"] = "rw,upperdir=/someone/else,workdir=/someone/work"
        self.state["mounts"][self.target] = overlay
        self.assertNotEqual(self.run_mount("stop").returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_start_preserves_original_config_priority(self):
        result = self.run_mount("start")
        self.assertEqual(result.returncode, 0, result.stderr)
        overlay = self.state["mounts"][self.target]
        self.assertEqual(overlay["SOURCE"], "mimic-node")
        self.assertIn(f"lowerdir={self.lower}:{self.defaults},", overlay["OPTIONS"])
        self.assertEqual((Path(self.state_dir).stat().st_mode & 0o777), 0o700)

    def test_failed_overlay_rolls_back_only_new_lower(self):
        self.state["fail"] = "overlay"
        self.assertNotEqual(self.run_mount("start").returncode, 0)
        self.assertNotIn(self.lower, self.state["mounts"])
        self.assertEqual([call for call in self.mutations() if call[0] == "umount"], [["umount", self.lower]])

    def test_failed_remount_rolls_back_only_new_lower(self):
        self.state["fail"] = "remount"
        self.assertNotEqual(self.run_mount("start").returncode, 0)
        self.assertEqual([call for call in self.mutations() if call[0] == "umount"], [["umount", self.lower]])

    def test_stop_accepts_owned_legacy_overlay(self):
        self.state["mounts"][self.target] = self.own_overlay("overlay")
        self.state["mounts"][self.lower] = {"FSTYPE": "ext4", "SOURCE": "/dev/mock", "OPTIONS": "ro"}
        result = self.run_mount("stop")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.mutations(), [["umount", self.target], ["umount", self.lower]])

    def test_stop_preserves_unrelated_lower(self):
        self.state["mounts"][self.lower] = {"FSTYPE": "ext4", "SOURCE": "/dev/other", "OPTIONS": "ro"}
        self.state["inodes"] = {self.lower: "2:200", self.target: "1:100"}
        self.assertNotEqual(self.run_mount("stop").returncode, 0)
        self.assertEqual(self.mutations(), [])

    def test_status_does_not_accept_arbitrary_mountpoint(self):
        self.state["mounts"][self.target] = {"FSTYPE": "tmpfs", "SOURCE": "tmpfs", "OPTIONS": "rw"}
        self.assertEqual(self.run_mount("status").returncode, 3)
        self.assertEqual(self.mutations(), [])


class InstallerSafety(unittest.TestCase):
    def test_check_reports_all_missing_commands(self):
        # Empty PATH forces missing dependencies. This used to exit at the first
        # `((issues++))` with `set -e`, hiding the rest of the report.
        result = subprocess.run(["/usr/bin/bash", str(ROOT / "install.sh"), "check"],
                                env=dict(os.environ, PATH="/nonexistent"), text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        for command in ("makepkg", "cargo", "git", "sing-box", "openssl"):
            self.assertIn(f"{command}: missing", result.stdout)

    def test_help_is_safe_without_root_or_tools(self):
        result = subprocess.run(["/usr/bin/bash", str(ROOT / "install.sh"), "help"],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("preserve /var/lib/mimic-node", result.stdout)


class IsolatedOverlayIntegration(unittest.TestCase):
    def test_real_overlay_in_private_user_and_mount_namespace(self):
        probe = subprocess.run(["unshare", "-Urnm", "true"], capture_output=True, text=True)
        if probe.returncode != 0:
            self.skipTest(f"Unprivileged user/mount namespaces unavailable: {probe.stderr.strip()}")
        scratch = ROOT / ".maintenance"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="overlay-integration-", dir=scratch) as temporary:
            base = Path(temporary)
            paths = {
                "/etc/sing-box": base / "etc/sing-box",
                "/var/lib/mimic-node": base / "var/lib/mimic-node",
                "/run/mimic-node": base / "run/mimic-node",
                "/usr/share/mimic-node/default": base / "usr/share/mimic-node/default",
            }
            target = paths["/etc/sing-box"]
            defaults = paths["/usr/share/mimic-node/default"]
            target.mkdir(parents=True)
            defaults.mkdir(parents=True)
            (target / "config.json").write_text("original config\n")
            (defaults / "config.json").write_text("package config\n")
            (defaults / "fallback.txt").write_text("package fallback\n")
            script = (ROOT / "overlay/usr/bin/mimic-mount").read_text()
            for original, replacement in paths.items():
                script = script.replace(original, str(replacement))
            executable = base / "mimic-mount"
            executable.write_text(script)
            command = r'''
mount --make-rprivate /
bash "$1" start
bash "$1" status
test "$(cat "$2/config.json")" = 'original config'
test "$(cat "$2/fallback.txt")" = 'package fallback'
printf 'persistent change\n' > "$2/config.json"
bash "$1" stop
test "$(cat "$2/config.json")" = 'original config'
test "$(cat "$3/upper/config.json")" = 'persistent change'
bash "$1" start
test "$(cat "$2/config.json")" = 'persistent change'
bash "$1" stop
'''
            result = subprocess.run(
                ["unshare", "-Urnm", "/usr/bin/bash", "-euc", command, "overlay-test",
                 str(executable), str(target), str(paths["/var/lib/mimic-node"])],
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
