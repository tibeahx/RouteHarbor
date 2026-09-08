#!/usr/bin/env python3
"""Host-safe checks: source procd scripts with disabled config and verify contracts.

Actual package installation and boot behavior are separate OpenWrt acceptance tests.
This suite never creates router paths or invokes network commands.
"""
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FILES = ROOT / "packaging/openwrt/openrhp/files"

class PackagingTests(unittest.TestCase):
    def test_shell_syntax(self):
        paths = list(FILES.glob("*.init")) + [FILES / "openrhp-setup", FILES / "openrhp-node-setup", ROOT / "scripts/sdk-build.sh"]
        for path in paths:
            with self.subTest(path=path.name):
                subprocess.run(["sh", "-n", str(path)], check=True)

    def test_disabled_gateway_and_node_make_no_changes(self):
        for name in ("openrhp.init", "openrhp-node.init"):
            with self.subTest(role=name), tempfile.TemporaryDirectory() as temp:
                trace = pathlib.Path(temp) / "trace"
                harness = '''
set -eu
config_load() { :; }
config_get_bool() { enabled=0; }
config_get() { echo unexpected-config >> "$TRACE"; }
procd_open_instance() { echo unexpected-process >> "$TRACE"; }
mkdir() { echo unexpected-directory >> "$TRACE"; }
chown() { echo unexpected-owner >> "$TRACE"; }
chmod() { echo unexpected-permissions >> "$TRACE"; }
uci() { echo unexpected-uci >> "$TRACE"; }
. "$INIT"
start_service
'''
                import os
                env = dict(os.environ, TRACE=str(trace), INIT=str(FILES / name))
                subprocess.run(["sh", "-c", harness], check=True, env=env)
                self.assertFalse(trace.exists(), trace.read_text() if trace.exists() else "")

    def test_privilege_and_durability_boundaries(self):
        core = (FILES / "openrhp.init").read_text()
        node = (FILES / "openrhp-node.init").read_text()
        guard = (FILES / "openrhp-guard.init").read_text()
        self.assertIn("procd_set_param user openrhp\n", core)
        self.assertIn("procd_set_param user openrhp-node\n", node)
        self.assertIn("--state /etc/openrhp", core)
        self.assertIn("--state-dir /etc/openrhp-helper", guard)
        self.assertLess(guard.index("quarantine --state-dir"), guard.index("procd_open_instance"))
        self.assertIn("START=18", guard)
        self.assertNotIn("--development", core)

    def test_setup_cannot_mutate_user_network_uci_or_chown_a_tree(self):
        for name in ("openrhp-setup", "openrhp-node-setup"):
            text = (FILES / name).read_text()
            self.assertNotIn("chown -R", text)
            self.assertIn('"$(id -u)" -eq 0', text)
            self.assertNotRegex(text, r"uci\s+(set|delete|commit)\s+(network|wireless|firewall|dhcp)\b")
            self.assertNotIn("curl", text)
            self.assertNotIn("wget", text)

    def test_recipe_retains_guard_and_leaves_package_format_to_sdk(self):
        recipe = (FILES.parent / "Makefile").read_text()
        self.assertIn("DEPENDS:=+openrhp-guard", recipe)
        self.assertIn("Package/openrhp-guard/prerm", recipe)
        self.assertIn("can-remove --state-dir /etc/openrhp-helper", recipe)
        self.assertIn("go1.27.1", recipe)
        self.assertIn("GOPROXY=off", recipe)
        script = (ROOT / "scripts/sdk-build.sh").read_text()
        self.assertNotRegex(script, r"\b(curl|wget)\b")
        self.assertIn("Refusing to replace an existing foreign SDK package directory", script)
        self.assertNotIn("ar r", script)

if __name__ == "__main__":
    unittest.main()
