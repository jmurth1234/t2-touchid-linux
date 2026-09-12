#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PamAssetTests(unittest.TestCase):
    def test_installer_manages_both_omarchy_lock_stacks(self):
        installer = (ROOT / "tools/install-pam.sh").read_text()

        self.assertIn("install_one omarchy-lock-password", installer)
        self.assertIn("install_one omarchy-lock-fingerprint", installer)
        self.assertIn("install_system_auth_hook", installer)
        self.assertIn("system-auth.original", installer)
        self.assertIn("pam_faillock\\.so[[:space:]]+authfail", installer)
        self.assertIn("pam_faillock\\.so[[:space:]]+authsucc", installer)
        self.assertIn("authfail_line != unix_line + 1", installer)
        self.assertIn("$1.installed", installer)
        self.assertIn("mv -f -- \"$tmp\" \"$target\"", installer)
        self.assertIn("$backup_dir/$1.absent", installer)

    def test_rollback_restores_or_removes_every_managed_stack(self):
        rollback = (ROOT / "tools/rollback-pam.sh").read_text()

        self.assertIn(
            "sudo omarchy-lock-password omarchy-lock-fingerprint",
            rollback,
        )
        self.assertIn("system-auth.original", rollback)
        self.assertIn("removed == 2", rollback)
        self.assertIn("$backup_dir/$name.absent", rollback)
        self.assertIn('rm -f -- "$target"', rollback)
        self.assertIn('rm -f -- "$backup" "$absent" "$installed"', rollback)
        self.assertIn('rm -f -- "$absent" "$installed"', rollback)
        self.assertIn("Refusing to overwrite changed PAM stack", rollback)

    def test_unprivileged_omarchy_password_stack_has_no_root_helper(self):
        password_stack = (ROOT / "pam/omarchy-lock-password").read_text()

        self.assertNotIn("t2-pam-unlock", password_stack)
        self.assertIn("pam_unix.so try_first_pass", password_stack)

    def test_sudo_skips_fingerprint_until_keybags_are_ready(self):
        sudo_stack = (ROOT / "pam/sudo").read_text()

        self.assertIn("[success=3 default=ignore]", sudo_stack)
        self.assertIn("[success=ignore default=2]", sudo_stack)
        self.assertIn("t2-pam-fingerprint-ready", sudo_stack)
        self.assertNotIn("t2-pam-unlock", sudo_stack)

    def test_pam_unlock_prompts_separately_without_shell_storage(self):
        helper = (ROOT / "src/t2-pam-unlock.sh").read_text()

        self.assertIn('unlock-keybags "$session"', helper)
        self.assertIn("t2-pam-fingerprint-ready", helper)
        self.assertNotIn("read -r password", helper)
        self.assertNotIn("printf '%s\\n'", helper)
        aks_tool = (ROOT / "src/t2-aks-tool.c").read_text()
        unlock_secret = aks_tool[
            aks_tool.index("static int unlock_keybag_secret") :
            aks_tool.index("static int protect_secret_buffer")
        ]
        self.assertIn('exchange.sep_status == -5', unlock_secret)
        self.assertIn("macOS password was rejected", unlock_secret)
        self.assertIn("sudo t2-keybag-unlock to retry", aks_tool)
        self.assertIn("keybag-password-rejected", helper)
        installer = (ROOT / "tools/install-pam.sh").read_text()
        self.assertIn(
            "local hook='auth optional pam_exec.so quiet seteuid ", installer
        )

    def test_sudo_prompt_warns_against_early_password_input(self):
        prompt = (ROOT / "src/t2-pam-fingerprint-prompt.c").read_text()

        self.assertIn("Do not type your password until", prompt)

    def test_every_successful_unlock_path_publishes_readiness(self):
        for name in (
            "t2-keybag-unlock.sh",
            "t2-pam-unlock.sh",
            "t2-credential-unlock.sh",
        ):
            source = (ROOT / "src" / name).read_text()
            self.assertIn("keybags-unlocked", source)
            self.assertIn("keybag-password-rejected", source)
            self.assertIn("install -o root -g root -m 0600", source)
            normalized = source.upper()
            self.assertIn('CMP -S -- "$SNAPSHOT" "$STATE_FILE"', normalized)
            self.assertIn('MV -F -- "$SNAPSHOT" "$READY_FILE"', normalized)

        loader = (ROOT / "src/t2-keybag-load.sh").read_text()
        self.assertIn('rm -f -- "$READY_FILE"', loader)

    def test_manual_unlock_refreshes_only_an_active_fprintd(self):
        helper = (ROOT / "src/t2-keybag-unlock.sh").read_text()

        self.assertIn("systemctl try-restart --no-block fprintd.service", helper)
        self.assertIn("systemd-ask-password", helper)
        self.assertIn("unlock-keybags-stdin", helper)
        self.assertNotIn('read -r password', helper)

    def test_interactive_unlock_service_is_bounded_and_hardened(self):
        service = (ROOT / "systemd/system/t2-interactive-unlock.service").read_text()
        fprintd = (ROOT / "systemd/system/fprintd.service").read_text()

        self.assertIn("Requires=t2-keybag-load.service", service)
        self.assertIn("ConditionPathExists=!/etc/credstore.encrypted/", service)
        self.assertIn("TimeoutStartSec=150", service)
        self.assertIn("LimitCORE=0", service)
        self.assertIn("LimitMEMLOCK=65536", service)
        self.assertIn("ReadWritePaths=/run/t2-touchid", service)
        self.assertIn("DevicePolicy=closed", service)
        self.assertIn("DeviceAllow=/dev/t2-aks rw", service)
        self.assertNotIn("Wants=t2-touchid-post-reboot.service t2-interactive-unlock.service", fprintd)
        self.assertNotIn("t2-interactive-unlock.service", fprintd.split("After=", 1)[1])
        install = (ROOT / "install.sh").read_text()
        self.assertNotIn("enable t2-interactive-unlock.service", install)
        self.assertIn("disable --now t2-interactive-unlock.service", install)
        self.assertIn("t2-interactive-unlock", (ROOT / "uninstall.sh").read_text())


if __name__ == "__main__":
    unittest.main()
