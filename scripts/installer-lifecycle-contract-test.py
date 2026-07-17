#!/usr/bin/env python3
"""Validate the installer-generated daemon lifecycle contract."""

from __future__ import annotations

import subprocess
import tempfile
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "hincyray-install.sh"
GUIDE = ROOT / "AGENTS.md"
HEREDOC_START = 'cat > "${STAGING}/etc/init.d/S99hincyray" << \'INITEOF\'\n'
HEREDOC_END = "\nINITEOF"


def generated_init(installer: str) -> str:
    try:
        start = installer.index(HEREDOC_START) + len(HEREDOC_START)
        end = installer.index(HEREDOC_END, start)
    except ValueError as error:
        raise AssertionError("cannot locate generated S99hincyray heredoc") from error
    script = installer[start:end]
    assert script.startswith("#!/bin/sh\n"), "generated init script has no shebang"
    return script


def require(text: str, markers: list[str], scope: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    assert not missing, f"{scope} is missing lifecycle markers: {missing}"


def main() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    guide = GUIDE.read_text(encoding="utf-8")
    init = generated_init(installer)

    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as file:
        file.write(init)
        generated_path = Path(file.name)
    try:
        subprocess.run(["sh", "-n", str(INSTALLER)], check=True)
        subprocess.run(["sh", "-n", str(generated_path)], check=True)
    finally:
        generated_path.unlink(missing_ok=True)

    require(
        init,
        [
            "daemon_pid() {",
            "daemon_identity() {",
            "acquire_lock() {",
            "LOCKDIR=/opt/var/run/hincyray.lifecycle.lock",
            'HINCYRAY_LIFECYCLE_OWNER',
            '[ -r "$PIDFILE" ] || return 1',
            'kill -0 "$pid" 2>/dev/null || return 1',
            '[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$DAEMON" ] || return 1',
            'nohup "$DAEMON" </dev/null >>"$LOGFILE" 2>&1 &',
            'api/core/start',
            'if PID="$(daemon_pid)"; then',
            'rm -f "$PIDFILE"',
        ],
        "generated init script",
    )
    require(
        installer,
        [
            'OLD_PID="$(cat "$PID_FILE" 2>/dev/null)"',
            'readlink "/proc/$OLD_PID/exe"',
            'HINCYRAY_LIFECYCLE_OWNER=$$ "$INIT_SCRIPT" stop',
            'process_is_daemon "$OLD_PID" && die "Existing daemon did not stop"',
            "begin_transaction() {",
            "commit_transaction() {",
            "do_rollback() {",
            '[ "$DAEMON_WAS_RUNNING" -eq 1 ]',
            'trap \'on_exit $?\' EXIT',
            'process_is_daemon "$NEW_PID"',
            'register_runtime_tree',
            'acquire_transaction_lock',
            'release_transaction_lock',
            'VERSION="0.21.6"',
            'HINCYRAY_GITHUB_TOKEN',
            'github_get() {',
            'api.github.com/repos/DurkaEbanaya/HincyRay/releases/tags/v${VERSION}',
            'select(.name == "hincyray")',
            'application/octet-stream',
            'raw.githubusercontent.com/DurkaEbanaya/HincyRay/v${VERSION}/scripts/wifi-segment-setup.sh',
            'Required dependencies unavailable after opkg install',
        ],
        "installer commit path",
    )
    require(
        guide,
        [
            "/opt/etc/init.d/S99hincyray start|stop|restart|status",
            "Never stop HincyRay with `pgrep -f`",
        ],
        "router operations guide",
    )

    forbidden = [
        r"\bpgrep\s+-[A-Za-z]*f\b",
        r"\bpkill\s+-[A-Za-z]*f\b",
        r"\bkillall\s+hincyray\b",
        r"\bpidof\s+hincyray\b",
    ]
    code_hits = [pattern for pattern in forbidden if re.search(pattern, installer) or re.search(pattern, init)]
    assert not code_hits, f"process-name lifecycle control is forbidden: {code_hits}"
    assert "remove_legacy()" not in installer, "foreign package state must not be mutated inside the HincyRay transaction"
    stop_index = installer.index('HINCYRAY_LIFECYCLE_OWNER=$$ "$INIT_SCRIPT" stop')
    runtime_snapshot_index = installer.index("register_runtime_tree", stop_index)
    assert stop_index < runtime_snapshot_index, "runtime state must be snapshotted after the daemon stops"

    print("installer lifecycle contract ok")


if __name__ == "__main__":
    main()
