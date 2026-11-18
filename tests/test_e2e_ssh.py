"""--host mode end to end against a throwaway sshd container on 127.0.0.1 (no cloud account, no cost)."""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from test_e2e import docker_up

SSHD_DIR = Path(__file__).parent / "sshd"


@pytest.mark.e2e
@pytest.mark.skipif(not docker_up() or not shutil.which("ssh-keygen"), reason="needs Docker and ssh-keygen")
def test_cli_host_mode_over_ssh(malicious_project: Path, tmp_path: Path) -> None:
    key = tmp_path / "id"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    subprocess.run(["docker", "build", "-q", "-t", "sandbox-scan-sshd-test", str(SSHD_DIR)], check=True)
    cid = subprocess.run(
        ["docker", "run", "-d", "--rm", "-p", "127.0.0.1::22", "-e", f"AUTH_KEY={key.with_suffix('.pub').read_text()}",
         "sandbox-scan-sshd-test"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip
    try:
        port = subprocess.run(["docker", "port", cid, "22/tcp"], capture_output=True, text=True, check=True).stdout
        port = port.strip().splitlines()[0].rsplit(":", 1)[1]
        time.sleep(2)
        out = tmp_path / "report"
        r = subprocess.run(
            [sys.executable, "-c", "from sandbox_scan.cli import main; main()", str(malicious_project),
             "--host", "root@127.0.0.1", "--port", port, "--key", str(key), "--out", str(out)],
            capture_output=True, text=True, timeout=1800,
        )  # fmt: skip
        assert r.returncode == 2, r.stdout + r.stderr
        assert json.loads((out / "report.json").read_text())["verdict"] == "DO NOT USE"
    finally:
        subprocess.run(["docker", "rm", "-f", cid], capture_output=True)
