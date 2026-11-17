"""End-to-end: the inert attack fixture must be caught, by the scanner alone and through the real Docker path."""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from test_scanner import scan

EXPECTED = {
    "npm-lifecycle-script", "typosquat?", "git-dependency", "pkg-source-override", "setup-py-cmdclass",
    "vscode-autorun-task", "vscode-exec-setting", "devcontainer-initializeCommand", "devcontainer-lifecycle",
    "devcontainer-privileged", "direnv", "npmrc-script-shell", "python-autoload", "pipe-to-shell", "reverse-shell",
    "b64-pipe-shell", "chmod-exec-tmp", "b64-exec", "cred-paths", "env-exfil", "exfil-endpoint", "cryptominer",
    "persistence", "powershell-dl-exec", "trojan-source", "symlink-escape", "git-hook", "git-config-exec",
    "binary-executable",
}  # fmt: skip


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(str(p.relative_to(root)).encode())
        if p.is_symlink():
            h.update(str(p.readlink()).encode())
        elif p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def test_scanner_finds_every_planted_attack(malicious_project: Path) -> None:
    before = tree_hash(malicious_project)
    found = scan(malicious_project)
    assert found >= EXPECTED, f"missed: {sorted(EXPECTED - found)}"
    assert tree_hash(malicious_project) == before  # scanning only reads


def docker_up() -> bool:
    return bool(shutil.which("docker")) and subprocess.run(["docker", "info"], capture_output=True).returncode == 0


@pytest.mark.skipif(not docker_up(), reason="needs a running Docker daemon")
def test_cli_local_says_do_not_use(malicious_project: Path, tmp_path: Path) -> None:
    out = tmp_path / "report"
    before = tree_hash(malicious_project)
    r = subprocess.run(
        [sys.executable, "-c", "from sandbox_scan.cli import main; main()", str(malicious_project), "--local",
         "--out", str(out)],
        capture_output=True, text=True, timeout=1800,
    )  # fmt: skip
    assert r.returncode == 2, r.stdout + r.stderr
    rep = json.loads((out / "report.json").read_text())
    assert rep["verdict"] == "DO NOT USE"
    assert {f["rule"] for f in rep["findings"]} >= EXPECTED
    assert tree_hash(malicious_project) == before  # never modified, never mounted
