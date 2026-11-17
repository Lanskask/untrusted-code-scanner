"""Local (Docker) mode: hardening flags, and that the original folder is never mounted."""

import subprocess
from pathlib import Path

import pytest

from sandbox_scan import local
from sandbox_scan.local import docker_argv


def test_docker_argv_is_hardened(tmp_path: Path) -> None:
    argv = docker_argv(tmp_path, "n1")
    assert argv[:3] == ["docker", "run", "--rm"]
    assert argv[argv.index("--name") + 1] == "n1"
    for flag in ("--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "--memory", "--user"):
        assert flag in argv
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert mounts == [f"{tmp_path}:/tmp/scan"]  # only our own temp dir, never the untrusted folder


def test_timeout_kills_the_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if argv[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(argv, 1)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(local.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(local.subprocess, "run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        local.run_local(tmp_path, "true", timeout=1)
    name = calls[0][calls[0].index("--name") + 1]
    assert ["docker", "rm", "-f", name] in calls


def test_permission_denied_hints_at_shared_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(
        local.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "mkdir: Permission denied")
    )
    with pytest.raises(RuntimeError, match=r"\$HOME"):
        local.run_local(tmp_path, "true")
