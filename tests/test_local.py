"""Local (Docker) mode: hardening flags, and that the original folder is never mounted."""

from pathlib import Path

from sandbox_scan.local import docker_argv


def test_docker_argv_is_hardened(tmp_path: Path) -> None:
    argv = docker_argv(tmp_path)
    assert argv[:3] == ["docker", "run", "--rm"]
    for flag in ("--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "--memory", "--user"):
        assert flag in argv
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert mounts == [f"{tmp_path}:/tmp/scan"]  # only our own temp dir, never the untrusted folder
