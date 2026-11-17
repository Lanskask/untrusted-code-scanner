"""Run the same scan inside a hardened local Docker container (no cloud account, no cost)."""

import os
import shutil
import subprocess
from pathlib import Path

# Pinned by digest so a moved tag cannot swap the scanning environment (python:3.12-slim, pulled 2026-11-17).
IMAGE = "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"


def docker_argv(tmp: Path, name: str) -> list[str]:
    """Build the `docker run` command. Only `tmp` (our tarball + scanner) is mounted, never the untrusted folder."""
    return [
        "docker", "run", "--rm", "-i", "--name", name,
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "512", "--memory", "2g",
        "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp/scan",
        "-v", f"{tmp}:/tmp/scan", "-w", "/tmp/scan",
        IMAGE, "bash", "-s",
    ]  # fmt: skip


def run_local(tmp: Path, driver: str, timeout: int = 3600) -> Path:
    """Run the bash driver in the container; return the path of results.tgz written into `tmp`."""
    if not shutil.which("docker"):
        raise SystemExit("docker not found. Install Docker Desktop/Colima, or use --host / --provision.")
    name = f"sandbox-scan-{os.getpid()}"
    try:
        r = subprocess.run(docker_argv(tmp, name), input=driver, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # killing the docker client does not stop the container; remove it so it does not run on
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        raise
    if r.returncode != 0:
        hint = " (the Docker VM must share $HOME read-write)" if "Permission denied" in r.stderr else ""
        raise RuntimeError("local scan failed" + hint + ": " + r.stderr[-800:])
    return tmp / "results.tgz"
