"""Run the same scan inside a hardened local Docker container (no cloud account, no cost)."""

import os
import shutil
import subprocess
from pathlib import Path

IMAGE = "python:3.12-slim"


def docker_argv(tmp: Path) -> list[str]:
    """Build the `docker run` command. Only `tmp` (our tarball + scanner) is mounted, never the untrusted folder."""
    return [
        "docker", "run", "--rm", "-i",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "512", "--memory", "2g",
        "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp/scan",
        "-v", f"{tmp}:/tmp/scan", "-w", "/tmp/scan",
        IMAGE, "bash", "-s",
    ]  # fmt: skip


def run_local(tmp: Path, driver: str) -> Path:
    """Run the bash driver in the container; return the path of results.tgz written into `tmp`."""
    if not shutil.which("docker"):
        raise SystemExit("docker not found. Install Docker Desktop/Colima, or use --host / --provision.")
    r = subprocess.run(docker_argv(tmp), input=driver, text=True, capture_output=True, timeout=3600)
    if r.returncode != 0:
        raise RuntimeError("local scan failed: " + r.stderr[-800:])
    return tmp / "results.tgz"
