"""ssh/scp transport and the optional DigitalOcean provisioner."""

import datetime
import shutil
import subprocess
import time
from pathlib import Path

from .textutil import clean, log


class Remote:
    def __init__(self, host: str, key: str | Path, tmp: str | Path) -> None:
        self.host = host
        self.opts = [
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={tmp}/known_hosts",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=30",
            "-i",
            str(key),
        ]

    def ssh(
        self, command: str, stdin: str | None = None, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["ssh", *self.opts, self.host, command], input=stdin, text=True, capture_output=True, timeout=timeout
        )

    def put(self, local: str | Path, remote: str) -> None:
        r = subprocess.run(
            ["scp", "-q", *self.opts, str(local), f"{self.host}:{remote}"], capture_output=True, text=True
        )
        if r.returncode:
            raise RuntimeError("scp upload failed: " + clean(r.stderr))

    def get(self, remote: str, local: str | Path) -> None:
        r = subprocess.run(
            ["scp", "-q", *self.opts, f"{self.host}:{remote}", str(local)], capture_output=True, text=True
        )
        if r.returncode:
            raise RuntimeError("scp download failed: " + clean(r.stderr))

    def wait_ready(self, attempts: int = 40) -> None:
        for _ in range(attempts):
            r = self.ssh("echo ok", timeout=30)
            if r.returncode == 0 and "ok" in r.stdout:
                return
            time.sleep(8)
        raise RuntimeError("VM never became reachable over SSH")


# --------------------------------------------------------------------------- #
# DigitalOcean provisioning (via doctl). Optional.
# --------------------------------------------------------------------------- #
class DigitalOcean:
    def __init__(self, tmp: str | Path, region: str, size: str) -> None:
        if not shutil.which("doctl"):
            raise SystemExit("doctl not found. Install it and run `doctl auth init`, or use --host.")
        self.tmp, self.region, self.size = Path(tmp), region, size
        self.key = self.tmp / "ephemeral_ed25519"
        self.droplet_id: str | None = None
        self.ssh_key_id: str | None = None
        self.name = "scan-" + datetime.datetime.now(datetime.UTC).strftime("%Y%m%d%H%M%S")

    def _doctl(self, *a: str) -> str:
        r = subprocess.run(["doctl", *a], capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError("doctl " + " ".join(a[:3]) + " failed: " + clean(r.stderr))
        return r.stdout.strip()

    def create(self) -> str:
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        self.ssh_key_id = self._doctl(
            "compute",
            "ssh-key",
            "import",
            self.name,
            "--public-key-file",
            f"{self.key}.pub",
            "--format",
            "ID",
            "--no-header",
        )
        out = self._doctl(
            "compute",
            "droplet",
            "create",
            self.name,
            "--image",
            "ubuntu-24-04-x64",
            "--size",
            self.size,
            "--region",
            self.region,
            "--ssh-keys",
            self.ssh_key_id,
            "--wait",
            "--format",
            "ID,PublicIPv4",
            "--no-header",
        )
        self.droplet_id, ip = out.split()[:2]
        return f"root@{ip}"

    def destroy(self) -> None:
        if not self.droplet_id and self.ssh_key_id:
            # create() may have died after the droplet existed (e.g. --wait timeout): find it by its unique name.
            found = self._doctl("compute", "droplet", "list", self.name, "--format", "ID", "--no-header").split()
            self.droplet_id = found[0] if found else None
        if self.droplet_id:
            subprocess.run(["doctl", "compute", "droplet", "delete", "-f", self.droplet_id], capture_output=True)
            log(f"[cleanup] destroyed droplet {self.droplet_id}")
            self.droplet_id = None
        if self.ssh_key_id:
            subprocess.run(["doctl", "compute", "ssh-key", "delete", "-f", self.ssh_key_id], capture_output=True)
            self.ssh_key_id = None
