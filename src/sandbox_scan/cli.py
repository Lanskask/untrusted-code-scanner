"""Command-line entry point."""

import argparse
import atexit
import datetime
import shutil
import sys
import tempfile
from importlib import resources
from pathlib import Path

from .local import run_local
from .pack import pack
from .remote import DigitalOcean, Remote
from .report import merge_findings, read_results, render, verdict
from .textutil import clean, log


def _asset(name: str) -> str:
    """Read a file shipped inside the package (the code that runs on the VM)."""
    return resources.files("sandbox_scan").joinpath(name).read_text(encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="folder with the untrusted codebase")
    ap.add_argument("--host", help="user@host of a FRESH, DISPOSABLE VM you already created")
    ap.add_argument("--key", help="dedicated SSH private key for that VM (required with --host)")
    ap.add_argument("--local", action="store_true", help="scan in a hardened local Docker container (free)")
    ap.add_argument("--provision", choices=["digitalocean"], help="create + destroy a throwaway VM for you")
    ap.add_argument("--port", type=int, help="ssh port of --host (default 22)")
    ap.add_argument("--region", help="--provision only (default nyc1)")
    ap.add_argument("--size", help="--provision only (default s-2vcpu-4gb)")
    ap.add_argument("--keep", action="store_true", help="do not destroy the provisioned VM afterwards")
    ap.add_argument("--out", help="report output dir (default ./scan-report-<timestamp>)")
    ap.add_argument("--max-mb", type=int, default=500)
    a = ap.parse_args()

    src = Path(a.path).resolve()
    if not src.is_dir():
        sys.exit("path must be a directory")
    if bool(a.host) + bool(a.provision) + a.local != 1:
        sys.exit("choose exactly one of --local, --host or --provision")
    if a.host and not a.key:
        sys.exit("--key is required with --host (use a dedicated throwaway key, not your real one)")

    for flag, val, ok in (
        ("--key", a.key, a.host),
        ("--port", a.port, a.host),
        ("--region", a.region, a.provision),
        ("--size", a.size, a.provision),
        ("--keep", a.keep, a.provision),
    ):
        if val and not ok:
            sys.exit(f"{flag} has no effect with the chosen mode; remove it")

    out_dir = Path(a.out or f"scan-report-{datetime.datetime.now():%Y%m%d-%H%M%S}")
    # Docker VMs (Colima, Docker Desktop) share only $HOME with containers, not the system temp dir.
    base = Path.home() / ".cache" / "sandbox_scan" if a.local else None
    if base:
        base.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="sandbox_scan_", dir=base))
    atexit.register(shutil.rmtree, tmp, True)
    provider = None

    try:
        log(f"[1/5] Packing {src} ...")
        size = pack(src, tmp / "code.tgz", a.max_mb)
        log(f"      {size / 1e6:.1f} MB of files packed")
        (tmp / "scanner.py").write_text(_asset("remote_scanner.py"))
        (tmp / "known_hosts").touch()

        if a.local:
            log("[2/5] Local Docker scan (network on only for pip/semgrep rules; your folder is never mounted) ...")
            log("[4/5] Scanning (first run pulls the image and installs semgrep, a few minutes) ...")
            res = read_results(run_local(tmp, _asset("remote_driver.sh")))
        else:
            if a.provision:
                log("[2/5] Creating disposable DigitalOcean droplet ...")
                provider = DigitalOcean(tmp, a.region or "nyc1", a.size or "s-2vcpu-4gb")
                host = provider.create()
                key = provider.key
            else:
                host, key = a.host, a.key
                log("[2/5] Using your VM " + clean(host) + " - make sure it is fresh and holds no credentials.")

            rem = Remote(host, key, tmp, a.port or 22)
            log("[3/5] Waiting for SSH ...")
            rem.wait_ready()
            rem.ssh("mkdir -p /tmp/scan")
            log("[4/5] Uploading and scanning (semgrep install can take a couple of minutes) ...")
            rem.put(tmp / "code.tgz", "/tmp/scan/code.tgz")
            rem.put(tmp / "scanner.py", "/tmp/scan/scanner.py")
            r = rem.ssh("bash -s", stdin=_asset("remote_driver.sh"), timeout=3600)
            if r.returncode != 0:
                raise RuntimeError("remote scan failed: " + clean(r.stderr[-800:]))
            rem.get("/tmp/scan/results.tgz", tmp / "results.tgz")

            res = read_results(tmp / "results.tgz")
    except Exception as e:
        log(f"\nERROR: {e}")
        res = None
    finally:
        if provider and not a.keep:
            provider.destroy()
        elif provider and a.keep:
            log(
                f"[keep] droplet {provider.droplet_id} left running - DESTROY IT YOURSELF: "
                f"doctl compute droplet delete -f {provider.droplet_id}"
            )

    if res is None:
        sys.exit(3)
    log("[5/5] Building report ...")
    findings, stats, notes, status = merge_findings(res)
    label, rc = verdict(findings, notes)
    render(findings, stats, notes, status, label, out_dir)
    if a.host:
        log("\nReminder: destroy your throwaway VM now.")
    sys.exit(rc)


if __name__ == "__main__":
    main()
