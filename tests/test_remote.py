"""Provisioner cleanup and CLI argument checks."""

import subprocess
import sys
from pathlib import Path

import pytest

from sandbox_scan import cli, remote


def test_destroy_deletes_droplet_even_if_create_failed_after_it_existed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        out = "42\n" if argv[:4] == ["doctl", "compute", "droplet", "list"] else ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    monkeypatch.setattr(remote.shutil, "which", lambda _: "/usr/bin/doctl")
    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    do = remote.DigitalOcean(tmp_path, "nyc1", "s-1vcpu-1gb")
    do.ssh_key_id = "7"  # create() got this far, then the droplet call failed with droplet_id still unset
    do.destroy()
    assert ["doctl", "compute", "droplet", "delete", "-f", "42"] in calls
    assert ["doctl", "compute", "ssh-key", "delete", "-f", "7"] in calls


@pytest.mark.parametrize("argv", [["x"], ["x", "--host", "h"], ["x", "--host", "h", "--provision", "digitalocean"]])
def test_cli_rejects_bad_args(argv: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["sandbox-scan", str(tmp_path), *argv[1:]])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code not in (0, None)


def test_destroy_reports_a_failed_delete_instead_of_claiming_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1 if "delete" in argv else 0, "", "403 forbidden")

    monkeypatch.setattr(remote.shutil, "which", lambda _: "/usr/bin/doctl")
    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    do = remote.DigitalOcean(tmp_path, "nyc1", "s-1vcpu-1gb")
    do.droplet_id = "42"
    do.destroy()
    out = capsys.readouterr().out
    assert "destroyed droplet" not in out
    assert "doctl compute droplet delete 42" in out  # tells the user the exact command to stop billing
