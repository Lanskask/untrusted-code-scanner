"""Rules the tool must never break. Each one fails loudly if a later change violates it."""

import ast
import tarfile
from pathlib import Path

import pytest

from sandbox_scan import remote
from sandbox_scan.local import docker_argv
from sandbox_scan.pack import pack
from sandbox_scan.report import merge_findings, verdict
from sandbox_scan.textutil import clean

SRC = Path(__file__).parent.parent / "src" / "sandbox_scan"
HOST_FILES = [p for p in SRC.glob("*.py") if p.name != "remote_scanner.py"]  # that one runs only in the sandbox


def calls(path: Path) -> list[ast.Call]:
    return [n for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, ast.Call)]


@pytest.mark.parametrize("path", HOST_FILES, ids=lambda p: p.name)
def test_host_code_never_evals_or_uses_a_shell(path: Path) -> None:
    for c in calls(path):
        name = ast.unparse(c.func)
        assert name not in {"eval", "exec", "compile", "os.system", "os.popen", "__import__"}, f"{name} in {path.name}"
        assert not any(k.arg == "shell" and ast.unparse(k.value) != "False" for k in c.keywords), path.name


def test_sandbox_scanner_never_runs_processes_or_opens_sockets() -> None:
    tree = ast.parse((SRC / "remote_scanner.py").read_text())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not imported & {"subprocess", "socket", "urllib", "http", "importlib", "ctypes", "pickle", "marshal"}
    names = {ast.unparse(c.func) for c in calls(SRC / "remote_scanner.py")}
    assert not names & {"eval", "exec", "compile", "os.system", "__import__"}


def test_docker_never_mounts_the_untrusted_folder(tmp_path: Path) -> None:
    argv = docker_argv(tmp_path / "ours", "n")
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "-v"] == [f"{tmp_path / 'ours'}:/tmp/scan"]
    assert not {"--privileged", "--network=host", "--pid=host", "-p", "--publish"} & set(argv)
    assert not any("docker.sock" in a for a in argv)
    assert "@sha256:" in argv[-3]  # image pinned by digest


def test_ssh_is_isolated(tmp_path: Path) -> None:
    argv = " ".join(remote.Remote("u@h", "k", tmp_path).opts)
    for need in ("-F /dev/null", "IdentityAgent=none", "ForwardAgent=no", "IdentitiesOnly=yes", "BatchMode=yes"):
        assert need in argv


def test_pack_never_follows_symlinks_or_ships_special_files(tmp_path: Path) -> None:
    src = tmp_path / "s"
    src.mkdir()
    (src / "link").symlink_to("/etc/hostname")
    pack(src, tmp_path / "o.tgz", 10)
    with tarfile.open(tmp_path / "o.tgz") as tf:
        member = tf.getmember("code/link") if "code/link" in tf.getnames() else tf.getmember("link")
        assert member.issym()  # stored as a link, content of /etc/hostname never copied


@pytest.mark.parametrize("ch", [chr(c) for c in [*range(0, 9), *range(11, 32), 127, 0x9B, 0x202E, 0x2066]])
def test_clean_removes_every_terminal_control_char(ch: str) -> None:
    assert ch not in clean(f"a{ch}b")


def test_fail_closed_when_results_are_missing() -> None:
    findings, _, notes, _ = merge_findings({})
    assert verdict(findings, notes)[0] == "INCONCLUSIVE - SCAN INCOMPLETE"  # silence is never "clean"


@pytest.mark.parametrize("notes", [[], ["scan INCOMPLETE"]])
def test_critical_always_wins(notes: list[str]) -> None:
    assert verdict([{"severity": "CRITICAL"}], notes) == ("DO NOT USE", 2)
