#!/usr/bin/env python3
"""
sandbox_scan.py - ship an UNTRUSTED codebase to a DISPOSABLE VM, scan it there
(static analysis only, nothing from the codebase is ever executed), pull back
a report, destroy the VM, and tell you what to do next.

Two ways to get a VM:

  A) Bring your own throwaway VM (any provider, fresh Ubuntu 22.04/24.04):
       ./sandbox_scan.py ./suspicious-code --host root@203.0.113.7 --key ~/.ssh/throwaway_ed25519

  B) Let the script create + destroy a DigitalOcean droplet (needs `doctl`
     authenticated, ideally against a separate team/project with nothing else in it):
       ./sandbox_scan.py ./suspicious-code --provision digitalocean

Safety properties:
  * Local machine only READS the folder and writes one tar.gz to a temp dir.
  * ssh/scp run with `-F /dev/null`, no agent, no forwarding, a dedicated key.
  * Remote side only scans (regex heuristics + semgrep + guarddog). It never
    runs, installs, builds or imports anything from the codebase.
  * Only a tar of JSON reports comes back; it is read in memory, never extracted.
  * Everything printed is stripped of control chars (hostile files can contain
    terminal escape sequences).

No scanner can PROVE code is safe. A clean result means "no known red flags".
"""
import argparse
import atexit
import datetime
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

# --------------------------------------------------------------------------- #
# Remote scanner (stdlib only; runs on the VM, never on your machine)
# --------------------------------------------------------------------------- #
REMOTE_SCANNER = r'''
import os, re, sys, json, stat
try:
    import tomllib
except Exception:
    tomllib = None

ROOT = os.path.abspath(sys.argv[1])
findings, per_file, per_rule = [], {}, {}
suppressed = {}
stats = {"files": 0, "text_files": 0, "binary_files": 0, "symlinks": 0, "skipped_large": 0}

def add(sev, rule, rel, line, detail, snippet=""):
    kf, kr = (rule, rel), rule
    per_file[kf] = per_file.get(kf, 0) + 1
    per_rule[kr] = per_rule.get(kr, 0) + 1
    if per_file[kf] > 5 or per_rule[kr] > 60:
        suppressed[rule] = suppressed.get(rule, 0) + 1
        return
    findings.append({"severity": sev, "rule": rule, "file": rel, "line": line,
                     "detail": detail, "snippet": snippet.strip()[:200]})

CODE_EXT = {".py",".js",".mjs",".cjs",".ts",".tsx",".jsx",".sh",".bash",".zsh",".ps1",".psm1",
            ".bat",".cmd",".rb",".php",".pl",".go",".rs",".java",".kt",".cs",".lua",".vbs"}
CODE_NAMES = {"Makefile","makefile","Dockerfile","justfile","Rakefile","Gemfile","Taskfile.yml"}

# (rule id, severity, regex, description, code_only)
LINE_RULES = [
 ("pipe-to-shell","CRITICAL",r"(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b","downloads and pipes to a shell",False),
 ("b64-exec","CRITICAL",r"\b(eval|exec)\s*\(\s*(base64\.b64decode|atob|Buffer\.from|codecs\.decode|zlib\.decompress|bytes\.fromhex)","executes decoded/obfuscated payload",False),
 ("b64-pipe-shell","CRITICAL",r"base64\s+(-d|--decode)[^\n]{0,120}\|\s*(ba|z|da)?sh\b","decodes base64 into a shell",False),
 ("py-exec-compile","CRITICAL",r"\bexec\s*\(\s*(compile|marshal\.loads)\b","exec of compiled/marshalled code",False),
 ("reverse-shell","CRITICAL",r"/dev/tcp/|bash\s+-i\s*>&|\bnc(at)?\s+(-\w+\s+)*-e\s|pty\.spawn\s*\(|os\.dup2\s*\([^)]*fileno","reverse-shell pattern",False),
 ("powershell-dl-exec","CRITICAL",r"(DownloadString|DownloadFile|Invoke-WebRequest|iwr)\b[^\n]{0,200}(IEX|Invoke-Expression)|(IEX|Invoke-Expression)[^\n]{0,200}(DownloadString|Net\.WebClient)","PowerShell download-and-execute",False),
 ("powershell-enc","HIGH",r"powershell[^\n]{0,80}(\s-enc\b|-encodedcommand|-w(indowstyle)?\s+hidden)","encoded/hidden PowerShell",False),
 ("cred-paths","HIGH",r"(\.ssh/(id_[a-z0-9]+|authorized_keys)|\.aws/credentials|\.git-credentials|\.docker/config\.json|\.kube/config|\.config/gcloud|Login Data|wallet\.dat|Local Storage/leveldb|Cookies\.sqlite|logins\.json|\.bash_history)","touches credential / browser / wallet paths",False),
 ("env-exfil","HIGH",r"(os\.environ|process\.env|getenv)[^\n]{0,160}(requests\.(post|get|put)|urlopen|urllib|fetch\(|axios|http\.request|XMLHttpRequest)|(requests\.(post|get|put)|urlopen|fetch\(|axios|http\.request|XMLHttpRequest)[^\n]{0,160}(os\.environ|process\.env|getenv)","env vars sent over network",False),
 ("exfil-endpoint","HIGH",r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|transfer\.sh|ngrok(-free)?\.(io|app|dev)|webhook\.site|requestbin|interact\.sh|oast\.(pro|live|site|fun|me)|burpcollaborator","known exfil / callback endpoint",False),
 ("cryptominer","HIGH",r"xmrig|stratum\+tcp|cryptonight|minerd\b|nicehash","cryptominer indicator",False),
 ("trojan-source","HIGH",r"[‪-‮⁦-⁩]","bidirectional Unicode control char (Trojan Source)",False),
 ("chmod-exec-tmp","HIGH",r"chmod\s+(\+x|[0-7]*7[0-7]*)\s+/(tmp|var/tmp|dev/shm)/","makes a file in /tmp executable",False),
 ("persistence","HIGH",r"(crontab\s+-|/etc/cron|\.bashrc|\.zshrc|\.profile\b|LaunchAgents|systemctl\s+enable|schtasks|CurrentVersion\\Run)","persistence mechanism",True),
 ("service-key-prefix","MEDIUM",r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)","embedded secret/key (leaked, or a lure)",False),
 ("dyn-exec","MEDIUM",r"\b(eval|exec)\s*\(|\bnew\s+Function\s*\(|\b__import__\s*\(","dynamic code execution",True),
 ("proc-spawn","MEDIUM",r"\bos\.system\s*\(|subprocess\.(Popen|run|call|check_output|check_call)|child_process|Runtime\.getRuntime\(\)\.exec|\bShell\.Execute|\bsystem\s*\(","spawns processes",True),
 ("hardcoded-ip-url","MEDIUM",r"https?://\d{1,3}(\.\d{1,3}){3}","URL to a raw IP address",False),
 ("long-b64-blob","MEDIUM",r"[A-Za-z0-9+/=]{400,}","very long base64-like blob",False),
 ("zero-width","MEDIUM",r"[​-‍⁠﻿]","zero-width characters in text",True),
 ("pkg-source-override","MEDIUM",r"(--extra-index-url|--index-url|--trusted-host|^\s*registry\s*=|^\s*@[\w-]+:registry\s*=)","package source override",False),
 ("git-dependency","MEDIUM",r"(git\+(https?|ssh)://|git://|\"github:)","dependency pulled straight from git",False),
]
LINE_RULES = [(i, s, re.compile(r, re.I if i in ("powershell-enc","powershell-dl-exec","cred-paths") else 0), d, c)
              for (i, s, r, d, c) in LINE_RULES]

POP_NPM = """react lodash express axios chalk commander moment request debug webpack typescript eslint prettier jquery vue next dotenv uuid async underscore bluebird yargs glob rimraf mkdirp minimist colors cross-env jest mocha socket.io mongoose body-parser cors redux tslib semver inquirer node-fetch ws rxjs classnames puppeteer nodemon passport jsonwebtoken bcrypt sequelize""".split()
POP_PYPI = """requests numpy pandas flask django urllib3 boto3 setuptools pip pytest scipy matplotlib pillow pyyaml cryptography sqlalchemy beautifulsoup4 selenium tensorflow torch scikit-learn jinja2 click certifi idna six python-dateutil pytz colorama aiohttp fastapi pydantic paramiko psycopg2 opencv-python lxml tqdm redis celery gunicorn uvicorn httpx rich attrs packaging wheel jsonschema protobuf grpcio""".split()
KNOWN_BACKENDS = {"setuptools.build_meta","setuptools.build_meta:__legacy__","hatchling.build","poetry.core.masonry.api",
                  "flit_core.buildapi","pdm.backend","maturin","scikit_build_core.build","mesonpy","uv_build"}
LIFECYCLE = {"preinstall","install","postinstall","prepublish","prepare","preprepare","postprepare"}

def lev1(a, b):
    """True if edit distance between a and b is exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if a == b[:i] + b[i+1:]:
            return True
    return False

def typosquat(names, popular, eco, rel):
    pop = set(popular)
    for n in names:
        n0 = n.lower().replace("_", "-").replace(".", "-") if eco == "pypi" else n.lower()
        if n0 in pop:
            continue
        for p in popular:
            if lev1(n0, p):
                add("HIGH", "typosquat?", rel, 0, "dependency '%s' is 1 edit away from popular %s package '%s' - verify on the registry" % (n, eco, p))
                break

def read_text(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(2_000_001)
    except Exception:
        return None, None
    if len(raw) > 2_000_000:
        stats["skipped_large"] += 1
        return None, "large"
    if b"\x00" in raw[:8000]:
        return None, raw[:8]
    return raw.decode("utf-8", "replace"), raw[:8]

MAGIC = [(b"\x7fELF","ELF executable"),(b"MZ","Windows PE executable"),
         (b"\xcf\xfa\xed\xfe","Mach-O executable"),(b"\xce\xfa\xed\xfe","Mach-O executable"),
         (b"\xca\xfe\xba\xbe","Mach-O/Java class"),(b"#!","script")]

def structural(rel, name, text, in_deps):
    parts = rel.split("/")
    low = name.lower()
    if in_deps:
        return
    if name == "package.json":
        try:
            pj = json.loads(text)
        except Exception:
            add("MEDIUM", "bad-json", rel, 0, "package.json does not parse"); return
        for k, v in (pj.get("scripts") or {}).items():
            if k in LIFECYCLE:
                add("HIGH", "npm-lifecycle-script", rel, 0, "'%s' runs automatically on install: %s" % (k, str(v)[:150]))
        deps = {}
        for sec in ("dependencies","devDependencies","optionalDependencies","peerDependencies"):
            deps.update(pj.get(sec) or {})
        typosquat(list(deps), POP_NPM, "npm", rel)
        for n, v in deps.items():
            if isinstance(v, str) and re.match(r"(git|http|https|file|github):|^[\w.-]+/[\w.-]+(#.*)?$", v):
                add("MEDIUM", "npm-nonregistry-dep", rel, 0, "'%s' -> %s" % (n, v[:100]))
    if re.match(r"requirements.*\.txt$", low):
        names = []
        for ln in text.splitlines():
            ln = ln.split("#")[0].strip()
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", ln)
            if m and not ln.startswith("-"):
                names.append(m.group(1))
        typosquat(names, POP_PYPI, "pypi", rel)
    if name == "setup.py" and re.search(r"os\.system|subprocess|urlopen|urllib|requests|\bexec\b|\beval\b|socket|base64", text):
        add("HIGH", "setup-py-active-code", rel, 0, "setup.py runs code at install time that does more than metadata")
    if name == "setup.py" and "cmdclass" in text:
        add("MEDIUM", "setup-py-cmdclass", rel, 0, "setup.py overrides install/build commands")
    if name == "pyproject.toml" and tomllib:
        try:
            t = tomllib.loads(text)
            be = (t.get("build-system") or {}).get("build-backend")
            if be and be not in KNOWN_BACKENDS:
                add("HIGH", "custom-build-backend", rel, 0, "non-standard build backend '%s' (runs code on pip install)" % be)
            if (t.get("build-system") or {}).get("backend-path"):
                add("HIGH", "in-tree-build-backend", rel, 0, "in-tree build backend (backend-path) executes repo code on build")
            proj = t.get("project") or {}
            names = []
            for d in (proj.get("dependencies") or []) + [x for v in (proj.get("optional-dependencies") or {}).values() for x in v]:
                m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", d)
                if m: names.append(m.group(1))
            typosquat(names, POP_PYPI, "pypi", rel)
        except Exception:
            pass
    if rel.endswith(".vscode/tasks.json") and re.search(r'"runOn"\s*:\s*"folderOpen"', text):
        add("CRITICAL", "vscode-autorun-task", rel, 0, "task with runOn=folderOpen executes when you open the folder (once trusted)")
    if ".vscode/" in rel and low == "settings.json" and re.search(
            r'"(python\.defaultInterpreterPath|git\.path|terminal\.integrated\.(shell|automationProfile|profiles)[^"]*|[\w.]*(Path|Executable|executablePath))"\s*:', text):
        add("HIGH", "vscode-exec-setting", rel, 0, "workspace setting that points the editor at an executable")
    if ".vscode/" in rel and low == "extensions.json":
        add("MEDIUM", "vscode-recommended-ext", rel, 0, "recommends extensions - do not install blindly")
    if ".devcontainer" in rel and low.endswith(".json"):
        if re.search(r'"initializeCommand"', text):
            add("CRITICAL", "devcontainer-initializeCommand", rel, 0, "initializeCommand runs on the HOST before the container starts")
        if re.search(r'"(onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"', text):
            add("HIGH", "devcontainer-lifecycle", rel, 0, "devcontainer runs commands on create/start")
        if re.search(r'--privileged|docker\.sock|"privileged"\s*:\s*true|--cap-add|--pid=host|--net(work)?=host', text):
            add("HIGH", "devcontainer-privileged", rel, 0, "privileged/host-sharing devcontainer settings")
    if low == ".envrc":
        add("HIGH", "direnv", rel, 0, ".envrc executes shell code when you cd in and run 'direnv allow'")
    if low in (".yarnrc.yml", ".yarnrc") and re.search(r"yarnPath", text):
        add("HIGH", "yarnpath", rel, 0, "yarnPath makes yarn execute a JS file from the repo")
    if low == ".npmrc" and re.search(r"script-shell|ignore-scripts\s*=\s*false", text):
        add("HIGH", "npmrc-script-shell", rel, 0, ".npmrc changes the shell/lifecycle-script behaviour")
    if low in ("sitecustomize.py", "usercustomize.py") or low.endswith(".pth"):
        add("HIGH", "python-autoload", rel, 0, "file auto-imported by the Python interpreter when on sys.path")
    if low == "build.rs":
        add("MEDIUM", "cargo-build-rs", rel, 0, "build.rs executes at 'cargo build' - review before building")
    if low == ".gitattributes" and re.search(r"\bfilter=", text):
        add("MEDIUM", "gitattributes-filter", rel, 0, "git filter attribute (only dangerous with a matching git config)")
    if ".husky" in parts or low == ".pre-commit-config.yaml":
        add("MEDIUM", "git-hook-manager", rel, 0, "runs hooks on commit/install")
    if parts[0] == ".git":
        if len(parts) >= 3 and parts[1] == "hooks" and not name.endswith(".sample"):
            add("HIGH", "git-hook", rel, 0, "active git hook - runs on your git commands")
        if rel == ".git/config" and re.search(r"fsmonitor|sshCommand|core\]?\s*\n?\s*pager|hooksPath|\[filter |textconv|^\s*\[alias\]|=\s*!", text, re.M):
            add("HIGH", "git-config-exec", rel, 0, ".git/config contains settings that can execute commands")

def walk():
    for dirpath, dirnames, filenames in os.walk(ROOT, followlinks=False):
        rel_dir = os.path.relpath(dirpath, ROOT)
        # report symlinked dirs (os.walk lists them in dirnames but does not follow)
        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if os.path.islink(p):
                handle_symlink(p)
                dirnames.remove(d)
        for fn in filenames:
            yield os.path.join(dirpath, fn)

def handle_symlink(p):
    stats["symlinks"] += 1
    rel = os.path.relpath(p, ROOT)
    try:
        tgt = os.readlink(p)
        real = os.path.realpath(p)
    except OSError:
        return
    if not (real == ROOT or real.startswith(ROOT + os.sep)):
        add("HIGH", "symlink-escape", rel, 0, "symlink points outside the project: %s" % tgt)

def main():
    for p in walk():
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        name = os.path.basename(p)
        if any(ord(c) in range(0x202a, 0x202f) or ord(c) in range(0x2066, 0x206a) for c in rel):
            add("HIGH", "trojan-source-filename", rel, 0, "bidi control char in file NAME (disguised extension)")
        if os.path.islink(p):
            handle_symlink(p); continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            add("MEDIUM", "special-file", rel, 0, "non-regular file (fifo/socket/device)"); continue
        stats["files"] += 1
        parts = rel.split("/")
        in_deps = any(x in ("node_modules","site-packages","vendor","third_party",".venv","venv") for x in parts)
        text, head = read_text(p)
        if text is None:
            stats["binary_files"] += 1
            if head and head != "large":
                for magic, label in MAGIC[:5]:
                    if head.startswith(magic):
                        if not in_deps:
                            add("HIGH", "binary-executable", rel, 0, "%s committed to repo" % label)
                        break
            elif st.st_size and name.lower().endswith((".exe",".dll",".so",".dylib",".node",".jar",".class",".pyc",".whl",".msi",".scr",".bin")) and not in_deps:
                add("MEDIUM", "binary-artifact", rel, 0, "binary artifact in repo")
            continue
        stats["text_files"] += 1
        ext = os.path.splitext(name)[1].lower()
        is_code = ext in CODE_EXT or name in CODE_NAMES or text.startswith("#!")
        if text.startswith("#!") and ext == "" and not in_deps:
            pass
        structural(rel, name, text, in_deps)
        hex_names = 0
        for i, line in enumerate(text.split("\n"), 1):
            if len(line) > 20000:
                if not in_deps:
                    add("MEDIUM", "minified-giant-line", rel, i, "single line >20k chars (minified/obfuscated?)")
                line = line[:20000]
            if "_0x" in line:
                hex_names += len(re.findall(r"\b_0x[a-f0-9]{4,6}\b", line))
            for rid, sev, rx, desc, code_only in LINE_RULES:
                if code_only and not is_code:
                    continue
                if in_deps and sev not in ("CRITICAL", "HIGH"):
                    continue
                if rid == "long-b64-blob" and ext in (".lock", ".json", ".svg", ".map") :
                    continue
                if rid == "pkg-source-override" and not re.search(r"(requirements|\.npmrc|\.yarnrc|pip\.conf|\.txt$)", rel, re.I):
                    continue
                m = rx.search(line)
                if m:
                    s = max(0, m.start() - 20)
                    add(sev, rid, rel, i, desc, line[s:s + 160])
        if hex_names >= 10 and not in_deps:
            add("HIGH", "obfuscated-js", rel, 0, "%d identifiers of the form _0x1234 (javascript-obfuscator style)" % hex_names)
    json.dump({"stats": stats, "findings": findings, "suppressed": suppressed}, sys.stdout)

main()
'''

# --------------------------------------------------------------------------- #
# Remote driver script (bash). Scans only; never executes anything from the code.
# --------------------------------------------------------------------------- #
REMOTE_DRIVER = r'''
set -u
W=/tmp/scan
cd "$W"
rm -rf code results && mkdir -p code results
# GNU tar strips leading '/' and refuses '..' members by default.
tar --no-same-owner --no-same-permissions -xzf code.tgz -C code || { echo "extract failed" >&2; exit 3; }
python3 scanner.py code > results/heuristics.json 2> results/heuristics.err || echo "heuristic scanner failed" >> results/status.txt

export DEBIAN_FRONTEND=noninteractive
if ! python3 -m venv venv >/dev/null 2>&1; then
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
  python3 -m venv venv >/dev/null 2>&1 || echo "venv unavailable" >> results/status.txt
fi
if [ -x venv/bin/pip ] && venv/bin/pip install -q semgrep guarddog >pip.log 2>&1; then
  echo "tools: semgrep+guarddog installed" >> results/status.txt
  timeout 900 venv/bin/semgrep scan --config p/security-audit --metrics off --json --quiet --disable-version-check code \
      > results/semgrep.json 2> results/semgrep.err || echo "semgrep failed/timeout" >> results/status.txt
  if find code -name package.json -not -path '*/node_modules/*' | grep -q .; then
    timeout 600 venv/bin/guarddog npm scan code --output-format json > results/guarddog_npm.json 2> results/guarddog_npm.err || true
  fi
  if find code \( -name setup.py -o -name pyproject.toml \) -not -path '*/node_modules/*' | grep -q .; then
    timeout 600 venv/bin/guarddog pypi scan code --output-format json > results/guarddog_pypi.json 2> results/guarddog_pypi.err || true
  fi
else
  echo "tools: could not install semgrep/guarddog (heuristics only)" >> results/status.txt
fi
tar -czf results.tgz -C results .
echo done
'''

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def clean(s):
    return CTRL.sub("?", str(s))


def log(msg):
    print(clean(msg), flush=True)


# --------------------------------------------------------------------------- #
# Local packing
# --------------------------------------------------------------------------- #
def pack(src: Path, dest: Path, max_mb: int):
    total = 0
    with tarfile.open(dest, "w:gz") as tf:
        for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                try:
                    st = p.lstat()
                except OSError:
                    continue
                import stat as _s
                if not (_s.S_ISREG(st.st_mode) or _s.S_ISDIR(st.st_mode) or _s.S_ISLNK(st.st_mode)):
                    continue  # skip fifos, sockets, devices
                total += st.st_size if _s.S_ISREG(st.st_mode) else 0
                if total > max_mb * 1024 * 1024:
                    raise SystemExit(f"Codebase larger than {max_mb} MB; raise --max-mb or prune it.")
                ti = tf.gettarinfo(str(p), arcname=str(p.relative_to(src)))
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = ""
                ti.mode &= 0o755  # drop setuid/setgid/sticky and group/world write
                if ti.isreg():
                    with open(p, "rb") as f:
                        tf.addfile(ti, f)
                else:
                    tf.addfile(ti)
    return total


# --------------------------------------------------------------------------- #
# SSH helpers
# --------------------------------------------------------------------------- #
class Remote:
    def __init__(self, host, key, tmp):
        self.host = host
        self.opts = [
            "-F", "/dev/null",
            "-o", "BatchMode=yes",
            "-o", "IdentityAgent=none",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={tmp}/known_hosts",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=30",
            "-i", str(key),
        ]

    def ssh(self, command, stdin=None, timeout=None):
        return subprocess.run(["ssh", *self.opts, self.host, command],
                              input=stdin, text=True, capture_output=True, timeout=timeout)

    def put(self, local, remote):
        r = subprocess.run(["scp", "-q", *self.opts, str(local), f"{self.host}:{remote}"],
                           capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError("scp upload failed: " + clean(r.stderr))

    def get(self, remote, local):
        r = subprocess.run(["scp", "-q", *self.opts, f"{self.host}:{remote}", str(local)],
                           capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError("scp download failed: " + clean(r.stderr))

    def wait_ready(self, attempts=40):
        for i in range(attempts):
            r = self.ssh("echo ok", timeout=30)
            if r.returncode == 0 and "ok" in r.stdout:
                return
            time.sleep(8)
        raise RuntimeError("VM never became reachable over SSH")


# --------------------------------------------------------------------------- #
# DigitalOcean provisioning (via doctl). Optional.
# --------------------------------------------------------------------------- #
class DigitalOcean:
    def __init__(self, tmp, region, size):
        if not shutil.which("doctl"):
            raise SystemExit("doctl not found. Install it and run `doctl auth init`, or use --host.")
        self.tmp, self.region, self.size = Path(tmp), region, size
        self.key = self.tmp / "ephemeral_ed25519"
        self.droplet_id = None
        self.ssh_key_id = None
        self.name = "scan-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    def _doctl(self, *a):
        r = subprocess.run(["doctl", *a], capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError("doctl " + " ".join(a[:3]) + " failed: " + clean(r.stderr))
        return r.stdout.strip()

    def create(self):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        self.ssh_key_id = self._doctl("compute", "ssh-key", "import", self.name,
                                      "--public-key-file", f"{self.key}.pub",
                                      "--format", "ID", "--no-header")
        out = self._doctl("compute", "droplet", "create", self.name,
                          "--image", "ubuntu-24-04-x64", "--size", self.size, "--region", self.region,
                          "--ssh-keys", self.ssh_key_id, "--wait",
                          "--format", "ID,PublicIPv4", "--no-header")
        self.droplet_id, ip = out.split()[:2]
        return f"root@{ip}"

    def destroy(self):
        if self.droplet_id:
            subprocess.run(["doctl", "compute", "droplet", "delete", "-f", self.droplet_id], capture_output=True)
            log(f"[cleanup] destroyed droplet {self.droplet_id}")
            self.droplet_id = None
        if self.ssh_key_id:
            subprocess.run(["doctl", "compute", "ssh-key", "delete", "-f", self.ssh_key_id], capture_output=True)
            self.ssh_key_id = None


# --------------------------------------------------------------------------- #
# Report handling
# --------------------------------------------------------------------------- #
def read_results(tgz_path):
    out = {}
    with tarfile.open(tgz_path, "r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or m.size > 50 * 1024 * 1024:
                continue
            name = os.path.basename(m.name)
            if name in {"heuristics.json", "semgrep.json", "guarddog_npm.json", "guarddog_pypi.json",
                        "status.txt", "heuristics.err"}:
                out[name] = tf.extractfile(m).read().decode("utf-8", "replace")
    return out


def load_json(s):
    try:
        return json.loads(s)
    except Exception:
        return None


def merge_findings(res):
    findings, notes = [], []
    h = load_json(res.get("heuristics.json", ""))
    if h is None:
        notes.append("Heuristic scanner produced no usable output - treat result as INCOMPLETE.")
        stats = {}
    else:
        findings += h.get("findings", [])
        stats = h.get("stats", {})
        for rule, n in (h.get("suppressed") or {}).items():
            notes.append(f"{n} more '{rule}' hits were suppressed (per-file/per-rule caps).")
    sg = load_json(res.get("semgrep.json", ""))
    if sg:
        for r in sg.get("results", []):
            sev = (r.get("extra", {}).get("severity") or "INFO").upper()
            findings.append({
                "severity": "MEDIUM" if sev == "ERROR" else "LOW",
                "rule": "semgrep:" + r.get("check_id", "?").split(".")[-1],
                "file": r.get("path", "?").replace("code/", "", 1),
                "line": r.get("start", {}).get("line", 0),
                "detail": (r.get("extra", {}).get("message") or "")[:200],
                "snippet": "",
            })
    else:
        notes.append("Semgrep results missing (install failed or timed out) - coverage INCOMPLETE; re-run.")
    for eco in ("npm", "pypi"):
        gd = load_json(res.get(f"guarddog_{eco}.json", ""))
        if not gd:
            continue
        results = gd.get("results") or {}
        for rule, val in results.items():
            if val:
                findings.append({"severity": "HIGH", "rule": f"guarddog-{eco}:{rule}", "file": "(package)",
                                 "line": 0, "detail": "GuardDog malware heuristic matched",
                                 "snippet": json.dumps(val)[:200]})
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["file"], f.get("line", 0)))
    return findings, stats, notes, res.get("status.txt", "")


def verdict(findings, notes):
    sev = {f["severity"] for f in findings}
    incomplete = any("INCOMPLETE" in n for n in notes)
    if "CRITICAL" in sev:
        return "DO NOT USE", 2
    if "HIGH" in sev:
        return "SUSPICIOUS - MANUAL REVIEW REQUIRED", 1
    if incomplete:
        return "INCONCLUSIVE - SCAN INCOMPLETE", 1
    if "MEDIUM" in sev:
        return "NO RED FLAGS, BUT REVIEW THE NOTES", 0
    return "NO KNOWN RED FLAGS", 0


NEXT_STEPS = {
    "DO NOT USE": """\
  1. Do NOT open the folder in your IDE, run, build or install anything from it.
  2. Keep it as a zip/archive only. Delete the extracted copy if you made one.
  3. Look at the CRITICAL items above - if they match what the sender described,
     it's still a bad sign; confirm with the sender over a DIFFERENT channel.
  4. If you already ran/opened it on your machine: treat the machine as
     compromised - rotate SSH keys, cloud/API tokens, npm/PyPI/GitHub tokens,
     browser-saved passwords; check ~/.ssh/authorized_keys, crontab, shell rc files.
  5. Report it to the platform/sender's security contact if appropriate.""",
    "SUSPICIOUS - MANUAL REVIEW REQUIRED": """\
  1. Read every HIGH finding yourself in a plain viewer (less/bat, or GitHub's web view).
     Most are explainable (a legit postinstall, a build script) - decide per item.
  2. Do not open in an IDE with workspace trust, and do not install dependencies,
     until each HIGH item is understood.
  3. Work in an isolated environment (disposable VM/Codespace) for the first run,
     with network off or allow-listed, and no credentials mounted.
  4. Install deps only with scripts disabled (npm ci --ignore-scripts; pip install
     --no-build-isolation is NOT safe; prefer wheels: pip install --only-binary=:all:).
  5. Consider asking the sender to explain the flagged items.""",
    "INCONCLUSIVE - SCAN INCOMPLETE": """\
  1. Re-run the scan (check the notes above for what failed - often a network or
     install timeout on the VM).
  2. Until it completes cleanly, treat the code as untrusted.""",
    "NO RED FLAGS, BUT REVIEW THE NOTES": """\
  1. Skim the MEDIUM items - process spawning, dynamic exec, and package sources
     should make sense for what this project does.
  2. First open/run it in a throwaway VM or container with no secrets and the
     network blocked; watch for unexpected connections (strace/tcpdump).
  3. Install deps with scripts disabled, pinned to lockfile versions.
  4. Only then move it to your real machine. Keep secrets out of the project's env.""",
    "NO KNOWN RED FLAGS": """\
  1. This means "nothing known was found", NOT "proven safe". Obfuscated or novel
     payloads can slip through static scans.
  2. Reasonable path: open it in an editor with workspace trust OFF, skim the entry
     points and dependency manifests, and run first in a disposable environment
     with no secrets before using it on your main machine.
  3. Pin dependencies to a lockfile and install with scripts disabled.""",
}


def render(findings, stats, notes, status, label, out_dir):
    log("\n" + "=" * 72)
    log(f" VERDICT: {label}")
    log("=" * 72)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    log(f" Files scanned: {stats.get('files', '?')}  (text {stats.get('text_files', '?')}, "
        f"binary {stats.get('binary_files', '?')}, symlinks {stats.get('symlinks', '?')})")
    log(" Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    if status.strip():
        log(" Remote status: " + clean(status.strip().replace("\n", " | ")))
    for n in notes:
        log(" NOTE: " + n)
    shown = 0
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        items = [f for f in findings if f["severity"] == sev]
        if not items:
            continue
        log(f"\n--- {sev} ({len(items)}) ---")
        limit = None if sev != "MEDIUM" else 15
        for f in items[:limit]:
            loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
            log(f"[{f['rule']}] {loc}\n    {f['detail']}" + (f"\n    > {f['snippet']}" if f.get("snippet") else ""))
            shown += 1
        if limit and len(items) > limit:
            log(f"    ... {len(items) - limit} more MEDIUM in the full report")
    log("\nWHAT TO DO NEXT:")
    log(NEXT_STEPS[label])
    log("\nCaveat: static scanning cannot prove code is safe. Treat 'clean' as 'no known red flags'.")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(
        {"verdict": label, "stats": stats, "notes": notes, "status": status, "findings": findings}, indent=2))
    log(f"\nFull report: {out_dir / 'report.json'}")


# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="folder with the untrusted codebase")
    ap.add_argument("--host", help="user@host of a FRESH, DISPOSABLE VM you already created")
    ap.add_argument("--key", help="dedicated SSH private key for that VM (required with --host)")
    ap.add_argument("--provision", choices=["digitalocean"], help="create + destroy a throwaway VM for you")
    ap.add_argument("--region", default="nyc1")
    ap.add_argument("--size", default="s-2vcpu-4gb")
    ap.add_argument("--keep", action="store_true", help="do not destroy the provisioned VM afterwards")
    ap.add_argument("--out", help="report output dir (default ./scan-report-<timestamp>)")
    ap.add_argument("--max-mb", type=int, default=500)
    a = ap.parse_args()

    src = Path(a.path).resolve()
    if not src.is_dir():
        sys.exit("path must be a directory")
    if bool(a.host) == bool(a.provision):
        sys.exit("choose exactly one of --host or --provision")
    if a.host and not a.key:
        sys.exit("--key is required with --host (use a dedicated throwaway key, not your real one)")

    out_dir = Path(a.out or f"scan-report-{datetime.datetime.now():%Y%m%d-%H%M%S}")
    tmp = Path(tempfile.mkdtemp(prefix="sandbox_scan_"))
    os.chmod(tmp, 0o700)
    atexit.register(shutil.rmtree, tmp, True)
    provider = None

    try:
        log(f"[1/5] Packing {src} ...")
        size = pack(src, tmp / "code.tgz", a.max_mb)
        log(f"      {size/1e6:.1f} MB of files packed")
        (tmp / "scanner.py").write_text(REMOTE_SCANNER)
        (tmp / "known_hosts").touch()

        if a.provision:
            log("[2/5] Creating disposable DigitalOcean droplet ...")
            provider = DigitalOcean(tmp, a.region, a.size)
            host = provider.create()
            key = provider.key
        else:
            host, key = a.host, a.key
            log("[2/5] Using your VM " + clean(host) + " - make sure it is fresh and holds no credentials.")

        rem = Remote(host, key, tmp)
        log("[3/5] Waiting for SSH ...")
        rem.wait_ready()
        rem.ssh("mkdir -p /tmp/scan")
        log("[4/5] Uploading and scanning (semgrep install can take a couple of minutes) ...")
        rem.put(tmp / "code.tgz", "/tmp/scan/code.tgz")
        rem.put(tmp / "scanner.py", "/tmp/scan/scanner.py")
        r = rem.ssh("bash -s", stdin=REMOTE_DRIVER, timeout=3600)
        if r.returncode != 0:
            raise RuntimeError("remote scan failed: " + clean(r.stderr[-800:]))
        rem.get("/tmp/scan/results.tgz", tmp / "results.tgz")

        res = read_results(tmp / "results.tgz")
    except Exception as e:
        log(f"\nERROR: {e}")
        res = None
        rc = 3
    finally:
        if provider and not a.keep:
            provider.destroy()
        elif provider and a.keep:
            log(f"[keep] droplet {provider.droplet_id} left running - DESTROY IT YOURSELF: "
                f"doctl compute droplet delete -f {provider.droplet_id}")

    if res is None:
        sys.exit(3)
    log("[5/5] Building report ...")
    findings, stats, notes, status = merge_findings(res)
    label, rc = verdict(findings, notes)
    render(findings, stats, notes, status, label, out_dir)
    if not a.provision:
        log("\nReminder: destroy your throwaway VM now.")
    sys.exit(rc)


if __name__ == "__main__":
    main()
