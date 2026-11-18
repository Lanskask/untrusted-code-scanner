"""Heuristic scanner. Runs on the throwaway VM (stdlib only), never on your machine.

Shipped as a file, not imported: `cli.py` uploads it and the VM runs `python3 scanner.py <dir>`.
"""

import os, re, sys, json, stat
from collections.abc import Iterator, Sequence
from typing import Any

try:
    import tomllib
except Exception:
    tomllib = None

ROOT = os.path.abspath(sys.argv[1])
findings: list[dict[str, Any]] = []
per_file: dict[tuple[str, str], int] = {}
per_rule: dict[str, int] = {}
suppressed: dict[str, int] = {}
stats: dict[str, int] = {"files": 0, "text_files": 0, "binary_files": 0, "symlinks": 0, "skipped_large": 0}
# Dependency and build-output folders are full of benign "scary" text and binaries. Their CRITICAL/HIGH hits are
# counted per folder and reported as ONE medium line, instead of drowning the real findings.
DEP_DIRS = ("node_modules", "site-packages", "vendor", "third_party", ".venv", "venv")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
ARCHIVE_EXT = (".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar")
BUILD_DIRS = ("target", "cargo-target", ".next", "dist", "build", "out")
dep_hits: dict[str, dict[str, int]] = {}  # dep folder -> {rule: count}
cur_dep: str | None = None  # set per file in main(); None = report normally


def add(sev: str, rule: str, rel: str, line: int, detail: str, snippet: str = "") -> None:
    if (
        cur_dep
        and sev == "CRITICAL"
        and os.path.basename(cur_dep) not in ("node_modules", "site-packages", ".venv", "venv")
    ):
        sev = "HIGH"  # a payload in dist/ or vendor/ must not shrink to one MEDIUM line; shown as HIGH, not summarized
    elif cur_dep and sev in ("CRITICAL", "HIGH"):
        hits = dep_hits.setdefault(cur_dep, {})
        hits[rule] = hits.get(rule, 0) + 1
        return
    kf, kr = (rule, rel), rule
    per_file[kf] = per_file.get(kf, 0) + 1
    per_rule[kr] = per_rule.get(kr, 0) + 1
    if per_file[kf] > 5 or per_rule[kr] > 60:
        suppressed[rule] = suppressed.get(rule, 0) + 1
        return
    findings.append(
        {"severity": sev, "rule": rule, "file": rel, "line": line, "detail": detail, "snippet": snippet.strip()[:200]}
    )


CODE_EXT = {
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".rb",
    ".php",
    ".pl",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".cs",
    ".lua",
    ".vbs",
}
CODE_NAMES = {"Makefile", "makefile", "Dockerfile", "justfile", "Rakefile", "Gemfile", "Taskfile.yml"}

# (rule id, severity, regex, description, code_only)
# Only the WHOLE environment (os.environ, dict(os.environ), JSON.stringify(process.env)) counts: reading one named
# variable next to a request is what every web app does. A single secret sent by name is not caught here.
_ENV = r"(os\.environ|process\.env)(?![\w.\[])"
_NET = r"(Net::HTTP|HTTParty|RestClient|requests\.(post|get|put)|urlopen|urllib|fetch\(|axios|http\.request|XMLHttpRequest)"
ENV_EXFIL = _ENV + r"[^\n]{0,160}" + _NET + "|" + _NET + r"[^\n]{0,160}" + _ENV

_SECRET_VAR = (
    r"(os\.environ(\.get\(|\[)|process\.env\.|getenv\(|\bENV\[)['\"]?\w*(TOKEN|SECRET|PASSW|KEY|CREDENTIAL)\w*"
)
ENV_SECRET_SEND = _SECRET_VAR + r"[^\n]{0,160}" + _NET + "|" + _NET + r"[^\n]{0,160}" + _SECRET_VAR

# Browser-extension IDs of MetaMask, Phantom, Coinbase Wallet and Binance Wallet are from public reports/memory and were
# NOT checked against the stores; wallet paths follow the campaigns cited in docs/RESEARCH.md section 5.
_WALLET = (
    r"(nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad"
    r"|fhbohimaelbohpjbbldcngcnapndodjp|exodus\.wallet|\.electrum|electrum/wallets|\.config/solana/id\.json"
    r"|atomic/Local Storage|Coinomi|UTC--\d{4}-\d\d-\d\dT)"
)
_SEED = r"(mnemonic|seed[ _]?phrase|recovery[ _]?phrase|private[ _]?key)"
_SEND = r"(fetch\(|axios|requests\.(post|put)|http\.request|XMLHttpRequest|api\.telegram\.org|discord(app)?\.com/api/webhooks)"
SEED_SEND = _SEED + r"[^\n]{0,160}" + _SEND + "|" + _SEND + r"[^\n]{0,160}" + _SEED
_ADDR = r"0x\[a-fA-F0-9\]\{40\}|\[13\]\[a-km-zA-HJ-NP-Z1-9\]\{25,34\}"

_RAW_RULES: list[tuple[str, str, str, str, bool]] = [
    (
        "clipboard-read",
        "MEDIUM",
        r"pyperclip\.paste|clipboard\.readText|navigator\.clipboard\.read|GetClipboardData|\bpbpaste\b",
        "reads the clipboard (address-swapping clipper?)",
        True,
    ),
    (
        "screen-capture",
        "MEDIUM",
        r"ImageGrab\.grab|pyautogui\.screenshot|pyscreenshot|\bmss\.mss|screenshot-desktop|\bscreencapture\b",
        "captures the screen",
        True,
    ),
    (
        "env-dump",
        "MEDIUM",
        r"JSON\.stringify\(\s*process\[?\.?['\"]?env|json\.dumps\(\s*(dict\()?os\.environ|\bENV\.to_h\b|os\.Environ\(\)",
        "serializes the whole environment",
        True,
    ),
    ("wallet-theft", "HIGH", _WALLET, "reads crypto-wallet files or wallet browser-extension data", False),
    ("seed-phrase-send", "MEDIUM", SEED_SEND, "seed phrase / private key next to a network call", True),
    ("crypto-address-regex", "MEDIUM", _ADDR, "crypto-address pattern in code (address-swapping clipper?)", True),
    (
        "env-secret-send",
        "MEDIUM",
        ENV_SECRET_SEND,
        "a secret-named environment variable sits next to a network call",
        False,
    ),
    (
        "pipe-to-shell",
        "CRITICAL",
        r"(curl|wget|fetch)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
        "downloads and pipes to a shell",
        False,
    ),
    (
        "b64-exec",
        "CRITICAL",
        r"\b(eval|exec)\s*\(\s*(base64\.b64decode|atob|Buffer\.from|codecs\.decode|zlib\.decompress|bytes\.fromhex)",
        "executes decoded/obfuscated payload",
        False,
    ),
    (
        "b64-pipe-shell",
        "CRITICAL",
        r"base64\s+(-d|--decode)[^\n]{0,120}\|\s*(ba|z|da)?sh\b",
        "decodes base64 into a shell",
        False,
    ),
    (
        "py-exec-compile",
        "CRITICAL",
        r"\bexec\s*\(\s*(compile|marshal\.loads)\b[^\n]*(b64|base64|zlib|marshal|urlopen|requests|decompress)|\bexec\s*\(\s*marshal\.loads",
        "exec of decoded/marshalled code",
        False,
    ),
    (
        "reverse-shell",
        "CRITICAL",
        r"/dev/tcp/|bash\s+-i\s*>&|\bnc(at)?\s+(-\w+\s+)*-e\s|pty\.spawn\s*\(|os\.dup2\s*\(\s*(s|\w*(sock|conn|client)\w*)\.fileno",
        "reverse-shell pattern",
        False,
    ),
    (
        "powershell-dl-exec",
        "CRITICAL",
        r"(DownloadString|DownloadFile|Invoke-WebRequest|iwr)\b[^\n]{0,200}(IEX|Invoke-Expression)|(IEX|Invoke-Expression)[^\n]{0,200}(DownloadString|Net\.WebClient)",
        "PowerShell download-and-execute",
        False,
    ),
    (
        "powershell-enc",
        "HIGH",
        r"powershell[^\n]{0,80}(\s-enc\b|-encodedcommand|-w(indowstyle)?\s+hidden)",
        "encoded/hidden PowerShell",
        False,
    ),
    (
        "cred-paths",
        "HIGH",
        r"(\.ssh/(id_[a-z0-9]+|authorized_keys)|\.aws/credentials|\.git-credentials|\.docker/config\.json|\.kube/config|\.config/gcloud|Login Data|wallet\.dat|Local Storage/leveldb|Cookies\.sqlite|logins\.json|\.bash_history)",
        "touches credential / browser / wallet paths",
        False,
    ),
    (
        "env-exfil",
        "HIGH",
        ENV_EXFIL,
        "env vars sent over network",
        False,
    ),
    (
        "exfil-endpoint",
        "HIGH",
        r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|transfer\.sh|ngrok(-free)?\.(io|app|dev)|webhook\.site|requestbin|interact\.sh|oast\.(pro|live|site|fun|me)|burpcollaborator",
        "known exfil / callback endpoint",
        False,
    ),
    (
        "cryptominer",
        "HIGH",
        r"xmrig|stratum\+(tcp|ssl)://[^\s\x27\"]+:\d{2,5}|cryptonight|minerd\b|nicehash",
        "cryptominer indicator",
        False,
    ),
    (
        "trojan-source",
        "HIGH",
        r"[\u202a-\u202e\u2066-\u2069]",
        "bidirectional Unicode control char (Trojan Source)",
        False,
    ),
    (
        "chmod-exec-tmp",
        "HIGH",
        r"chmod\s+(\+x|[0-7]*7[0-7]*)\s+/(tmp|var/tmp|dev/shm)/",
        "makes a file in /tmp executable",
        False,
    ),
    (
        "persistence",
        "HIGH",
        r"(crontab\s+-|/etc/cron|\.bashrc|\.zshrc|[~/]\.profile\b|LaunchAgents|systemctl\s+enable|schtasks|CurrentVersion\\Run)",
        "persistence mechanism",
        True,
    ),
    (
        "service-key-prefix",
        "MEDIUM",
        r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        "embedded secret/key (leaked, or a lure)",
        False,
    ),
    (
        "dyn-exec",
        "MEDIUM",
        r"\b(eval|exec)\s*\(|\bnew\s+Function\s*\(|\b__import__\s*\(",
        "dynamic code execution",
        True,
    ),
    (
        "proc-spawn",
        "MEDIUM",
        r"\bos\.system\s*\(|subprocess\.(Popen|run|call|check_output|check_call)|child_process|Runtime\.getRuntime\(\)\.exec|\bShell\.Execute|\bsystem\s*\(",
        "spawns processes",
        True,
    ),
    ("hardcoded-ip-url", "MEDIUM", r"https?://\d{1,3}(\.\d{1,3}){3}", "URL to a raw IP address", False),
    ("long-b64-blob", "MEDIUM", r"[A-Za-z0-9+/=]{400,}", "very long base64-like blob", False),
    ("zero-width", "MEDIUM", r"[\u200b-\u200d\u2060\ufeff]", "zero-width characters in text", True),
    (
        "pkg-source-override",
        "MEDIUM",
        r"(--extra-index-url|--index-url|--trusted-host|^\s*registry\s*=|^\s*@[\w-]+:registry\s*=)",
        "package source override",
        False,
    ),
    (
        "lockfile-foreign-host",
        "HIGH",
        r"(resolved|tarball)\"?:?\s*\"?https?://(?!registry\.npmjs\.org/|registry\.yarnpkg\.com/)",
        "lockfile fetches a package from outside the public registry (dependency substitution)",
        False,
    ),
    (
        "git-dependency",
        "MEDIUM",
        r"(git\+(https?|ssh)://|git://|\"github:)",
        "dependency pulled straight from git",
        False,
    ),
]
LINE_RULES: list[tuple[str, str, re.Pattern[str], str, bool]] = [
    (i, s, re.compile(r, re.I if i in ("powershell-enc", "powershell-dl-exec", "cred-paths") else 0), d, c)
    for (i, s, r, d, c) in _RAW_RULES
]

POP_NPM = """react lodash express axios chalk commander moment request debug webpack typescript eslint prettier jquery vue next dotenv uuid async underscore bluebird yargs glob rimraf mkdirp minimist colors cross-env jest mocha socket.io mongoose body-parser cors redux tslib semver inquirer node-fetch ws rxjs classnames puppeteer nodemon passport jsonwebtoken bcrypt sequelize""".split()
POP_PYPI = """requests numpy pandas flask django urllib3 boto3 setuptools pip pytest scipy matplotlib pillow pyyaml cryptography sqlalchemy beautifulsoup4 selenium tensorflow torch scikit-learn jinja2 click certifi idna six python-dateutil pytz colorama aiohttp fastapi pydantic paramiko psycopg2 opencv-python lxml tqdm redis celery gunicorn uvicorn httpx rich attrs packaging wheel jsonschema protobuf grpcio""".split()
KNOWN_BACKENDS = {
    "setuptools.build_meta",
    "setuptools.build_meta:__legacy__",
    "hatchling.build",
    "poetry.core.masonry.api",
    "flit_core.buildapi",
    "pdm.backend",
    "maturin",
    "scikit_build_core.build",
    "mesonpy",
    "uv_build",
}
SAFE_LIFECYCLE = {"husky", "husky install", "patch-package", "node-gyp rebuild"}  # exact values only
LIFECYCLE = {"preinstall", "install", "postinstall", "prepublish", "prepare", "preprepare", "postprepare"}


def lev1(a: str, b: str) -> bool:
    """True if edit distance between a and b is exactly 1."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diff) == 2 and diff[1] == diff[0] + 1:  # two adjacent letters swapped
            return a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
        return len(diff) == 1
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if a == b[:i] + b[i + 1 :]:
            return True
    return False


KNOWN_LEGIT = {"preact", "enquirer"}  # real packages one edit from a popular one; extend only with evidence


def typosquat(names: Sequence[str], popular: Sequence[str], eco: str, rel: str) -> None:
    pop = set(popular)
    for n in names:
        n0 = n.lower().replace("_", "-").replace(".", "-") if eco == "pypi" else n.lower()
        if n0 in pop or len(n0) < 5 or n0 in KNOWN_LEGIT:
            continue
        for p in popular:
            if lev1(n0, p):
                add(
                    "HIGH",
                    "typosquat?",
                    rel,
                    0,
                    "dependency '%s' is 1 edit away from popular %s package '%s' - verify on the registry"
                    % (n, eco, p),
                )
                break


def read_text(path: str) -> tuple[str | None, bytes | str | None]:  # 2nd item: first bytes, or "large"
    try:
        with open(path, "rb") as f:
            raw = f.read(2_000_001)
    except Exception:
        return None, None
    if len(raw) > 2_000_000:
        stats["skipped_large"] += 1
        return None, "large"
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace"), raw[:20]
    if b"\x00" in raw[:8000]:
        return None, raw[:20]
    return raw.decode("utf-8", "replace"), raw[:20]


def is_object_file(head: bytes) -> bool:
    """Relocatable object (.o): Mach-O MH_OBJECT or ELF ET_REL. Not runnable, so only MEDIUM."""
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") and len(head) >= 16:
        return int.from_bytes(head[12:16], "little") == 1
    if head[:4] == b"\x7fELF" and len(head) >= 18:
        return int.from_bytes(head[16:18], "little" if head[5] == 1 else "big") == 1
    return False


MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "Windows PE executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"\xce\xfa\xed\xfe", "Mach-O executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java class"),
    (b"#!", "script"),
]


def structural(rel: str, name: str, text: str, in_deps: bool) -> None:
    parts = rel.split("/")
    low = name.lower()
    if in_deps:
        return
    if name == "package.json":
        try:
            pj = json.loads(text)
        except Exception:
            add("MEDIUM", "bad-json", rel, 0, "package.json does not parse")
            return
        for k, v in (pj.get("scripts") or {}).items():
            if k in LIFECYCLE and str(v).strip() not in SAFE_LIFECYCLE and not str(v).startswith("npx only-allow "):
                add(
                    "HIGH", "npm-lifecycle-script", rel, 0, "'%s' runs automatically on install: %s" % (k, str(v)[:150])
                )
        deps = {}
        for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
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
    if name == "setup.py" and re.search(
        r"os\.system|subprocess|urlopen|urllib|requests|\bexec\b|\beval\b|socket|base64", text
    ):
        add("HIGH", "setup-py-active-code", rel, 0, "setup.py runs code at install time that does more than metadata")
    if name == "setup.py" and "cmdclass" in text:
        add("MEDIUM", "setup-py-cmdclass", rel, 0, "setup.py overrides install/build commands")
    if name == "pyproject.toml" and tomllib:
        try:
            t = tomllib.loads(text)
            be = (t.get("build-system") or {}).get("build-backend")
            if be and be not in KNOWN_BACKENDS:
                add(
                    "HIGH",
                    "custom-build-backend",
                    rel,
                    0,
                    "non-standard build backend '%s' (runs code on pip install)" % be,
                )
            if (t.get("build-system") or {}).get("backend-path"):
                add(
                    "HIGH",
                    "in-tree-build-backend",
                    rel,
                    0,
                    "in-tree build backend (backend-path) executes repo code on build",
                )
            proj = t.get("project") or {}
            names = []
            for d in (proj.get("dependencies") or []) + [
                x for v in (proj.get("optional-dependencies") or {}).values() for x in v
            ]:
                m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", d)
                if m:
                    names.append(m.group(1))
            typosquat(names, POP_PYPI, "pypi", rel)
        except Exception:
            pass
    if rel.endswith(".vscode/tasks.json") and re.search(r'"runOn"\s*:\s*"folderOpen"', text):
        add(
            "CRITICAL",
            "vscode-autorun-task",
            rel,
            0,
            "task with runOn=folderOpen executes when you open the folder (once trusted)",
        )
    if (
        ".vscode/" in rel
        and low == "settings.json"
        and re.search(
            r'"(python\.defaultInterpreterPath|git\.path|terminal\.integrated\.(shell|automationProfile|profiles)[^"]*|[\w.]*(Path|Executable|executablePath))"\s*:',
            text,
        )
    ):
        add("HIGH", "vscode-exec-setting", rel, 0, "workspace setting that points the editor at an executable")
    if ".vscode/" in rel and low == "extensions.json":
        add("MEDIUM", "vscode-recommended-ext", rel, 0, "recommends extensions - do not install blindly")
    if ".devcontainer" in rel and low.endswith(".json"):
        if re.search(r'"initializeCommand"', text):
            add(
                "CRITICAL",
                "devcontainer-initializeCommand",
                rel,
                0,
                "initializeCommand runs on the HOST before the container starts",
            )
        if re.search(
            r'"(onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"', text
        ):
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
        add(
            "MEDIUM", "gitattributes-filter", rel, 0, "git filter attribute (only dangerous with a matching git config)"
        )
    if ".husky" in parts or low == ".pre-commit-config.yaml":
        add("MEDIUM", "git-hook-manager", rel, 0, "runs hooks on commit/install")
    if parts[0] == ".git":
        if len(parts) >= 3 and parts[1] == "hooks" and not name.endswith(".sample"):
            add("HIGH", "git-hook", rel, 0, "active git hook - runs on your git commands")
        if rel == ".git/config" and re.search(
            r"fsmonitor|sshCommand|core\]?\s*\n?\s*pager|hooksPath|\[filter |textconv|^\s*\[alias\]|=\s*!", text, re.M
        ):
            add("HIGH", "git-config-exec", rel, 0, ".git/config contains settings that can execute commands")


def walk() -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(ROOT, followlinks=False):
        # report symlinked dirs (os.walk lists them in dirnames but does not follow)
        for d in list(dirnames):
            p = os.path.join(dirpath, d)
            if os.path.islink(p):
                handle_symlink(p)
                dirnames.remove(d)
        for fn in filenames:
            yield os.path.join(dirpath, fn)


SENSITIVE = re.compile(
    r"(^|/)(\.ssh|\.aws|\.gnupg|\.kube|\.docker|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.config/gcloud|etc|root|proc|var/run)(/|$)"
)


def handle_symlink(p: str) -> None:
    global cur_dep
    cur_dep = None  # walk() calls this between files; a symlink escape is never summarized away
    stats["symlinks"] += 1
    rel = os.path.relpath(p, ROOT)
    try:
        tgt = os.readlink(p)
        real = os.path.realpath(p)
    except OSError:
        return
    # a venv's bin/python -> the system python is normal; any other link out of the project is not
    venv_python = any(x in (".venv", "venv") for x in rel.split("/")) and os.path.basename(tgt).startswith("python")
    if not (real == ROOT or real.startswith(ROOT + os.sep)) and not venv_python:
        sev = "HIGH" if SENSITIVE.search(tgt) else "MEDIUM"  # a link to a cache dir is noise; to ~/.ssh or /etc is not
        add(sev, "symlink-escape", rel, 0, "symlink points outside the project: %s" % tgt)


def scan_one(p: str) -> None:
    global cur_dep
    cur_dep = None
    rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
    name = os.path.basename(p)
    if any(ord(c) in range(0x202A, 0x202F) or ord(c) in range(0x2066, 0x206A) for c in rel):
        add("HIGH", "trojan-source-filename", rel, 0, "bidi control char in file NAME (disguised extension)")
    if os.path.islink(p):
        handle_symlink(p)
        return
    try:
        st = os.lstat(p)
    except OSError:
        return
    if not stat.S_ISREG(st.st_mode):
        add("MEDIUM", "special-file", rel, 0, "non-regular file (fifo/socket/device)")
        return
    stats["files"] += 1
    parts = rel.split("/")
    in_deps = any(x in DEP_DIRS for x in parts)
    top = next((i for i, x in enumerate(parts[:-1]) if x in DEP_DIRS + BUILD_DIRS), None)
    if top is not None:
        in_deps = True
        cur_dep = "/".join(parts[: top + 1])
    text, head = read_text(p)
    if text is None:
        stats["binary_files"] += 1
        ext = os.path.splitext(name)[1].lower()
        if not in_deps and (head == "large" or ext in ARCHIVE_EXT or ext in CODE_EXT):
            why = "over 2 MB" if head == "large" else "archive" if ext in ARCHIVE_EXT else "code file with NUL bytes"
            add("MEDIUM", "unscanned-file", rel, 0, "content not inspected (%s); review it by hand" % why)
        if isinstance(head, bytes) and head:
            for magic, label in MAGIC[:5]:
                if head.startswith(magic):
                    if is_object_file(head):
                        if not in_deps:
                            add("MEDIUM", "binary-artifact", rel, 0, "compiled object file in repo")
                        break
                    if ".bin" in parts:
                        cur_dep = None  # node_modules/.bin is on PATH for `npm run`: never summarized away
                    add("HIGH", "binary-executable", rel, 0, "%s committed to repo" % label)
                    break
        elif (
            st.st_size
            and name.lower().endswith(
                (".exe", ".dll", ".so", ".dylib", ".node", ".jar", ".class", ".pyc", ".whl", ".msi", ".scr", ".bin")
            )
            and not in_deps
        ):
            add("MEDIUM", "binary-artifact", rel, 0, "binary artifact in repo")
        return
    stats["text_files"] += 1
    ext = os.path.splitext(name)[1].lower()
    is_code = ext in CODE_EXT or name in CODE_NAMES or text.startswith("#!")
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
            if ext in (".md", ".rst", ".adoc") and sev in ("CRITICAL", "HIGH") and rid != "trojan-source":
                sev = "MEDIUM"  # prose that quotes `curl | sh` or ~/.ssh does not run; still listed
            if rid == "trojan-source" and not is_code:
                sev = "MEDIUM"  # bidi chars in scraped data are common; in code they hide logic
            if rid == "long-b64-blob" and ext in (".lock", ".json", ".svg", ".map"):
                continue
            if rid == "lockfile-foreign-host" and name not in LOCKFILES:
                continue
            if rid == "pkg-source-override" and not re.search(
                r"(requirements|\.npmrc|\.yarnrc|pip\.conf|\.txt$)", rel, re.I
            ):
                continue
            m = rx.search(line)
            if m:
                s = max(0, m.start() - 20)
                add(sev, rid, rel, i, desc, line[s : s + 160])
    if hex_names >= 10 and not in_deps:
        add(
            "HIGH",
            "obfuscated-js",
            rel,
            0,
            "%d identifiers of the form _0x1234 (javascript-obfuscator style)" % hex_names,
        )


def main() -> None:
    global cur_dep
    for p in walk():
        try:
            scan_one(p)
        except Exception as e:  # fail closed: a crash on one file is itself a finding, never a lost scan
            cur_dep = None
            add("HIGH", "scanner-error", os.path.relpath(p, ROOT), 0, "scanner crashed on this file: %r" % e)
    for d, hits in dep_hits.items():
        seen = ", ".join("%s x%d" % kv for kv in sorted(hits.items()))
        add("MEDIUM", "dependency-findings", d, 0, "not inspected individually; patterns seen inside: " + seen)
    json.dump({"stats": stats, "findings": findings, "suppressed": suppressed}, sys.stdout)


main()
