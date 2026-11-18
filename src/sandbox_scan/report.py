"""Merge remote results into findings, pick a verdict, render the report."""

import json
import os
import tarfile
from pathlib import Path
from typing import Any, Literal, TypedDict, get_args

from .textutil import clean, log

RESULT_FILES = {
    "heuristics.json",
    "semgrep.json",
    "guarddog_npm.json",
    "guarddog_pypi.json",
    "status.txt",
    "heuristics.err",
    "semgrep.err",
    "guarddog_npm.err",
    "guarddog_pypi.err",
}
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]  # most severe first; remote_scanner.py repeats this type
SEVERITIES: tuple[Severity, ...] = get_args(Severity)
SEV_ORDER: dict[Severity, int] = {s: i for i, s in enumerate(SEVERITIES)}


class Finding(TypedDict):
    severity: Severity
    rule: str
    file: str
    line: int
    detail: str
    snippet: str


class Incomplete(str):
    """A note that says coverage is missing; verdict() reads the type, not the wording."""


def read_results(tgz_path: str | Path) -> dict[str, str]:
    out = {}
    with tarfile.open(tgz_path, "r:gz") as tf:
        for n, m in enumerate(tf):
            if n >= 100:  # we expect about 10 files; stop walking an archive a compromised VM made huge
                break
            if not m.isfile() or m.size > 50 * 1024 * 1024:
                continue
            name = os.path.basename(m.name)
            f = tf.extractfile(m) if name in RESULT_FILES else None
            if f is not None:
                out[name] = f.read().decode("utf-8", "replace")
    return out


def load_json(s: str) -> Any:  # noqa: ANN401 - arbitrary JSON
    try:
        return json.loads(s)
    except Exception:
        return None


def parse_finding(f: object) -> Finding | None:
    """Check one finding from the VM (untrusted JSON); None if it is not a well-formed Finding."""
    if not isinstance(f, dict):
        return None
    sev, line = f.get("severity"), f.get("line")
    if not isinstance(sev, str) or sev not in SEV_ORDER or not isinstance(line, int) or isinstance(line, bool):
        return None
    text = [f.get(k, "" if k == "snippet" else None) for k in ("rule", "file", "detail", "snippet")]
    if not all(isinstance(t, str) for t in text) or not f.get("rule"):
        return None
    return Finding(severity=sev, rule=text[0], file=text[1], line=line, detail=text[2], snippet=text[3])


def merge_findings(res: dict[str, str]) -> tuple[list[Finding], dict[str, Any], list[str], str]:
    findings: list[Finding] = []
    notes: list[str] = []
    h = load_json(res.get("heuristics.json", ""))
    if not isinstance(h, dict) or not isinstance(h.get("findings"), list):
        notes.append(Incomplete("Heuristic scanner produced no usable output - treat result as INCOMPLETE."))
        stats = {}
    else:
        parsed = [parse_finding(f) for f in h["findings"]]
        findings += [f for f in parsed if f]
        if bad := parsed.count(None):  # a finding we cannot read must lower trust, never vanish
            lost_critical = any(
                p is None and isinstance(f, dict) and f.get("severity") == "CRITICAL"
                for p, f in zip(parsed, h["findings"], strict=True)
            )
            findings.append(
                Finding(
                    severity="CRITICAL" if lost_critical else "HIGH",
                    rule="malformed-finding",
                    file="(scanner output)",
                    line=0,
                    detail=f"{bad} finding(s) from the VM were malformed and dropped; treat the scan as unreliable",
                    snippet="",
                )
            )
        stats = h.get("stats")
        suppressed = h.get("suppressed") or {}
        if not isinstance(stats, dict) or not isinstance(suppressed, dict):
            notes.append(Incomplete("Heuristic scanner stats are malformed - treat result as INCOMPLETE."))
            stats, suppressed = {}, {}
        for rule, n in suppressed.items():
            notes.append(f"{n} more '{rule}' hits were suppressed (per-file/per-rule caps).")
    sg = load_json(res.get("semgrep.json", ""))
    if sg:
        for r in sg.get("results", []):
            sev = (r.get("extra", {}).get("severity") or "INFO").upper()
            findings.append(
                Finding(
                    severity="MEDIUM" if sev == "ERROR" else "LOW",
                    rule="semgrep:" + r.get("check_id", "?").split(".")[-1],
                    file=r.get("path", "?").replace("code/", "", 1),
                    line=r.get("start", {}).get("line", 0),
                    detail=(r.get("extra", {}).get("message") or "")[:200],
                    snippet="",
                )
            )
    else:
        notes.append(Incomplete("Semgrep results missing (install failed or timed out) - coverage INCOMPLETE; re-run."))
        if err := res.get("semgrep.err", "").strip():
            notes.append("semgrep stderr: " + clean(err[-300:]))
    for eco in ("npm", "pypi"):
        gd = load_json(res.get(f"guarddog_{eco}.json", ""))
        if not gd:
            if f"guarddog_{eco}.err" in res:  # the driver ran it (the file exists) but it gave no result
                err = clean(res[f"guarddog_{eco}.err"].strip()[-300:])
                notes.append(
                    Incomplete(
                        f"guarddog ({eco}) gave no result - coverage INCOMPLETE" + (f"; stderr: {err}" if err else "")
                    )
                )
            continue
        results = gd.get("results") or {}
        for rule, val in results.items():
            if val:
                findings.append(
                    Finding(
                        severity="HIGH",
                        rule=f"guarddog-{eco}:{rule}",
                        file="(package)",
                        line=0,
                        detail="GuardDog malware heuristic matched",
                        snippet=json.dumps(val)[:200],
                    )
                )
    # dependency summaries first: render() shows only 15 MEDIUM lines and this is where a poisoned package would show
    findings.sort(
        key=lambda f: (
            SEV_ORDER.get(f["severity"], 9),
            f["rule"] != "dependency-findings",
            f["file"],
            f.get("line", 0),
        )
    )
    return findings, stats, notes, res.get("status.txt", "")


def verdict(findings: list[Finding], notes: list[str]) -> tuple[str, int]:
    sev = {f["severity"] for f in findings}
    incomplete = any(isinstance(n, Incomplete) for n in notes)
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


def render(
    findings: list[Finding], stats: dict[str, Any], notes: list[str], status: str, label: str, out_dir: Path
) -> None:
    log("\n" + "=" * 72)
    log(f" VERDICT: {label}")
    log("=" * 72)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    log(
        f" Files scanned: {stats.get('files', '?')}  (text {stats.get('text_files', '?')}, "
        f"binary {stats.get('binary_files', '?')}, symlinks {stats.get('symlinks', '?')})"
    )
    log(" Findings: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    if n := sum(1 for f in findings if f["rule"] == "unscanned-file"):
        log(f" Not inspected: {n} file(s) (large, archive or unreadable); see the unscanned-file lines")
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
    (out_dir / "report.json").write_text(
        json.dumps({"verdict": label, "stats": stats, "notes": notes, "status": status, "findings": findings}, indent=2)
    )
    log(f"\nFull report: {out_dir / 'report.json'}")
