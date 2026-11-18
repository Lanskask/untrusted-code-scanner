"""Question: how many projects that are assumed benign does the heuristic scanner flag?

Usage: python3 experiments/benign_fp.py DIR [DIR ...]   (each DIR is one project; paths are arguments, not committed)

Answer (2026-11-18): own 9 projects 8 flagged before tuning, 0 after (a fit). Held-out: 5 more own projects plus
flask, requests, express, lodash, fastapi, axios flagged 7 of 11 before tuning, 3 of 18 after. Fresh set: django,
pytest, black, react, vue core, svelte, gin, ripgrep, click, httpx flagged 7 of 10 before tuning.
The numbers belong in docs/RESEARCH.md section 4.3, which is the place to read them.
"""

import collections
import json
import subprocess
import sys
from importlib import resources

SCANNER = str(resources.files("sandbox_scan").joinpath("remote_scanner.py"))


def main(dirs: list[str]) -> None:
    flagged = 0
    for d in dirs:
        try:
            out = subprocess.run([sys.executable, "-I", SCANNER, d], capture_output=True, text=True, timeout=300)
            r = json.loads(out.stdout)
        except Exception as e:  # keep going: one huge or broken project must not hide the rest
            print(f"{d}: FAILED ({type(e).__name__})")
            continue
        sev = collections.Counter(f["severity"] for f in r["findings"])
        high = collections.Counter(f["rule"] for f in r["findings"] if f["severity"] in ("CRITICAL", "HIGH"))
        flagged += bool(high)
        print(f"{d}: files={r['stats']['files']} C={sev['CRITICAL']} H={sev['HIGH']} M={sev['MEDIUM']} {dict(high)}")
    print(f"flagged {flagged} of {len(dirs)}")


if __name__ == "__main__":
    main(sys.argv[1:])
