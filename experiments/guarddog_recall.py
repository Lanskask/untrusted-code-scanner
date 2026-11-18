"""Question: does the heuristic scanner flag sample code that other people wrote as malicious test cases?

Usage: python3 experiments/guarddog_recall.py PATH/TO/guarddog/tests/analyzer/sourcecode

GuardDog's rule-test samples mark the lines a rule must catch with a `ruleid:` comment. Each such file is scanned alone;
"hit" means the heuristics reported at least one finding of any severity. Samples are inert test snippets written by
GuardDog's authors; they are only read, never run. A hit says nothing about precision, and GuardDog's rules target
different things than ours, so misses are expected. Answer: see docs/RESEARCH.md section 5.2.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from pathlib import Path

SCANNER = str(resources.files("sandbox_scan").joinpath("remote_scanner.py"))


def main(root: str) -> None:
    hits = misses = 0
    for f in sorted(Path(root).rglob("*")):
        if not f.is_file() or "ruleid:" not in f.read_text(errors="replace"):
            continue
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(f, Path(d) / f.name)
            out = subprocess.run([sys.executable, "-I", SCANNER, d], capture_output=True, text=True, timeout=60)
            found = json.loads(out.stdout)["findings"]
        if found:
            hits += 1
            print(f"HIT  {f.name}: {sorted({x['rule'] for x in found})}")
        else:
            misses += 1
            print(f"MISS {f.name}")
    print(f"hits {hits}, misses {misses}, of {hits + misses}")


if __name__ == "__main__":
    main(sys.argv[1])
