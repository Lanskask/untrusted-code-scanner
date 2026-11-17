# Decision log

## 2026-11-17 Split the single file into a `src/` package

- Decision: `sandbox_scan.py` became the `sandbox_scan` package. The VM-side scanner and bash driver are real files
  (`remote_scanner.py`, `remote_driver.sh`) that `cli.py` reads with `importlib.resources` and uploads.
- Reason: the user asked not to have the scanner embedded as a string; python-pro layout (src, pyproject, ruff, ty,
  pytest).
- The scanner is shipped, not imported: it must run on the VM with stdlib only and must never execute on the local
  machine.

## 2026-11-17 `remote_scanner.py` moved verbatim

- Decision: no style rewrite; ruff style rules and `ty` skip this one file.
- Reason: behavior-preserving refactor, verified by characterization tests. Restyling a dense regex table is risk
  without benefit.

## 2026-11-17 Literal bidi and zero-width characters replaced by `\uXXXX` escapes

- Reason: the scanner's own regexes contained literal Trojan Source characters; a security tool should not ship source
  that hides characters in review. Regex semantics are identical.
