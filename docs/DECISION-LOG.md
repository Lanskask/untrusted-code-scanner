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

## 2026-11-17 Inert attack fixture is committed; items git cannot hold are built in `conftest.py`

- Decision: `tests/fixtures/malicious_project/` holds the text attacks (hosts end in `.invalid`, nothing is ever run).
  `tests/conftest.py::malicious_project` copies it and adds `.git/hooks`, `.git/config`, an ELF header in
  `node_modules/.bin`, Trojan Source characters and a symlink to `/etc`.
- Reason: a symlink to `/etc` in the repo made pytest's collection crash with `PermissionError`, and git cannot store
  `.git/` contents. ruff, ty and pytest skip `tests/fixtures`.

## 2026-11-17 `tar -m` when the driver extracts the code

- Decision: `remote_driver.sh` extracts with `tar -m` (do not set mtimes).
- Reason: measured. The e2e test on the fixture failed with `tar: escape_link: Cannot utime: Permission denied`: a
  hostile symlink aborted the whole scan with exit 3, so a repo could dodge scanning. Found by the e2e test, not by the
  unit tests.

## 2026-11-17 semgrep keeps stderr and is retried once

- Decision: dropped `--quiet`; one retry; each failed attempt is logged with its exit code.
- Reason: measured. semgrep failed with exit 1 and empty stderr on 3 of about 7 runs, never when run by hand (including
  on the same fixture). Cause unknown; `--quiet` hid it.

## 2026-11-17 Invariant tests instead of a proof language

- Decision: rules that must not break live in `tests/test_invariants.py` (AST checks, argv checks, fail-closed verdict).
  Bend 2 `LAWS.bend` was not adopted.
- Reason: see the Bend answer in the session; the proofs would cover a Bend model, not the Docker, ssh and semgrep calls
  that carry the risk, and no tool makes a scanner "100% secure".
