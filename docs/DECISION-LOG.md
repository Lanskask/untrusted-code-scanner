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

## 2026-11-17 Docker e2e test is a separate target

- Decision: `make test` skips tests marked `e2e`; `make e2e` runs the real Docker scan.
- Reason: measured. `make test` took 70 s and needs network because of the Docker run; without it, 0.45 s.

## 2026-11-17 A failed droplet delete is reported loudly

- Decision: `DigitalOcean.destroy()` checks the exit code of `doctl compute droplet delete` and, on failure, prints that
  the droplet is still billing plus the exact command to run.
- Reason: the user asked whether the tool knows that only deleting stops billing. It deletes (never powers off), but it
  printed "destroyed" even when the delete failed, for example with a token without delete rights.

## 2026-11-18 Dependency and build folders are summarized, not scanned line by line

- Decision: CRITICAL/HIGH hits inside `node_modules`, `.venv`, `venv`, `site-packages`, `vendor`, `third_party`,
  `target`, `cargo-target`, `.next`, `dist`, `build` and `out` become one MEDIUM `dependency-findings` line per folder,
  listing the rules seen and their counts. Kept as HIGH: binaries in `node_modules/.bin`, and symlinks leaving the
  project, except a venv link to a `python*` executable.
- Reason: measured in `docs/RESEARCH.md`: 8 of 9 benign projects got DO NOT USE or SUSPICIOUS, almost all from these
  folders. Trade-off accepted by the user: a malicious package inside `node_modules` now shows as MEDIUM only (measured
  by `make e2e`: semgrep and GuardDog reported nothing under `node_modules` for the fixture, so do not count on them
  there), so a MEDIUM `dependency-findings` line with `reverse-shell` or `pipe-to-shell` deserves a manual look.

## 2026-11-17 Research document states that it proves nothing

- Decision: `docs/RESEARCH.md` is an honest engineering write-up (threat model, test-checked properties, measured runs,
  limits, unverified comparison), not a proof of security or detection.
- Reason: the user asked for a document proving the tool is secure and finds malicious code. Neither can be proven:
  static analysis is undecidable in general, and the only detection evidence is a fixture written by the rule author.
  Measured: 8 of 9 benign projects get DO NOT USE or SUSPICIOUS (mostly from `.venv`, `node_modules`, build output),
  which the document reports as the weakest property.

## 2026-11-18 `env-exfil` flags only the whole environment

- Decision: the rule matches `os.environ` or `process.env` only when not followed by `.`, `[` or a word character, next
  to a network call (`dict(os.environ)`, `JSON.stringify(process.env)`); `getenv` was dropped.
- Reason: measured. Reading one named variable beside `fetch(` fired on ordinary Next.js code (`EDU_Platform`). Accepted
  cost: one secret sent by name (`+process.env.NPM_TOKEN`) is no longer caught by this rule; `exfil-endpoint` still
  covers known endpoints. Data-flow analysis is out of reach for a line scanner.

## 2026-11-18 Bidi characters in non-code files, and object files, are MEDIUM

- Decision: `trojan-source` is MEDIUM outside code files (HIGH in code). A Mach-O `MH_OBJECT` or ELF `ET_REL` file is a
  MEDIUM `binary-artifact`; real executables stay HIGH. The header decides, never the `.o` name.
- Reason: measured. Scraped JSON data and compiler output caused the last 2 of 9 benign projects to be flagged. After
  these changes `experiments/benign_fp.py` flags 0 of 9.

## 2026-11-18 Reject flags the chosen mode would ignore; `--port`; swapped-letter typosquats

- Decision: `--key`, `--port` need `--host`; `--region`, `--size`, `--keep` need `--provision`; otherwise the CLI exits.
  `lev1` also accepts two adjacent swapped letters. `semgrep.err` is shipped back. `dependency-findings` lines sort
  first among MEDIUM lines.
- Reason: a silently ignored `--keep` or `--key` is a surprise on a tool that handles untrusted code. `semgrep.err` was
  read by `report.py` but never in `RESULT_FILES`, so the stderr note could not appear. `render()` shows only 15 MEDIUM
  lines sorted by name, which could hide the dependency summary.

## 2026-11-18 `--host` is tested end to end against a local sshd container

- Decision: `tests/test_e2e_ssh.py` runs the real `ssh`/`scp` path against a throwaway container on `127.0.0.1`.
  DigitalOcean is covered only by unit tests (including: the droplet is destroyed when ssh never comes up).
- Reason: real droplets cost money and the owner's rule is to show cloud commands and wait. The ssh transport, `--port`,
  the driver script and the report are the same code on both paths.

## 2026-11-18 Incomplete scans are a type, symlink escapes depend on the target, results tar is capped

- Decision: `verdict()` reads `isinstance(note, Incomplete)` instead of searching the text for `INCOMPLETE`.
  `symlink-escape` is HIGH when the target is sensitive (`.ssh`, `.aws`, `.gnupg`, `.kube`, `/etc`, `/root`, `/proc`,
  credentials files) and MEDIUM otherwise. `read_results` stops after 100 archive members. A new MEDIUM rule
  `env-secret-send` covers one secret-named variable (`TOKEN`, `SECRET`, `PASSW`, `KEY`, `CREDENTIAL`) next to a network
  call, the case the narrowed `env-exfil` no longer reports.
- Reason: a quoted word in a note must not change a verdict; wandb run logs link to a cache directory and flagged
  projects as HIGH; a compromised VM could return an enormous tar; the `env-exfil` change left a gap. `env-secret-send`
  stays MEDIUM because legitimate code does `fetch(url, {headers: {Authorization: process.env.KEY}})`.
- Not done: running `--provision digitalocean` for real (see `docs/RESEARCH.md` section 6).

## 2026-11-18 Wallet-theft rules; DigitalOcean region picked at run time

- Decision: new rules `wallet-theft` (HIGH), `seed-phrase-send` and `crypto-address-regex` (MEDIUM). `--provision` picks
  the first available region that offers the size unless `--region` is given. A failed ssh-key delete is reported.
- Reason: the user asked about wallet-stealing code (research in `docs/RESEARCH.md` section 5.1). The first real
  `--provision` run failed with `Size is not available in this region` in the default `nyc1`: availability changes, so a
  fixed default region is a bug found only by running it.

## 2026-11-18 GuardDog stderr is shipped back; semgrep flakiness closed as not reproducible

- Decision: `guarddog_npm.err` and `guarddog_pypi.err` are returned and shown as a note when GuardDog produced no
  result. No further work on the semgrep failure.
- Reason: measured. 39 sequential loop runs and 5 parallel full scans did not fail (`docs/RESEARCH.md` section 4.2), so
  more retries or code would be guesses. The failure stays observable (stderr in the report) and fail-closed.

## 2026-11-18 Tuning from a held-out check; docs are MEDIUM

- Decision: CRITICAL/HIGH line rules in `.md`, `.rst`, `.adoc` become MEDIUM; `py-exec-compile` needs decoding or
  fetching on the line; `cryptominer` needs `stratum+tcp://host:port`; exact `husky`, `husky install`, `patch-package`,
  `node-gyp rebuild` lifecycle values are skipped; typosquat skips names under 5 letters and `preact`.
- Reason: measured. On 11 projects the rules had never seen, 7 were flagged; reading each finding showed prose, a config
  loader, a test string and a git-hook installer (`docs/RESEARCH.md` section 4.3). After: 3 of 18 flagged, all with a
  reason to read. The earlier 0 of 9 was a fit to the tuning set.

## 2026-11-18 Second tuning round and new stealer-capability rules

- Decision: `reverse-shell` matches `os.dup2` only on a socket-like name; `persistence` needs `~/.profile` or
  `/.profile`; `npx only-allow` and `enquirer` are skipped; new MEDIUM rules `clipboard-read`, `screen-capture`,
  `env-dump`; Ruby `Net::HTTP`/`HTTParty`/`RestClient` and `ENV[...]` join `env-secret-send`.
- Reason: measured on 10 fresh projects (7 flagged before, 6 after, all by design) and on GuardDog's 33 sample files (22
  hit before, 28 after; only 10 reach HIGH). More HIGH rules would raise recall but the benign sets show where it costs:
  `proc-spawn` and `dyn-exec` stay MEDIUM.

## 2026-11-18 Project declared finished; one decision rule

- Decision: the project is finished at the current feature set. The README states one rule: exit 2 means do not open it;
  exit 0 means no known red flags, and unknown code is still opened only in a disposable environment. Open items
  (semgrep flakiness, by-design false positives, duplicate `guarddog-npm`/`guarddog-pypi` findings) are not worked on.
- Reason: my requirement (an "enough" tool, no endless work) and a theorem: whether arbitrary code is harmful is
  undecidable (Rice's theorem), so no scanner can certify "safe". Measured: 2 real DigitalOcean runs gave DO NOT USE and
  left no droplet (`docs/RESEARCH.md` section 4.4); 97 unit and 2 end-to-end tests pass. Further ideas are listed in
  `docs/SECURITY-IMPROVEMENTS.md`.

## 2026-11-18 Fail closed on hostile layouts (items 1 to 4 of the security review)

- Decision: a crash on one file gives a HIGH `scanner-error` instead of losing the scan; `dist`, `build`, `vendor` and
  similar folders keep CRITICAL as HIGH (only `node_modules`, `site-packages`, `.venv`, `venv` are fully summarized);
  files over 2 MB, archives and code files with NUL bytes give a MEDIUM `unscanned-file` and a "Not inspected" report
  line; UTF-16 files with a BOM are decoded; a GuardDog run with no result makes the scan INCOMPLETE.
- Reason: measured. A `package.json` of `[1]` crashed the scanner (reproduced), and the review's probes showed each
  disguise gave exit 0 or 1 for a `curl | sh`. 7 disguise tests now never give exit 0. False-positive cost measured on
  13 own projects before and after: 1 flagged both times, only 13 more MEDIUM lines, no new HIGH. Skipped as not worth
  it: more obfuscation rules, dynamic analysis (`docs/SECURITY-IMPROVEMENTS.md`).
