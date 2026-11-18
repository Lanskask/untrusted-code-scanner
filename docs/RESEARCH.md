# Static pre-screening of untrusted code in a disposable sandbox: design, evidence and limits of `sandbox-scan`

## Abstract

Developers regularly receive code from people they cannot vouch for: a take-home test, a client repository, a "quick
fix" from a stranger. Much of the danger fires before anyone runs the program: an npm `postinstall` script, a
`.vscode/tasks.json` task set to `runOn: folderOpen`, a git hook, a build backend. `sandbox-scan` ships such a folder to
a throwaway environment, analyses it statically (nothing from the folder is executed), and returns a verdict with next
steps. This document states what the tool does, which design properties are checked by tests, what was measured, and
what cannot be claimed. **It does not prove that the tool is secure, and it does not prove that the tool finds malicious
code.** No static scanner can show that code is safe, and the evidence below is one hand-made attack fixture and nine
benign projects (most of them flagged), not a benchmark.

## 1. Problem and threat model

**Asset:** the developer's machine and credentials (SSH keys, cloud tokens, browser data).

**Attacker:** the author of the code. They control every byte of the folder: file names, symlinks, file contents,
manifests, hidden folders such as `.git` and `.vscode`.

**What the attacker wants:** code execution on the developer's machine, by a route that needs little more than "open it"
or "install it".

**What the tool must protect against, in its own operation:**

1. The scan itself must not run anything from the folder (no `npm install`, no `pip install`, no `import`).
2. The folder must not touch the developer's machine more than a read (no mount into a container, no shared agent).
3. The scan output (file names, snippets) is attacker-controlled text and must not attack the terminal.
4. A hostile folder must not be able to make the scan silently fail and look clean.

**Out of scope:** kernel or hypervisor escapes (Docker shares the host kernel, a documented limit); malware that is
obfuscated beyond the patterns; backdoors in the transitive dependencies that `npm install` would fetch; logic bugs that
are not malicious in form.

## 2. Method

Three execution modes run the same pipeline (pack, upload, scan, pull back JSON, render):

| Mode                       | Environment                                          | Cost        |
| -------------------------- | ---------------------------------------------------- | ----------- |
| `--local`                  | hardened Docker container on the developer's machine | free        |
| `--host user@ip --key K`   | the user's own fresh VM, over `ssh`/`scp`            | the VM      |
| `--provision digitalocean` | a droplet the tool creates and deletes (via `doctl`) | a few cents |

Analysis has three layers: (a) a stdlib-only heuristic scanner (`remote_scanner.py`) with about 30 line rules and many
file-level rules (lifecycle scripts, autorun editor tasks, devcontainer commands, git hooks, symlink escapes,
executables, Trojan Source characters, typosquatted package names); (b) Semgrep with the `p/security-audit` rule set;
(c) GuardDog, a package malware scanner. Findings map to five verdicts and exit codes: DO NOT USE (2), SUSPICIOUS (1),
INCONCLUSIVE (1), NO RED FLAGS BUT REVIEW THE NOTES (0), NO KNOWN RED FLAGS (0). Semgrep results can never raise the
verdict above MEDIUM; a missing Semgrep result forces INCONCLUSIVE.

## 3. Design properties and how each is checked

These are properties of the code, enforced by tests in `tests/test_invariants.py` unless noted. They are checks that
fail if a later change breaks them, not proofs.

| Property                                                                          | Check                                                |
| --------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Host code never calls `eval`, `exec`, `compile`, `os.system`, or `shell=True`     | AST scan of every host module                        |
| The VM-side scanner cannot spawn processes, open sockets, or load code            | import and call scan of `remote_scanner.py`          |
| Docker mounts only the tool's own temp folder; never the untrusted folder         | argv test                                            |
| No `--privileged`, host network, host PID, published ports or `docker.sock`       | argv test                                            |
| Container: all capabilities dropped, `no-new-privileges`, pids and memory limits  | argv test (`tests/test_local.py`)                    |
| Base image pinned by digest, not by a movable tag                                 | argv test                                            |
| `ssh` ignores user config and agent, no forwarding, dedicated key                 | option test                                          |
| Packed archive strips setuid and world-write bits, skips fifos/sockets/devices    | pack tests; symlinks stored as links, never followed |
| Every terminal control character and bidi override in output is neutralised       | parametrised test over C0, C1 and bidi characters    |
| A missing result is never reported as clean                                       | `merge_findings({})` gives INCONCLUSIVE              |
| A CRITICAL finding always yields DO NOT USE                                       | verdict test, with and without incomplete notes      |
| A paid droplet is deleted even if creation failed midway; a failed delete is loud | cleanup tests with a fake `doctl`                    |

Known weak spot: the verdict recognises an incomplete scan by looking for the word `INCOMPLETE` in note text. A test
covers the current wording, but the coupling is fragile.

## 4. Measured results

All numbers below come from runs executed for this document on one macOS machine (Colima, Docker, image
`python:3.12-slim` pinned by digest, Semgrep 1.185.0). Date: 2026-11-17.

### 4.1 Attack fixture

`tests/fixtures/malicious_project/` is a hand-written, inert project that imitates 29 distinct attack patterns (hosts
end in `.invalid` or use documentation IP ranges; nothing in it is ever run).

| Run                                  | Result                                                                                     |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| Heuristic scanner alone              | all 29 expected rules fired (`tests/test_e2e.py`)                                          |
| Full `sandbox-scan --local` (Docker) | verdict DO NOT USE, exit 2; CRITICAL=8, HIGH=40, MEDIUM=5; GuardDog fired for npm and PyPI |
| Fixture folder before and after      | byte-identical (hash compared), so the scan only read it                                   |

**Caveat that matters:** the fixture was written by the same person who wrote the rules, in the same session. A rule
that fires on its own author's example says little about unseen attacks. This is a regression test, not a detection
rate.

### 4.2 Bugs the end-to-end run found

- A symlink to `/etc` made `tar` fail while unpacking (`Cannot utime: Permission denied`), aborting the scan with
  exit 3. A hostile repository could therefore avoid being scanned. Fixed with `tar -m`. The unit tests had missed it
  because they never ran the real driver.
- Semgrep failed intermittently (exit 1, empty stderr) in 3 of about 7 container runs, never by hand. Cause unknown. The
  driver now keeps stderr and retries once. While Semgrep is missing the verdict is INCONCLUSIVE, never clean.
- `destroy()` printed "destroyed" when `doctl ... delete` had failed. Now it reports the failure and the command to stop
  billing.
- Semgrep, second look: after the retry and the stderr capture (`semgrep.err` was only now shipped back to the report)
  the fixture was scanned 5 times in parallel in local containers. All 5 had no semgrep failure. The earlier failures
  happened while the first image pull and installs were running, so a network or load cause is plausible, but it was not
  reproduced and the cause stays unknown.
- Also measured: a reverse shell planted in `node_modules` yields one MEDIUM `dependency-findings` line; semgrep and
  GuardDog report nothing there.

### 4.3 Benign projects (false positives)

The heuristic scanner alone (no Semgrep or GuardDog) was run on 9 of the author's own projects, which are assumed benign
(not audited). Counts are CRITICAL and HIGH findings; "own code" means outside dependency and build folders
(`node_modules`, `.venv`, `target`, `.next`).

| Project                 | Files | CRITICAL | HIGH | In own code                                                                     |
| ----------------------- | ----- | -------- | ---- | ------------------------------------------------------------------------------- |
| `EDU_Platform`          | 697   | 0        | 27   | 4 `env-exfil` (Next.js reads `process.env` near a `fetch(`), plus 21 in `.next` |
| `Price_of_Living`       | 7369  | 4        | 6    | none: all in `.venv`                                                            |
| `fast-jira-replacement` | 1423  | 5        | 6    | none: all in `scripts/.venv`                                                    |
| `instagram_summariser`  | 7094  | 16       | 47   | none: all in `.venv`                                                            |
| `lean-be-service`       | 6063  | 0        | 60   | none: compiled Rust output flagged `binary-executable`                          |
| `software_factory`      | 2106  | 6        | 5    | none: all in `.venv`                                                            |
| `thumbnail-generator`   | 3436  | 0        | 2    | none: one in `node_modules/unenv`, one Trojan Source hit in `node_modules/vite` |
| `tiny_triaging_layer`   | 145   | 0        | 0    | clean                                                                           |
| `Looking_for_a_Job`     | 744   | 0        | 1    | 1 `trojan-source` in a scraped JSON data file                                   |

Result before the fix: **8 of 9 benign projects would receive DO NOT USE or SUSPICIOUS; only 1 of 9 is clean.** Four of
them would be DO NOT USE purely because they contain a Python virtual environment. Causes:

- Dependency folders were scanned for CRITICAL and HIGH line rules by design, because a poisoned dependency is a real
  attack route. Ordinary libraries contain `pipe-to-shell` text, `persistence` strings (`.bashrc`) and `exec(compile(`
  in their code. Every virtual environment also has `bin/python` symlinks that point outside the project, which fired
  `symlink-escape`.
- Build output (`target/release`, `.next`) was reported as "committed to repo".
- `env-exfil` fires on any line that mixes `process.env` and `fetch(`.

#### After the fix (PR #5, then the rule changes below)

CRITICAL and HIGH hits inside dependency and build folders become one MEDIUM `dependency-findings` line per folder.
Binaries in `node_modules/.bin` and symlinks that leave the project stay HIGH, except a venv link to a `python*`
executable. A first re-run left 2 of 9 projects SUSPICIOUS: `EDU_Platform` (6 `env-exfil`) and `Looking_for_a_Job` (1
`trojan-source` in scraped JSON). Two rule changes followed: `env-exfil` only matches the whole environment, and bidi
characters in non-code files are MEDIUM. Object files (`.o`) are MEDIUM too. Final run, same 9 projects, saved as
`experiments/benign_fp.py`:

| Project                 | Files | CRITICAL | HIGH | MEDIUM |
| ----------------------- | ----- | -------- | ---- | ------ |
| `EDU_Platform`          | 697   | 0        | 0    | 1      |
| `Price_of_Living`       | 7369  | 0        | 0    | 1      |
| `fast-jira-replacement` | 1423  | 0        | 0    | 1      |
| `instagram_summariser`  | 7094  | 0        | 0    | 131    |
| `lean-be-service`       | 777   | 0        | 0    | 83     |
| `software_factory`      | 2119  | 0        | 0    | 57     |
| `thumbnail-generator`   | 3436  | 0        | 0    | 61     |
| `tiny_triaging_layer`   | 145   | 0        | 0    | 0      |
| `Looking_for_a_Job`     | 744   | 0        | 0    | 17     |

**0 of 9 are flagged (was 8 of 9).** `lean-be-service` went from 6063 to 777 files between runs; the cause was not
checked. The rules were tuned on these same 9 projects, so this is a fit to them, not a measured false-positive rate.

Costs, stated plainly:

- A malicious package inside `node_modules` now shows as MEDIUM, not CRITICAL. The fixture now contains one (a reverse
  shell in `node_modules/evil/index.js`); `make e2e` checks that its `dependency-findings` line names `reverse-shell`.
  Semgrep and GuardDog reported nothing under `node_modules`, so this single MEDIUM line is the only signal.
- One secret sent by name (`+process.env.NPM_TOKEN`) is no longer caught by `env-exfil`.
- Only benign projects were measured. The malicious fixture still gives DO NOT USE.

## 5. Comparison with existing tools

Everything in this section comes from web searches and from general knowledge, and is **unverified**: no tool below was
run side by side with `sandbox-scan`.

| Tool                                       | What it does                                                          | Difference from `sandbox-scan`                                                                     |
| ------------------------------------------ | --------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| GuardDog (DataDog)                         | heuristic and Semgrep-based malware detection for npm, PyPI, Go, etc. | We run it, but also check editor, git and devcontainer triggers it does not target, and sandbox it |
| Semgrep                                    | pattern-based static analysis for bugs and security                   | Tuned for your own code; we use it only as a MEDIUM-level signal                                   |
| OSV-Scanner, `npm audit`, `pip-audit`      | match dependencies against known-vulnerability or malware advisories  | Look up names and versions; they do not read the folder's own scripts                              |
| Socket, Phylum and similar services        | analyse packages in registries, often as a paid service               | Registry-centric and hosted; we scan an arbitrary local folder and send nothing to a vendor        |
| ClamAV and antivirus engines               | signature matching for known binaries                                 | Weak on source-level lures; complementary                                                          |
| Dynamic sandboxes (Cuckoo-style, microVMs) | run the sample and watch behaviour                                    | Stronger against obfuscation, much heavier; `sandbox-scan` never executes the code                 |

Stated benefit, bounded by the above: one command that checks the "fires on open or install" triggers, runs the other
scanners inside a throwaway environment, and fails closed. Not claimed: better detection than any listed tool.

Test corpora found by search (unverified): Backstabber's Knife Collection (real malicious npm, PyPI and RubyGems
packages, access by request), the OpenSSF `malicious-packages` repository (OSV-format reports), and the Trojan Source
proof-of-concept repository. A 2026 npm benchmark reportedly gives GuardDog an F1 of 93.32 percent (arXiv 2603.27549).
`sandbox-scan` has not been run on any of these.

## 6. Limitations

1. **No guarantee.** Static analysis cannot decide whether a program is malicious (Rice's theorem). "No known red flags"
   means exactly that.
2. **No detection rate.** There is no measured recall on real malware and no benchmark run.
3. **Line-based rules** miss patterns split over lines, and encodings or obfuscation outside the patterns.
4. **False positives:** reduced on projects that ship dependencies or build output (section 4.3), still 2 of 9 benign
   projects flagged (see above: 0 of 9 after rule tuning on the same projects).
5. **Typosquat check** uses a small name list; it catches one edit or one adjacent swap only.
6. **Dependency and build folders** (`node_modules`, `vendor`, `.venv`, `target`, `dist` and similar) are reduced to one
   MEDIUM summary line each; individual hits there are not reported, so a poisoned dependency is easier to miss.
7. **Container isolation** shares the host kernel. For stronger isolation use `--provision` or a VM.
8. **Untested paths:** DigitalOcean provisioning has never run against a real droplet; only fake-`doctl` unit tests
   cover it. The SSH/`scp` mode is tested end to end against a local sshd container, not a real VM. GuardDog's JSON
   shape is parsed defensively and was seen only through the fixture.
9. **Semgrep flakiness** (section 4.2): 3 failures in about 7 runs earlier, 0 in 5 later; cause unknown.
10. **Not run for real:** `--provision digitalocean` (a droplet would cost money and the run was not permitted in this
    session).

## 7. Is this article-worthy?

No. It is an engineering write-up. The idea (scan before open, in a sandbox, fail closed) is not new, there is no
benchmark, and the one finding of interest (a symlink aborting extraction) is a bug fix. A publishable result would need
the corpora in section 5, measured precision and recall against GuardDog and Semgrep alone, and an adversarial test by
someone other than the rule author.

## 8. Reproduce

```bash
make test    # fast checks, including the invariants
make e2e     # real Docker scan of the attack fixture, about a minute
```
