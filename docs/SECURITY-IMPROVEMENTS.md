# Security improvements: where `sandbox-scan` is less certain than it looks

## Summary

Nothing here makes a project provably safe; static analysis cannot. The question is narrower: where does the tool
currently say "no red flags" (exit 0) or lose findings when it should not, and what is the cheapest way to close that.

Method (2026-11-18): read `README.md`, `docs/RESEARCH.md`, `docs/DECISION-LOG.md` and every file in `src/sandbox_scan/`;
ran `make test` (97 passed, 2 deselected); ran `remote_scanner.py` on 20 tiny inert probe folders written in the
scratchpad (one dangerous-looking line each, hosts end in `.invalid`, nothing executed); fed the results to
`report.merge_findings` and `report.verdict`. Every "probe" result below comes from those runs. Claims marked
**unverified** come from memory and were not checked.

The four findings that matter most, all measured:

1. A one-line `package.json` (`[1]`, or `"scripts": "x"`) anywhere outside dependency folders crashes the heuristic
   scanner (`AttributeError`). All heuristic findings are lost and DO NOT USE (exit 2) becomes INCONCLUSIVE (exit 1).
2. Putting a payload in any folder named `dist`, `build`, `out`, `target`, `vendor` or `third_party`, at any depth,
   turns a CRITICAL `pipe-to-shell` into one MEDIUM `dependency-findings` line: verdict "NO RED FLAGS, BUT REVIEW THE
   NOTES", exit 0.
3. A script is silently not scanned if it is larger than 2 MB, has a NUL byte in its first 8000 bytes, or is UTF-16 (a
   valid encoding for `.ps1`). Same for a payload inside a `.zip`. Each gave zero findings and would get exit 0.
4. A GuardDog crash is only a plain note, not `Incomplete`, so it can end in "NO KNOWN RED FLAGS" although GuardDog is
   the only third-party signal that can reach HIGH.

All four are small fixes. After them, returns drop fast: more line rules chase obfuscation that a regex scanner cannot
win against.

## Ranked improvements

Ranking is by certainty gained per unit of work. Effort: S is under a day with a test, M a few days, L a week or more.

| Id  | Gap                                                                                                                                                        | Effect on security                                                                                                                        | Effort | Evidence from the repo                                                                                                                                                                                                             |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Scanner crashes on a hostile `package.json`; no per-file error handling in `main()`/`structural()`                                                         | An attacker downgrades DO NOT USE to INCONCLUSIVE and hides every CRITICAL line from the report                                           | S      | Probe: `package.json` = `[1]` gives `AttributeError: 'list' object has no attribute 'get'`; `{"scripts":"x"}` gives `'str' object has no attribute 'items'`. `merge_findings` then returns INCONCLUSIVE, exit 1                    |
| 2   | `BUILD_DIRS` and `DEP_DIRS` match a folder name at any depth, and CRITICAL hits there become one MEDIUM line                                               | Any payload moved into `dist/`, `src/build/`, `lib/vendor/` gets exit 0; `"main": "dist/index.js"` is a normal place for code that runs   | S      | Probe: `dist/run.sh`, `src/build/helper.sh`, `lib/vendor/x.sh` with `curl ... \| sh` each give one MEDIUM `dependency-findings`; `verdict()` returns `NO RED FLAGS, BUT REVIEW THE NOTES`, 0. `structural()` is also skipped there |
| 3   | Files read as "binary" or "large" are not scanned and not reported: > 2 MB, NUL in the first 8000 bytes, UTF-16, unknown binaries, archives                | Padding a script, adding one NUL byte, saving `.ps1` as UTF-16, or zipping the payload removes it from view while the verdict stays clean | S      | Probes `big`, `nul`, `utf16`, `zip`: 0 findings each. `stats.skipped_large` exists but `render()` never prints it; `.zip`/`.tgz`/`.7z` are not in the `binary-artifact` list                                                       |
| 4   | GuardDog failure is a plain note, not `Incomplete`                                                                                                         | The only HIGH-capable third-party scanner can fail and the report still says NO KNOWN RED FLAGS                                           | S      | Measured: heuristics clean, semgrep ok, `guarddog_npm.err` = traceback gives `('NO KNOWN RED FLAGS', 0)`. Contrast semgrep, which is `Incomplete`                                                                                  |
| 5   | No evasion regression test: the fixture tests that rules fire, not that simple disguises fail closed                                                       | Gaps 1 to 3 were invisible to 97 passing tests; the next refactor can reopen them                                                         | S      | `tests/test_e2e.py` checks 29 rules on the author's own fixture; `docs/RESEARCH.md` 4.1 calls it "a regression test, not a detection rate"                                                                                         |
| 6   | "Clean" does not say what was not inspected                                                                                                                | The user reads exit 0 as coverage of the whole folder; it is coverage of text files under 2 MB outside dependency and build folders       | S      | `render()` prints files/text/binary/symlinks only; suppressed hits are a note, skipped files are not                                                                                                                               |
| 7   | Lockfiles are not checked: `resolved` URLs off the registry, `uv.lock`/`poetry.lock` sources                                                               | A lockfile that points `react` at an attacker's tarball installs it on `npm ci`; the manifest looks normal                                | S      | Probe `lock`: `package-lock.json` with `"resolved": "https://evil.invalid/react-18.2.0.tgz"` gave 0 findings. `long-b64-blob` explicitly skips `.lock` and `.json`                                                                 |
| 8   | Code-only rules skip extensions not in `CODE_EXT`: `.mts`, `.cts`, `.pyw`, `.ipynb`, `.vue`, `.svelte`, `.gradle`, `.kts`, `.groovy`, `.fish`, `.swift`    | `persistence`, `dyn-exec`, `proc-spawn`, clipboard and screen rules do not run on those files                                             | S      | Probe: `~/.zshrc` append in `a.py` gives HIGH `persistence`; the same line in `a.mts` gives 0 findings                                                                                                                             |
| 9   | Missing install- or open-time triggers: `.pnpmfile.cjs`, `.yarnrc.yml` `plugins`, `.cargo/config.toml` wrappers, `.gitmodules` `ext::` URLs, `conftest.py` | Each runs code when the user runs a common command (`pnpm install`, `yarn`, `cargo build`, `pytest`); none raises a structural finding    | S each | Probes `pnpmf`, `yarnplug`, `cargocfg`, `gitmod`, `jetbrains`: 0 findings. Exact trigger semantics of each tool are **unverified** (from memory)                                                                                   |
| 10  | Invisible Unicode beyond the current set: Hangul filler U+3164/U+115F, tag characters U+E0000-E007F, LRM/RLM/ALM                                           | The "invisible backdoor" JavaScript trick (an identifier made of U+3164) passes; **unverified** that it still runs in current Node        | S      | Probe `hangul`: 0 findings. `zero-width` covers `​-‍⁠﻿` only; `trojan-source` covers `‪-‮⁦-⁩`                                                                                                                                      |
| 11  | semgrep and GuardDog are installed unpinned from PyPI on every run, with the network on during the scan                                                    | A compromised release runs inside the sandbox each time; a parser bug in semgrep/GuardDog on hostile input would have outbound network    | M      | `remote_driver.sh`: `pip install -q semgrep guarddog`; `local.docker_argv` has no `--network none`. Mitigated by the sandbox itself, so this is defence in depth, not a detection gain                                             |
| 12  | Known-malicious dependency lookup is absent                                                                                                                | Names and versions already reported as malware are not matched; typosquat only catches 1 edit from about 90 names                         | M      | `POP_NPM`/`POP_PYPI` lists in `remote_scanner.py`. OSV-Scanner reading the OpenSSF `malicious-packages` advisories would cover this (**unverified**, needs a test run)                                                             |
| 13  | No recall number on real malware                                                                                                                           | Without it every "clean" is a guess of unknown quality                                                                                    | M-L    | `docs/RESEARCH.md` section 6, item 2: "No detection rate". Only the own fixture and 33 GuardDog samples (28 any finding, 10 HIGH or CRITICAL) were measured                                                                        |
| 14  | semgrep "success" is any non-empty JSON, even if it scanned zero files or skipped some                                                                     | Small: semgrep is capped at MEDIUM. Matters only for the INCONCLUSIVE logic                                                               | S      | Measured: `{"results": [], "paths": {"scanned": []}}` gives NO KNOWN RED FLAGS. Whether semgrep honours a repo-supplied `.semgrepignore` or `.gitignore` and skips files over 1 MB by default is **unverified**                    |
| 15  | Obfuscation beyond fixed patterns: string splitting, `\x` escapes, `String.fromCharCode`, `getattr(__builtins__, ...)`, delayed or remote second stage     | Real, but a line regex cannot close it; each new rule is one more pattern for the attacker to avoid                                       | L      | Probe `split`: `c="cu""rl"; $c ... \| s""h` gave 0 findings. Only `_0x` identifiers are detected (`obfuscated-js`)                                                                                                                 |
| 16  | Dynamic analysis (install in the sandbox, record network and file access)                                                                                  | The strongest answer to items 15 and delayed payloads                                                                                     | L      | Contradicts the design rule "nothing from the codebase is ever executed" (`README.md`); listed for completeness                                                                                                                    |
| 17  | Local Docker shares the host kernel                                                                                                                        | Only matters if a parser bug becomes code execution and then a kernel exploit; `--provision` already avoids it                            | M      | Documented in `docs/RESEARCH.md` section 6, item 7. The container already drops all capabilities and sets `no-new-privileges`, pids and memory limits                                                                              |
| 18  | Host-side parsing of `results.tgz` from a compromised sandbox                                                                                              | Denial of service at most: a 50 MB cap per member and 100 members, but gzip is still decompressed to skip large members                   | S      | `report.read_results`; output is passed through `clean()` before printing                                                                                                                                                          |

## Worth doing

Status 2026-11-18: items 1 to 5 below are done (`docs/DECISION-LOG.md`). The lockfile `resolved`-host check is done too.

These five give the most certainty for the least work. All are S and none changes the design.

1. **Fail closed per file (item 1).** Wrap the per-file body of `main()` in `try/except Exception` and add a HIGH
   `scanner-error` finding with the file name, so one hostile file cannot erase the rest. A test with `package.json` =
   `[1]` next to a `curl | sh` line must still give DO NOT USE.
2. **Stop the `dist/` downgrade (item 2).** Summarize only real installed-dependency folders (`node_modules`, `.venv`,
   `venv`, `site-packages`), and only at the depth where they are normally found; for `dist`, `build`, `out`, `target`,
   `vendor`, `third_party` keep CRITICAL as HIGH (exit 1). Re-run `experiments/benign_fp.py` on the benign projects
   listed in `docs/RESEARCH.md` 4.3 to see the false-positive cost before choosing; that measurement is what makes it M
   rather than S if it is noisy.
3. **Make unscanned files visible (items 3 and 6).** Decode files with a UTF-16 BOM; give a MEDIUM `unscanned-file` to a
   code-extension file with NULs, to every file over 2 MB, and to archives (`.zip`, `.tar*`, `.tgz`, `.7z`, `.rar`); add
   a "Not inspected" line to the report header. A verdict of exit 0 then says what it did not cover.
4. **GuardDog failure is `Incomplete` (item 4).** When the driver ran GuardDog for an ecosystem and no JSON came back,
   wrap the note in `Incomplete`, as for semgrep. One line in `report.merge_findings` plus a test.
5. **One evasion regression test (item 5).** A parametrised test that builds the probes from this document (payload in
   `dist/`, NUL byte, padding past 2 MB, UTF-16 `.ps1`, zipped payload, crashing `package.json`) and asserts that the
   verdict is never exit 0. It turns this document into a check that a later change cannot silently undo.

If there is time for a sixth, the lockfile `resolved`-host check (item 7) is the cheapest real detection gain.

## Not worth doing

| Item                                         | Reason                                                                                                                                                                                                                               |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| More obfuscation rules (15)                  | Regex against obfuscation is an arms race with no end point; each rule adds false positives (`docs/RESEARCH.md` 4.3 shows the cost) and the attacker reads the rules. Treat "obfuscated or minified own code" as a reason for review |
| Dynamic analysis (16)                        | A different product. It breaks the "never execute" rule that makes the tool safe to run, and needs network capture, timeouts and anti-evasion work. If wanted, run the project in a throwaway VM by hand after the scan              |
| gVisor or Firecracker for `--local` (17)     | Protects against a chain of two bugs (parser RCE, then kernel exploit) in a scan that runs no attacker code; `--provision` already gives a separate kernel                                                                           |
| Full real-malware benchmark (13, full form)  | Backstabber's Knife Collection needs a request for access (**unverified**) and handling live malware; a few hundred OpenSSF or GuardDog samples run through the heuristics alone would answer "roughly how often" for far less       |
| Hardening host-side tar parsing (18)         | Worst case is a slow or failed scan, which already ends in exit 3, not "clean"                                                                                                                                                       |
| Bigger typosquat lists or registry lookups   | A static list ages; a known-malware lookup (item 12) answers the real question ("is this package reported bad") better                                                                                                               |
| Fixing semgrep "scanned nothing" first (14)  | semgrep can only add MEDIUM; the heuristics and GuardDog fixes above matter more                                                                                                                                                     |
| Every remaining trigger file (9) in one pass | Add a trigger only when it runs on a command a reviewer is likely to type (`pnpm install`, `cargo build`, `pytest`); JetBrains and `mise` configs need a trust prompt (**unverified**) and are rarer                                 |

Where "enough" ends: after the five items above and the lockfile check, the tool fails closed on the disguises tested
here and says what it did not read. Past that, certainty comes from the user's next step (open in a throwaway VM with no
secrets), not from more rules.
