# Handoff: sandbox_scan.py (untrusted-code scanner)

## Goal
A programmer receives code from others that they must edit locally but can't trust. They asked (1) how to check it safely (VM? Docker microVM? remote server? Vagrant?) and (2) for a Python script that pushes a codebase to a disposable remote machine, scans it for malicious code, and says what to do next. They want to be "sure" they can work on the code.

## Advice already given (don't re-litigate)
- Plain Docker shares the host kernel, so it is not enough for hostile code. gVisor, Kata or Firecracker microVMs are better. A snapshot-reverted local VM is solid. A disposable cloud VM or Codespace with no credentials is best.
- Vagrant is only a VM wrapper, and its default `/vagrant` synced folder shares the host project dir (disable it).
- Most attacks fire before "running": npm postinstall, setup.py, build backends, `.vscode/tasks.json` `runOn: folderOpen`, devcontainer `initializeCommand`, `.envrc`, git hooks and git config, dependency typosquats.
- No scanner proves safety. "Clean" means "no known red flags", so a first run in a disposable environment with no secrets is still advised.

## Deliverable
`/home/claude/sandbox_scan.py` (single file, stdlib only locally; already sent to the user). Don't paste it here; read it.

How it works:
- It packs the folder into a tar.gz (strips setuid and world-write bits, skips special files).
- It uploads over ssh/scp with `-F /dev/null`, no agent, no forwarding, and a dedicated `--key`.
- On the VM it runs an embedded stdlib heuristic scanner (`REMOTE_SCANNER`), then semgrep (`p/security-audit`) and GuardDog in a venv. It never executes or installs anything from the codebase.
- Only `results.tgz` (JSON) comes back and is read in memory. Output is stripped of control chars.
- Modes: `--host user@ip --key K` (user's own fresh VM) or `--provision digitalocean` (via `doctl`; creates an ephemeral key and droplet, destroys both in `finally` unless `--keep`).
- Verdicts and exit codes:
  - DO NOT USE → 2
  - SUSPICIOUS - MANUAL REVIEW REQUIRED → 1
  - INCONCLUSIVE - SCAN INCOMPLETE → 1
  - NO RED FLAGS, BUT REVIEW THE NOTES → 0
  - NO KNOWN RED FLAGS → 0
- Each verdict prints next steps (`NEXT_STEPS`). It also writes `report.json`.
- Severity policy: the built-in rules and GuardDog drive the verdict. Semgrep results are only MEDIUM or LOW. A missing semgrep result forces INCONCLUSIVE.

## Verified vs not verified
Verified locally (fake booby-trapped repo and clean repo):
- The scanner flagged b64-exec, pipe-to-shell, reverse-shell, vscode-autorun-task, npm-lifecycle-script, git-hook, git-config-exec, exfil-endpoint, env-exfil, typosquats, trojan-source, symlink-escape and binary-executable.
- The clean repo produced no findings.
- Pack, results parsing, verdict logic and rendering worked in a simulated pipeline.
- The CLI argument checks worked.

NOT verified:
- Real SSH/scp transfer to a VM.
- DigitalOcean provisioning and teardown (`doctl` flags and output parsing: `--format ID,PublicIPv4 --no-header`).
- semgrep and GuardDog installing and running on a fresh Ubuntu 24.04 droplet.
- GuardDog CLI invocation and JSON shape (`guarddog npm|pypi scan <dir> --output-format json`; results are parsed defensively as `results: {rule: truthy}`).
- The remote driver's `python3 -m venv` fallback via apt.

## Known limitations and ideas
- Static only. It doesn't audit transitive dependencies that `npm install` or `pip install` would fetch.
- Line-by-line regexes miss multi-line patterns. Typosquat lists are small (about 50 names per ecosystem) and may produce false positives, such as `color` vs `colors`.
- Possible additions:
  - Hetzner, AWS or GCP provisioners.
  - osv-scanner and gitleaks on the VM.
  - A `--no-provision` dry run that scans locally.
  - Unit tests with fixture repos.
  - A markdown report.
  - Other languages' manifests (Cargo, Gradle, Maven, Go).
  - Optional dynamic sandbox stage (network-off container or microVM with strace).
- The script's remote host trust is `StrictHostKeyChecking=accept-new` with a temp known_hosts, which is fine for throwaway VMs.

## Suggested skills for the next agent
- `anthropic-skills:tdd`: to add fixture-based tests for the scanner rules and the verdict logic.
- `anthropic-skills:docs`: only if the user wants a README or usage guide as a doc.
- No other skills are required.

## Next-session focus
The user hasn't stated one. Likely candidates: test the script against a real VM, add a provider, or harden detection. Ask which.
