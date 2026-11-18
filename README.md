# sandbox-scan

Ship an untrusted codebase to a disposable VM, scan it there (static analysis only, nothing from the codebase is ever
executed), pull back a report and get a verdict with next steps. `HANDOFF.md` is the original single-file design note
(historical; the code now lives in `src/sandbox_scan/`).

## How to read the verdict

Exit 2 (DO NOT USE): do not open, run or install it. Exit 0: no known red flags, which is not proof of safety (static
scanning cannot prove that); open unknown code in a VM or devcontainer anyway.

## Usage

```bash
make setup
make run ARGS="./suspicious-code --local"                    # free, needs Docker
make run ARGS="./suspicious-code --host root@203.0.113.7 --key ~/.ssh/throwaway_ed25519 [--port 2222]"
make run ARGS="./suspicious-code --provision digitalocean"   # needs doctl; creates and destroys a droplet
make test      # fast unit tests
make e2e       # real Docker scans (about 2.5 minutes): --local and --host over a local sshd container
make lint
```

## Prerequisites

On your machine (all modes):

- Python 3.11 or newer, and [`uv`](https://docs.astral.sh/uv/) (`make setup` and `make install` use it).
- `make` (ships with macOS and most Linux distributions).

Per mode, install only what that mode needs:

| Mode                       | You need                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `--local` (free)           | Docker running (Docker Desktop or Colima) whose VM shares `$HOME` read-write; internet to pull the image   |
| `--host user@ip --key K`   | OpenSSH client (`ssh`, `scp`); your own fresh Ubuntu-like VM with `python3`, `bash`, `tar` and internet    |
| `--provision digitalocean` | `doctl` logged in (`doctl auth init`), `ssh-keygen`, and a DigitalOcean account (paid; billed per droplet) |

The VM or container downloads `semgrep` and `guarddog` rules and packages on the fly (`pip`, plus `apt` for
`python3-venv` if missing). Without internet the scan still runs the built-in heuristics but reports
`INCONCLUSIVE - SCAN INCOMPLETE`.

Droplet size: the default `--size s-2vcpu-4gb` (Basic, 4 GiB RAM, 2 vCPUs, about $24 per month) is what this tool
requests. Smaller tiers (512 MiB, 1 GiB) are untested here; installing `semgrep` and `guarddog` is likely too heavy for
them. Check DigitalOcean's current billing rules before a long run. The droplet exists for a few minutes and is
destroyed after the scan.

### DigitalOcean setup (`--provision`)

```bash
doctl auth login --scopes "read write"   # opens the browser; "read" alone cannot create a droplet
doctl account get                         # check that it works
```

The tool runs `doctl compute ssh-key import|delete` and `doctl compute droplet create|list|delete`, so it needs write
access. A personal access token with custom scopes limited to droplets and SSH keys (`doctl auth init`) is narrower; the
exact scope names are not verified here. The scan always ends by deleting the droplet and the key (power-off would keep
billing). If a delete fails, the tool prints `FAILED to delete droplet ... IT IS STILL BILLING` with the exact
`doctl compute droplet delete <id>` command; run it, then check `doctl compute droplet list`. With `--keep` nothing is
deleted.

## Install and local scan

```bash
make install                                  # global `sandbox-scan` command (editable: keep this repo in place)
sandbox-scan ~/Downloads/some-code --local    # free: hardened Docker container, folder is never mounted
```

`make install` puts the command in `~/.local/bin`; run `uv tool update-shell` if it is not on your `PATH`. `--local`
needs a running Docker whose VM shares `$HOME` read-write (Docker Desktop, Colima; Lima mounts it read-only by default).

Exit codes: `2` DO NOT USE, `1` suspicious or inconclusive, `0` no red flags, `3` the scan could not run (nothing was
judged). "Clean" never means "proven safe". Flags that the chosen mode would ignore (for example `--key` with `--local`)
are rejected instead of silently dropped.

Dependency and build folders (`node_modules`, `.venv`, `target`, `dist` and similar) are not inspected file by file:
each becomes one MEDIUM `dependency-findings` line that lists the patterns seen inside. Read those lines.

## Layout

| Path                                 | Role                                                          |
| ------------------------------------ | ------------------------------------------------------------- |
| `src/sandbox_scan/cli.py`            | argument parsing and the 5-step flow                          |
| `src/sandbox_scan/local.py`          | hardened `docker run` for `--local`                           |
| `src/sandbox_scan/textutil.py`       | `log()` and `clean()` (strips control characters)             |
| `src/sandbox_scan/pack.py`           | tar.gz of the folder (strips setuid and world-write bits)     |
| `src/sandbox_scan/remote.py`         | ssh/scp wrapper and the DigitalOcean provisioner              |
| `src/sandbox_scan/report.py`         | merge results, verdict, next steps, rendering                 |
| `src/sandbox_scan/remote_scanner.py` | heuristic scanner; uploaded and run on the VM, never imported |
| `src/sandbox_scan/remote_driver.sh`  | VM-side bash driver (heuristics, semgrep, GuardDog)           |
| `tests/`                             | rule, verdict, invariant and e2e tests; inert attack fixture  |
| `experiments/`                       | saved analysis scripts (false-positive measurement)           |
