# sandbox-scan

Ship an untrusted codebase to a disposable VM, scan it there (static analysis only, nothing from the codebase is ever
executed), pull back a report and get a verdict with next steps. See `HANDOFF.md` for the design background.

## Usage

```bash
make setup
make run ARGS="./suspicious-code --host root@203.0.113.7 --key ~/.ssh/throwaway_ed25519"
make run ARGS="./suspicious-code --provision digitalocean"   # needs doctl; creates and destroys a droplet
make test
make lint
```

Exit codes: `2` DO NOT USE, `1` suspicious or inconclusive, `0` no red flags. "Clean" never means "proven safe".

## Layout

| Path                                 | Role                                                          |
| ------------------------------------ | ------------------------------------------------------------- |
| `src/sandbox_scan/cli.py`            | argument parsing and the 5-step flow                          |
| `src/sandbox_scan/pack.py`           | tar.gz of the folder (strips setuid and world-write bits)     |
| `src/sandbox_scan/remote.py`         | ssh/scp wrapper and the DigitalOcean provisioner              |
| `src/sandbox_scan/report.py`         | merge results, verdict, next steps, rendering                 |
| `src/sandbox_scan/remote_scanner.py` | heuristic scanner; uploaded and run on the VM, never imported |
| `src/sandbox_scan/remote_driver.sh`  | VM-side bash driver (heuristics, semgrep, GuardDog)           |
| `tests/`                             | fixture-based rule tests, verdict and packing tests           |
