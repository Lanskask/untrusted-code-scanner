set -u
W=/tmp/scan
cd "$W"
rm -rf code results && mkdir -p code results
# GNU tar strips leading '/' and refuses '..' members by default.
tar --no-same-owner --no-same-permissions -xzf code.tgz -C code || { echo "extract failed" >&2; exit 3; }
python3 scanner.py code > results/heuristics.json 2> results/heuristics.err || echo "heuristic scanner failed" >> results/status.txt

export DEBIAN_FRONTEND=noninteractive
if ! python3 -m venv venv >/dev/null 2>&1; then
  apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq python3-venv python3-pip >/dev/null 2>&1
  python3 -m venv venv >/dev/null 2>&1 || echo "venv unavailable" >> results/status.txt
fi
if [ -x venv/bin/pip ] && venv/bin/pip install -q semgrep guarddog >pip.log 2>&1; then
  echo "tools: semgrep+guarddog installed" >> results/status.txt
  timeout 900 venv/bin/semgrep scan --config p/security-audit --metrics off --json --quiet --disable-version-check code \
      > results/semgrep.json 2> results/semgrep.err || echo "semgrep failed/timeout" >> results/status.txt
  if find code -name package.json -not -path '*/node_modules/*' | grep -q .; then
    timeout 600 venv/bin/guarddog npm scan code --output-format json > results/guarddog_npm.json 2> results/guarddog_npm.err || true
  fi
  if find code \( -name setup.py -o -name pyproject.toml \) -not -path '*/node_modules/*' | grep -q .; then
    timeout 600 venv/bin/guarddog pypi scan code --output-format json > results/guarddog_pypi.json 2> results/guarddog_pypi.err || true
  fi
else
  echo "tools: could not install semgrep/guarddog (heuristics only)" >> results/status.txt
fi
tar -czf results.tgz -C results .
echo done
