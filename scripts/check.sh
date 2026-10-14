#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

case "${TEST_RUNS:-2}" in
  ''|*[!0-9]*|0) echo 'TEST_RUNS must be a positive integer' >&2; exit 2 ;;
esac
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
for ((run = 1; run <= ${TEST_RUNS:-2}; run++)); do
  echo "Rust test run $run/${TEST_RUNS:-2}"
  cargo test --locked --all-features
done
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 -m unittest discover -s tests -p 'test_*.py'
shellcheck install.sh scripts/check.sh scripts/install-skill.sh overlay/usr/bin/mimic-mount
python3 scripts/smoke-test.py --binary "${CARGO_TARGET_DIR:-target}/debug/mimictl"
