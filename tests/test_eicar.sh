#!/bin/bash
set -euo pipefail

# Spiral Guardian — EICAR antivirus detection test
#
# v1.1.0 FAIL-CLOSED FIX. The v1.0.0 version skipped each scanner that was not
# installed, and then exited 0 when PASS=0 and FAIL=0 — reporting success
# having tested absolutely nothing. On this machine, where neither YARA nor
# ClamAV is installed, it printed two SKIPs and a green exit code.
#
# Exit codes:
#   0 — at least one scanner ran AND every scanner that ran detected EICAR
#   1 — a scanner ran and failed to detect EICAR
#   3 — NO scanner was available; nothing was tested (NOT a pass)

echo "=== EICAR Detection Test ==="

EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
TEST_FILE="$(mktemp -t eicar-test).txt"
trap 'rm -f "$TEST_FILE"' EXIT

printf '%s\n' "$EICAR" > "$TEST_FILE"
echo "Created test file: $TEST_FILE"

PASS=0
FAIL=0
AVAILABLE=0

RULES_DIR="${GUARDIAN_YARA_RULES:-$HOME/guardian/yara-rules}"

if command -v yr &>/dev/null && [ -d "$RULES_DIR" ]; then
  AVAILABLE=$((AVAILABLE + 1))
  echo -n "YARA-X: "
  if yr scan "$RULES_DIR" "$TEST_FILE" 2>/dev/null | grep -qi "eicar"; then
    echo "DETECTED (PASS)"; PASS=$((PASS + 1))
  else
    echo "NOT DETECTED (FAIL)"; FAIL=$((FAIL + 1))
  fi
else
  echo "YARA-X: UNAVAILABLE (binary or rule set absent) — not tested"
fi

if command -v clamscan &>/dev/null; then
  AVAILABLE=$((AVAILABLE + 1))
  echo -n "ClamAV: "
  if clamscan --no-summary "$TEST_FILE" 2>/dev/null | grep -qi "found"; then
    echo "DETECTED (PASS)"; PASS=$((PASS + 1))
  else
    echo "NOT DETECTED (FAIL)"; FAIL=$((FAIL + 1))
  fi
else
  echo "ClamAV: UNAVAILABLE (not installed) — not tested"
fi

echo ""
echo "Scanners available: $AVAILABLE | passed: $PASS | failed: $FAIL"

if [ "$AVAILABLE" -eq 0 ]; then
  echo "RESULT: INCONCLUSIVE — no malware scanner is installed, so NOTHING was tested."
  echo "This is NOT a passing result."
  exit 3
fi

if [ "$FAIL" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi

echo "RESULT: PASS"
exit 0
