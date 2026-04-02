#!/bin/bash
set -euo pipefail

# Spiral Guardian — EICAR antivirus test
# Creates the standard EICAR test file and verifies detection

echo "=== EICAR Detection Test ==="

EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
TEST_FILE="/tmp/eicar-test-$(date +%s).txt"

echo "$EICAR" > "$TEST_FILE"
echo "Created test file: $TEST_FILE"

PASS=0
FAIL=0

# Test YARA-X
if command -v yr &>/dev/null; then
  echo -n "YARA-X: "
  if yr scan ~/guardian/yara-rules/rules/ "$TEST_FILE" 2>/dev/null | grep -qi "eicar"; then
    echo "DETECTED (PASS)"
    ((PASS++))
  else
    echo "NOT DETECTED (FAIL)"
    ((FAIL++))
  fi
else
  echo "YARA-X: not installed (SKIP)"
fi

# Test ClamAV (Jetson only)
if command -v clamscan &>/dev/null; then
  echo -n "ClamAV: "
  if clamscan --no-summary "$TEST_FILE" 2>/dev/null | grep -qi "found"; then
    echo "DETECTED (PASS)"
    ((PASS++))
  else
    echo "NOT DETECTED (FAIL)"
    ((FAIL++))
  fi
else
  echo "ClamAV: not installed (SKIP)"
fi

rm -f "$TEST_FILE"
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
