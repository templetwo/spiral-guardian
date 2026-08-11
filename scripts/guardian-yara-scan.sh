#!/bin/bash
set -euo pipefail

# Spiral Guardian — YARA scan wrapper
# Called via sudoers by guardian_user.
#
# v1.1.0: logs to GUARDIAN_HOME instead of /var/guardian (which required root),
# and exits 3 — a distinct code — when no scanner is installed, so "no scanner"
# can never be mistaken for "scanned, nothing found".
#
# NOTE: neither yr (YARA-X) nor yara is installed on the Mac Studio as of
# 2026-08-10, and no rule set has been fetched. Run update-yara-rules.sh first.

TARGET="${1:-.}"
RULES_DIR="${GUARDIAN_YARA_RULES:-$HOME/guardian/yara-rules}"
GUARDIAN_HOME="${GUARDIAN_HOME:-$HOME/.sovereign/guardian}"
LOG="$GUARDIAN_HOME/logs/yara-scan.log"

mkdir -p "$(dirname "$LOG")"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] YARA scan: $TARGET" >> "$LOG"

if [ ! -d "$RULES_DIR" ]; then
  echo "ERROR: rule directory $RULES_DIR does not exist. Run update-yara-rules.sh." | tee -a "$LOG"
  exit 4
fi

if command -v yr &>/dev/null; then
  SCANNER=yr
elif command -v yara &>/dev/null; then
  SCANNER=yara
else
  echo "ERROR: neither yr (YARA-X) nor yara found in PATH — NOTHING WAS SCANNED." | tee -a "$LOG"
  exit 3
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] using scanner: $SCANNER" >> "$LOG"

if [ "$SCANNER" = "yr" ]; then
  for rules in "$RULES_DIR/protections-artifacts/yara/rules/" "$RULES_DIR/rules/malware/"; do
    [ -d "$rules" ] || { echo "SKIP (absent): $rules" | tee -a "$LOG"; continue; }
    yr scan "$rules" "$TARGET" 2>&1 | tee -a "$LOG"
  done
else
  INDEX="$RULES_DIR/rules/malware/index.yar"
  [ -f "$INDEX" ] || { echo "ERROR: $INDEX missing" | tee -a "$LOG"; exit 4; }
  yara -r "$INDEX" "$TARGET" 2>&1 | tee -a "$LOG"
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] YARA scan complete" >> "$LOG"
