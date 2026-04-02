#!/bin/bash
set -euo pipefail

# Spiral Guardian — YARA-X scan wrapper
# Called via sudoers by guardian_user

TARGET="${1:-.}"
RULES_DIR="${GUARDIAN_YARA_RULES:-$HOME/guardian/yara-rules}"
LOG="/var/guardian/logs/yara-scan.log"

mkdir -p "$(dirname "$LOG")"

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] YARA scan: $TARGET" >> "$LOG"

if command -v yr &>/dev/null; then
  yr scan "$RULES_DIR/protections-artifacts/yara/rules/" "$TARGET" 2>&1 | tee -a "$LOG"
  yr scan "$RULES_DIR/rules/malware/" "$TARGET" 2>&1 | tee -a "$LOG"
elif command -v yara &>/dev/null; then
  yara -r "$RULES_DIR/rules/malware/index.yar" "$TARGET" 2>&1 | tee -a "$LOG"
else
  echo "ERROR: Neither yr (YARA-X) nor yara found in PATH" | tee -a "$LOG"
  exit 1
fi

echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] YARA scan complete" >> "$LOG"
