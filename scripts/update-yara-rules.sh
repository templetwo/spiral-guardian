#!/bin/bash
set -euo pipefail

# Spiral Guardian — Weekly YARA rule updater

RULES_DIR="${GUARDIAN_YARA_RULES:-$HOME/guardian/yara-rules}"
mkdir -p "$RULES_DIR"

cd "$RULES_DIR"

if [ -d "protections-artifacts" ]; then
  cd protections-artifacts && git pull && cd ..
else
  git clone https://github.com/elastic/protections-artifacts.git
fi

if [ -d "rules" ]; then
  cd rules && git pull && cd ..
else
  git clone https://github.com/Yara-Rules/rules.git
fi

echo "[$(date)] YARA rules updated"
