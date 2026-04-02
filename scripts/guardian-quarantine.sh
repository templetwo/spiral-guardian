#!/bin/bash
set -euo pipefail

# Spiral Guardian — Privileged quarantine wrapper
# Called via sudoers by guardian_user ONLY
# NEVER accepts raw paths — operates on SHA256 hashes

ACTION="${1:-list}"
TARGET="${2:-}"

QUARANTINE_DIR="/var/guardian/quarantine"
METADATA_DIR="/var/guardian/quarantine-metadata"

mkdir -p "$QUARANTINE_DIR" "$METADATA_DIR"

case "$ACTION" in
  isolate)
    [ -z "$TARGET" ] && { echo "ERROR: hash required"; exit 1; }
    FILE=$(find /Users/vaquez -type f -exec shasum -a 256 {} + 2>/dev/null | grep "^$TARGET" | head -1 | awk '{print $2}')
    if [ -z "$FILE" ]; then
      echo "ERROR: No file found with hash $TARGET"
      exit 1
    fi
    BASENAME=$(basename "$FILE")
    mv "$FILE" "$QUARANTINE_DIR/${TARGET}_${BASENAME}"
    echo "{\"action\":\"isolate\",\"hash\":\"$TARGET\",\"original_path\":\"$FILE\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$METADATA_DIR/${TARGET}.json"
    echo "QUARANTINED: $FILE"
    ;;
  release)
    [ -z "$TARGET" ] && { echo "ERROR: hash required"; exit 1; }
    META="$METADATA_DIR/${TARGET}.json"
    [ ! -f "$META" ] && { echo "ERROR: No record for $TARGET"; exit 1; }
    ORIGINAL_PATH=$(python3 -c "import json; print(json.load(open('$META'))['original_path'])")
    QUARANTINED_FILE=$(ls "$QUARANTINE_DIR/${TARGET}_"* 2>/dev/null | head -1)
    mv "$QUARANTINED_FILE" "$ORIGINAL_PATH"
    rm "$META"
    echo "RELEASED: $ORIGINAL_PATH"
    ;;
  list)
    echo "=== Quarantined Files ==="
    ls -la "$QUARANTINE_DIR/" 2>/dev/null || echo "(empty)"
    echo "=== Metadata ==="
    for f in "$METADATA_DIR"/*.json; do
      [ -f "$f" ] && cat "$f" && echo
    done
    ;;
  *)
    echo "Usage: guardian-quarantine.sh {isolate|release|list} [sha256-hash]"
    exit 1
    ;;
esac
