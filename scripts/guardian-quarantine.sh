#!/bin/bash
set -euo pipefail

# Spiral Guardian — Privileged quarantine wrapper
# Called via sudoers by guardian_user ONLY.
# NEVER accepts raw paths — operates on SHA256 hashes.
#
# v1.1.0 changes:
#   * GUARDIAN_HOME replaces the hardcoded /var/guardian (which required root).
#   * The search root is no longer hardcoded to /Users/vaquez — that is the
#     MacBook's username and this script also runs on the Mac Studio, where it
#     would have silently found nothing and reported "no file with that hash".
#   * The hash argument is validated as a 64-character hex digest before it is
#     used in a glob or a filename.
#   * `find | shasum` over an entire home directory is extremely expensive.
#     GUARDIAN_SCAN_ROOT should be pointed at the narrowest plausible subtree.

ACTION="${1:-list}"
TARGET="${2:-}"

GUARDIAN_HOME="${GUARDIAN_HOME:-$HOME/.sovereign/guardian}"
QUARANTINE_DIR="$GUARDIAN_HOME/quarantine"
METADATA_DIR="$GUARDIAN_HOME/quarantine-metadata"
SCAN_ROOT="${GUARDIAN_SCAN_ROOT:-$HOME}"

mkdir -p "$QUARANTINE_DIR" "$METADATA_DIR"

validate_hash() {
  if [ -z "$1" ]; then
    echo "ERROR: sha256 hash required" >&2
    exit 1
  fi
  if ! printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "ERROR: not a 64-character lowercase sha256 hex digest" >&2
    exit 1
  fi
}

case "$ACTION" in
  isolate)
    validate_hash "$TARGET"
    echo "Searching $SCAN_ROOT for sha256 $TARGET (this can take a long time)..."
    FILE=$(find "$SCAN_ROOT" -type f -exec shasum -a 256 {} + 2>/dev/null \
             | grep "^$TARGET" | head -1 | awk '{print $2}')
    if [ -z "$FILE" ]; then
      echo "ERROR: no file with hash $TARGET under $SCAN_ROOT"
      echo "NOTE: this means NOT FOUND IN THE SEARCHED SUBTREE, not that the file does not exist."
      exit 1
    fi
    BASENAME=$(basename "$FILE")
    mv "$FILE" "$QUARANTINE_DIR/${TARGET}_${BASENAME}"
    printf '{"action":"isolate","hash":"%s","original_path":"%s","timestamp":"%s"}\n' \
      "$TARGET" "$FILE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$METADATA_DIR/${TARGET}.json"
    echo "QUARANTINED: $FILE"
    ;;
  release)
    validate_hash "$TARGET"
    META="$METADATA_DIR/${TARGET}.json"
    [ ! -f "$META" ] && { echo "ERROR: no quarantine record for $TARGET"; exit 1; }
    ORIGINAL_PATH=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['original_path'])" "$META")
    QUARANTINED_FILE=$(find "$QUARANTINE_DIR" -maxdepth 1 -name "${TARGET}_*" | head -1)
    [ -z "$QUARANTINED_FILE" ] && { echo "ERROR: metadata exists but the quarantined file is missing"; exit 1; }
    [ -e "$ORIGINAL_PATH" ] && { echo "ERROR: $ORIGINAL_PATH already exists; refusing to overwrite"; exit 1; }
    mv "$QUARANTINED_FILE" "$ORIGINAL_PATH"
    rm "$META"
    echo "RELEASED: $ORIGINAL_PATH"
    ;;
  list)
    echo "=== Quarantined Files ($QUARANTINE_DIR) ==="
    ls -la "$QUARANTINE_DIR/" 2>/dev/null || echo "(empty)"
    echo "=== Metadata ==="
    shopt -s nullglob
    FOUND=0
    for f in "$METADATA_DIR"/*.json; do
      cat "$f"; echo; FOUND=1
    done
    [ "$FOUND" -eq 0 ] && echo "(no quarantine records)"
    ;;
  *)
    echo "Usage: guardian-quarantine.sh {isolate|release|list} [sha256-hash]"
    exit 1
    ;;
esac
