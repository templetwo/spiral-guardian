#!/bin/bash
set -euo pipefail

# Spiral Guardian — Restic backup script
# Runs nightly via launchd/cron

REPO="${GUARDIAN_BACKUP_REPO:-/Volumes/BackupDrive/spiral-guardian-backup}"
export RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-$HOME/.config/restic/password}"

echo "[$(date)] Starting backup..."

restic backup --repo "$REPO" --tag "temple-vault" ~/temple-vault/
restic backup --repo "$REPO" --tag "research" ~/liminal-k-ssm/ ~/phenomenological-compass/ ~/context-field-conditioning/ 2>/dev/null || true
restic backup --repo "$REPO" --tag "config" ~/.ssh/ ~/.config/claude/ ~/.gitconfig

restic forget --repo "$REPO" --keep-daily 7 --keep-weekly 4 --keep-monthly 12 --prune

echo "[$(date)] Backup complete"
