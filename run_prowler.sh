#!/bin/bash
# run_prowler.sh
# Runs Prowler and ingests findings into PostgreSQL automatically.
# Works for single or multi-account setups.

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/prowler_cron.log"
VENV="$SCRIPT_DIR/.venv/bin/python"

# Load env vars (DB creds, AWS profile, etc.)
source "$SCRIPT_DIR/.env"

# ── Logging ───────────────────────────────────────────────────────────────────
log() { echo "[$(date -u '+%H:%M:%S UTC')] $*" | tee -a "$LOG_FILE"; }

log "───────────────────────────────────────────"
log "Starting Prowler scan + ingest"

# ── Run Prowler + ingest ──────────────────────────────────────────────────────
log "Running Prowler..."
"$VENV" "$SCRIPT_DIR/prowler_ingest.py" --run 2>&1 | tee -a "$LOG_FILE"

log "Done."
