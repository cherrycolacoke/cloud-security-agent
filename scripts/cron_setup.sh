#!/bin/bash
# cron_setup.sh
# -------------
# Sets up nightly cron job for the AI Cloud Security Agent.
# Run this ONCE to install the cron job.
#
# Usage: bash cron_setup.sh

PROJECT_DIR="$HOME/Desktop/cloud-security-agent"
PYTHON="$PROJECT_DIR/.venv/bin/python3"
LOG="$PROJECT_DIR/logs/cron.log"
ENV_FILE="$PROJECT_DIR/.env"

# ── Verify everything exists ─────────────────────────────────────────────────
echo "Checking project setup..."

[ -f "$PYTHON" ]             || { echo "ERROR: venv not found at $PYTHON"; exit 1; }
[ -f "$ENV_FILE" ]           || { echo "ERROR: .env not found at $ENV_FILE"; exit 1; }
[ -f "$PROJECT_DIR/run_full_scan.py" ] || { echo "ERROR: run_full_scan.py not found"; exit 1; }

echo "✓ Python venv: $PYTHON"
echo "✓ .env file:   $ENV_FILE"
echo "✓ Orchestrator: $PROJECT_DIR/run_full_scan.py"

# ── Create logs directory ────────────────────────────────────────────────────
mkdir -p "$PROJECT_DIR/logs"

# ── The cron line ─────────────────────────────────────────────────────────────
# Runs at 1:00am every night
# Sources .env so DB credentials and AWS profile are available
# Logs output to cron.log
CRON_LINE="0 1 * * * source $ENV_FILE && cd $PROJECT_DIR && $PYTHON run_full_scan.py >> $LOG 2>&1"

# ── Install cron job ──────────────────────────────────────────────────────────
# Check if already installed
if crontab -l 2>/dev/null | grep -q "run_full_scan.py"; then
    echo ""
    echo "⚠  Cron job already installed. Current crontab:"
    crontab -l | grep "run_full_scan"
    echo ""
    read -p "Replace it? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Skipped."
        exit 0
    fi
    # Remove old entry
    crontab -l | grep -v "run_full_scan" | crontab -
fi

# Add new entry
(crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -

echo ""
echo "✓ Cron job installed:"
echo "  $CRON_LINE"
echo ""
echo "Verify with:  crontab -l"
echo "Check logs:   tail -f $LOG"
echo "Remove cron:  crontab -r"
