#!/bin/bash
# steampipe_setup.sh
# ------------------
# Installs Steampipe, the AWS plugin, and wires it up to your
# existing cloud_security PostgreSQL database.
#
# Run this ONCE after you have an AWS account.
# For now (no AWS account) it sets everything up so you're ready to go.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$SCRIPT_DIR/steampipe_setup.log"

log() { echo "[$(date -u '+%H:%M:%S UTC')] $*" | tee -a "$LOG"; }

log "═══════════════════════════════════════════"
log "Steampipe Setup for AI Cloud Security Agent"
log "═══════════════════════════════════════════"

# ── 1. Install Steampipe ──────────────────────────────────────────────────────
if command -v steampipe &>/dev/null; then
    log "✓ Steampipe already installed: $(steampipe --version)"
else
    log "Installing Steampipe via Homebrew..."
    brew tap turbot/tap
    brew install steampipe
    log "✓ Steampipe installed: $(steampipe --version)"
fi

# ── 2. Install AWS plugin ─────────────────────────────────────────────────────
log "Installing Steampipe AWS plugin..."
steampipe plugin install aws
log "✓ AWS plugin installed"

# ── 3. Configure AWS plugin ───────────────────────────────────────────────────
PLUGIN_DIR="$HOME/.steampipe/config"
mkdir -p "$PLUGIN_DIR"

cat > "$PLUGIN_DIR/aws.spc" << 'EOF'
connection "aws" {
  plugin  = "aws"
  profile = "default"       # matches your ~/.aws/credentials profile
  regions = ["us-east-1"]   # add more regions as needed e.g. ["us-east-1", "us-west-2"]

  # Increase max connections to avoid throttling on large accounts
  max_error_retry_attempts = 9
  min_error_retry_delay    = 25
}
EOF
log "✓ AWS plugin config written to $PLUGIN_DIR/aws.spc"

# ── 4. Start Steampipe service (exposes Postgres on port 9193) ────────────────
log "Starting Steampipe service..."
steampipe service start
log "✓ Steampipe service running on port 9193"

# ── 5. Print connection info ──────────────────────────────────────────────────
log ""
log "Steampipe Postgres connection details:"
log "  Host:     localhost"
log "  Port:     9193"
log "  Database: steampipe"
log "  User:     steampipe"
log "  Password: (shown by: steampipe service status)"
log ""
log "Test with:"
log "  steampipe query \"select instance_id, instance_state, instance_type from aws_ec2_instance limit 5;\""
log ""
log "Done. Run steampipe_ingest.py to sync AWS inventory into cloud_security DB."
