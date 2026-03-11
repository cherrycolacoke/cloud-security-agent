#!/bin/bash
# deploy.sh
# ─────────────────────────────────────────────────────────────────────────────
# One-command deployment for the AI Cloud Security Agent.
# Runs on any machine with Docker installed (Mac, Linux, EC2).
#
# Usage:
#   bash deploy.sh              # start everything
#   bash deploy.sh --scan       # run a full scan now
#   bash deploy.sh --stop       # stop all containers
#   bash deploy.sh --logs       # tail dashboard logs
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

log()     { echo -e "${BLUE}[$(date -u '+%H:%M:%S')]${RESET} $*"; }
success() { echo -e "${GREEN}✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*"; }
error()   { echo -e "${RED}✗${RESET}  $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Handle flags ──────────────────────────────────────────────────────────────
case "${1:-start}" in
  --stop)
    log "Stopping all containers..."
    docker compose down
    success "Stopped."
    exit 0
    ;;
  --logs)
    docker compose logs -f dashboard
    exit 0
    ;;
  --scan)
    log "Running full scan now..."
    docker compose run --rm scanner
    exit 0
    ;;
  --sample)
    log "Running sample scan (no AWS needed)..."
    docker compose run --rm scanner python3 run_full_scan.py --sample
    exit 0
    ;;
esac

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   AI Cloud Security Agent — Deployment       ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""

# ── Check prerequisites ───────────────────────────────────────────────────────
log "Checking prerequisites..."

command -v docker &>/dev/null  || error "Docker not installed. Get it at https://docs.docker.com/get-docker/"
docker compose version &>/dev/null || error "Docker Compose not installed."
command -v aws &>/dev/null     || warn "AWS CLI not found — scans won't work but dashboard will still start."

success "Docker $(docker --version | awk '{print $3}' | tr -d ',')"
success "Docker Compose $(docker compose version --short)"

# ── Check .env ────────────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  warn ".env not found — creating from .env.example"
  cp .env.example .env
  echo ""
  echo -e "${YELLOW}Please edit .env and set your values, then run this script again.${RESET}"
  echo -e "  ${BOLD}nano .env${RESET}"
  echo ""
  exit 1
fi

source .env
success ".env loaded"

# ── Check accounts.yaml ───────────────────────────────────────────────────────
if [ ! -f "accounts.yaml" ]; then
  error "accounts.yaml not found. Copy accounts.yaml and fill in your AWS account details."
fi
success "accounts.yaml found"

# ── Check AWS credentials ─────────────────────────────────────────────────────
if aws sts get-caller-identity &>/dev/null; then
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
  success "AWS credentials valid — account ${ACCOUNT_ID}"
else
  warn "AWS credentials not configured — dashboard will start but scans will fail."
  warn "Run: aws configure"
fi

# ── Start the stack ───────────────────────────────────────────────────────────
echo ""
log "Building and starting containers..."
docker compose up -d --build

# ── Wait for Postgres to be healthy ──────────────────────────────────────────
log "Waiting for database to be ready..."
for i in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U "${PGUSER:-secadmin}" &>/dev/null; then
    success "Database is ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    error "Database failed to start. Run: docker compose logs postgres"
  fi
  sleep 2
done

# ── Get dashboard URL ─────────────────────────────────────────────────────────
DASHBOARD_IP=$(curl -sf http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "localhost")

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   ✓ Deployment Complete!                     ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard:${RESET}  http://${DASHBOARD_IP}"
echo ""
echo -e "  ${BOLD}Run a scan:${RESET}"
echo -e "    bash deploy.sh --scan          ${BLUE}# full live scan${RESET}"
echo -e "    bash deploy.sh --sample        ${BLUE}# sample data (no AWS needed)${RESET}"
echo ""
echo -e "  ${BOLD}Other commands:${RESET}"
echo -e "    bash deploy.sh --logs          ${BLUE}# tail dashboard logs${RESET}"
echo -e "    bash deploy.sh --stop          ${BLUE}# stop everything${RESET}"
echo -e "    docker compose logs -f         ${BLUE}# all container logs${RESET}"
echo ""
