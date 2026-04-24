#!/bin/bash
# =============================================================================
# check_health.sh
# Honeypot project health check script
# Run as: bash /home/cowrie/honeypot/scripts/check_health.sh
# =============================================================================

# ── Paths ─────────────────────────────────────────────────────────────────────
LOG_FILE="/home/cowrie/honeypot/logs/raw-logs/cowrie.json"
DB_FILE="/home/cowrie/honeypot/logs/analysis/honeypot.db"
DASHBOARD_URL="http://localhost:5000"
LOG_STALE_HOURS=24

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
RESET='\033[0m'

PASS="${GREEN}✔${RESET}"
FAIL="${RED}✘${RESET}"
WARN="${YELLOW}⚠${RESET}"

# ── Counters ──────────────────────────────────────────────────────────────────
errors=0
warnings=0

# ── Helpers ───────────────────────────────────────────────────────────────────
section() {
    echo ""
    echo -e "${CYAN}── $1 ${DIM}─────────────────────────────────────────${RESET}"
}

pass()  { echo -e "  ${PASS}  $1"; }
fail()  { echo -e "  ${FAIL}  $1"; ((errors++)); }
warn()  { echo -e "  ${WARN}  $1"; ((warnings++)); }

# ── Header ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${CYAN}║       HONEYPOT HEALTH CHECK              ║${RESET}"
echo -e "${CYAN}║       $(date '+%Y-%m-%d %H:%M:%S')               ║${RESET}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${RESET}"

# ── 1. Systemctl services ─────────────────────────────────────────────────────
section "Systemctl Services"

check_service() {
    local name=$1
    local status
    status=$(systemctl is-active "$name" 2>/dev/null)
    if [ "$status" = "active" ]; then
        pass "$name — active"
    else
        fail "$name — $status"
    fi
}

check_service "cowrie"
check_service "honeypot-dashboard"
check_service "cowrie-split.path"

# cowrie-split.service is oneshot — check it isn't in failed state instead
split_state=$(systemctl is-failed "cowrie-split.service" 2>/dev/null)
if [ "$split_state" = "failed" ]; then
    fail "cowrie-split.service — last run failed"
else
    pass "cowrie-split.service — no failure recorded"
fi

# ── 2. Dashboard reachability ─────────────────────────────────────────────────
section "Dashboard"

http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$DASHBOARD_URL" 2>/dev/null)

if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
    # 401 is fine — means auth is working and dashboard is up
    pass "Reachable at $DASHBOARD_URL (HTTP $http_code)"
elif [ "$http_code" = "000" ]; then
    fail "Not reachable at $DASHBOARD_URL — no response"
else
    warn "Reachable but returned HTTP $http_code"
fi

# ── 3. Database ───────────────────────────────────────────────────────────────
section "Database"

if [ -f "$DB_FILE" ]; then
    size=$(du -sh "$DB_FILE" | cut -f1)
    pass "Exists — $DB_FILE ($size)"

    # Check it's a valid SQLite file
    if command -v sqlite3 &>/dev/null; then
        session_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM sessions;" 2>/dev/null)
        if [ $? -eq 0 ]; then
            pass "Readable — $session_count sessions recorded"
        else
            warn "File exists but could not query — may be corrupt"
        fi
    else
        warn "sqlite3 not installed — skipping query check"
    fi
else
    fail "Not found — $DB_FILE"
fi

# ── 4. Cowrie log file ────────────────────────────────────────────────────────
section "Cowrie Log"

if [ -f "$LOG_FILE" ]; then
    size=$(du -sh "$LOG_FILE" | cut -f1)
    pass "Exists — $LOG_FILE ($size)"

    # Check how recently it was modified
    last_modified=$(stat -c %Y "$LOG_FILE" 2>/dev/null)
    now=$(date +%s)
    age_seconds=$(( now - last_modified ))
    age_hours=$(( age_seconds / 3600 ))
    age_minutes=$(( (age_seconds % 3600) / 60 ))

    if [ "$age_hours" -ge "$LOG_STALE_HOURS" ]; then
        warn "Last modified ${age_hours}h ago — cowrie may not be receiving connections"
    else
        pass "Last modified ${age_hours}h ${age_minutes}m ago"
    fi

    # Line count as a sanity check
    line_count=$(wc -l < "$LOG_FILE")
    pass "$line_count events logged"
else
    fail "Not found — $LOG_FILE"
fi

# ── 5. Disk space ─────────────────────────────────────────────────────────────
section "Disk Space"

disk_usage=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
disk_avail=$(df -h / | awk 'NR==2 {print $4}')

if [ "$disk_usage" -ge 90 ]; then
    fail "Disk ${disk_usage}% full — ${disk_avail} remaining"
elif [ "$disk_usage" -ge 75 ]; then
    warn "Disk ${disk_usage}% full — ${disk_avail} remaining"
else
    pass "Disk ${disk_usage}% used — ${disk_avail} remaining"
fi

# ── 6. Memory ─────────────────────────────────────────────────────────────────
section "Memory"

mem_available=$(free -m | awk 'NR==2 {print $7}')
mem_total=$(free -m | awk 'NR==2 {print $2}')
mem_used_pct=$(( (mem_total - mem_available) * 100 / mem_total ))

if [ "$mem_available" -lt 100 ]; then
    fail "Only ${mem_available}MB available — system may be under pressure"
elif [ "$mem_available" -lt 300 ]; then
    warn "${mem_available}MB available (${mem_used_pct}% used)"
else
    pass "${mem_available}MB available (${mem_used_pct}% used)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}── Summary ───────────────────────────────────────────${RESET}"
echo ""

if [ "$errors" -eq 0 ] && [ "$warnings" -eq 0 ]; then
    echo -e "  ${GREEN}All checks passed.${RESET}"
elif [ "$errors" -eq 0 ]; then
    echo -e "  ${YELLOW}${warnings} warning(s), no errors.${RESET}"
else
    echo -e "  ${RED}${errors} error(s), ${warnings} warning(s).${RESET}"
fi

echo ""
exit $errors