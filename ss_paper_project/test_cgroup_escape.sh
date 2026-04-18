#!/usr/bin/env bash
# test_cgroup_escape.sh
#
# Validate that the unified monitor detects all 5 Houdini cgroup escape attacks.
#
# Each test:
#   1. Starts the monitor in background (writes to a tmp log)
#   2. Waits for training to finish
#   3. Runs the attack via docker compose in the escape project
#   4. Polls the monitor log for an expected alert string
#   5. Tears everything down and reports PASS / FAIL
#
# Usage:
#   cd /home/azureuser/ss-project/ss_paper_project
#   sudo bash test_cgroup_escape.sh [case1|case2|case3|case4|case5|all]
#
# Requirements:
#   - Docker + docker compose
#   - python3 with pandas + scikit-learn  (pip install -r monitor/requirements.txt)
#   - Root / sudo for iptables (case5 only)
#   - Apport enabled on host (case1): sudo systemctl enable --now apport
#
# Exit codes: 0 = all selected cases passed, 1 = one or more failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="$(realpath "${SCRIPT_DIR}/../container_cgroup_escape_exploitation/attacks")"
MONITOR_DIR="${SCRIPT_DIR}/monitor"

# How long (seconds) to let the attack run before declaring no-detect
ATTACK_TIMEOUT=120
# How long to wait after docker compose up for the attack to start producing load
ATTACK_WARMUP=15
# 25 training rounds * ~2.5s each (docker commands + 1s sleep) + 15s buffer for
# detection loop to emit its first [HOST] line after training finishes
TRAINING_WAIT=150

PASS=0
FAIL=0
SKIP=0

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo -e "[$(date '+%H:%M:%S')] $*"; }
pass() { echo -e "${GRN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL + 1)); }
skip() { echo -e "${YLW}[SKIP]${NC} $*"; SKIP=$((SKIP + 1)); }

start_monitor() {
    local logfile="$1"
    log "Starting monitor (log → ${logfile})"
    cd "${MONITOR_DIR}"
    # Use conda python explicitly so both sudo and non-sudo runs share the same
    # interpreter that has pandas/sklearn installed
    PYTHON="${PYTHON:-/home/azureuser/miniconda3/bin/python3}"
    # -u: unbuffered — without this, output is block-buffered when redirected to
    # a file and the log stays empty until the buffer fills or the process exits
    PYTHONUNBUFFERED=1 "${PYTHON}" -u monitor.py >"${logfile}" 2>&1 &
    MONITOR_PID=$!
    log "Monitor PID=${MONITOR_PID}; waiting for training to finish (max ${TRAINING_WAIT}s)..."

    # Poll for the "Baseline established" message rather than sleeping a fixed amount.
    # This is robust to variance in docker command latency across machines.
    local waited=0
    while (( waited < TRAINING_WAIT )); do
        if ! kill -0 "${MONITOR_PID}" 2>/dev/null; then
            log "Monitor crashed during training — check ${logfile}"
            return 1
        fi
        if grep -q "Baseline established" "${logfile}" 2>/dev/null; then
            log "Training complete (${waited}s)."
            return 0
        fi
        sleep 3
        (( waited += 3 ))
    done
    log "Training did not finish within ${TRAINING_WAIT}s — check ${logfile}"
    return 1
}

stop_monitor() {
    if [[ -n "${MONITOR_PID:-}" ]] && kill -0 "${MONITOR_PID}" 2>/dev/null; then
        kill "${MONITOR_PID}" 2>/dev/null || true
        wait "${MONITOR_PID}" 2>/dev/null || true
        unset MONITOR_PID
    fi
}

wait_for_alert() {
    local logfile="$1"
    local pattern="$2"
    local timeout="${3:-${ATTACK_TIMEOUT}}"
    local elapsed=0

    log "Waiting up to ${timeout}s for pattern: '${pattern}'"
    while (( elapsed < timeout )); do
        if grep -qiE "${pattern}" "${logfile}" 2>/dev/null; then
            return 0
        fi
        sleep 5
        (( elapsed += 5 ))
    done
    return 1
}

compose_down() {
    local dir="$1"
    (cd "${dir}" && docker compose down --remove-orphans --volumes 2>/dev/null || true)
}

cleanup_all() {
    stop_monitor
    # Best-effort teardown of any compose stacks that may be running
    for d in "${ATTACKS_DIR}"/case*; do
        (cd "${d}" && docker compose down --remove-orphans 2>/dev/null || true) &
    done
    # Remove case4 test container if left behind
    docker rm -f case4_test 2>/dev/null || true
    wait
}
trap cleanup_all EXIT

# Pre-run: kill any stale state from a previous interrupted run
pre_cleanup() {
    log "Pre-flight cleanup (stale containers / monitors)..."
    # Kill any python monitor.py processes still running
    pkill -f "monitor.py" 2>/dev/null || true
    # Tear down all attack compose stacks
    for d in "${ATTACKS_DIR}"/case*; do
        (cd "${d}" && docker compose down --remove-orphans --volumes 2>/dev/null || true) &
    done
    docker rm -f case4_test 2>/dev/null || true
    wait
    # Prune dangling build cache to avoid slow rebuilds and disk fill
    docker image prune -f 2>/dev/null || true
    log "Pre-flight cleanup done."
}
pre_cleanup

# ---------------------------------------------------------------------------
# Individual case runners
# ---------------------------------------------------------------------------

run_case1() {
    local logfile
    logfile="$(mktemp /tmp/monitor_case1_XXXX.log)"
    log "=== Case 1: Exception handling / coredump helper ==="

    # Check apport/systemd-coredump is available
    if ! (systemctl is-active --quiet apport 2>/dev/null || \
          systemctl is-active --quiet systemd-coredump 2>/dev/null); then
        skip "Case 1: Neither apport nor systemd-coredump is active — enable one first."
        return
    fi

    local attack_dir="${ATTACKS_DIR}/case1_exception_handling"
    start_monitor "${logfile}" || { fail "Case 1: monitor failed to start"; return; }

    log "Launching case1 attack..."
    (cd "${attack_dir}" && docker compose up -d)
    sleep "${ATTACK_WARMUP}"

    # Expected alert: HOUDINI-CASE1 or coredump_helper
    if wait_for_alert "${logfile}" "HOUDINI-CASE1|coredump_helper|CASE-1"; then
        pass "Case 1: coredump helper escape detected"
    else
        fail "Case 1: no alert within ${ATTACK_TIMEOUT}s"
        log "Last 30 lines of monitor log:"
        tail -30 "${logfile}" || true
    fi

    compose_down "${attack_dir}"
    stop_monitor
    rm -f "${logfile}"
}

run_case2() {
    local logfile
    logfile="$(mktemp /tmp/monitor_case2_XXXX.log)"
    log "=== Case 2: Data sync / RFA writeback ==="

    local attack_dir="${ATTACKS_DIR}/case2_data_sync"
    mkdir -p "${attack_dir}/io_data"
    start_monitor "${logfile}" || { fail "Case 2: monitor failed to start"; return; }

    log "Launching case2 victim + attacker..."
    (cd "${attack_dir}" && docker compose build --quiet && docker compose up -d victim)
    sleep 10
    # Run attacker in foreground so we can wait for it; detach to background here
    (cd "${attack_dir}" && docker compose run --rm attacker) &
    CASE2_ATTACKER_PID=$!
    sleep "${ATTACK_WARMUP}"

    if wait_for_alert "${logfile}" "HOUDINI-CASE2|iowait|dirty_pages|CASE-2"; then
        pass "Case 2: RFA writeback escape detected"
    else
        fail "Case 2: no alert within ${ATTACK_TIMEOUT}s"
        tail -30 "${logfile}" || true
    fi

    kill "${CASE2_ATTACKER_PID}" 2>/dev/null || true
    wait "${CASE2_ATTACKER_PID}" 2>/dev/null || true
    compose_down "${attack_dir}"
    stop_monitor
    rm -f "${logfile}"
}

run_case3() {
    local logfile
    logfile="$(mktemp /tmp/monitor_case3_XXXX.log)"
    log "=== Case 3: journald amplification ==="

    local attack_dir="${ATTACKS_DIR}/case3_journald"
    start_monitor "${logfile}" || { fail "Case 3: monitor failed to start"; return; }

    log "Launching case3 attacker..."
    (cd "${attack_dir}" && docker compose build --quiet && docker compose up attacker) &
    CASE3_PID=$!
    sleep "${ATTACK_WARMUP}"

    if wait_for_alert "${logfile}" "HOUDINI-CASE3|journald|CASE-3" 180; then
        pass "Case 3: journald escape detected"
    else
        fail "Case 3: no alert within 180s (journald CPU may be low — try --su mode)"
        tail -30 "${logfile}" || true
    fi

    kill "${CASE3_PID}" 2>/dev/null || true
    wait "${CASE3_PID}" 2>/dev/null || true
    compose_down "${attack_dir}"
    stop_monitor
    rm -f "${logfile}"
}

run_case4() {
    local logfile
    logfile="$(mktemp /tmp/monitor_case4_XXXX.log)"
    log "=== Case 4: Container engine / TTY flood ==="

    local attack_dir="${ATTACKS_DIR}/case4_container_engine"
    start_monitor "${logfile}" || { fail "Case 4: monitor failed to start"; return; }

    log "Launching case4 (must allocate TTY — using docker run directly)..."
    docker run -d --name case4_test --cpus=1 --cpuset-cpus=0 \
        "$(cd "${attack_dir}" && docker compose config --images 2>/dev/null | head -1 || \
           docker build -q "${attack_dir}")" \
        /app/run.sh 2>/dev/null &
    CASE4_DOCKER_PID=$!
    sleep "${ATTACK_WARMUP}"

    if wait_for_alert "${logfile}" "HOUDINI-CASE4|engine_overhead|CASE-4|kworker"; then
        pass "Case 4: container engine TTY escape detected"
    else
        fail "Case 4: no alert within ${ATTACK_TIMEOUT}s"
        tail -30 "${logfile}" || true
    fi

    docker rm -f case4_test 2>/dev/null || true
    kill "${CASE4_DOCKER_PID}" 2>/dev/null || true
    wait "${CASE4_DOCKER_PID}" 2>/dev/null || true
    compose_down "${attack_dir}"
    stop_monitor
    rm -f "${logfile}"
}

run_case5() {
    local logfile
    logfile="$(mktemp /tmp/monitor_case5_XXXX.log)"
    log "=== Case 5: NET softirq / iptables ==="

    if [[ "${EUID}" -ne 0 ]]; then
        skip "Case 5: requires root (iptables setup). Re-run with sudo."
        return
    fi

    local attack_dir="${ATTACKS_DIR}/case5_softirq"
    log "Setting up iptables decoy rules..."
    (cd "${attack_dir}" && CASE5_IPTABLES_RULES=2000 bash setup_iptables.sh)

    start_monitor "${logfile}" || {
        (cd "${attack_dir}" && bash cleanup_iptables.sh)
        fail "Case 5: monitor failed to start"
        return
    }

    log "Launching case5 packet flood..."
    (cd "${attack_dir}" && docker compose build --quiet && docker compose up -d)
    sleep "${ATTACK_WARMUP}"

    if wait_for_alert "${logfile}" "HOUDINI-CASE5|softirq|ksoftirqd|CASE-5"; then
        pass "Case 5: NET softirq escape detected"
    else
        fail "Case 5: no alert within ${ATTACK_TIMEOUT}s"
        tail -30 "${logfile}" || true
    fi

    compose_down "${attack_dir}"
    (cd "${attack_dir}" && bash cleanup_iptables.sh)
    stop_monitor
    rm -f "${logfile}"
}

# ---------------------------------------------------------------------------
# Quick smoke test — no attack needed; just verifies the monitor starts and
# reads /proc without crashing.
# ---------------------------------------------------------------------------

run_smoke() {
    log "=== Smoke test: monitor starts and produces host metrics ==="
    local logfile
    logfile="$(mktemp /tmp/monitor_smoke_XXXX.log)"
    start_monitor "${logfile}" || { fail "Smoke: monitor crashed during training"; return; }

    # wait_for_alert polls every 5s; [HOST] appears on the first detection cycle
    # which starts immediately after training — allow 20s for one cycle to complete
    if wait_for_alert "${logfile}" "\[HOST\]" 20; then
        pass "Smoke: monitor running and emitting host metrics"
    else
        fail "Smoke: no [HOST] line in monitor output"
        cat "${logfile}" || true
    fi

    stop_monitor
    rm -f "${logfile}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TARGET="${1:-all}"

case "${TARGET}" in
    smoke) run_smoke ;;
    case1) run_case1 ;;
    case2) run_case2 ;;
    case3) run_case3 ;;
    case4) run_case4 ;;
    case5) run_case5 ;;
    all)
        run_smoke
        run_case1
        run_case2
        run_case3
        run_case4
        run_case5
        ;;
    *)
        echo "Usage: $0 [smoke|case1|case2|case3|case4|case5|all]"
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo -e "Results: ${GRN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YLW}${SKIP} skipped${NC}"
echo "========================================"

(( FAIL == 0 ))
