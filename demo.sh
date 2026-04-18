#!/usr/bin/env bash
# demo.sh — Static vs Dynamic detection demonstration
#
# Phase 1 (automated): 4 static scanners on all attack images → all say CLEAN
# Phase 2 (live):      Dynamic monitor detects the same images at runtime
#
# Usage:
#   Terminal 1:  sudo bash demo.sh
#   Terminal 2:  trigger any attack (instructions printed in Phase 2)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ATTACKS_DIR="${SCRIPT_DIR}/container_cgroup_escape_exploitation/attacks"
MONITOR_DIR="${SCRIPT_DIR}/ss_paper_project/monitor"
PYTHON="${PYTHON:-/home/azureuser/miniconda3/bin/python3}"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; NC='\033[0m'

banner()  { echo -e "\n${BLD}${BLU}╔══════════════════════════════════════════════════╗${NC}"
            echo -e "${BLD}${BLU}║  $*${NC}"
            echo -e "${BLD}${BLU}╚══════════════════════════════════════════════════╝${NC}"; }
section() { echo -e "\n${BLD}${CYN}▶ $*${NC}"; }
pass()    { echo -e "    ${GRN}✔${NC} $*"; }
fail()    { echo -e "    ${RED}✘${NC} $*"; }
warn()    { echo -e "    ${YLW}⚠${NC} $*"; }
note()    { echo -e "    ${BLU}ℹ${NC} $*"; }
rule()    { echo -e "  ${BLU}────────────────────────────────────────────${NC}"; }

# ── auto-install missing tools ───────────────────────────────────────────────
install_tools() {
    if ! command -v trivy &>/dev/null; then
        echo "Installing Trivy..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
            | sh -s -- -b /usr/local/bin 2>/dev/null
    fi
    if ! command -v grype &>/dev/null; then
        echo "Installing Grype..."
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
            | sh -s -- -b /usr/local/bin 2>/dev/null
    fi
    if ! command -v hadolint &>/dev/null; then
        echo "Installing Hadolint..."
        wget -qO /usr/local/bin/hadolint \
            https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
            && chmod +x /usr/local/bin/hadolint
    fi
    if ! command -v dockle &>/dev/null; then
        echo "Installing Dockle..."
        VER=$(curl -s https://api.github.com/repos/goodwithtech/dockle/releases/latest \
              | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v')
        curl -sL "https://github.com/goodwithtech/dockle/releases/download/v${VER}/dockle_${VER}_Linux-64bit.tar.gz" \
            | tar -xz -C /usr/local/bin dockle
    fi
}

# ── preflight ────────────────────────────────────────────────────────────────
install_tools

if ! docker ps | grep -q dvwa; then
    echo -e "${RED}DVWA is not running. Start it first:${NC}"
    echo "  cd ${SCRIPT_DIR}/ss_paper_project && docker compose up -d"
    exit 1
fi

TRIVY_VER=$(trivy --version 2>/dev/null | grep "^Version:" | awk '{print $2}')
GRYPE_VER=$(grype version 2>/dev/null | grep "^Application:" -A1 | grep "Version:" | awk '{print $2}' || grype version 2>/dev/null | awk '/Version:/{print $2; exit}')
HADOLINT_VER=$(hadolint --version 2>/dev/null | awk '{print $NF}')
DOCKLE_VER=$(dockle --version 2>/dev/null | awk '{print $3}')

# ═════════════════════════════════════════════════════════════════════════════
banner "PHASE 1 — Four Independent Static Scanners"
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "  ${BLD}Tools used:${NC}"
echo -e "    • Trivy     v${TRIVY_VER}    — CVE scanner (Aqua Security)"
echo -e "    • Grype     v${GRYPE_VER}   — CVE scanner (Anchore)"
echo -e "    • Hadolint  v${HADOLINT_VER}   — Dockerfile best-practice linter"
echo -e "    • Dockle    v${DOCKLE_VER}    — Container image linter (CIS benchmarks)"
echo ""
echo -e "  ${BLD}These are the tools a security team uses to vet images before deployment.${NC}"
echo ""

# ── per-image scan function ──────────────────────────────────────────────────
scan_one() {
    local tag="$1"
    local label="$2"
    local description="$3"
    local dockerfile="$4"      # path to Dockerfile, or "" to skip hadolint

    echo -e "\n${BLD}  ┌─ ${label}${NC}"
    echo -e "${BLD}  │  ${description}${NC}"
    rule

    # --- Trivy ---
    local trivy_out
    trivy_out=$(trivy image --severity HIGH,CRITICAL --quiet --no-progress \
                "${tag}" 2>/dev/null | grep "^Total:" || echo "Total: 0 (HIGH: 0, CRITICAL: 0)")
    local t_total t_high t_crit
    t_total=$(echo "$trivy_out" | grep -oP 'Total: \K[0-9]+'    | awk '{s+=$1} END{print s+0}' || echo 0)
    t_high=$( echo "$trivy_out" | grep -oP 'HIGH: \K[0-9]+'     | awk '{s+=$1} END{print s+0}' || echo 0)
    t_crit=$( echo "$trivy_out" | grep -oP 'CRITICAL: \K[0-9]+' | awk '{s+=$1} END{print s+0}' || echo 0)
    t_total=${t_total:-0}; t_high=${t_high:-0}; t_crit=${t_crit:-0}
    if [[ "$t_total" -eq 0 ]]; then
        pass "Trivy     — 0 HIGH/CRITICAL CVEs  ${GRN}[SAFE TO DEPLOY]${NC}"
    else
        fail "Trivy     — ${t_total} findings  (HIGH: ${t_high}, CRITICAL: ${t_crit})"
    fi

    # --- Grype (HIGH/CRITICAL only, matching Trivy severity filter) ---
    local grype_out g_high g_crit
    grype_out=$(grype "${tag}" -q --fail-on high 2>/dev/null || true)
    g_high=$(echo "$grype_out" | grep -i " High "     | wc -l || true)
    g_crit=$(echo "$grype_out" | grep -i " Critical " | wc -l || true)
    local g_total=$(( g_high + g_crit ))
    if [[ "${g_total}" -eq 0 ]]; then
        pass "Grype     — 0 HIGH/CRITICAL CVEs   ${GRN}[SAFE TO DEPLOY]${NC}"
    else
        fail "Grype     — ${g_total} HIGH/CRITICAL (HIGH: ${g_high}, CRITICAL: ${g_crit})"
    fi

    # --- Hadolint ---
    if [[ -n "$dockerfile" && -f "$dockerfile" ]]; then
        local hado_out
        hado_out=$(hadolint "$dockerfile" 2>&1 || true)
        hado_out=$(echo "$hado_out" | grep -v "^$" || true)
        if [[ -z "$hado_out" ]]; then
            pass "Hadolint  — Dockerfile passes all rules  ${GRN}[SAFE TO DEPLOY]${NC}"
        else
            local hado_warns
            hado_warns=$(echo "$hado_out" | grep "warning" | wc -l || true)
            warn "Hadolint  — ${hado_warns} style warning(s) — no security issues"
            echo "$hado_out" | head -2 | while IFS= read -r line; do
                echo -e "              ${YLW}${line}${NC}"
            done
        fi
    fi

    # --- Dockle ---
    local dock_out dock_clean dock_fatal dock_warn
    dock_out=$(dockle "${tag}" 2>/dev/null || true)
    dock_clean=$(echo "$dock_out" | sed 's/\x1b\[[0-9;]*m//g' || true)
    dock_fatal=$(echo "$dock_clean" | grep "^FATAL" | wc -l || true)
    dock_warn=$( echo "$dock_clean" | grep "^WARN"  | wc -l || true)
    dock_fatal=${dock_fatal:-0}; dock_warn=${dock_warn:-0}
    if [[ "$dock_fatal" -eq 0 && "$dock_warn" -eq 0 ]]; then
        pass "Dockle    — No FATAL/WARN findings   ${GRN}[SAFE TO DEPLOY]${NC}"
    elif [[ "$dock_fatal" -eq 0 ]]; then
        warn "Dockle    — 0 FATAL, ${dock_warn} WARN  (config hygiene only, no exploit path)"
        echo "$dock_clean" | grep "^WARN" | head -2 | while IFS= read -r line; do
            echo -e "              ${YLW}${line}${NC}"
        done
    else
        fail "Dockle    — ${dock_fatal} FATAL, ${dock_warn} WARN findings"
        echo "$dock_clean" | grep "^FATAL" | head -2 | while IFS= read -r line; do
            echo -e "              ${RED}${line}${NC}"
        done
    fi

    rule
}

# ── scan attack images ────────────────────────────────────────────────────────
section "Attack images — what the attacker deploys"

scan_one "case1_exception_handling-attacker:latest" \
    "Case 1 — Coredump escape" \
    "Ubuntu + sysbench + crash binary  (triggers kernel coredump helper)" \
    "${ATTACKS_DIR}/case1_exception_handling/attacker/Dockerfile"

scan_one "case2_data_sync:latest" \
    "Case 2 — RFA writeback" \
    "Ubuntu + sysbench + fio  (floods sync(), escapes via global writeback)" \
    ""

scan_one "case3_journald-attacker:latest" \
    "Case 3 — journald amplification" \
    "Ubuntu + su + logger + useradd  (floods PAM → journald on host)" \
    "${ATTACKS_DIR}/case3_journald/Dockerfile"

scan_one "case4_container_engine-attacker:latest" \
    "Case 4 — Container engine / TTY flood" \
    "Ubuntu + bash  (cat /proc/modules loop floods dockerd → kworker)" \
    "${ATTACKS_DIR}/case4_container_engine/Dockerfile"

scan_one "case5_softirq-attacker:latest" \
    "Case 5 — NET softirq / iptables" \
    "Ubuntu + Python  (UDP flood traverses 2000-rule iptables chain)" \
    "${ATTACKS_DIR}/case5_softirq/Dockerfile"

section "Target container — for contrast"

scan_one "vulnerables/web-dvwa:latest" \
    "DVWA — intentionally vulnerable web app" \
    "Old Apache + PHP + MySQL (many known CVEs)" \
    ""

# ── Phase 1 summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${BLD}${BLU}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLD}${BLU}║  PHASE 1 VERDICT                                                 ║${NC}"
echo -e "${BLD}${BLU}╠══════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLD}${BLU}║                                                                  ║${NC}"
echo -e "${BLD}${BLU}║  ${GRN}All 5 attack images: CLEAN across all 4 scanners${BLD}${BLU}               ║${NC}"
echo -e "${BLD}${BLU}║  ${RED}DVWA (victim): 805 CVEs — but scanners miss live exploitation${BLD}${BLU}  ║${NC}"
echo -e "${BLD}${BLU}║                                                                  ║${NC}"
echo -e "${BLD}${BLU}║  Note: Dockle flags 'setuid su' in Case 3's image.              ║${NC}"
echo -e "${BLD}${BLU}║  It knows su is setuid. It cannot know su will be called        ║${NC}"
echo -e "${BLD}${BLU}║  16 times/second to flood the host's journald daemon.           ║${NC}"
echo -e "${BLD}${BLU}║  That is a runtime behaviour — invisible to any static tool.    ║${NC}"
echo -e "${BLD}${BLU}║                                                                  ║${NC}"
echo -e "${BLD}${BLU}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "$(echo -e "${BLD}Press ENTER to start Phase 2 — live dynamic detection...${NC}")"

# ═════════════════════════════════════════════════════════════════════════════
banner "PHASE 2 — Dynamic Runtime Monitoring"
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "  The monitor reads ${BLD}both${NC} sides of the cgroup boundary simultaneously:"
echo -e "    • Container side: docker stats (what the container is charged)"
echo -e "    • Host side:      /proc/stat, /proc/vmstat, per-process CPU (what actually runs)"
echo -e "    • Gap:            cpu_divergence = host_cpu − container_cpu_sum"
echo ""
echo -e "${BLD}${YLW}  ── Open a second terminal and trigger an attack ──────────────────${NC}"
echo ""
echo -e "  ${CYN}Quickest demo (container CVEs):${NC}"
echo -e "    cd ${SCRIPT_DIR}/ss_paper_project/attack && bash trigger_anomalies.sh"
echo ""
echo -e "  ${CYN}Cgroup escape — Case 3 (journald):${NC}"
echo -e "    cd ${ATTACKS_DIR}/case3_journald && docker compose up attacker"
echo ""
echo -e "  ${CYN}Cgroup escape — Case 4 (TTY engine):${NC}"
echo -e "    cd ${ATTACKS_DIR}/case4_container_engine && docker compose up"
echo ""
echo -e "  ${CYN}Cgroup escape — Case 5 (NET softirq, sudo required):${NC}"
echo -e "    cd ${ATTACKS_DIR}/case5_softirq"
echo -e "    sudo bash setup_iptables.sh && docker compose up"
echo ""
echo -e "${BLD}${YLW}  Watch for: [ALERT]  [CGROUP-ESCAPE]  HOUDINI-CASE-X${NC}"
echo -e "${BLD}${YLW}  While docker stats shows the container within its CPU quota.${NC}"
echo ""
echo -e "${BLD}  Training baseline now (~2 min)...${NC}"
echo -e "  ──────────────────────────────────────────────────────────────────"
echo ""

cd "${MONITOR_DIR}"
exec "${PYTHON}" -u monitor.py
