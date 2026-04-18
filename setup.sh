#!/usr/bin/env bash
# setup.sh — One-time environment setup for the cgroup escape detection demo.
#
# Run this ONCE before the demo day (not during the presentation).
# It installs all tools, pulls all Docker images, and does a preflight check.
#
# Usage:
#   sudo bash setup.sh
#
# Requirements:
#   - Ubuntu/Debian Linux (x86-64)
#   - Docker installed and running
#   - Internet access (for downloading tools and images)
#   - Python 3 with pip  (conda or system Python both work)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; BLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${GRN}✔${NC} $*"; }
fail() { echo -e "  ${RED}✘${NC} $*"; }
info() { echo -e "  ${BLU}ℹ${NC} $*"; }
step() { echo -e "\n${BLD}${BLU}▶ $*${NC}"; }

# Detect best available Python (prefer miniconda, fall back to system)
detect_python() {
    for candidate in \
        /home/azureuser/miniconda3/bin/python3 \
        /opt/conda/bin/python3 \
        /usr/bin/python3 \
        python3
    do
        if command -v "$candidate" &>/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
    echo "python3"
}
PYTHON="${PYTHON:-$(detect_python)}"

echo ""
echo -e "${BLD}${BLU}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLD}${BLU}║  Cgroup Escape Detection — Environment Setup             ║${NC}"
echo -e "${BLD}${BLU}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Python interpreter: ${PYTHON}"
info "Working directory:  ${SCRIPT_DIR}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
step "1 / 5  Checking system requirements"
# ─────────────────────────────────────────────────────────────────────────────

ERRORS=0

if ! command -v docker &>/dev/null; then
    fail "Docker not found. Install Docker Engine first: https://docs.docker.com/engine/install/"
    ERRORS=$((ERRORS + 1))
else
    DOCKER_VER=$(docker --version | awk '{print $3}' | tr -d ',')
    ok "Docker ${DOCKER_VER}"
fi

if ! docker info &>/dev/null 2>&1; then
    fail "Docker daemon is not running or current user has no access."
    info "Fix: sudo systemctl start docker  OR  sudo usermod -aG docker \$USER && newgrp docker"
    ERRORS=$((ERRORS + 1))
else
    ok "Docker daemon reachable"
fi

if ! command -v "$PYTHON" &>/dev/null; then
    fail "Python not found at ${PYTHON}"
    ERRORS=$((ERRORS + 1))
else
    PY_VER=$("$PYTHON" --version 2>&1 | awk '{print $2}')
    ok "Python ${PY_VER} (${PYTHON})"
fi

if [[ "$ERRORS" -gt 0 ]]; then
    echo ""
    fail "Fix the above errors before continuing."
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
step "2 / 5  Installing Python packages"
# ─────────────────────────────────────────────────────────────────────────────

if "$PYTHON" -m pip install -q --root-user-action=ignore -r "${SCRIPT_DIR}/requirements.txt"; then
    PANDAS_VER=$("$PYTHON"  -c "import pandas;   print(pandas.__version__)"   2>/dev/null)
    SKLEARN_VER=$("$PYTHON" -c "import sklearn;   print(sklearn.__version__)"  2>/dev/null)
    NUMPY_VER=$( "$PYTHON"  -c "import numpy;     print(numpy.__version__)"    2>/dev/null)
    ok "pandas ${PANDAS_VER}  scikit-learn ${SKLEARN_VER}  numpy ${NUMPY_VER}"
else
    fail "pip install failed. Try: ${PYTHON} -m pip install -r requirements.txt"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
step "3 / 5  Installing static scanner tools"
# ─────────────────────────────────────────────────────────────────────────────

# --- Trivy ---
if command -v trivy &>/dev/null; then
    ok "Trivy $(trivy --version 2>/dev/null | grep '^Version:' | awk '{print $2}') already installed"
else
    info "Installing Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin
    ok "Trivy $(trivy --version 2>/dev/null | grep '^Version:' | awk '{print $2}') installed"
fi

# Pre-warm Trivy vulnerability database (avoids a slow download during the demo)
info "Warming Trivy vulnerability database (may take a minute)..."
trivy image --download-db-only --quiet 2>/dev/null && ok "Trivy DB cached" || true

# --- Grype ---
if command -v grype &>/dev/null; then
    ok "Grype $(grype version 2>/dev/null | grep 'Version:' | awk '{print $2}' | head -1) already installed"
else
    info "Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
        | sh -s -- -b /usr/local/bin
    ok "Grype $(grype version 2>/dev/null | grep 'Version:' | awk '{print $2}' | head -1) installed"
fi

# Pre-warm Grype vulnerability database
info "Warming Grype vulnerability database (may take a minute)..."
grype db update --quiet 2>/dev/null && ok "Grype DB cached" || true

# --- Hadolint ---
if command -v hadolint &>/dev/null; then
    ok "Hadolint $(hadolint --version 2>/dev/null | awk '{print $NF}') already installed"
else
    info "Installing Hadolint..."
    wget -qO /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
    chmod +x /usr/local/bin/hadolint
    ok "Hadolint $(hadolint --version 2>/dev/null | awk '{print $NF}') installed"
fi

# --- Dockle ---
if command -v dockle &>/dev/null; then
    ok "Dockle $(dockle --version 2>/dev/null | awk '{print $3}') already installed"
else
    info "Installing Dockle..."
    VER=$(curl -s https://api.github.com/repos/goodwithtech/dockle/releases/latest \
          | grep '"tag_name"' | cut -d'"' -f4 | tr -d 'v')
    curl -sL "https://github.com/goodwithtech/dockle/releases/download/v${VER}/dockle_${VER}_Linux-64bit.tar.gz" \
        | tar -xz -C /usr/local/bin dockle
    ok "Dockle $(dockle --version 2>/dev/null | awk '{print $3}') installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "4 / 5  Building / pulling Docker images"
# ─────────────────────────────────────────────────────────────────────────────

ATTACKS_DIR="${SCRIPT_DIR}/container_cgroup_escape_exploitation/attacks"

# DVWA — pull from registry
info "Pulling DVWA (victim web app)..."
if docker pull vulnerables/web-dvwa:latest -q; then
    ok "vulnerables/web-dvwa:latest"
else
    fail "Could not pull DVWA — check internet connection"
fi

# Attack images — build locally
build_image() {
    local context="$1"
    local tag="$2"
    local label="$3"
    if docker image inspect "${tag}" &>/dev/null 2>&1; then
        ok "${tag} (already built)"
    else
        info "Building ${label}..."
        if docker build -q -t "${tag}" "${context}" 2>/dev/null; then
            ok "${tag}"
        else
            fail "Build failed: ${tag} — run: docker build -t ${tag} ${context}"
        fi
    fi
}

build_image "${ATTACKS_DIR}/case1_exception_handling/attacker" \
    "case1_exception_handling-attacker:latest" "Case 1 attacker"

build_image "${ATTACKS_DIR}/case2_data_sync" \
    "case2_data_sync:latest" "Case 2"

build_image "${ATTACKS_DIR}/case3_journald" \
    "case3_journald-attacker:latest" "Case 3 attacker"

build_image "${ATTACKS_DIR}/case4_container_engine" \
    "case4_container_engine-attacker:latest" "Case 4 attacker"

build_image "${ATTACKS_DIR}/case5_softirq" \
    "case5_softirq-attacker:latest" "Case 5 attacker"

# Start DVWA so the monitor has a container to watch
info "Starting DVWA container..."
cd "${SCRIPT_DIR}/ss_paper_project"
if docker compose up -d 2>/dev/null; then
    ok "DVWA container running"
else
    fail "Could not start DVWA — check docker-compose.yml in ss_paper_project/"
fi
cd "${SCRIPT_DIR}"

# ─────────────────────────────────────────────────────────────────────────────
step "5 / 5  Preflight check"
# ─────────────────────────────────────────────────────────────────────────────

PASS=0; FAIL=0

check() {
    local label="$1"; shift
    if eval "$@" &>/dev/null 2>&1; then
        ok "${label}"
        PASS=$((PASS + 1))
    else
        fail "${label}"
        FAIL=$((FAIL + 1))
    fi
}

check "trivy available"    "trivy --version"
check "grype available"    "grype version"
check "hadolint available" "hadolint --version"
check "dockle available"   "dockle --version"
check "pandas importable"  "${PYTHON} -c 'import pandas'"
check "scikit-learn importable" "${PYTHON} -c 'import sklearn'"
check "DVWA container up"  "docker ps | grep -q dvwa"
check "case1 image exists" "docker image inspect case1_exception_handling-attacker:latest"
check "case2 image exists" "docker image inspect case2_data_sync:latest"
check "case3 image exists" "docker image inspect case3_journald-attacker:latest"
check "case4 image exists" "docker image inspect case4_container_engine-attacker:latest"
check "case5 image exists" "docker image inspect case5_softirq-attacker:latest"
check "monitor.py syntax"  "${PYTHON} -m py_compile ${SCRIPT_DIR}/ss_paper_project/monitor/monitor.py"

echo ""
echo -e "${BLD}${BLU}╔══════════════════════════════════════════════════════════╗${NC}"
if [[ "$FAIL" -eq 0 ]]; then
    echo -e "${BLD}${BLU}║  ${GRN}All ${PASS} checks passed. Ready to demo.${BLD}${BLU}                      ║${NC}"
    echo -e "${BLD}${BLU}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLD}${BLU}║                                                          ║${NC}"
    echo -e "${BLD}${BLU}║  To run the full demo:                                   ║${NC}"
    echo -e "${BLD}${BLU}║    sudo bash demo.sh                                     ║${NC}"
    echo -e "${BLD}${BLU}║                                                          ║${NC}"
    echo -e "${BLD}${BLU}║  To run the monitor only:                                ║${NC}"
    echo -e "${BLD}${BLU}║    cd ss_paper_project/monitor                           ║${NC}"
    echo -e "${BLD}${BLU}║    sudo ${PYTHON} -u monitor.py   ║${NC}"
    echo -e "${BLD}${BLU}║                                                          ║${NC}"
else
    echo -e "${BLD}${BLU}║  ${YLW}${PASS} passed, ${RED}${FAIL} failed${BLD}${BLU}. Fix the errors above before the demo.  ║${NC}"
fi
echo -e "${BLD}${BLU}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
