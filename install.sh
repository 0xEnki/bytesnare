#!/usr/bin/env bash
# =============================================================================
#  ShadowNet — Enterprise-Grade Automated Linux Installer
# =============================================================================
#  This script automates the full deployment of ShadowNet:
#    1. Verifies root/sudo privileges and OS compatibility
#    2. Installs system dependencies (python3, venv, build tools)
#    3. Creates / repairs a Python virtual environment
#    4. Installs all Python requirements
#    5. Creates a secure system-wide launcher (/usr/local/bin/shadownet)
# =============================================================================

set -euo pipefail

# ----- Constants -------------------------------------------------------------
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
REQUIREMENTS="${PROJECT_DIR}/requirements.txt"
LAUNCHER_PATH="/usr/local/bin/shadownet"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10
SHADOWNET_MODULE="shadownet"

# ----- Styling helpers -------------------------------------------------------
BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
MAGENTA="\033[0;35m"
RESET="\033[0m"

checkmark="${GREEN}✓${RESET}"
cross="${RED}✗${RESET}"
arrow="${CYAN}➜${RESET}"
star="${YELLOW}★${RESET}"

echo_success() { echo -e "  ${checkmark} ${BOLD}${GREEN}$1${RESET}"; }
echo_failure() { echo -e "  ${cross} ${BOLD}${RED}$1${RESET}"; }
echo_info()    { echo -e "  ${arrow} ${BOLD}$1${RESET}"; }
echo_warn()    { echo -e "  ${YELLOW}⚠ $1${RESET}"; }
echo_title()   { echo -e "\n${MAGENTA}${BOLD}━━━ $1 ━━━${RESET}\n"; }

# =============================================================================
#  1.  PRIVILEGE & OS CHECK
# =============================================================================

echo_title "1/6  —  Privilege & OS Verification"

if [[ $EUID -ne 0 ]]; then
    echo_warn "Not running as root. Re-executing with sudo..."
    exec sudo "$0" "$@"
fi
echo_success "Root privileges confirmed"

if ! command -v lsb_release &>/dev/null; then
    apt-get update -qq && apt-get install -y -qq lsb-release >/dev/null 2>&1
fi

OS="$(lsb_release -is 2>/dev/null || echo "unknown")"
OS_VERSION="$(lsb_release -rs 2>/dev/null || echo "?")"

case "$(echo "$OS" | tr '[:upper:]' '[:lower:]')" in
    debian|ubuntu|kali|linuxmint|pop|elementary|zorin)
        echo_success "OS detected: ${OS} ${OS_VERSION} (compatible)"
        ;;
    *)
        echo_warn "OS '${OS}' may not be fully supported. Continuing anyway..."
        ;;
esac

echo -e "  ${checkmark} Architecture: $(uname -m)"
echo -e "  ${checkmark} Kernel: $(uname -r)"

# =============================================================================
#  2.  SYSTEM DEPENDENCIES
# =============================================================================

echo_title "2/6  —  System Dependencies"

PKGS=()
if ! command -v python3 &>/dev/null; then
    PKGS+=(python3)
fi
if ! command -v python3-config &>/dev/null; then
    PKGS+=(python3-dev)
fi
if ! python3 -c "import ensurepip" &>/dev/null 2>&1; then
    PKGS+=(python3-venv python3-pip)
fi
if ! command -v gcc &>/dev/null || ! command -v make &>/dev/null; then
    PKGS+=(build-essential)
fi

# libffi-dev may be needed for aiohttp speedups / cryptography
if ! ldconfig -p 2>/dev/null | grep -q libffi; then
    PKGS+=(libffi-dev)
fi

# libssl-dev for aiohttp speedups
if ! ldconfig -p 2>/dev/null | grep -q libssl; then
    PKGS+=(libssl-dev)
fi

if [[ ${#PKGS[@]} -gt 0 ]]; then
    echo_info "Installing missing system packages: ${PKGS[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PKGS[@]}"
    echo_success "System dependencies installed"
else
    echo_success "All system dependencies already satisfied"
fi

# Verify Python version
PYTHON_VERSION="$(python3 --version 2>&1 | grep -oP '\d+\.\d+')"
PYTHON_MAJOR="${PYTHON_VERSION%%.*}"
PYTHON_MINOR="${PYTHON_VERSION#*.}"
if [[ "$PYTHON_MAJOR" -lt "$PYTHON_MIN_MAJOR" ]] || \
   { [[ "$PYTHON_MAJOR" -eq "$PYTHON_MIN_MAJOR" ]] && \
     [[ "$PYTHON_MINOR" -lt "$PYTHON_MIN_MINOR" ]]; }; then
    echo_failure "Python ${PYTHON_VERSION} < ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} — upgrade required"
    exit 1
fi
echo -e "  ${checkmark} Python $(python3 --version) (minimum ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} satisfied)"

# =============================================================================
#  3.  VIRTUAL ENVIRONMENT (smart detection)
# =============================================================================

echo_title "3/6  —  Virtual Environment"

create_venv() {
    echo_info "Creating fresh virtual environment in ${VENV_DIR}..."
    rm -rf "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
    echo_success "Virtual environment created"
}

# Determine if existing venv is healthy
VENV_OK=false
if [[ -d "$VENV_DIR" ]]; then
    VENV_PYTHON="${VENV_DIR}/bin/python3"
    if [[ -x "$VENV_PYTHON" ]]; then
        # Check that the symlink target exists (not a broken symlink due to dir relocation)
        if "$VENV_PYTHON" --version &>/dev/null 2>&1; then
            # Check that the venv path is consistent (not moved)
            VENV_PATH_MARKER="${VENV_DIR}/pyvenv.cfg"
            if [[ -f "$VENV_PATH_MARKER" ]] && grep -q "home" "$VENV_PATH_MARKER" 2>/dev/null; then
                VENV_OK=true
                echo_success "Existing virtual environment is healthy"
            else
                echo_warn "Existing venv appears corrupted (missing or malformed pyvenv.cfg)"
            fi
        else
            echo_warn "Existing venv python binary is broken (directory moved?)"
        fi
    else
        echo_warn "Existing venv has no python3 binary"
    fi
fi

if [[ "$VENV_OK" != "true" ]]; then
    create_venv
fi

VENV_PYTHON="${VENV_DIR}/bin/python3"
VENV_PIP="${VENV_DIR}/bin/pip"

echo_info "Upgrading pip inside virtual environment..."
"$VENV_PYTHON" -m pip install --upgrade pip --quiet
echo_success "pip upgraded to $("$VENV_PIP" --version | cut -d' ' -f2)"

# =============================================================================
#  4.  INSTALL PYTHON REQUIREMENTS
# =============================================================================

echo_title "4/6  —  Python Dependencies"

if [[ ! -f "$REQUIREMENTS" ]]; then
    echo_failure "requirements.txt not found at ${REQUIREMENTS}"
    exit 1
fi

echo_info "Installing Python packages from requirements.txt..."
"$VENV_PYTHON" -m pip install \
    --quiet \
    --no-input \
    -r "$REQUIREMENTS" 2>&1 | grep -v "already satisfied" || true

echo_success "Python dependencies installed"
echo -e "  ${arrow} Packages installed:"
"$VENV_PIP" list --format=columns 2>/dev/null | grep -iE "rich|watchdog|aiohttp|yaml" | \
    while IFS= read -r line; do echo "    ${checkmark} ${line}"; done

# Verify critical imports
echo_info "Verifying imports..."
"$VENV_PYTHON" -c "
import rich, watchdog, aiohttp, yaml
print('  ✓ rich', rich.__version__)
print('  ✓ watchdog', watchdog.__version__)
print('  ✓ aiohttp', aiohttp.__version__)
print('  ✓ pyyaml', yaml.__version__)
"
echo_success "All imports verified successfully"

# =============================================================================
#  5.  CREATE SYSTEM-WIDE LAUNCHER
# =============================================================================

echo_title "5/6  —  System Launcher"

# Determine the site-packages path inside the venv
VENV_SITE_PACKAGES=$("$VENV_PYTHON" -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || true)
if [[ -z "$VENV_SITE_PACKAGES" ]]; then
    VENV_SITE_PACKAGES="$VENV_DIR/lib/python$PYTHON_VERSION/site-packages"
fi

echo_info "Installing launcher to ${LAUNCHER_PATH}..."

cat > /tmp/shadownet_launcher.sh << LAUNCHER_EOF
#!/usr/bin/env bash
# ShadowNet system-wide launcher (auto-generated by install.sh)
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR}"
VENV_PYTHON="${VENV_DIR}/bin/python3"
SHADOWNET_MODULE="${SHADOWNET_MODULE}"

if [[ ! -x "\$VENV_PYTHON" ]]; then
    echo "[✗] ShadowNet virtual environment is broken or missing."
    echo "    Run 'sudo ${PROJECT_DIR}/install.sh' to repair."
    exit 1
fi

# Ensure we are running with sufficient privileges for firewall operations
if [[ \$EUID -ne 0 ]]; then
    exec sudo PYTHONPATH="\${PYTHONPATH:-}" "\$VENV_PYTHON" -m "\$SHADOWNET_MODULE" "\$@"
else
    exec "\$VENV_PYTHON" -m "\$SHADOWNET_MODULE" "\$@"
fi
LAUNCHER_EOF

install -m 755 /tmp/shadownet_launcher.sh "$LAUNCHER_PATH"
rm -f /tmp/shadownet_launcher.sh

echo_success "Launcher installed at ${LAUNCHER_PATH}"
echo -e "  ${arrow} Run ${BOLD}\`shadownet\`${RESET} from anywhere to start ShadowNet"

# =============================================================================
#  6.  FINAL VERIFICATION
# =============================================================================

echo_title "6/6  —  Deployment Verification"

VERIFY_FAILED=false

# Verify launcher exists and is executable
if [[ -x "$LAUNCHER_PATH" ]]; then
    echo_success "Launcher executable: ${LAUNCHER_PATH}"
else
    echo_failure "Launcher not found or not executable"
    VERIFY_FAILED=true
fi

# Verify venv python works
if "$VENV_PYTHON" --version &>/dev/null; then
    echo_success "Virtual environment Python: $("$VENV_PYTHON" --version 2>&1)"
else
    echo_failure "Virtual environment Python broken"
    VERIFY_FAILED=true
fi

# Verify module can be imported
if "$VENV_PYTHON" -c "from ${SHADOWNET_MODULE} import main; print('  ✓ Module import OK')" &>/dev/null; then
    echo_success "ShadowNet module import successful"
else
    echo_failure "ShadowNet module failed to import"
    VERIFY_FAILED=true
fi

# Verify honeyfile directory exists
if [[ -d "${PROJECT_DIR}" ]]; then
    echo_success "Project directory: ${PROJECT_DIR}"
fi

echo ""
if [[ "$VERIFY_FAILED" == "true" ]]; then
    echo -e "${RED}${BOLD}━━━  DEPLOYMENT COMPLETED WITH WARNINGS  ━━━${RESET}"
    echo -e "${YELLOW}  Some checks failed. Review the output above.${RESET}\n"
    exit 1
else
    echo -e "${GREEN}${BOLD}━━━  SHADOWNET DEPLOYED SUCCESSFULLY  ━━━${RESET}"
    echo -e "\n${star} ${BOLD}Quick start:${RESET}"
    echo -e "  ${arrow} ${CYAN}shadownet${RESET}          Launch ShadowNet"
    echo -e "  ${arrow} ${CYAN}shadownet --help${RESET}   Show help"
    echo -e "\n${star} ${BOLD}Configuration:${RESET}"
    echo -e "  ${arrow} Edit ${CYAN}${PROJECT_DIR}/config.yaml${RESET}"
    echo -e "  ${arrow} Logs written to ${CYAN}${PROJECT_DIR}/logs/shadownet.log${RESET}"
    echo -e "\n${star} ${BOLD}Uninstall:${RESET}"
    echo -e "  ${arrow} ${CYAN}rm \"${LAUNCHER_PATH}\" && rm -rf \"${VENV_DIR}\"${RESET}\n"
fi
