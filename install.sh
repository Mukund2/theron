#!/bin/bash
#
# Theron Installer
# Usage: curl -fsSL https://get.theron.dev | sh
#
# This script:
# 1. Detects your OS
# 2. Checks for Python 3.11+, installs if missing
# 3. Installs Theron via pip
# 4. Runs theron setup to configure automatic protection
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Minimum Python version
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=11

print_banner() {
    echo ""
    echo -e "${BLUE}${BOLD}"
    echo "  _____ _                            "
    echo " |_   _| |__   ___ _ __ ___  _ __    "
    echo "   | | | '_ \\ / _ \\ '__/ _ \\| '_ \\   "
    echo "   | | | | | |  __/ | | (_) | | | |  "
    echo "   |_| |_| |_|\\___|_|  \\___/|_| |_|  "
    echo -e "${NC}"
    echo ""
    echo -e "  ${BOLD}Security proxy for agentic AI systems${NC}"
    echo ""
}

info() {
    echo -e "${BLUE}==>${NC} ${BOLD}$1${NC}"
}

success() {
    echo -e "${GREEN}==>${NC} ${BOLD}$1${NC}"
}

warn() {
    echo -e "${YELLOW}==>${NC} ${BOLD}$1${NC}"
}

error() {
    echo -e "${RED}==>${NC} ${BOLD}$1${NC}"
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            ;;
        Linux*)
            OS="linux"
            # Detect distro
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO=$ID
            elif [ -f /etc/debian_version ]; then
                DISTRO="debian"
            elif [ -f /etc/redhat-release ]; then
                DISTRO="rhel"
            else
                DISTRO="unknown"
            fi
            ;;
        *)
            error "Unsupported operating system: $(uname -s)"
            echo "For Windows, use PowerShell:"
            echo "  irm https://get.theron.dev/install.ps1 | iex"
            exit 1
            ;;
    esac
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get Python version as comparable number (e.g., 3.11 -> 311)
get_python_version() {
    local python_cmd=$1
    if command_exists "$python_cmd"; then
        $python_cmd -c "import sys; print(f'{sys.version_info.major}{sys.version_info.minor:02d}')" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

# Find suitable Python
find_python() {
    local min_version="${MIN_PYTHON_MAJOR}${MIN_PYTHON_MINOR}"

    # Check common Python commands
    for cmd in python3.13 python3.12 python3.11 python3 python; do
        local version=$(get_python_version "$cmd")
        if [ "$version" -ge "$min_version" ]; then
            PYTHON_CMD="$cmd"
            PYTHON_VERSION=$($cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            return 0
        fi
    done

    return 1
}

# Install Python on macOS
install_python_macos() {
    info "Installing Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ on macOS..."

    # Try Homebrew first
    if command_exists brew; then
        info "Using Homebrew to install Python..."
        brew install python@3.12

        # Add to PATH for this session
        export PATH="/opt/homebrew/opt/python@3.12/bin:/usr/local/opt/python@3.12/bin:$PATH"

        if find_python; then
            success "Python installed successfully via Homebrew"
            return 0
        fi
    fi

    # Fall back to official installer
    info "Downloading official Python installer..."
    local pkg_url="https://www.python.org/ftp/python/3.12.4/python-3.12.4-macos11.pkg"
    local pkg_file="/tmp/python-installer.pkg"

    curl -fsSL "$pkg_url" -o "$pkg_file"

    warn "Python installer downloaded. Running installer (may require password)..."
    sudo installer -pkg "$pkg_file" -target /
    rm -f "$pkg_file"

    # The official installer puts python3.12 in /usr/local/bin
    export PATH="/usr/local/bin:$PATH"

    if find_python; then
        success "Python installed successfully"
        return 0
    fi

    return 1
}

# Install Python on Linux
install_python_linux() {
    info "Installing Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ on Linux..."

    case "$DISTRO" in
        ubuntu|debian|pop|linuxmint)
            info "Using apt to install Python..."

            # Check Ubuntu version for deadsnakes PPA
            if [ "$DISTRO" = "ubuntu" ]; then
                sudo apt-get update
                sudo apt-get install -y software-properties-common
                sudo add-apt-repository -y ppa:deadsnakes/ppa
                sudo apt-get update
            fi

            sudo apt-get install -y python3.12 python3.12-venv python3-pip
            ;;
        fedora)
            info "Using dnf to install Python..."
            sudo dnf install -y python3.12
            ;;
        rhel|centos|rocky|almalinux)
            info "Using dnf to install Python..."
            sudo dnf install -y python3.12
            ;;
        arch|manjaro)
            info "Using pacman to install Python..."
            sudo pacman -Sy --noconfirm python
            ;;
        opensuse*)
            info "Using zypper to install Python..."
            sudo zypper install -y python312
            ;;
        *)
            error "Unknown Linux distribution: $DISTRO"
            echo "Please install Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ manually and run this script again."
            exit 1
            ;;
    esac

    if find_python; then
        success "Python installed successfully"
        return 0
    fi

    return 1
}

# Install Python based on OS
install_python() {
    case "$OS" in
        macos)
            install_python_macos
            ;;
        linux)
            install_python_linux
            ;;
    esac
}

# Install Theron
install_theron() {
    info "Installing Theron..."

    # Use pip to install theron
    # Using --user to avoid permission issues
    $PYTHON_CMD -m pip install --user --upgrade pip
    $PYTHON_CMD -m pip install --user theron

    # Make sure user bin is in PATH
    local user_bin
    if [ "$OS" = "macos" ]; then
        user_bin="$HOME/Library/Python/$PYTHON_VERSION/bin"
    else
        user_bin="$HOME/.local/bin"
    fi

    export PATH="$user_bin:$PATH"

    # Verify installation
    if command_exists theron; then
        success "Theron installed successfully"
        return 0
    fi

    # Try to find theron in common locations
    for bin_path in "$user_bin" "$HOME/.local/bin" "/usr/local/bin"; do
        if [ -x "$bin_path/theron" ]; then
            export PATH="$bin_path:$PATH"
            success "Theron installed successfully"
            return 0
        fi
    done

    error "Theron installation failed"
    return 1
}

# Run theron setup
run_setup() {
    info "Configuring Theron..."

    if theron setup; then
        success "Theron configured successfully"
        return 0
    else
        error "Setup failed"
        return 1
    fi
}

# Print final instructions
print_success() {
    echo ""
    echo ""
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo -e "${GREEN}${BOLD}                  Installation Complete!                    ${NC}"
    echo -e "${GREEN}${BOLD}============================================================${NC}"
    echo ""
    echo -e "  ${BOLD}NEXT STEP:${NC}"
    echo ""
    echo -e "  ${YELLOW}Close this terminal and open a new one.${NC}"
    echo ""
    echo "  That's it! After you restart your terminal:"
    echo ""
    echo "    - Theron starts automatically in the background"
    echo "    - All your AI agents are now protected"
    echo "    - You don't need to do anything else"
    echo ""
    echo "  Just use your AI agents normally:"
    echo ""
    echo "    $ claude           # Protected automatically"
    echo "    $ your-ai-agent    # Protected automatically"
    echo ""
    echo -e "  ${BOLD}Optional:${NC}"
    echo ""
    echo -e "    View dashboard:   ${BLUE}http://localhost:8080${NC}"
    echo "    Check status:     theron setup --status"
    echo "    Uninstall:        theron setup --uninstall"
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo ""
}

# Main installation flow
main() {
    print_banner

    # Detect OS
    info "Detecting operating system..."
    detect_os
    success "Detected: $OS"

    # Check for Python
    info "Checking for Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+..."
    if find_python; then
        success "Found Python $PYTHON_VERSION ($PYTHON_CMD)"
    else
        warn "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ not found"
        install_python

        if ! find_python; then
            error "Failed to install Python. Please install Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ manually."
            exit 1
        fi
    fi

    # Install Theron
    install_theron

    # Run setup
    run_setup

    # Success!
    print_success
}

# Run main
main
