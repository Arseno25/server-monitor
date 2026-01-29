#!/bin/bash
# Server Process Monitoring MCP Server - Installation Script with Auto-Update
# Usage: chmod +x install.sh && ./install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Get installation path
INSTALL_PATH=$(pwd)
REPO_NAME="Arseno25/server-monitor"
VERSION_FILE=".version"
BACKUP_DIR=".backup_before_update"

# Files to preserve during update
PRESERVE_FILES=(
    "config.py"
    ".env"
    "venv/"
)

# ============================================================
# Helper Functions
# ============================================================

# Print banner
print_banner() {
    echo -e ""
    echo -e "${BLUE} ╭──────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BLUE} │                                                          │${NC}"
    echo -e "${BLUE} │  ${BOLD}${GREEN}⚡ SERVER PROCESS MONITORING MCP${NC}${BLUE}                       │${NC}"
    echo -e "${BLUE} │     ${CYAN}Forensic Investigator for Silent Failures${NC}${BLUE}            │${NC}"
    echo -e "${BLUE} │                                                          │${NC}"
    echo -e "${BLUE} ╰──────────────────────────────────────────────────────────╯${NC}"
    echo -e ""
}

# Get current installed version
get_current_version() {
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE" 2>/dev/null || echo "unknown"
    else
        echo "none"
    fi
}

# Get latest version from GitHub
get_latest_version() {
    # Try getting latest tag
    LATEST_TAG=$(curl -s -f "https://api.github.com/repos/$REPO_NAME/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || true

    if [ -z "$LATEST_TAG" ]; then
        echo "main"
    else
        echo "$LATEST_TAG"
    fi
}

# Compare versions (returns 0 if equal, 1 if first is newer, 2 if second is newer)
compare_versions() {
    if [[ "$1" == "$2" ]]; then
        return 0
    fi
    if [[ "$1" == "none" ]]; then
        return 2
    fi
    if [[ "$2" == "none" ]]; then
        return 1
    fi
    # Simple version comparison for v1.0.0 format
    if [[ $1 == v* ]] && [[ $2 == v* ]]; then
        if [ "$1" \> "$2" ]; then
            return 1
        else
            return 2
        fi
    fi
    # Default: second is newer
    return 2
}

# Backup current installation
backup_installation() {
    echo -e "  ${YELLOW}⚠${NC} Creating backup of current installation..."

    # Create backup directory with timestamp
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="$BACKUP_DIR/$TIMESTAMP"

    mkdir -p "$BACKUP_PATH"

    # Backup important files
    for file in "${PRESERVE_FILES[@]}"; do
        if [ -e "$file" ]; then
            cp -r "$file" "$BACKUP_PATH/" 2>/dev/null || true
        fi
    done

    # Also backup current version
    cp "$VERSION_FILE" "$BACKUP_PATH/" 2>/dev/null || true

    # Create backup of source files
    if [ -d "src" ]; then
        cp -r src "$BACKUP_PATH/"
    fi

    if [ -f "server.py" ]; then
        cp server.py "$BACKUP_PATH/"
    fi

    if [ -f "requirements.txt" ]; then
        cp requirements.txt "$BACKUP_PATH/"
    fi

    echo -e "  ${GREEN}✓${NC} Backup created at: $BACKUP_PATH"
}

# Restore from backup
restore_backup() {
    local backup_path=$1
    echo -e "  ${YELLOW}⚠${NC} Restoring from backup: $backup_path"

    # Restore files
    for file in "${PRESERVE_FILES[@]}"; do
        if [ -e "$backup_path/$file" ]; then
            cp -r "$backup_path/$file" ./ 2>/dev/null || true
        fi
    done

    echo -e "  ${GREEN}✓${NC} Backup restored"
}

# Download and update to new version
update_to_version() {
    local target_version=$1
    local download_url=$2

    echo -e ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}                    🔄 UPDATING TO $target_version${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e ""

    # Create backup
    backup_installation
    echo ""

    # Download new version
    echo -e "  ${BLUE}→${NC} Downloading $target_version..."

    if ! curl -L -f "$download_url" -o Server-monitor-update.tar.gz 2>/dev/null; then
        echo -e "  ${RED}✗${NC} Failed to download update"
        restore_backup "$BACKUP_PATH/$(ls -t $BACKUP_DIR | head -1)"
        return 1
    fi

    # Verify download
    if ! file Server-monitor-update.tar.gz 2>/dev/null | grep -q "gzip compressed data"; then
        echo -e "  ${RED}✗${NC} Downloaded file is not valid"
        rm -f Server-monitor-update.tar.gz
        restore_backup "$BACKUP_PATH/$(ls -t $BACKUP_DIR | head -1)"
        return 1
    fi

    echo -e "  ${GREEN}✓${NC} Download complete"

    # Create temp directory for extraction
    TEMP_DIR=".update_temp"
    mkdir -p "$TEMP_DIR"

    echo -e "  ${BLUE}→${NC} Extracting update..."
    tar -xzf Server-monitor-update.tar.gz -C "$TEMP_DIR" --strip-components=1
    rm -f Server-monitor-update.tar.gz

    # Update source files (preserve user config)
    echo -e "  ${BLUE}→${NC} Applying update..."

    # Remove old source directory
    rm -rf src

    # Move new files
    mv "$TEMP_DIR/src" ./
    mv "$TEMP_DIR/server.py" ./
    mv "$TEMP_DIR/requirements.txt" ./
    mv "$TEMP_DIR/install.sh" ./

    # Update version file
    echo "$target_version" > "$VERSION_FILE"

    # Clean up temp directory
    rm -rf "$TEMP_DIR"

    echo -e "  ${GREEN}✓${NC} Update applied successfully"
    echo ""

    return 0
}

# Check for updates
check_for_updates() {
    local current_version=$(get_current_version)
    local latest_version=$(get_latest_version)

    echo -e "${BLUE}[Check]${NC} Checking for updates..."
    echo -e "  Current version: ${YELLOW}$current_version${NC}"
    echo -e "  Latest version:  ${YELLOW}$latest_version${NC}"
    echo ""

    compare_versions "$current_version" "$latest_version"
    local result=$?

    if [ $result -eq 0 ]; then
        echo -e "  ${GREEN}✓${NC} Already up to date!"
        echo ""
        return 0
    elif [ $result -eq 2 ]; then
        echo -e "  ${YELLOW}⚠${NC} ${BOLD}Update available!${NC}"
        echo ""

        # Determine download URL
        if [ "$latest_version" == "main" ]; then
            DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/main.tar.gz"
        else
            DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/refs/tags/$latest_version.tar.gz"
        fi

        # Ask user if they want to update (for interactive mode)
        if [ "$AUTO_UPDATE" != "true" ]; then
            echo -e "  ${CYAN}Would you like to update? (y/N)${NC}"
            read -r response
            if [[ ! "$response" =~ ^[Yy]$ ]]; then
                echo -e "  ${YELLOW}⚠${NC} Update skipped. Continuing with current version..."
                echo ""
                return 0
            fi
        fi

        # Auto-update
        if update_to_version "$latest_version" "$DOWNLOAD_URL"; then
            echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║              ✅ Update Complete!                         ║${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "  ${GREEN}✓${NC} Updated from ${YELLOW}$current_version${NC} to ${YELLOW}$latest_version${NC}"
            echo -e "  ${CYAN}ℹ${NC} Your configuration has been preserved"
            echo ""

            # Check if requirements changed
            if [ -d "venv" ]; then
                echo -e "  ${BLUE}→${NC} Updating Python dependencies..."
                source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
                pip install -r requirements.txt -q 2>/dev/null || true
                echo -e "  ${GREEN}✓${NC} Dependencies updated"
                echo ""
            fi

            return 0
        else
            echo -e "  ${RED}✗${NC} Update failed. Changes rolled back."
            return 1
        fi
    fi

    return 0
}

# ============================================================
# Main Installation Script
# ============================================================

print_banner

# Parse command line arguments
AUTO_UPDATE="false"
FORCE_UPDATE="false"
SKIP_UPDATE="false"

for arg in "$@"; do
    case $arg in
        --auto-update)
            AUTO_UPDATE="true"
            ;;
        --force-update)
            FORCE_UPDATE="true"
            ;;
        --skip-update)
            SKIP_UPDATE="true"
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --auto-update    Automatically update without prompting"
            echo "  --force-update   Force update even if already latest"
            echo "  --skip-update    Skip update check"
            echo "  --help           Show this help message"
            echo ""
            exit 0
            ;;
        *)
            ;;
    esac
done

# Check for updates (skip if first-time install or explicitly requested)
if [ -d "src" ] && [ -f "server.py" ] && [ "$SKIP_UPDATE" != "true" ]; then
    if ! check_for_updates; then
        echo -e "  ${RED}✗${NC} Update check failed. Continuing with current version..."
        echo ""
    fi

    # Exit after successful update (let user run again if needed)
    if [ "$AUTO_UPDATE" == "true" ] && [ "$SKIP_UPDATE" != "true" ]; then
        current_version=$(get_current_version)
        latest_version=$(get_latest_version)
        compare_versions "$current_version" "$latest_version"
        if [ $? -ne 0 ]; then
            exit 0
        fi
    fi
fi

# ============================================================
# STEP 0: Bootstrap (Download Source) - First time install only
# ============================================================
if [ ! -d "src" ] || [ ! -f "server.py" ]; then
    echo -e "${YELLOW}[Step 0/6]${NC} Project files not found. Bootstrapping..."

    # 0.1 Determine Sudo Usage
    if [ "$(id -u)" -eq 0 ]; then
        SUDO_CMD=""
    else
        if ! command -v sudo &> /dev/null; then
            echo -e "  ${RED}✗${NC} Script requires 'sudo' or root privileges to install dependencies."
            exit 1
        fi
        SUDO_CMD="sudo"
    fi

    # 0.2 Check and Install Dependencies
    MISSING_DEPS=()
    for cmd in curl tar gzip file; do
        if ! command -v $cmd &> /dev/null; then
            MISSING_DEPS+=($cmd)
        fi
    done

    if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
        echo -e "  ${YELLOW}⚠${NC} Missing dependencies: ${MISSING_DEPS[*]}"
        echo -e "  ${BLUE}→${NC} Attempting to install..."

        if command -v apt-get &> /dev/null; then
            $SUDO_CMD apt-get update -qq
            $SUDO_CMD apt-get install -y -qq "${MISSING_DEPS[@]}"
        elif command -v yum &> /dev/null; then
            $SUDO_CMD yum install -y -q "${MISSING_DEPS[@]}"
        elif command -v apk &> /dev/null; then
            $SUDO_CMD apk add --no-cache "${MISSING_DEPS[@]}"
        else
            echo -e "  ${RED}✗${NC} Could not detect package manager. Please install: ${MISSING_DEPS[*]}"
            exit 1
        fi
        echo -e "  ${GREEN}✓${NC} Dependencies installed"
    fi

    # 0.3 Download Source
    echo -e "  ${BLUE}→${NC} Fetching latest release info..."

    LATEST_TAG=$(curl -s -f "https://api.github.com/repos/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || true

    if [ -z "$LATEST_TAG" ]; then
        echo -e "  ${YELLOW}⚠${NC} Could not find latest release. Falling back to main branch..."
        DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/main.tar.gz"
        VERSION="main"
    else
        echo -e "  ${GREEN}✓${NC} Found latest version: ${GREEN}$LATEST_TAG${NC}"
        DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/refs/tags/$LATEST_TAG.tar.gz"
        VERSION="$LATEST_TAG"
    fi

    echo -e "  ${BLUE}→${NC} Downloading $VERSION..."

    if ! curl -L -f "$DOWNLOAD_URL" -o Server-monitor.tar.gz; then
        echo -e "  ${RED}✗${NC} Failed to download source code from $DOWNLOAD_URL"
        rm -f Server-monitor.tar.gz
        exit 1
    fi

    if ! file Server-monitor.tar.gz | grep -q "gzip compressed data"; then
        echo -e "  ${RED}✗${NC} Downloaded file is not a valid gzip package"
        head -n 5 Server-monitor.tar.gz
        rm -f Server-monitor.tar.gz
        exit 1
    fi

    echo -e "  ${BLUE}→${NC} Extracting..."
    tar -xzf Server-monitor.tar.gz --strip-components=1
    rm Server-monitor.tar.gz

    # Save version
    echo "$VERSION" > "$VERSION_FILE"

    echo -e "  ${GREEN}✓${NC} Source code downloaded"
    echo ""
fi

# ============================================================
# STEP 1: Check Prerequisites
# ============================================================
echo -e "${YELLOW}[Step 1/6]${NC} Checking prerequisites..."
echo ""

# Check Python exists
if ! command -v python3 &> /dev/null; then
    echo -e "  ${RED}✗${NC} Python 3 not found"
    echo -e "    Install: ${BLUE}sudo apt install python3 python3-venv python3-pip${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python 3 found"

# Check Python version >= 3.10
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.10"

version_compare() {
    printf '%s\n%s' "$1" "$2" | sort -V | head -n1
}

if [ "$(version_compare "$REQUIRED_VERSION" "$PYTHON_VERSION")" != "$REQUIRED_VERSION" ]; then
    echo -e "  ${RED}✗${NC} Python $REQUIRED_VERSION+ required (found: $PYTHON_VERSION)"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python version: $PYTHON_VERSION"

# Check venv module
if ! python3 -m venv --help &> /dev/null; then
    echo -e "  ${RED}✗${NC} python3-venv not installed"
    echo -e "    Install: ${BLUE}sudo apt install python3-venv${NC}"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} python3-venv available"

echo ""

# ============================================================
# STEP 2: Check Required Files
# ============================================================
echo -e "${YELLOW}[Step 2/6]${NC} Checking required files..."
echo ""

if [ ! -f "requirements.txt" ]; then
    echo -e "  ${RED}✗${NC} requirements.txt not found"
    echo -e "    Make sure you run this from the project root"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} requirements.txt"

if [ ! -f "server.py" ]; then
    echo -e "  ${RED}✗${NC} server.py not found"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} server.py"

if [ ! -d "src" ]; then
    echo -e "  ${RED}✗${NC} src/ directory not found"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} src/ directory"

echo ""

# ============================================================
# STEP 3: Create Virtual Environment
# ============================================================
echo -e "${YELLOW}[Step 3/6]${NC} Setting up virtual environment..."
echo ""

if [ -d "venv" ]; then
    echo -e "  ${GREEN}✓${NC} Virtual environment already exists"
else
    echo -e "  ${BLUE}→${NC} Creating virtual environment..."
    python3 -m venv venv

    if [ ! -d "venv" ]; then
        echo -e "  ${RED}✗${NC} Failed to create virtual environment"
        exit 1
    fi
    echo -e "  ${GREEN}✓${NC} Virtual environment created"
fi

echo ""

# ============================================================
# STEP 4: Activate Virtual Environment
# ============================================================
echo -e "${YELLOW}[Step 4/6]${NC} Activating virtual environment..."
echo ""

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo -e "  ${GREEN}✓${NC} Activated (Linux)"
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
    echo -e "  ${GREEN}✓${NC} Activated (Windows/Git Bash)"
else
    echo -e "  ${RED}✗${NC} Could not find activate script"
    echo -e "    Expected: venv/bin/activate or venv/Scripts/activate"
    echo -e "    Try removing venv folder and run again"
    exit 1
fi

echo ""

# ============================================================
# STEP 5: Install Dependencies
# ============================================================
echo -e "${YELLOW}[Step 5/6]${NC} Installing dependencies..."
echo ""

echo -e "  ${BLUE}→${NC} Upgrading pip..."
pip install --upgrade pip -q 2>/dev/null

echo -e "  ${BLUE}→${NC} Installing requirements..."
pip install -r requirements.txt -q 2>/dev/null

echo -e "  ${GREEN}✓${NC} Dependencies installed"

echo ""

# ============================================================
# STEP 6: Verify Installation
# ============================================================
echo -e "${YELLOW}[Step 6/6]${NC} Verifying installation..."
echo ""

if python -c "from src.presentation import register_tools" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} All modules imported successfully"
else
    echo -e "  ${YELLOW}⚠${NC} Module import check failed (may still work)"
fi

if python -c "import mcp" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} MCP SDK installed"
else
    echo -e "  ${RED}✗${NC} MCP SDK not installed"
fi

echo ""

# ============================================================
# SUCCESS
# ============================================================
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              ✅ Installation Complete!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Show current version
CURRENT_VER=$(get_current_version)
if [ "$CURRENT_VER" != "none" ]; then
    echo -e "  ${CYAN}Version:${NC} $CURRENT_VER"
    echo ""
fi

# Quick Start
echo -e "${BLUE}Quick Start:${NC}"
echo ""
echo "  1. Activate virtualenv:"
echo -e "     ${YELLOW}source venv/bin/activate${NC}"
echo ""
echo "  2. Run server:"
echo -e "     ${YELLOW}python server.py${NC}"
echo ""
echo "  3. Update to latest version (run anytime):"
echo -e "     ${YELLOW}./install.sh --auto-update${NC}"
echo ""

# MCP Configuration
echo -e "${BLUE}MCP Client Configuration:${NC}"
echo ""
echo -e "  Add this to your ${YELLOW}claude_desktop_config.json${NC} or ${YELLOW}.cursor/mcp.json${NC}:"
echo ""
echo '  {'
echo '    "mcpServers": {'
echo '      "Server-forensics": {'
echo '        "command": "ssh",'
echo '        "args": ['
echo '          "-i",'
echo '          "/path/to/your/private-key.pem",'
echo '          "user@your-Server-ip",'
echo '          "python",'
echo "          \"$INSTALL_PATH/server.py\""
echo '        ]'
echo '      }'
echo '    }'
echo '  }'
echo ""
echo -e "  ${YELLOW}Note:${NC} Replace /path/to/private-key.pem and user@your-Server-ip with actual values."
echo ""

# Available Tools
echo -e "${BLUE}Available Tools:${NC}"
echo ""
echo "  System Monitoring:"
echo "  • scan_process_anomalies  - Detect zombie/stuck processes"
echo "  • deep_docker_inspect     - Docker container analysis"
echo "  • check_resource_leaks    - FD/connection leak detection"
echo "  • read_kernel_ring_buffer - Read dmesg for OOM/segfaults"
echo "  • analyze_background_tasks- Find hidden resource hogs"
echo ""
echo "  Security Detection (NEW):"
echo "  • detect_ddos_attack      - DDoS/flood attack detection"
echo "  • detect_brute_force_attack- Brute force attack detection"
echo "  • detect_port_scan        - Port scanning detection"
echo "  • analyze_security_logs   - Security log analysis"
echo "  • detect_system_anomalies - System anomaly detection"
echo "  • analyze_network_forensics- Network forensics analysis"
echo "  • detect_malware_indicators- Malware detection"
echo ""
echo "  Remediation:"
echo "  • kill_process            - Terminate processes (safety checked)"
echo "  • restart_container       - Restart Docker containers"
echo ""

# Auto-update suggestion
if [ "$CURRENT_VER" != "none" ]; then
    echo -e "${CYAN}💡 Tip:${NC} Add ${YELLOW}./install.sh --auto-update${NC} to cron for automatic updates"
    echo ""
fi
