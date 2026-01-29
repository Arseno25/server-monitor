#!/bin/bash
# Server Process Monitoring MCP Server - Installation Script with Auto-Update
# Usage: chmod +x install.sh && ./install.sh

set -e

# =====================================================================
# MODERN TERMINAL ANIMATIONS & COLORS
# =====================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
NC='\033[0m' # No Color

# Gradient colors for special effects
GRADIENT=($CYAN $BLUE $MAGENTA)

# =====================================================================
# ANIMATION UTILITIES
# =====================================================================

# Spinner frames - modern dot animation
SPINNER_FRAMES=("\e[0m.\e[0m" "\e[0m..\e[0m" "\e[0m...\e[0m" "\e[0m....\e[0m")

# Progress bar frames
PROGRESS_FRAMES=("▏" "▎" "▍" "▌" "▋" "▊" "▉" "█")

# Loading frames - modern spinner
LOADING_FRAMES=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")

# Success animation frames
SUCCESS_FRAMES=("⚪" "⚫" "●")

# Wave animation for title
WAVE_FRAMES=("░" "▒" "▓" "█")

# Hide cursor
hide_cursor() {
    tput civis 2>/dev/null || echo -en "\033[?25l"
}

# Show cursor
show_cursor() {
    tput cvvis 2>/dev/null || echo -en "\033[?25h"
}

# Clear line
clear_line() {
    echo -en "\r\033[K"
}

# Move cursor up
move_up() {
    local lines=$1
    echo -en "\033[${lines}A"
}

# =====================================================================
# ANIMATION FUNCTIONS
# =====================================================================

# Modern spinner with message
spinner() {
    local message=$1
    local pid=$2
    local delay=0.1
    local spin=0
    local temp=""

    hide_cursor

    while kill -0 $pid 2>/dev/null; do
        temp=${LOADING_FRAMES[$spin]}
        spin=$(( (spin + 1) % ${#LOADING_FRAMES[@]} ))
        clear_line
        echo -ne "${CYAN}${temp}${NC} ${message}"
        sleep $delay
    done

    wait $pid
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        clear_line
        echo -e "${GREEN}✓${NC} $message"
    else
        clear_line
        echo -e "${RED}✗${NC} $message"
    fi

    show_cursor
    return $exit_code
}

# Progress bar animation
progress_bar() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))
    local empty=$((width - filled))

    # Build progress bar
    local bar=""
    bar+="${CYAN}"
    for ((i=0; i<filled; i++)); do
        bar+="█"
    done
    bar+="${DIM}"
    for ((i=0; i<empty; i++)); do
        bar+="░"
    done
    bar+="${NC}"

    # Add percentage
    local percent_str="${BOLD}${percentage}%${NC}"

    # Draw progress bar
    clear_line
    echo -ne "  [$bar] $percent_str"
}

# Animated dots
loading_dots() {
    local message=$1
    local duration=${2:-3}
    local dots=0

    hide_cursor

    for ((i=0; i<duration*10; i++)); do
        clear_line
        echo -ne "${CYAN}${message:0:3}${NC} "
        for ((j=0; j<dots; j++)); do
            echo -ne "${YELLOW}.${NC}"
        done
        dots=$(( (dots + 1) % 4 ))
        sleep 0.1
    done

    clear_line
    show_cursor
}

# Typing effect
type_text() {
    local text=$1
    local delay=${2:-0.03}
    local color=${3:-$CYAN}

    echo -ne "${color}"
    for ((i=0; i<${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo -e "${NC}"
}

# Pulse effect
pulse_text() {
    local text=$1
    local cycles=${2:-3}
    local delay=${3:-0.15}

    for ((cycle=0; cycle<cycles; cycle++)); do
        for intensity in 2 1 0 1 2; do
            clear_line
            if [ $intensity -eq 2 ]; then
                echo -e "${BOLD}${text}${NC}"
            elif [ $intensity -eq 1 ]; then
                echo -e "${text}${NC}"
            else
                echo -e "${DIM}${text}${NC}"
            fi
            sleep $delay
        done
    done
    clear_line
}

# Success checkmark animation
checkmark_animation() {
    local delay=0.1
    local steps=(" " "✓" "✓")
    local colors=("$DIM" "$YELLOW" "$GREEN")

    clear_line
    for ((i=0; i<${#steps[@]}; i++)); do
        clear_line
        echo -e "${colors[$i]}${steps[$i]}${NC}"
        sleep $delay
    done
}

# Wave text effect
wave_text() {
    local text=$1
    local delay=${2:-0.1}

    for ((pass=0; pass<2; pass++)); do
        clear_line
        echo -ne "${CYAN}"
        for ((i=0; i<${#text}; i++)); do
            local wave=$(( (i + pass) % 4 ))
            case $wave in
                0) echo -ne "${DIM}${text:$i:1}${NC}" ;;
                1) echo -ne "${text:$i:1}" ;;
                2) echo -ne "${BOLD}${text:$i:1}${NC}" ;;
                3) echo -ne "${text:$i:1}" ;;
            esac
        done
        echo -ne "${NC}"
        sleep $delay
    done
    clear_line
}

# =====================================================================
# MODERN BANNER
# =====================================================================

print_banner() {
    local title="⚡ SERVER PROCESS MONITORING MCP"
    local subtitle="Forensic Investigator for Silent Failures"

    echo -e ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}        ${BOLD}${GREEN}$title${NC}        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     ${DIM}${CYAN}$subtitle${NC}     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo -e ""
}

# Animated welcome
welcome_animation() {
    clear_line
    type_text "🚀 Initializing installation process..." 0.02 $CYAN
    echo ""
}

# Success celebration
celebrate_success() {
    local message=$1

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}                    ${BOLD}${GREEN}✨ SUCCESS! ✨${NC}                      ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}  $message${NC}"
    echo ""

    # Animated sparkles
    for ((i=0; i<3; i++)); do
        clear_line
        echo -e "${YELLOW}✨${NC} ${CYAN}✨${NC} ${MAGENTA}✨${NC}"
        sleep 0.2
        clear_line
        echo -e "${CYAN}✨${NC} ${MAGENTA}✨${NC} ${YELLOW}✨${NC}"
        sleep 0.2
    done
    clear_line
    echo ""
}

# =====================================================================
# INSTALLATION VARIABLES
# =====================================================================

INSTALL_PATH=$(pwd)
REPO_NAME="Arseno25/server-monitor"
VERSION_FILE=".version"
BACKUP_DIR=".backup_before_update"

PRESERVE_FILES=(
    "config.py"
    ".env"
    "venv/"
)

# =====================================================================
# HELPER FUNCTIONS
# =====================================================================

get_current_version() {
    if [ -f "$VERSION_FILE" ]; then
        cat "$VERSION_FILE" 2>/dev/null || echo "unknown"
    else
        echo "none"
    fi
}

get_latest_version() {
    LATEST_TAG=$(curl -s -f "https://api.github.com/repos/$REPO_NAME/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || true
    if [ -z "$LATEST_TAG" ]; then
        echo "main"
    else
        echo "$LATEST_TAG"
    fi
}

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
    if [[ $1 == v* ]] && [[ $2 == v* ]]; then
        if [ "$1" \> "$2" ]; then
            return 1
        else
            return 2
        fi
    fi
    return 2
}

print_step() {
    local step=$1
    local total=$2
    local title=$3

    echo ""
    echo -e "${BOLD}${YELLOW}[Step $step/$total]${NC} $title"
    echo ""
}

# =====================================================================
# BACKUP & UPDATE FUNCTIONS
# =====================================================================

backup_installation() {
    echo -e "  ${YELLOW}⚠${NC} Creating backup..."

    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="$BACKUP_DIR/$TIMESTAMP"
    mkdir -p "$BACKUP_PATH"

    # Animated backup
    for file in "${PRESERVE_FILES[@]}"; do
        if [ -e "$file" ]; then
            cp -r "$file" "$BACKUP_PATH/" 2>/dev/null || true
            progress_bar $((${#PRESERVE_FILES[@]} - ${#PRESERVE_FILES[@]} + 1)) ${#PRESERVE_FILES[@]}
        fi
    done

    cp "$VERSION_FILE" "$BACKUP_PATH/" 2>/dev/null || true

    if [ -d "src" ]; then
        cp -r src "$BACKUP_PATH/"
    fi

    if [ -f "server.py" ]; then
        cp server.py "$BACKUP_PATH/"
    fi

    if [ -f "requirements.txt" ]; then
        cp requirements.txt "$BACKUP_PATH/"
    fi

    clear_line
    echo -e "  ${GREEN}✓${NC} Backup created at: ${CYAN}$BACKUP_PATH${NC}"
}

restore_backup() {
    local backup_path=$1
    echo -e "  ${YELLOW}⚠${NC} Restoring from backup..."

    for file in "${PRESERVE_FILES[@]}"; do
        if [ -e "$backup_path/$file" ]; then
            cp -r "$backup_path/$file" ./ 2>/dev/null || true
        fi
    done

    echo -e "  ${GREEN}✓${NC} Backup restored"
}

update_to_version() {
    local target_version=$1
    local download_url=$2

    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${NC}            ${BOLD}${CYAN}🔄 UPDATING TO $target_version${NC}              ${MAGENTA}║${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    backup_installation
    echo ""

    # Download with animation
    echo -e "  ${CYAN}↓${NC} Downloading $target_version..."
    (
        if ! curl -L -f "$download_url" -o Server-monitor-update.tar.gz 2>/dev/null; then
            exit 1
        fi

        if ! file Server-monitor-update.tar.gz 2>/dev/null | grep -q "gzip compressed data"; then
            rm -f Server-monitor-update.tar.gz
            exit 1
        fi

        TEMP_DIR=".update_temp"
        mkdir -p "$TEMP_DIR"
        tar -xzf Server-monitor-update.tar.gz -C "$TEMP_DIR" --strip-components=1
        rm -f Server-monitor-update.tar.gz

        rm -rf src
        mv "$TEMP_DIR/src" ./
        mv "$TEMP_DIR/server.py" ./
        mv "$TEMP_DIR/requirements.txt" ./
        mv "$TEMP_DIR/install.sh" ./

        echo "$target_version" > "$VERSION_FILE"
        rm -rf "$TEMP_DIR"
    ) &

    spinner "Downloading and extracting..." $!

    if [ $? -ne 0 ]; then
        echo -e "  ${RED}✗${NC} Failed to download update"
        restore_backup "$BACKUP_PATH/$(ls -t $BACKUP_DIR 2>/dev/null | head -1)"
        return 1
    fi

    echo ""
    echo -e "  ${GREEN}✓${NC} Update applied successfully"
    echo ""

    return 0
}

check_for_updates() {
    local current_version=$(get_current_version)
    local latest_version=$(get_latest_version)

    echo -e "${BLUE}[Check]${NC} Checking for updates..."
    echo -e "  Current: ${YELLOW}$current_version${NC}"
    echo -e "  Latest:  ${GREEN}$latest_version${NC}"
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

        if [ "$latest_version" == "main" ]; then
            DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/main.tar.gz"
        else
            DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/refs/tags/$latest_version.tar.gz"
        fi

        if [ "$AUTO_UPDATE" != "true" ]; then
            echo -ne "  ${CYAN}Update now?${NC} [Y/n] "
            read -r response
            if [[ "$response" =~ ^[Nn]$ ]]; then
                echo -e "  ${YELLOW}⚠${NC} Update skipped."
                echo ""
                return 0
            fi
        fi

        if update_to_version "$latest_version" "$DOWNLOAD_URL"; then
            echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║${NC}                    ${BOLD}${GREEN}✨ UPDATE COMPLETE! ✨${NC}                 ${GREEN}║${NC}"
            echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "  ${GREEN}✓${NC} Updated: ${YELLOW}$current_version${NC} → ${GREEN}$latest_version${NC}"
            echo -e "  ${CYAN}ℹ${NC} Your configuration has been preserved"
            echo ""

            if [ -d "venv" ]; then
                echo -e "  ${CYAN}↓${NC} Updating dependencies..."
                (
                    source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
                    pip install -r requirements.txt -q 2>/dev/null
                ) &

                spinner "Updating Python packages..." $!
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

# =====================================================================
# MAIN SCRIPT
# =====================================================================

print_banner

# Parse arguments
AUTO_UPDATE="false"
FORCE_UPDATE="false"
SKIP_UPDATE="false"

for arg in "$@"; do
    case $arg in
        --auto-update) AUTO_UPDATE="true" ;;
        --force-update) FORCE_UPDATE="true" ;;
        --skip-update) SKIP_UPDATE="true" ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --auto-update    Update automatically"
            echo "  --force-update   Force update"
            echo "  --skip-update    Skip update check"
            echo "  --help           Show help"
            echo ""
            exit 0
            ;;
    esac
done

welcome_animation

# Check for updates
if [ -d "src" ] && [ -f "server.py" ] && [ "$SKIP_UPDATE" != "true" ]; then
    if ! check_for_updates; then
        echo -e "  ${RED}✗${NC} Update check failed. Continuing..."
        echo ""
    fi

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
# STEP 0: Bootstrap
# ============================================================
if [ ! -d "src" ] || [ ! -f "server.py" ]; then
    print_step 0 6 "Bootstrapping..."

    if [ "$(id -u)" -eq 0 ]; then
        SUDO_CMD=""
    else
        if ! command -v sudo &> /dev/null; then
            echo -e "  ${RED}✗${NC} Requires sudo or root"
            exit 1
        fi
        SUDO_CMD="sudo"
    fi

    # Check dependencies
    MISSING_DEPS=()
    for cmd in curl tar gzip file; do
        if ! command -v $cmd &> /dev/null; then
            MISSING_DEPS+=($cmd)
        fi
    done

    if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
        echo -e "  ${YELLOW}⚠${NC} Installing dependencies: ${MISSING_DEPS[*]}"

        if command -v apt-get &> /dev/null; then
            $SUDO_CMD apt-get update -qq
            $SUDO_CMD apt-get install -y -qq "${MISSING_DEPS[@]}"
        elif command -v yum &> /dev/null; then
            $SUDO_CMD yum install -y -q "${MISSING_DEPS[@]}"
        elif command -v apk &> /dev/null; then
            $SUDO_CMD apk add --no-cache "${MISSING_DEPS[@]}"
        fi

        echo -e "  ${GREEN}✓${NC} Dependencies installed"
    fi

    # Download source
    echo -e "  ${CYAN}↓${NC} Fetching latest release..."

    LATEST_TAG=$(curl -s -f "https://api.github.com/repos/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || true

    if [ -z "$LATEST_TAG" ]; then
        echo -e "  ${YELLOW}⚠${NC} Using main branch"
        DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/main.tar.gz"
        VERSION="main"
    else
        echo -e "  ${GREEN}✓${NC} Found: ${GREEN}$LATEST_TAG${NC}"
        DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/refs/tags/$LATEST_TAG.tar.gz"
        VERSION="$LATEST_TAG"
    fi

    echo -e "  ${CYAN}↓${NC} Downloading $VERSION..."

    (
        if ! curl -L -f "$DOWNLOAD_URL" -o Server-monitor.tar.gz; then
            exit 1
        fi

        if ! file Server-monitor.tar.gz | grep -q "gzip compressed data"; then
            rm -f Server-monitor.tar.gz
            exit 1
        fi

        tar -xzf Server-monitor.tar.gz --strip-components=1
        rm Server-monitor.tar.gz

        echo "$VERSION" > "$VERSION_FILE"
    ) &

    spinner "Downloading and extracting..." $!

    echo ""
fi

# ============================================================
# STEP 1: Prerequisites
# ============================================================
print_step 1 6 "Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo -e "  ${RED}✗${NC} Python 3 not found"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python 3 found"

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.10"

version_compare() {
    printf '%s\n%s' "$1" "$2" | sort -V | head -n1
}

if [ "$(version_compare "$REQUIRED_VERSION" "$PYTHON_VERSION")" != "$REQUIRED_VERSION" ]; then
    echo -e "  ${RED}✗${NC} Python $REQUIRED_VERSION+ required (found: $PYTHON_VERSION)"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Python $PYTHON_VERSION"

if ! python3 -m venv --help &> /dev/null; then
    echo -e "  ${RED}✗${NC} python3-venv not installed"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} python3-venv available"

# ============================================================
# STEP 2: Required Files
# ============================================================
print_step 2 6 "Checking required files..."

FILES_OK=true
if [ ! -f "requirements.txt" ]; then
    echo -e "  ${RED}✗${NC} requirements.txt"
    FILES_OK=false
fi
if [ ! -f "server.py" ]; then
    echo -e "  ${RED}✗${NC} server.py"
    FILES_OK=false
fi
if [ ! -d "src" ]; then
    echo -e "  ${RED}✗${NC} src/"
    FILES_OK=false
fi

if [ "$FILES_OK" = false ]; then
    exit 1
fi

echo -e "  ${GREEN}✓${NC} All files present"

# ============================================================
# STEP 3: Virtual Environment
# ============================================================
print_step 3 6 "Setting up virtual environment..."

if [ -d "venv" ]; then
    echo -e "  ${GREEN}✓${NC} Virtual environment exists"
else
    echo -e "  ${CYAN}↓${NC} Creating virtual environment..."

    (
        python3 -m venv venv
    ) &

    spinner "Creating virtual environment..." $!

    if [ ! -d "venv" ]; then
        echo -e "  ${RED}✗${NC} Failed to create venv"
        exit 1
    fi
fi

# ============================================================
# STEP 4: Activate
# ============================================================
print_step 4 6 "Activating virtual environment..."

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo -e "  ${GREEN}✓${NC} Activated (Linux)"
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
    echo -e "  ${GREEN}✓${NC} Activated (Windows)"
else
    echo -e "  ${RED}✗${NC} No activate script found"
    exit 1
fi

# ============================================================
# STEP 5: Dependencies
# ============================================================
print_step 5 6 "Installing dependencies..."

echo -e "  ${CYAN}↓${NC} Upgrading pip..."

(
    pip install --upgrade pip -q 2>/dev/null
) &

spinner "Upgrading pip..." $!

echo -e "  ${CYAN}↓${NC} Installing requirements..."

(
    pip install -r requirements.txt -q 2>/dev/null
) &

spinner "Installing packages..." $!

# ============================================================
# STEP 6: Verification
# ============================================================
print_step 6 6 "Verifying installation..."

if python -c "from src.presentation import register_tools" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Modules imported"
else
    echo -e "  ${YELLOW}⚠${NC} Import check failed"
fi

if python -c "import mcp" 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} MCP SDK installed"
else
    echo -e "  ${RED}✗${NC} MCP SDK not found"
fi

# ============================================================
# SUCCESS
# ============================================================

CURRENT_VER=$(get_current_version)
celebrate_success "Installation Complete!"

if [ "$CURRENT_VER" != "none" ]; then
    echo -e "  ${CYAN}Version:${NC} $CURRENT_VER"
    echo ""
fi

echo -e "${BOLD}${BLUE}Quick Start:${NC}"
echo ""
echo -e "  1. Activate:"
echo -e "     ${YELLOW}source venv/bin/activate${NC}"
echo ""
echo -e "  2. Run server:"
echo -e "     ${YELLOW}python server.py${NC}"
echo ""
echo -e "  3. Update:"
echo -e "     ${YELLOW}./install.sh --auto-update${NC}"
echo ""

echo -e "${BOLD}${BLUE}MCP Configuration:${NC}"
echo ""
echo -e "  Add to ${YELLOW}claude_desktop_config.json${NC}:"
echo ""
echo '  {'
echo '    "mcpServers": {'
echo '      "Server-forensics": {'
echo '        "command": "ssh",'
echo '        "args": ["-i", "/path/key.pem", "user@host", "python", "'"$INSTALL_PATH"'"]'
echo '      }'
echo '    }'
echo '  }'
echo ""

echo -e "${BOLD}${BLUE}Available Tools (${CYAN}14 total${NC}${BOLD}):${NC}"
echo ""
echo -e "  ${DIM}System Monitoring:${NC}"
echo "  • scan_process_anomalies"
echo "  • deep_docker_inspect"
echo "  • check_resource_leaks"
echo "  • read_kernel_ring_buffer"
echo "  • analyze_background_tasks"
echo ""
echo -e "  ${GREEN}Security Detection (NEW):${NC}"
echo "  • detect_ddos_attack"
echo "  • detect_brute_force_attack"
echo "  • detect_port_scan"
echo "  • analyze_security_logs"
echo "  • detect_system_anomalies"
echo "  • analyze_network_forensics"
echo "  • detect_malware_indicators"
echo ""
echo -e "  ${DIM}Remediation:${NC}"
echo "  • kill_process"
echo "  • restart_container"
echo ""

if [ "$CURRENT_VER" != "none" ]; then
    echo -e "${CYAN}💡${NC} Add to cron: ${YELLOW}0 2 * * * $PWD/install.sh --auto-update${NC}"
    echo ""
fi
