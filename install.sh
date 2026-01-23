#!/bin/bash
# VPS Process Monitoring MCP Server - Installation Script
# Usage: chmod +x install.sh && ./install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Small banner
echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}     🔍 ${GREEN}VPS Process Monitoring MCP Server${NC}                 ${BLUE}║${NC}"
echo -e "${BLUE}║${NC}        Forensic Diagnosis for Silent Failures           ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Get installation path
INSTALL_PATH=$(pwd)
REPO_NAME="Arseno25/vps-monitor"

# ============================================================
# STEP 0: Bootstrap (Download Source)
# ============================================================
if [ ! -d "src" ] || [ ! -f "server.py" ]; then
    echo -e "${YELLOW}[Step 0/6]${NC} Project files not found. Bootstrapping..."
    
    # Check if curl and tar are available
    if ! command -v curl &> /dev/null || ! command -v tar &> /dev/null; then
        echo -e "  ${RED}✗${NC} curl and tar are required for auto-installation"
        exit 1
    fi

    echo -e "  ${BLUE}→${NC} Fetching latest release info..."
    # Get latest release tag from GitHub API
    LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO_NAME/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$LATEST_TAG" ]; then
        echo -e "  ${YELLOW}⚠${NC} Could not find latest release. Falling back to main branch..."
        DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/refs/heads/main.tar.gz"
        VERSION="main"
    else
        echo -e "  ${GREEN}✓${NC} Found latest version: ${GREEN}$LATEST_TAG${NC}"
        DOWNLOAD_URL="https://github.com/$REPO_NAME/archive/refs/tags/$LATEST_TAG.tar.gz"
        VERSION="$LATEST_TAG"
    fi

    echo -e "  ${BLUE}→${NC} Downloading $VERSION..."
    curl -L "$DOWNLOAD_URL" -o vps-monitor.tar.gz
    
    echo -e "  ${BLUE}→${NC} Extracting..."
    # Extract strip-components=1 to dump contents directly into current dir
    tar -xzf vps-monitor.tar.gz --strip-components=1
    rm vps-monitor.tar.gz
    
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
    
    # Verify venv was created
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

# Check for activate script (Linux path)
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo -e "  ${GREEN}✓${NC} Activated (Linux)"
# Check for Windows-style path (Git Bash on Windows)
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

# Quick Start
echo -e "${BLUE}Quick Start:${NC}"
echo ""
echo "  1. Activate virtualenv:"
echo -e "     ${YELLOW}source venv/bin/activate${NC}"
echo ""
echo "  2. Run server:"
echo -e "     ${YELLOW}python server.py${NC}"
echo ""

# MCP Configuration
echo -e "${BLUE}MCP Client Configuration:${NC}"
echo ""
echo -e "  Add this to your ${YELLOW}claude_desktop_config.json${NC} or ${YELLOW}.cursor/mcp.json${NC}:"
echo ""
echo '  {'
echo '    "mcpServers": {'
echo '      "vps-forensics": {'
echo '        "command": "ssh",'
echo '        "args": ['
echo '          "-i",'
echo '          "/path/to/your/private-key.pem",'
echo '          "user@your-vps-ip",'
echo '          "python",'
echo "          \"$INSTALL_PATH/server.py\""
echo '        ]'
echo '      }'
echo '    }'
echo '  }'
echo ""
echo -e "  ${YELLOW}Note:${NC} Replace /path/to/private-key.pem and user@your-vps-ip with actual values."
echo ""

# Available Tools
echo -e "${BLUE}Available Tools:${NC}"
echo ""
echo "  • scan_process_anomalies  - Detect zombie/stuck processes"
echo "  • deep_docker_inspect     - Docker container analysis"
echo "  • check_resource_leaks    - FD/connection leak detection"
echo "  • read_kernel_ring_buffer - Read dmesg for OOM/segfaults"
echo "  • analyze_background_tasks- Find hidden resource hogs"
echo "  • kill_process            - Terminate processes (safety checked)"
echo "  • restart_container       - Restart Docker containers"
echo ""