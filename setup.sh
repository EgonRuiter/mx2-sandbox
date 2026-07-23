#!/usr/bin/env bash
# MX2 macOS/Linux Local Development Setup Script
set -e

# ANSI Color Codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN} Setting up MX2 Local Sandbox Environment    ${NC}"
echo -e "${CYAN}=============================================${NC}"

# 1. Verify Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "[-] Python3 not found on PATH. Please install Python 3.9+."
    exit 1
fi
echo -e "${GREEN}[+] Found Python: $(python3 --version)${NC}"

# 2. Create Virtual Environment
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creating Python virtual environment in '.venv'...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}[+] Virtual environment created successfully.${NC}"
else
    echo -e "${GREEN}[+] Virtual environment '.venv' already exists.${NC}"
fi

# 3. Activate Virtual Environment
echo -e "${YELLOW}[*] Activating virtual environment...${NC}"
source .venv/bin/activate

# 4. Install Developer Dependencies
echo -e "${YELLOW}[*] Upgrading pip and installing dev dependencies...${NC}"
python3 -m pip install --upgrade pip
pip install -e .[dev]
echo -e "${GREEN}[+] Dependencies successfully installed.${NC}"

# 5. Install Pre-Commit Hooks
if command -v pre-commit &> /dev/null; then
    echo -e "${YELLOW}[*] Registering git pre-commit hooks...${NC}"
    pre-commit install
    echo -e "${GREEN}[+] Pre-commit hooks installed.${NC}"
fi

# 6. Run Verification Test Suite
echo -e "${YELLOW}[*] Running verification tests...${NC}"
python3 -m unittest discover -s tests -p "test_*.py"

echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN} Setup Completed Successfully!               ${NC}"
echo -e "${GREEN} You are now ready to write code for MX2!    ${NC}"
echo -e "${GREEN}=============================================${NC}"
