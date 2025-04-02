#!/bin/bash

# Color codes
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
NC="\033[0m"

PY_CMD=$(command -v python3 || command -v python)
[ -z "$PY_CMD" ] && { echo -e "${RED}Python not found!${NC}"; exit 1; }

# Required system tools
SYSTEM_TOOLS=(
    "assetfinder"
    "sublist3r"
    "httpx-toolkit"
)

# Required Python packages
PYTHON_PACKAGES=(
    "requests"
    "beautifulsoup4"
    "scapy"
    "cryptography"
    "jinja2"
    "lxml"
    "jsbeautifier"
)

install_system_tools() {
    echo -e "${CYAN}\n[1/4] Updating System${NC}"
    sudo apt-get update -qq > /dev/null

    echo -e "${CYAN}\n[2/4] Installing System Tools${NC}"
    for tool in "${SYSTEM_TOOLS[@]}"; do
        echo -ne "${YELLOW}Checking ${tool}...${NC}"
        
        if command -v $tool &>/dev/null; then
            echo -e "\r${GREEN}✓ ${tool} already installed${NC}"
            continue
        fi
        
        if sudo apt-get install -y $tool > /dev/null 2>&1; then
            echo -e "\r${GREEN}✓ ${tool} installed successfully${NC}"
        else
            echo -e "\r${RED}✗ Failed to install ${tool}${NC}"
        fi
    done
}

install_python_packages() {
    echo -e "${CYAN}\n[3/4] Installing Python Packages${NC}"
    
    for pkg in "${PYTHON_PACKAGES[@]}"; do
        echo -ne "${YELLOW}Installing ${pkg}...${NC}"
        
        # Try user installation first
        if $PY_CMD -m pip install --user --disable-pip-version-check $pkg > /dev/null 2>&1; then
            echo -e "\r${GREEN}✓ ${pkg} installed (user space)${NC}"
            continue
        fi
        
        # Fall back to system installation
        if $PY_CMD -m pip install --break-system-packages --root-user-action=ignore --disable-pip-version-check $pkg > /dev/null 2>&1; then
            echo -e "\r${YELLOW}✓ ${pkg} installed (system with override)${NC}"
            continue
        fi
        
        if [ "$pkg" == "jsbeautifier" ]; then
            if $PY_CMD -m pip install --user js-beautifier > /dev/null 2>&1; then
                echo -e "\r${GREEN}✓ jsbeautifier installed (as js-beautifier)${NC}"
                continue
            fi
        fi
        
        echo -e "\r${RED}✗ Failed to install ${pkg}${NC}"
    done
}

verify_installations() {
    echo -e "${CYAN}\n[4/4] Verifying Installations${NC}"
    
    echo -e "${YELLOW}System Tools:${NC}"
    for tool in "${SYSTEM_TOOLS[@]}"; do
        if command -v $tool &>/dev/null; then
            echo -e "${GREEN}✓ ${tool} found${NC}"
        else
            echo -e "${RED}✗ ${tool} missing${NC}"
        fi
    done
    
    # Verify Python packages
    echo -e "\n${YELLOW}Python Packages:${NC}"
    $PY_CMD -c "
import sys
deps = {pkg:pkg for pkg in ['requests', 'bs4', 'scapy', 'cryptography', 'jinja2', 'lxml', 'jsbeautifier']}
deps['beautifulsoup4'] = 'bs4'

for pkg, imp in deps.items():
    try:
        __import__(imp)
        print(f'\033[1;32m✓ {pkg}\033[0m')
    except ImportError:
        print(f'\033[1;31m✗ {pkg}\033[0m')
    "
}

echo -e "${CYAN}Starting Renumscan Complete Installation${NC}"

install_system_tools
install_python_packages
verify_installations

echo -e "\n${CYAN}Final Configuration${NC}"
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo -e "${YELLOW}Adding user binaries to PATH...${NC}"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc
fi

echo -e "\n${GREEN}Installation Complete!${NC}"
echo -e "Run Renumscan with: ${CYAN}${PY_CMD} main.py${NC}"
echo -e "Available tools: ${CYAN}assetfinder, sublist3r, httpx${NC}"