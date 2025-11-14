#!/bin/bash
# NYX Scanner - Installation Script
# Installs NYX as a global command

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo " _   _ __   __ __  __"
echo "| \\ | |\\ \\ / / \\ \\/ /"
echo "|  \\| | \\ V /   \\  / "
echo "| |\\  |  | |    /  \\ "
echo "|_| \\_|  |_|   /_/\\_\\"
echo -e "${NC}"
echo -e "${GREEN}NYX Scanner - Installation Script${NC}"
echo ""

# Check if running as root (for system-wide install)
if [ "$EUID" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    NYX_PATH="/opt/nyx-framework"
    echo -e "${YELLOW}[*]${NC} Installing system-wide (requires root)..."
else
    INSTALL_DIR="$HOME/.local/bin"
    NYX_PATH="$(pwd)"
    echo -e "${YELLOW}[*]${NC} Installing for current user..."
fi

# Check Python version
echo -e "${BLUE}[*]${NC} Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!]${NC} Python 3 not found. Please install Python 3.6 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}[✓]${NC} Python $PYTHON_VERSION found"

# Create install directory if it doesn't exist
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${BLUE}[*]${NC} Creating $INSTALL_DIR directory..."
    mkdir -p "$INSTALL_DIR"
fi

# If root install, copy framework to /opt
if [ "$EUID" -eq 0 ]; then
    echo -e "${BLUE}[*]${NC} Copying NYX framework to $NYX_PATH..."
    mkdir -p "$NYX_PATH"
    cp -r . "$NYX_PATH/"
    chmod +x "$NYX_PATH/nyx_standalone.py"
fi

# Create wrapper script
echo -e "${BLUE}[*]${NC} Creating NYX command wrapper..."
cat > "$INSTALL_DIR/nyx" << EOF
#!/bin/bash
# NYX Scanner - Command Wrapper
exec python3 "$NYX_PATH/nyx_standalone.py" "\$@"
EOF

chmod +x "$INSTALL_DIR/nyx"

# Check if install directory is in PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${YELLOW}[!]${NC} $INSTALL_DIR is not in your PATH"
    
    # Detect shell and add to PATH
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    
    echo -e "${BLUE}[*]${NC} Adding $INSTALL_DIR to PATH in $SHELL_RC..."
    echo "" >> "$SHELL_RC"
    echo "# Added by NYX Scanner installer" >> "$SHELL_RC"
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$SHELL_RC"
    
    echo -e "${YELLOW}[!]${NC} Please run: ${GREEN}source $SHELL_RC${NC} or restart your terminal"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    NYX Scanner Installed Successfully!     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Installation Details:${NC}"
echo -e "  Command:     ${GREEN}nyx${NC}"
echo -e "  Location:    ${GREEN}$INSTALL_DIR/nyx${NC}"
echo -e "  Framework:   ${GREEN}$NYX_PATH${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo -e "  ${GREEN}nyx scan 192.168.1.1${NC}              # Basic scan"
echo -e "  ${GREEN}nyx scan target.com -s${NC}            # With service detection"
echo -e "  ${GREEN}nyx scan 10.10.10.10 -p top-1000${NC}  # Scan top 1000 ports"
echo -e "  ${GREEN}nyx web${NC}                           # Start web interface"
echo -e "  ${GREEN}nyx --help${NC}                        # Show all options"
echo ""
echo -e "${YELLOW}Note:${NC} If 'nyx' command is not found, run:"
echo -e "  ${GREEN}source $SHELL_RC${NC}  or  ${GREEN}exec \$SHELL${NC}"
echo ""
