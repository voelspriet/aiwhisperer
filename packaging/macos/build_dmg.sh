#!/bin/bash
# Build script for creating AIWhisperer macOS .dmg installer
#
# This script:
# 1. Creates a standalone executable using PyInstaller
# 2. Packages it into a .dmg disk image
#
# Requirements:
# - macOS (this script only works on macOS)
# - Python 3.9+ with pip
# - PyInstaller (pip install pyinstaller)
# - create-dmg (brew install create-dmg) - optional, for fancy DMG
#
# Usage:
#   ./packaging/macos/build_dmg.sh
#
# Output:
#   dist/AIWhisperer-{version}-macos-{arch}.dmg

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${GREEN}AIWhisperer macOS Build Script${NC}"
echo "================================"
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo -e "${RED}Error: This script must be run on macOS${NC}"
    exit 1
fi

# Get version from setup.py
VERSION=$(grep -o 'version="[^"]*"' "$PROJECT_ROOT/setup.py" | cut -d'"' -f2)
if [[ -z "$VERSION" ]]; then
    VERSION="0.0.0"
fi
echo "Version: $VERSION"

# Get architecture
ARCH=$(uname -m)
echo "Architecture: $ARCH"

# Output filename
DMG_NAME="AIWhisperer-${VERSION}-macos-${ARCH}.dmg"
echo "Output: $DMG_NAME"
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Check for Python
echo -e "${YELLOW}Checking dependencies...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Python: $PYTHON_VERSION"

# Check for pip
if ! python3 -m pip --version &> /dev/null; then
    echo -e "${RED}Error: pip is required${NC}"
    exit 1
fi

# Install/upgrade PyInstaller
echo ""
echo -e "${YELLOW}Installing PyInstaller...${NC}"
python3 -m pip install --upgrade pyinstaller

# Install aiwhisperer dependencies
echo ""
echo -e "${YELLOW}Installing AIWhisperer dependencies...${NC}"
python3 -m pip install -e ".[spacy]"

# Download spaCy model if not present (optional, for better detection)
echo ""
echo -e "${YELLOW}Checking spaCy models...${NC}"
python3 -m spacy download nl_core_news_sm 2>/dev/null || echo "Note: Dutch model not installed (optional)"
python3 -m spacy download en_core_web_sm 2>/dev/null || echo "Note: English model not installed (optional)"

# Clean previous builds
echo ""
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf "$PROJECT_ROOT/build"
rm -rf "$PROJECT_ROOT/dist"

# Build with PyInstaller
echo ""
echo -e "${YELLOW}Building executable with PyInstaller...${NC}"
python3 -m PyInstaller "$SCRIPT_DIR/aiwhisperer.spec" --clean --noconfirm

# Check if build succeeded
if [[ ! -f "$PROJECT_ROOT/dist/aiwhisperer" ]]; then
    echo -e "${RED}Error: PyInstaller build failed${NC}"
    exit 1
fi

echo -e "${GREEN}Executable built successfully!${NC}"

# Create DMG
echo ""
echo -e "${YELLOW}Creating DMG installer...${NC}"

# Create a temporary directory for DMG contents
DMG_TEMP="$PROJECT_ROOT/dist/dmg_temp"
rm -rf "$DMG_TEMP"
mkdir -p "$DMG_TEMP"

# Copy executable
cp "$PROJECT_ROOT/dist/aiwhisperer" "$DMG_TEMP/"

# Create README for the DMG
cat > "$DMG_TEMP/README.txt" << 'EOF'
AIWhisperer - Secure AI Document Analysis
==========================================

Installation:
1. Copy 'aiwhisperer' to /usr/local/bin/ or another directory in your PATH
2. Make it executable: chmod +x /usr/local/bin/aiwhisperer

Quick Install (run in Terminal):
    sudo cp aiwhisperer /usr/local/bin/
    sudo chmod +x /usr/local/bin/aiwhisperer

Usage:
    aiwhisperer check              # Verify installation
    aiwhisperer encode doc.txt     # Sanitize a document
    aiwhisperer decode out.txt -m mapping.json  # Restore values

For more information:
    aiwhisperer --help

Note: For PDF conversion and advanced NER detection, you may need
to install additional dependencies. Run 'aiwhisperer check' for details.
EOF

# Create install script
cat > "$DMG_TEMP/install.command" << 'EOF'
#!/bin/bash
# AIWhisperer Installer
# Double-click this file to install aiwhisperer to /usr/local/bin

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "AIWhisperer Installer"
echo "====================="
echo ""

# Check if /usr/local/bin exists
if [[ ! -d "/usr/local/bin" ]]; then
    echo "Creating /usr/local/bin..."
    sudo mkdir -p /usr/local/bin
fi

# Copy executable
echo "Installing aiwhisperer to /usr/local/bin..."
sudo cp "$SCRIPT_DIR/aiwhisperer" /usr/local/bin/
sudo chmod +x /usr/local/bin/aiwhisperer

echo ""
echo "Installation complete!"
echo ""
echo "You can now use aiwhisperer from any terminal:"
echo "    aiwhisperer --help"
echo ""
echo "Press any key to close this window..."
read -n 1
EOF
chmod +x "$DMG_TEMP/install.command"

# Check if create-dmg is available (for fancy DMG)
if command -v create-dmg &> /dev/null; then
    echo "Using create-dmg for fancy DMG..."
    
    # Remove existing DMG if present
    rm -f "$PROJECT_ROOT/dist/$DMG_NAME"
    
    create-dmg \
        --volname "AIWhisperer $VERSION" \
        --volicon "$SCRIPT_DIR/icon.icns" 2>/dev/null || true \
        --window-pos 200 120 \
        --window-size 600 400 \
        --icon-size 100 \
        --icon "aiwhisperer" 150 190 \
        --icon "install.command" 450 190 \
        --icon "README.txt" 300 320 \
        --hide-extension "aiwhisperer" \
        --hide-extension "install.command" \
        "$PROJECT_ROOT/dist/$DMG_NAME" \
        "$DMG_TEMP"
else
    echo "Using hdiutil for basic DMG (install create-dmg for fancy DMG)..."
    
    # Create DMG using hdiutil
    rm -f "$PROJECT_ROOT/dist/$DMG_NAME"
    hdiutil create \
        -volname "AIWhisperer $VERSION" \
        -srcfolder "$DMG_TEMP" \
        -ov \
        -format UDZO \
        "$PROJECT_ROOT/dist/$DMG_NAME"
fi

# Clean up
rm -rf "$DMG_TEMP"

# Verify DMG was created
if [[ -f "$PROJECT_ROOT/dist/$DMG_NAME" ]]; then
    echo ""
    echo -e "${GREEN}Success!${NC}"
    echo ""
    echo "DMG created: dist/$DMG_NAME"
    echo "Size: $(du -h "$PROJECT_ROOT/dist/$DMG_NAME" | cut -f1)"
    echo ""
    echo "To test the DMG:"
    echo "    open dist/$DMG_NAME"
else
    echo -e "${RED}Error: DMG creation failed${NC}"
    exit 1
fi
