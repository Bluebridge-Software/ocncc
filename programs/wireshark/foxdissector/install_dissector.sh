#!/bin/bash

# Escher Wireshark Dissector Installation Script
# Supports Linux, macOS, and Windows (via Git Bash/WSL)

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DISSECTOR_FILE="fox_dissector.lua"

echo "===================================="
echo "Escher Wireshark Dissector Installer"
echo "===================================="
echo ""

# Check if Wireshark is installed
if ! command -v wireshark &> /dev/null && ! command -v tshark &> /dev/null; then
    echo "ERROR: Wireshark does not appear to be installed."
    echo "Please install Wireshark first: https://www.wireshark.org/download.html"
    exit 1
fi

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

echo "Detected OS: $OS"
echo ""

# Determine plugin directory
case $OS in
    linux)
        PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
        ;;
    macos)
        PLUGIN_DIR="$HOME/.local/lib/wireshark/plugins"
        ;;
    windows)
        PLUGIN_DIR="$APPDATA/Wireshark/plugins"
        ;;
    *)
        echo "ERROR: Unsupported operating system: $OSTYPE"
        echo ""
        echo "Please manually copy $DISSECTOR_FILE to your Wireshark plugins directory."
        echo "See ESCHER_DISSECTOR_README.md for manual installation instructions."
        exit 1
        ;;
esac

echo "Target directory: $PLUGIN_DIR"
echo ""

# Create plugin directory if it doesn't exist
if [ ! -d "$PLUGIN_DIR" ]; then
    echo "Creating plugin directory: $PLUGIN_DIR"
    mkdir -p "$PLUGIN_DIR"
fi

# Check if dissector file exists
if [ ! -f "$SCRIPT_DIR/$DISSECTOR_FILE" ]; then
    echo "ERROR: Cannot find $DISSECTOR_FILE in $SCRIPT_DIR"
    exit 1
fi

# Copy dissector
echo "Installing dissector..."
cp "$SCRIPT_DIR/$DISSECTOR_FILE" "$PLUGIN_DIR/"

if [ $? -eq 0 ]; then
    echo "✓ Successfully installed $DISSECTOR_FILE"
else
    echo "✗ Failed to install $DISSECTOR_FILE"
    exit 1
fi

echo ""
echo "===================================="
echo "Installation Complete!"
echo "===================================="
echo ""
echo "Next steps:"
echo "1. Restart Wireshark"
echo "2. Verify installation: Help → About Wireshark → Plugins tab"
echo "3. Look for 'escher_dissector.lua' in the list"
echo ""
echo "To use the dissector:"
echo "- It will auto-decode traffic on ports 5000-5001 (TCP/UDP)"
echo "- For other ports: Right-click packet → Decode As... → ESCHER"
echo ""
echo "Documentation:"
echo "- See ESCHER_DISSECTOR_README.md for detailed usage"
echo "- See ESCHER_QUICK_REFERENCE.md for protocol reference"
echo ""
echo "Test messages:"
echo "- Run: python3 escher_test_generator.py"
echo "- This creates sample .escher files for testing"
echo ""
