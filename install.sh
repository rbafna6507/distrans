#!/bin/bash

# Installation script for distrans CLI

set -e

echo "Building distrans..."
cargo build --release

echo ""
echo "distrans built successfully!"
echo ""
echo "Binary location: ./target/release/distrans"
echo ""
echo "Installation options:"
echo ""
echo "1. Use directly from the build directory:"
echo "   ./target/release/distrans --help"
echo ""
echo "2. Add to your PATH by adding this line to your ~/.zshrc or ~/.bashrc:"
echo "   export PATH=\"\$PATH:$(pwd)/target/release\""
echo ""
echo "3. Install globally (requires sudo):"
echo "   sudo cp target/release/distrans /usr/local/bin/"
echo ""
echo "4. Create an alias in your shell config:"
echo "   alias distrans='$(pwd)/target/release/distrans'"
echo ""

read -p "Would you like to install globally to /usr/local/bin? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "Installing to /usr/local/bin..."
    sudo cp target/release/distrans /usr/local/bin/
    echo "✓ distrans installed successfully!"
    echo "You can now run: distrans --help"
else
    echo "Skipping global installation."
    echo "You can still use: ./target/release/distrans"
fi
