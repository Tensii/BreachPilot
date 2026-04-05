#!/usr/bin/env bash
# Make all tools in ~/go/bin/ global by symlinking to /usr/local/bin

set -e

SOURCE_DIR="/home/ubuntu/go/bin"
DEST_DIR="/usr/local/bin"

if [ ! -d "$SOURCE_DIR" ]; then
    echo "[!] Source directory $SOURCE_DIR not found."
    exit 1
fi

echo "[*] Symlinking tools from $SOURCE_DIR to $DEST_DIR..."

for tool in "$SOURCE_DIR"/*; do
    if [ -x "$tool" ]; then
        name=$(basename "$tool")
        echo "[+] Symlinking $name..."
        sudo ln -sf "$tool" "$DEST_DIR/$name"
    fi
done

# Also ensure ~/.local/bin is in .bashrc for the current user
BASHRC="/home/ubuntu/.bashrc"
LOCAL_BIN_EXPORT='export PATH="$HOME/.local/bin:$PATH"'
if ! grep -q ".local/bin" "$BASHRC"; then
    echo "[*] Adding ~/.local/bin to $BASHRC..."
    echo "" >> "$BASHRC"
    echo "# Added by BreachPilot Setup" >> "$BASHRC"
    echo "$LOCAL_BIN_EXPORT" >> "$BASHRC"
fi

echo "[+] Done. Tools are now global."
