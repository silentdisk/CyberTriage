#!/usr/bin/env bash
# ==============================================================================
# CyberTriage Automated Environment Setup Script
#
# Prepares the local Python virtual environment, installs dependencies, and
# sets up a template .env configuration file if one does not already exist.
#
# This script does NOT start Docker, Switch Core, Mattermost, or the agent.
# It does NOT overwrite existing credentials in .env.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=================================================================="
echo "  CyberTriage Local Environment Setup"
echo "=================================================================="

# 1. Check for Python 3 (3.10+) availability
PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "[-] Error: Python 3 (3.10+) was not found in PATH." >&2
    echo "    Please install Python 3.10 or higher and try again." >&2
    exit 1
fi

PYTHON_VERSION="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')"
echo "[+] Detected Python binary: $PYTHON_BIN (version $PYTHON_VERSION)"

# 2. Check for pip availability
if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    echo "[-] Error: pip is not available for $PYTHON_BIN." >&2
    echo "    Please install pip (e.g., 'python3 -m ensurepip') and try again." >&2
    exit 1
fi
echo "[+] Detected pip for $PYTHON_BIN"

# 3. Create virtual environment if it does not already exist
VENV_DIR="venv"
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/python" ]; then
    echo "[+] Virtual environment already exists in '$VENV_DIR'."
else
    echo "[*] Creating Python virtual environment in '$VENV_DIR'..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo "[+] Virtual environment created successfully."
fi

# 4. Install dependencies from requirements.txt
if [ -f "requirements.txt" ]; then
    echo "[*] Installing dependencies from requirements.txt..."
    "$VENV_DIR/bin/pip" install -r requirements.txt --quiet
    echo "[+] Dependencies installed successfully."
else
    echo "[-] Error: requirements.txt not found in $SCRIPT_DIR." >&2
    exit 1
fi

# 5. Set up .env without overwriting existing credentials
if [ -f ".env" ]; then
    echo "[+] Existing .env file found. Preserving current configuration (will not overwrite)."
else
    if [ -f ".env.example" ]; then
        cp ".env.example" ".env"
        echo "[+] Initialized .env from .env.example template."
        echo "    Remember to edit .env and insert your own GEMINI_API_KEY."
    else
        echo "[!] Warning: .env.example not found. Please create a .env file manually."
    fi
fi

# 6. Print next steps
echo ""
echo "=================================================================="
echo "  Setup Complete! Next Steps:"
echo "=================================================================="
echo ""
echo "1. Activate your virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. (Optional) Configure your Gemini API key in .env for live AI investigation:"
echo "   GEMINI_API_KEY=\"your_gemini_api_key_here\""
echo ""
echo "3. Run the offline test suite:"
echo "   pytest"
echo ""
echo "4. Run the end-to-end incident investigation demo:"
echo "   python demo_investigation.py"
echo ""
echo "For full details, including Switch Core and Mattermost integration:"
echo "  - See RUN_GUIDE.md"
echo "  - See README.md"
echo "=================================================================="
