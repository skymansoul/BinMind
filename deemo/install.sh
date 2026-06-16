#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMAND_NAME="${COMMAND_NAME:-binmind}"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"
TARGET_DIR=""
INSTALL_DEPS=1
FORCE_INSTALL=0

usage() {
    cat <<'USAGE'
Usage:
  ./install.sh              Install dependencies, then install binmind
  ./install.sh --system     Install binmind to /usr/local/bin
  ./install.sh --user       Install binmind to ~/.local/bin
  ./install.sh --no-deps    Install command only, skip dependency installation
  ./install.sh --force      Force reinstall even if already installed
  ./install.sh -h|--help    Show this help

Environment:
  COMMAND_NAME=name         Override installed command name
  VENV_DIR=/path/to/venv    Override Python virtual environment path
USAGE
}

need_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "Error: root permission is required. Please install sudo or run as root." >&2
        exit 1
    fi
}

install_system_dependencies() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "Warning: apt-get not found; skipping system dependency installation." >&2
        echo "Please ensure the following packages are installed manually:" >&2
        echo "  python3 python3-pip python3-venv radare2 file binutils gdb build-essential libssl-dev libffi-dev" >&2
        return
    fi

    echo "[+] Installing Ubuntu/Debian system dependencies..."
    need_root apt-get update -qq
    need_root apt-get install -y -qq \
        python3 \
        python3-pip \
        python3-venv \
        radare2 \
        file \
        binutils \
        gdb \
        build-essential \
        libssl-dev \
        libffi-dev \
        git \
        wget \
        curl
}

install_python_dependencies() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 is not installed." >&2
        exit 1
    fi

    if [ ! -f "$PROJECT_DIR/requirements.txt" ]; then
        echo "Error: requirements.txt not found in $PROJECT_DIR." >&2
        exit 1
    fi

    echo "[+] Creating Python virtual environment: $VENV_DIR"
    if [ -d "$VENV_DIR" ] && [ "$FORCE_INSTALL" -eq 0 ]; then
        echo "[!] Virtual environment already exists: $VENV_DIR"
        echo "    Use --force to recreate it."
    else
        if [ -d "$VENV_DIR" ]; then
            echo "[+] Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        fi
        python3 -m venv "$VENV_DIR"
        if [ $? -ne 0 ]; then
            echo "Error: Failed to create virtual environment." >&2
            exit 1
        fi
    fi

    echo "[+] Installing Python dependencies..."
    "$VENV_DIR/bin/python" -m pip install --upgrade -q pip setuptools wheel
    
    echo "[+] Installing requirements from requirements.txt..."
    if ! "$VENV_DIR/bin/python" -m pip install -q -r "$PROJECT_DIR/requirements.txt"; then
        echo "Warning: Some dependencies failed to install." >&2
        echo "This may be normal for optional dependencies." >&2
    fi
}

verify_installation() {
    echo "[+] Verifying installation..."
    
    if [ ! -x "$VENV_DIR/bin/python" ]; then
        echo "Error: Python virtual environment not properly created." >&2
        return 1
    fi
    
    if [ ! -f "$PROJECT_DIR/main.py" ]; then
        echo "Error: main.py not found." >&2
        return 1
    fi
    
    echo "[+] Running basic health check..."
    if "$VENV_DIR/bin/python" "$PROJECT_DIR/main.py" --health >/dev/null 2>&1; then
        echo "[+] Health check passed!"
    else
        echo "Warning: Health check failed. Some features may not work." >&2
    fi
    
    return 0
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --system)
            TARGET_DIR="/usr/local/bin"
            ;;
        --user)
            TARGET_DIR="${HOME}/.local/bin"
            ;;
        --no-deps)
            INSTALL_DEPS=0
            ;;
        --force)
            FORCE_INSTALL=1
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

if [ -z "$TARGET_DIR" ]; then
    if [ -w "/usr/local/bin" ]; then
        TARGET_DIR="/usr/local/bin"
    else
        TARGET_DIR="${HOME}/.local/bin"
    fi
fi

echo "[*] Starting binmind installation..."
echo "[*] Project directory: $PROJECT_DIR"
echo "[*] Target directory: $TARGET_DIR"
echo "[*] Virtual environment: $VENV_DIR"

if [ "$INSTALL_DEPS" -eq 1 ]; then
    install_system_dependencies
    install_python_dependencies
else
    echo "[+] Skipping dependency installation (--no-deps)."
fi

PYTHON_BIN="$VENV_DIR/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
    echo "[!] Using system Python: $PYTHON_BIN"
fi

# Ensure binmind script has execute permissions
chmod +x "$PROJECT_DIR/binmind" 2>/dev/null || true

TARGET="$TARGET_DIR/$COMMAND_NAME"
TMP_LAUNCHER="$(mktemp)"
trap 'rm -f "$TMP_LAUNCHER"' EXIT

cat > "$TMP_LAUNCHER" <<EOF
#!/usr/bin/env bash
exec "$PYTHON_BIN" "$PROJECT_DIR/main.py" "\$@"
EOF

echo "[+] Installing launcher to $TARGET..."
if [ "$TARGET_DIR" = "/usr/local/bin" ]; then
    need_root mkdir -p "$TARGET_DIR"
    need_root install -m 755 "$TMP_LAUNCHER" "$TARGET"
else
    mkdir -p "$TARGET_DIR"
    install -m 755 "$TMP_LAUNCHER" "$TARGET"
fi

verify_installation

echo ""
echo "[+] Installed $COMMAND_NAME -> $TARGET"
if ! command -v "$COMMAND_NAME" >/dev/null 2>&1; then
    echo "[!] Note: $TARGET_DIR is not in PATH for this shell."
    echo "    Add this line to ~/.bashrc or ~/.zshrc:"
    echo "      export PATH=\"$TARGET_DIR:\$PATH\""
    echo "    Or run this in current shell:"
    echo "      source ~/.bashrc  # for bash"
    echo "      source ~/.zshrc   # for zsh"
fi
echo ""
echo "[+] Installation complete!"
echo "    Try: $COMMAND_NAME --help"
echo "    Run health check: $COMMAND_NAME --health"