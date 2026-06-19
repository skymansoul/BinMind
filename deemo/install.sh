#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMAND_NAME="${COMMAND_NAME:-binmind}"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"
TARGET_DIR=""
INSTALL_DEPS=1

usage() {
    cat <<'USAGE'
Usage:
  ./install.sh              Install dependencies, then install binmind
  ./install.sh --system     Install binmind to /usr/local/bin
  ./install.sh --user       Install binmind to ~/.local/bin
  ./install.sh --no-deps    Install command only, skip dependency installation
  ./install.sh -help        Show this help

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
        echo "apt-get not found; skipping system dependency installation."
        return
    fi

    echo "Installing Ubuntu/Kali system dependencies..."
    need_root apt-get update
    need_root apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        radare2 \
        file \
        binutils \
        gdb \
        build-essential \
        libssl-dev \
        libffi-dev
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

    echo "Creating Python virtual environment: $VENV_DIR"
    python3 -m venv "$VENV_DIR"

    echo "Installing Python dependencies from requirements.txt..."
    "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
    "$VENV_DIR/bin/python" -m pip install -r "$PROJECT_DIR/requirements.txt"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help|-help)
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

if [ "$INSTALL_DEPS" -eq 1 ]; then
    install_system_dependencies
    install_python_dependencies
else
    echo "Skipping dependency installation."
fi

PYTHON_BIN="$VENV_DIR/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

chmod +x "$PROJECT_DIR/binmind"
TARGET="$TARGET_DIR/$COMMAND_NAME"
TMP_LAUNCHER="$(mktemp)"
trap 'rm -f "$TMP_LAUNCHER"' EXIT

cat > "$TMP_LAUNCHER" <<EOF
#!/usr/bin/env bash
exec "$PYTHON_BIN" "$PROJECT_DIR/main.py" "\$@"
EOF

if [ "$TARGET_DIR" = "/usr/local/bin" ]; then
    need_root mkdir -p "$TARGET_DIR"
    need_root install -m 755 "$TMP_LAUNCHER" "$TARGET"
else
    mkdir -p "$TARGET_DIR"
    install -m 755 "$TMP_LAUNCHER" "$TARGET"
fi

echo "Installed $COMMAND_NAME -> $TARGET"
if ! command -v "$COMMAND_NAME" >/dev/null 2>&1; then
    echo "Note: $TARGET_DIR is not in PATH for this shell."
    echo "Add this line to ~/.bashrc or ~/.zshrc:"
    echo "  export PATH=\"$TARGET_DIR:\$PATH\""
fi
echo "Try: $COMMAND_NAME -help"
