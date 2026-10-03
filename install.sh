#!/usr/bin/env bash

set -euo pipefail


# ============================================================================
# Basic configuration
# ============================================================================

PROJECT_DIR="$(
    CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &&
    pwd
)"

COMMAND_NAME="${COMMAND_NAME:-binmind}"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"
SYSTEM_PYTHON="${SYSTEM_PYTHON:-/usr/bin/python3}"

PIP_INDEX_URL="${PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
SETUPTOOLS_VERSION="${SETUPTOOLS_VERSION:-75.8.2}"

ANGR_VERSION="${ANGR_VERSION:-9.2.223}"
Z3_VERSION="${Z3_VERSION:-4.13.0.0}"
MULPYPLEXER_VERSION="${MULPYPLEXER_VERSION:-0.9}"

TARGET_DIR=""
INSTALL_DEPS=1
INSTALL_SYSTEM_DEPS=1
INSTALL_DEV_DEPS=0
FORCE_INSTALL=0

REQUIREMENTS_FILE=""


# ============================================================================
# Help
# ============================================================================

usage() {
    cat <<'USAGE'
BinMind installer

Usage:
  ./install.sh
  ./install.sh --user
  ./install.sh --system
  ./install.sh --dev
  ./install.sh --no-deps
  ./install.sh --no-system-deps
  ./install.sh --force
  ./install.sh -h
  ./install.sh --help

Options:
  --user
      Install the binmind launcher to ~/.local/bin.

  --system
      Install the binmind launcher to /usr/local/bin.

  --dev
      Install requirements-dev.txt instead of requirements.txt.

  --no-deps
      Skip Python dependency installation.

  --no-system-deps
      Skip apt update and system dependency installation.

  --force
      Delete and recreate the Python virtual environment.

  -h, --help
      Show this help.

Environment variables:
  COMMAND_NAME=name
      Override the installed command name.

  VENV_DIR=/path/to/venv
      Override the virtual environment path.

  SYSTEM_PYTHON=/path/to/python3
      Override the Python interpreter used to create the virtual environment.

  PIP_INDEX_URL=https://example.com/simple
      Override the Python package index.

  SETUPTOOLS_VERSION=version
      Override the setuptools version.

  ANGR_VERSION=version
      Override the expected angr component version.

  Z3_VERSION=version
      Override the expected z3-solver version.

Examples:
  ./install.sh --user
  ./install.sh --system
  ./install.sh --user --dev
  ./install.sh --system --force
  ./install.sh --system --force --no-system-deps
  ./install.sh --system --no-deps --no-system-deps
USAGE
}


# ============================================================================
# Privilege helper
# ============================================================================

need_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
        return
    fi

    if command -v sudo >/dev/null 2>&1; then
        sudo "$@"
        return
    fi

    echo "Error: root permission is required." >&2
    echo "Install sudo or run this installer as root." >&2
    exit 1
}


# ============================================================================
# pip wrapper
# ============================================================================

run_pip() {
    env \
        -u HTTP_PROXY \
        -u HTTPS_PROXY \
        -u ALL_PROXY \
        -u http_proxy \
        -u https_proxy \
        -u all_proxy \
        PIP_INDEX_URL="$PIP_INDEX_URL" \
        PIP_DISABLE_PIP_VERSION_CHECK=1 \
        PIP_DEFAULT_TIMEOUT=120 \
        PYTHONNOUSERSITE=1 \
        "$VENV_DIR/bin/python" -m pip "$@"
}


# ============================================================================
# System dependencies
# ============================================================================

install_system_dependencies() {
    if [ "$INSTALL_SYSTEM_DEPS" -eq 0 ]; then
        echo "[+] Skipping system dependencies (--no-system-deps)."
        return
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        echo "[!] apt-get was not found." >&2
        echo "[!] Install these packages manually:" >&2
        echo "    python3 python3-pip python3-venv" >&2
        echo "    file binutils gdb build-essential" >&2
        echo "    libssl-dev libffi-dev git wget curl unzip" >&2
        return
    fi

    echo "[+] Updating apt package index..."
    need_root apt-get update

    echo "[+] Installing Ubuntu/Debian system dependencies..."

    need_root apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        file \
        binutils \
        gdb \
        build-essential \
        libssl-dev \
        libffi-dev \
        git \
        wget \
        curl \
        unzip

    if apt-cache show radare2 >/dev/null 2>&1; then
        echo "[+] Installing radare2..."
        need_root apt-get install -y radare2
    else
        echo "[!] radare2 is unavailable from the current apt source." >&2
        echo "[!] Continuing without radare2." >&2
    fi
}


# ============================================================================
# Virtual environment
# ============================================================================

virtual_environment_is_healthy() {
    if [ ! -d "$VENV_DIR" ]; then
        return 1
    fi

    if [ ! -x "$VENV_DIR/bin/python" ]; then
        return 1
    fi

    if ! "$VENV_DIR/bin/python" -m pip install --help \
        >/dev/null 2>&1; then
        return 1
    fi

    return 0
}


create_virtual_environment() {
    if [ ! -x "$SYSTEM_PYTHON" ]; then
        echo "Error: system Python is unavailable:" >&2
        echo "       $SYSTEM_PYTHON" >&2
        exit 1
    fi

    echo "[+] System Python:"
    "$SYSTEM_PYTHON" --version

    if [ "$FORCE_INSTALL" -eq 1 ] && [ -d "$VENV_DIR" ]; then
        echo "[+] Removing existing virtual environment:"
        echo "    $VENV_DIR"

        rm -rf -- "$VENV_DIR"
    fi

    if [ -d "$VENV_DIR" ]; then
        echo "[+] Checking existing virtual environment..."

        if virtual_environment_is_healthy; then
            echo "[+] Existing virtual environment has a working pip."
        else
            echo "[!] Existing virtual environment is damaged."
            echo "[!] Recreating virtual environment..."

            rm -rf -- "$VENV_DIR"
        fi
    fi

    if [ ! -d "$VENV_DIR" ]; then
        echo "[+] Creating Python virtual environment:"
        echo "    $VENV_DIR"

        "$SYSTEM_PYTHON" -m venv "$VENV_DIR"
    else
        echo "[+] Reusing Python virtual environment:"
        echo "    $VENV_DIR"
    fi

    if [ ! -x "$VENV_DIR/bin/python" ]; then
        echo "Error: virtual environment Python is unavailable:" >&2
        echo "       $VENV_DIR/bin/python" >&2
        exit 1
    fi

    echo "[+] Virtual environment Python:"
    "$VENV_DIR/bin/python" --version

    if ! "$VENV_DIR/bin/python" -m pip install --help \
        >/dev/null 2>&1; then
        echo "Error: pip failed its health check." >&2
        exit 1
    fi
}


# ============================================================================
# Packaging tools
# ============================================================================

prepare_pip() {
    echo "[+] Initializing pip with ensurepip..."

    "$VENV_DIR/bin/python" -m ensurepip --upgrade

    echo "[+] Current pip version:"
    "$VENV_DIR/bin/python" -m pip --version

    echo "[+] Python package index:"
    echo "    $PIP_INDEX_URL"

    echo "[+] Installing compatible setuptools and wheel..."

    run_pip install \
        --no-cache-dir \
        --upgrade \
        "setuptools==$SETUPTOOLS_VERSION" \
        wheel

    echo "[+] Verifying setuptools..."

    "$VENV_DIR/bin/python" - <<'PY'
import setuptools

print(f"[OK] setuptools {setuptools.__version__}")
PY

    echo "[+] Verifying distutils compatibility..."

    "$VENV_DIR/bin/python" - <<'PY'
import setuptools
import distutils

print("[OK] setuptools vendored distutils is available")
PY

    echo "[+] Pre-installing mulpyplexer..."

    run_pip install \
        --no-cache-dir \
        "mulpyplexer==$MULPYPLEXER_VERSION"

    echo "[+] Packaging tools:"

    "$VENV_DIR/bin/python" -m pip show \
        pip \
        setuptools \
        wheel \
        mulpyplexer
}


# ============================================================================
# Z3 installation
# ============================================================================

install_z3_from_verified_wheel() {
    local wheel_dir
    local z3_wheels
    local z3_wheel

    wheel_dir="$VENV_DIR/.install-wheels"

    echo "[+] Preparing verified Z3 wheel..."

    rm -rf -- "$wheel_dir"
    mkdir -p "$wheel_dir"

    run_pip download \
        --no-cache-dir \
        --no-deps \
        --dest "$wheel_dir" \
        "z3-solver==$Z3_VERSION"

    shopt -s nullglob
    z3_wheels=(
        "$wheel_dir"/z3_solver-"$Z3_VERSION"-*.whl
    )
    shopt -u nullglob

    if [ "${#z3_wheels[@]}" -ne 1 ]; then
        echo "Error: expected exactly one Z3 wheel, found:" >&2
        echo "       ${#z3_wheels[@]}" >&2
        return 1
    fi

    z3_wheel="${z3_wheels[0]}"

    echo "[+] Z3 wheel:"
    echo "    $z3_wheel"

    echo "[+] Z3 wheel SHA-256:"
    sha256sum "$z3_wheel"

    echo "[+] Checking Z3 wheel CRC..."

    if ! unzip -tq "$z3_wheel"; then
        echo "Error: downloaded Z3 wheel failed CRC validation." >&2
        return 1
    fi

    echo "[+] Z3 wheel CRC validation passed."

    run_pip install \
        --no-cache-dir \
        --no-deps \
        "$z3_wheel"

    "$VENV_DIR/bin/python" - <<'PY'
import z3

print(f"[OK] Z3 {z3.get_version_string()}")
PY

    rm -rf -- "$wheel_dir"
}


# ============================================================================
# Requirements selection
# ============================================================================

select_requirements_file() {
    if [ "$INSTALL_DEV_DEPS" -eq 1 ]; then
        REQUIREMENTS_FILE="$PROJECT_DIR/requirements-dev.txt"
    else
        REQUIREMENTS_FILE="$PROJECT_DIR/requirements.txt"
    fi

    if [ ! -f "$REQUIREMENTS_FILE" ]; then
        echo "Error: requirements file was not found:" >&2
        echo "       $REQUIREMENTS_FILE" >&2
        exit 1
    fi
}


# ============================================================================
# Metadata validation
# ============================================================================

verify_package_metadata() {
    echo "[+] Validating Python package metadata..."

    "$VENV_DIR/bin/python" - <<'PY'
import sys
import site
from email.parser import Parser
from pathlib import Path

metadata_files = []

for directory in site.getsitepackages():
    root = Path(directory)

    if root.is_dir():
        metadata_files.extend(
            root.glob("*.dist-info/METADATA")
        )

if not metadata_files:
    print(
        "Error: no Python package METADATA files were found.",
        file=sys.stderr,
    )
    sys.exit(1)

invalid = []

for metadata_path in sorted(metadata_files):
    try:
        file_size = metadata_path.stat().st_size

        if file_size == 0:
            invalid.append(
                (metadata_path, "file is empty")
            )
            continue

        text = metadata_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        metadata = Parser().parsestr(text)

        package_name = metadata.get("Name")
        package_version = metadata.get("Version")

        if not package_name:
            invalid.append(
                (metadata_path, "missing Name field")
            )
            continue

        if not package_version:
            invalid.append(
                (metadata_path, "missing Version field")
            )
            continue

    except Exception as exc:
        invalid.append(
            (metadata_path, str(exc))
        )

if invalid:
    print(
        "Error: invalid package metadata detected:",
        file=sys.stderr,
    )

    for metadata_path, reason in invalid:
        print(
            f"  - {metadata_path}: {reason}",
            file=sys.stderr,
        )

    sys.exit(1)

print(
    f"[OK] Validated {len(metadata_files)} "
    "package METADATA files."
)
PY
}


# ============================================================================
# Dependency installation
# ============================================================================

install_python_dependencies() {
    if [ "$INSTALL_DEPS" -eq 0 ]; then
        echo "[+] Skipping Python dependencies (--no-deps)."
        return
    fi

    create_virtual_environment
    prepare_pip
    install_z3_from_verified_wheel
    select_requirements_file

    if [ "$INSTALL_DEV_DEPS" -eq 1 ]; then
        echo "[+] Installing development dependencies..."
    else
        echo "[+] Installing runtime dependencies..."
    fi

    echo "[+] Requirements file:"
    echo "    $REQUIREMENTS_FILE"

    run_pip install \
        --no-cache-dir \
        --prefer-binary \
        --upgrade-strategy only-if-needed \
        -r "$REQUIREMENTS_FILE"

    verify_package_metadata

    echo "[+] Checking Python dependency consistency..."

    local pip_check_output
    local pip_check_status

    set +e

    pip_check_output="$(
        "$VENV_DIR/bin/python" -m pip check 2>&1
    )"

    pip_check_status=$?

    set -e

    echo "$pip_check_output"

    if printf '%s\n' "$pip_check_output" |
        grep -qi "invalid metadata"; then
        echo "Error: pip detected invalid package metadata." >&2
        return 1
    fi

    if printf '%s\n' "$pip_check_output" |
        grep -qi "skipping.*dist-info"; then
        echo "Error: pip skipped damaged package metadata." >&2
        return 1
    fi

    if [ "$pip_check_status" -ne 0 ]; then
        echo "Error: pip check failed." >&2
        return "$pip_check_status"
    fi
}


# ============================================================================
# Project verification
# ============================================================================

verify_project_files() {
    echo "[+] Verifying project files..."

    if [ ! -f "$PROJECT_DIR/binmind.py" ]; then
        echo "Error: binmind.py was not found:" >&2
        echo "       $PROJECT_DIR/binmind.py" >&2
        return 1
    fi

    if [ ! -r "$PROJECT_DIR/binmind.py" ]; then
        echo "Error: binmind.py is not readable:" >&2
        echo "       $PROJECT_DIR/binmind.py" >&2
        return 1
    fi

    if [ ! -x "$VENV_DIR/bin/python" ]; then
        echo "Error: virtual environment Python is unavailable:" >&2
        echo "       $VENV_DIR/bin/python" >&2
        return 1
    fi

    echo "[+] Project files are available."
}


verify_python_dependencies() {
    echo "[+] Verifying Python dependencies..."

    "$VENV_DIR/bin/python" - <<'PY'
import importlib
import sys
from importlib.metadata import (
    PackageNotFoundError,
    version,
)

required_modules = {
    "angr": "angr",
    "archinfo": "archinfo",
    "claripy": "claripy",
    "cle": "cle",
    "pyvex": "pyvex",
    "z3": "z3-solver",
    "pwnlib": "pwntools",
    "openai": "openai",
    "requests": "requests",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "pydantic": "pydantic",
    "pefile": "pefile",
    "numpy": "numpy",
    "frida": "frida",
    "macholib": "macholib",
    "graphviz": "graphviz",
    "pytest": "pytest",
    "pytest_cov": "pytest-cov",
}

failed = []

for module_name, distribution_name in required_modules.items():
    try:
        importlib.import_module(module_name)

        installed_version = version(distribution_name)

        print(
            f"[OK] {module_name} "
            f"({distribution_name} {installed_version})"
        )

    except PackageNotFoundError:
        failed.append(
            (
                module_name,
                f"distribution metadata missing: "
                f"{distribution_name}",
            )
        )

    except Exception as exc:
        failed.append(
            (module_name, str(exc))
        )

if failed:
    print(
        "\nError: required Python dependencies failed:",
        file=sys.stderr,
    )

    for module_name, reason in failed:
        print(
            f"  - {module_name}: {reason}",
            file=sys.stderr,
        )

    sys.exit(1)

print("\nAll required Python dependencies passed.")
PY
}


verify_angr_versions() {
    echo "[+] Verifying angr component versions..."

    ANGR_EXPECTED_VERSION="$ANGR_VERSION" \
        "$VENV_DIR/bin/python" - <<'PY'
import os
import sys
from importlib.metadata import (
    PackageNotFoundError,
    version,
)

expected = os.environ["ANGR_EXPECTED_VERSION"]

packages = [
    "angr",
    "archinfo",
    "claripy",
    "cle",
    "pyvex",
]

failed = False

for package in packages:
    try:
        installed_version = version(package)

        print(
            f"[INFO] {package} {installed_version}"
        )

        if installed_version != expected:
            print(
                f"[FAILED] Expected {package}=={expected}, "
                f"got {installed_version}",
                file=sys.stderr,
            )
            failed = True

    except PackageNotFoundError:
        print(
            f"[FAILED] Package metadata not found: "
            f"{package}",
            file=sys.stderr,
        )
        failed = True

if failed:
    sys.exit(1)

print("[OK] angr component versions are consistent.")
PY
}


verify_z3_version() {
    echo "[+] Verifying Z3 version..."

    Z3_EXPECTED_VERSION="$Z3_VERSION" \
        "$VENV_DIR/bin/python" - <<'PY'
import os
import sys
from importlib.metadata import (
    PackageNotFoundError,
    version,
)

expected = os.environ["Z3_EXPECTED_VERSION"]

try:
    installed = version("z3-solver")
except PackageNotFoundError:
    print(
        "[FAILED] z3-solver metadata not found",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"[INFO] z3-solver {installed}")

if installed != expected:
    print(
        f"[FAILED] Expected z3-solver=={expected}, "
        f"got {installed}",
        file=sys.stderr,
    )
    sys.exit(1)

print("[OK] Z3 version is correct.")
PY
}


verify_cli() {
    echo "[+] Verifying BinMind CLI..."

    "$VENV_DIR/bin/python" \
        "$PROJECT_DIR/binmind.py" \
        version
}


verify_installation() {
    echo "[+] Running installation verification..."

    verify_project_files
    verify_package_metadata

    if [ "$INSTALL_DEPS" -eq 1 ]; then
        verify_python_dependencies
        verify_angr_versions
        verify_z3_version
    fi

    verify_cli

    echo "[+] Installation verification passed."
}


# ============================================================================
# Launcher
# ============================================================================

install_launcher() {
    local python_bin
    local target
    local tmp_launcher

    python_bin="$VENV_DIR/bin/python"
    target="$TARGET_DIR/$COMMAND_NAME"
    tmp_launcher="$(mktemp)"

    trap 'rm -f "$tmp_launcher"' EXIT

    cat > "$tmp_launcher" <<EOF
#!/usr/bin/env bash

set -euo pipefail

exec "$python_bin" "$PROJECT_DIR/binmind.py" "\$@"
EOF

    echo "[+] Installing launcher:"
    echo "    $target"

    if [ "$TARGET_DIR" = "/usr/local/bin" ]; then
        need_root mkdir -p "$TARGET_DIR"
        need_root install -m 755 "$tmp_launcher" "$target"
    else
        mkdir -p "$TARGET_DIR"
        install -m 755 "$tmp_launcher" "$target"
    fi

    rm -f "$tmp_launcher"
    trap - EXIT
}


verify_launcher() {
    local target

    target="$TARGET_DIR/$COMMAND_NAME"

    if [ ! -x "$target" ]; then
        echo "Error: installed launcher is unavailable:" >&2
        echo "       $target" >&2
        return 1
    fi

    echo "[+] Verifying installed launcher..."
    "$target" version
}


# ============================================================================
# Argument parsing
# ============================================================================

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

        --dev)
            INSTALL_DEV_DEPS=1
            ;;

        --no-deps)
            INSTALL_DEPS=0
            ;;

        --no-system-deps)
            INSTALL_SYSTEM_DEPS=0
            ;;

        --force)
            FORCE_INSTALL=1
            ;;

        *)
            echo "Error: unknown option: $1" >&2
            echo "" >&2
            usage >&2
            exit 2
            ;;
    esac

    shift
done


# ============================================================================
# Default target
# ============================================================================

if [ -z "$TARGET_DIR" ]; then
    if [ -w "/usr/local/bin" ]; then
        TARGET_DIR="/usr/local/bin"
    else
        TARGET_DIR="${HOME}/.local/bin"
    fi
fi


# ============================================================================
# Main installation
# ============================================================================

echo "[*] Starting BinMind installation..."
echo "[*] Project directory  : $PROJECT_DIR"
echo "[*] Target directory   : $TARGET_DIR"
echo "[*] Virtual environment: $VENV_DIR"
echo "[*] System Python      : $SYSTEM_PYTHON"
echo "[*] Python index       : $PIP_INDEX_URL"
echo "[*] angr version       : $ANGR_VERSION"
echo "[*] Z3 version         : $Z3_VERSION"

if [ "$INSTALL_DEV_DEPS" -eq 1 ]; then
    echo "[*] Install mode       : development"
else
    echo "[*] Install mode       : runtime"
fi


install_system_dependencies


if [ "$INSTALL_DEPS" -eq 1 ]; then
    install_python_dependencies
else
    echo "[+] Skipping dependency installation (--no-deps)."

    if [ ! -x "$VENV_DIR/bin/python" ]; then
        echo "Error: --no-deps was specified, but the virtual environment" >&2
        echo "       does not contain an executable Python interpreter:" >&2
        echo "       $VENV_DIR/bin/python" >&2
        exit 1
    fi

    if ! "$VENV_DIR/bin/python" -m pip install --help \
        >/dev/null 2>&1; then
        echo "Error: --no-deps was specified, but pip is damaged." >&2
        exit 1
    fi
fi


verify_installation
install_launcher
verify_launcher


# ============================================================================
# Completion
# ============================================================================

echo ""
echo "[+] BinMind installation completed successfully."
echo "[+] Launcher:"
echo "    $TARGET_DIR/$COMMAND_NAME"
echo ""
echo "Verify installation:"
echo "    $TARGET_DIR/$COMMAND_NAME version"
echo ""
echo "Show help:"
echo "    $TARGET_DIR/$COMMAND_NAME --help"
echo ""

case ":${PATH:-}:" in
    *":$TARGET_DIR:"*)
        ;;

    *)
        echo "[!] $TARGET_DIR is not currently in PATH."
        echo "[!] Add this line to your shell configuration:"
        echo ""
        echo "    export PATH=\"$TARGET_DIR:\$PATH\""
        echo ""

        if [ "$TARGET_DIR" = "${HOME}/.local/bin" ]; then
            echo "For Bash:"
            echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
            echo "    source ~/.bashrc"
            echo ""
        fi
        ;;
esac