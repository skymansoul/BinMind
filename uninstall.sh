#!/usr/bin/env bash
# uninstall.sh — BinMind 卸载/清理脚本 (与 install.sh 对称)
#
# 默认行为(只卸载"安装物"):
#   * 删除 install.sh 注册的命令启动器 (binmind)
#   * 不删除项目源码、不删除分析成果、不卸载系统包/radare2
#
# 需要显式开关的动作:
#   --purge-venv      删除虚拟环境 (默认保留)
#   --purge-caches    删除可再生缓存 (__pycache__/.api_cache/.pytest_cache/test_reports/测试报告)
#   --purge-runtime   删除运行期状态 (logs/ exported_reports/ data/vulnerabilities.db data/api_tasks/)
#   --purge-results   删除分析产物目录 results/ 与 reports/ (含上游提交的样例报告, 谨慎)
#   --all             以上全部 = 一键清空, 便于重新测试 install.sh
#
set -euo pipefail

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMMAND_NAME="${COMMAND_NAME:-binmind}"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"

FORCED_TARGET_DIR=""
EXPLICIT_TARGET=0
PURGE_VENV=0
PURGE_CACHES=0
PURGE_RUNTIME=0
PURGE_RESULTS=0
DRY_RUN=0
ASSUME_YES=0
FORCE=0

REMOVED_ITEMS=0
SKIPPED_ITEMS=0
FAILED_ITEMS=0

usage() {
    cat <<'USAGE'
Usage:
  ./uninstall.sh                  Remove the installed binmind command
  ./uninstall.sh --all            Full clean: command + venv + caches + runtime + results
  ./uninstall.sh --purge-venv     Also delete the Python virtual environment
  ./uninstall.sh --purge-caches   Also delete regenerable caches (__pycache__, .api_cache, ...)
  ./uninstall.sh --purge-runtime  Also delete runtime state (logs/, exported_reports/, DB, api_tasks/)
  ./uninstall.sh --purge-results  Also delete results/ and reports/
  ./uninstall.sh --user           Only look in ~/.local/bin
  ./uninstall.sh --system         Only look in /usr/local/bin
  ./uninstall.sh --dry-run        Show what would be removed, change nothing
  ./uninstall.sh --yes            Do not ask for confirmation (required when no TTY)
  ./uninstall.sh --force          Remove the command even if it does not look like
                                  a BinMind launcher
  ./uninstall.sh -h|--help        Show this help

Environment:
  COMMAND_NAME=name         Name of the installed command (default: binmind)
  VENV_DIR=/path/to/venv    Virtual environment purged by --purge-venv

What is never touched:
  project sources (binmind.py, install.sh, modules/, tests/, ...), samples/,
  system packages, radare2, and any PATH line you added to your shell rc files.

Typical clean re-test of install.sh:
  ./uninstall.sh --all --yes && ./install.sh --user
USAGE
}

say()  { printf '%s\n' "$*"; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
err()  { printf 'Error: %s\n' "$*" >&2; }

need_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        err "root permission is required for this action (install sudo or run as root)"
        exit 1
    fi
}

confirm() {
    # 返回 0=确认, 1=用户拒绝, 2=无法询问(非交互且未加 --yes)
    [ "$ASSUME_YES" -eq 1 ] && return 0
    local prompt="$1" reply=""
    if [ -t 0 ]; then
        printf '%s [y/N] ' "$prompt"
        read -r reply || return 2
    elif [ -r /dev/tty ] && [ -w /dev/tty ]; then
        # stdin 被重定向(终端包装器/管道)时仍走控制终端询问;
        # 加超时避免在无人应答的场景下永久挂起。
        printf '%s [y/N] ' "$prompt" > /dev/tty
        read -r -t 20 reply < /dev/tty || return 2
    else
        return 2
    fi
    case "$reply" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

launcher_candidates() {
    if [ "$EXPLICIT_TARGET" -eq 1 ]; then
        printf '%s\n' "$FORCED_TARGET_DIR/$COMMAND_NAME"
    else
        printf '%s\n' "/usr/local/bin/$COMMAND_NAME" "$HOME/.local/bin/$COMMAND_NAME"
    fi
}

is_binmind_launcher() {
    # install.sh 生成的启动器有两种形态: 直接 exec python binmind.py,
    # 或委托给项目自带 binmind 脚本; 两者都含 binmind 关键字。
    local f="$1"
    [ -f "$f" ] || return 1
    grep -qE 'binmind(\.py)?("|[[:space:]])' "$f" 2>/dev/null
}

venv_is_safe_to_remove() {
    # 与 install.sh 同一套护栏: 只删真正的 venv, 且拒绝危险路径
    case "$VENV_DIR" in
        ""|"/"|"$HOME"|"$PROJECT_DIR")
            return 1
            ;;
    esac
    [ -f "$VENV_DIR/pyvenv.cfg" ] || return 1
    return 0
}

remove_path() {
    # $1=路径 $2=人类可读描述; 统一处理 dry-run / 确认 / 权限 / 计数
    local path="$1" label="$2"
    if [ ! -e "$path" ]; then
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        say "[dry-run] would remove $label: $path"
        return 0
    fi
    local rc=0
    confirm "Delete $label: $path ?" || rc=$?
    if [ "$rc" -eq 1 ]; then
        warn "skipped: $path"
        SKIPPED_ITEMS=$((SKIPPED_ITEMS + 1))
        return 0
    fi
    if [ "$rc" -eq 2 ]; then
        err "cannot ask for confirmation (no TTY); re-run with --yes to delete: $path"
        FAILED_ITEMS=$((FAILED_ITEMS + 1))
        return 1
    fi
    if [ -w "$(dirname -- "$path")" ]; then
        rm -rf -- "$path"
    else
        need_root rm -rf -- "$path"
    fi
    say "[+] removed $label: $path"
    REMOVED_ITEMS=$((REMOVED_ITEMS + 1))
    return 0
}

remove_launcher() {
    local target="$1"
    [ -e "$target" ] || return 0

    if ! is_binmind_launcher "$target"; then
        if [ "$FORCE" -ne 1 ]; then
            err "$target does not look like a BinMind launcher; refusing (use --force to override)"
            FAILED_ITEMS=$((FAILED_ITEMS + 1))
            return 1
        fi
        warn "removing $target although it does not look like a BinMind launcher (--force)"
    fi
    remove_path "$target" "command" || true
    return 0
}

purge_venv() {
    if [ ! -e "$VENV_DIR" ]; then
        say "[+] virtual environment not present: $VENV_DIR"
        return 0
    fi
    if ! venv_is_safe_to_remove; then
        err "refusing to remove '$VENV_DIR' — not a recognised virtual environment"
        FAILED_ITEMS=$((FAILED_ITEMS + 1))
        return 1
    fi
    remove_path "$VENV_DIR" "virtual environment" || true
    return 0
}

purge_caches() {
    local p
    for p in \
        "$PROJECT_DIR/.api_cache" \
        "$PROJECT_DIR/.pytest_cache" \
        "$PROJECT_DIR/.temp" \
        "$PROJECT_DIR/.temp_test" \
        "$PROJECT_DIR/test_reports" \
        "$PROJECT_DIR/tests/build_results.json" \
        "$PROJECT_DIR/tests/regression_report.json" \
        "$PROJECT_DIR/tests/report.json" \
        "$PROJECT_DIR/final_report.json"; do
        remove_path "$p" "cache" || true
    done

    # 字节码缓存: 只清理项目内、排除 venv
    local n=0
    local dir
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        n=$((n + 1))
        remove_path "$dir" "bytecode cache" || true
    done < <(find "$PROJECT_DIR" -type d -name __pycache__ -not -path "$VENV_DIR/*" 2>/dev/null)
    [ "$n" -gt 0 ] || say "[+] no __pycache__ directories found"
    return 0
}

purge_runtime() {
    local p
    for p in \
        "$PROJECT_DIR/logs" \
        "$PROJECT_DIR/exported_reports" \
        "$PROJECT_DIR/data/api_tasks" \
        "$PROJECT_DIR/data/vulnerabilities.db" \
        "$PROJECT_DIR/data/vulnerabilities.db-wal" \
        "$PROJECT_DIR/data/vulnerabilities.db-shm"; do
        remove_path "$p" "runtime state" || true
    done
    return 0
}

purge_results() {
    local p
    for p in "$PROJECT_DIR/results" "$PROJECT_DIR/reports"; do
        if [ -d "$p" ] && [ "$DRY_RUN" -ne 1 ]; then
            warn "$p may contain upstream sample reports as well as your own analysis output"
        fi
        remove_path "$p" "analysis output directory" || true
    done
    return 0
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --system)
            FORCED_TARGET_DIR="/usr/local/bin"
            EXPLICIT_TARGET=1
            ;;
        --user)
            FORCED_TARGET_DIR="${HOME}/.local/bin"
            EXPLICIT_TARGET=1
            ;;
        --purge-venv)
            PURGE_VENV=1
            ;;
        --purge-caches|--purge-data)
            PURGE_CACHES=1
            ;;
        --purge-runtime)
            PURGE_RUNTIME=1
            ;;
        --purge-results)
            PURGE_RESULTS=1
            ;;
        --all|--purge-all)
            PURGE_VENV=1
            PURGE_CACHES=1
            PURGE_RUNTIME=1
            PURGE_RESULTS=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        --yes|-y)
            ASSUME_YES=1
            ;;
        --force)
            FORCE=1
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
    shift
done

say "[*] BinMind uninstaller"
say "[*] Project directory: $PROJECT_DIR"
say "[*] Command name:      $COMMAND_NAME"
say "[*] Virtual env:       $VENV_DIR"
[ "$DRY_RUN" -eq 1 ] && say "[*] Mode:              dry-run (nothing will be changed)"
say ""

found_launcher=0
while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    if [ -e "$candidate" ]; then
        found_launcher=1
        remove_launcher "$candidate" || true
    fi
done < <(launcher_candidates)

if [ "$found_launcher" -eq 0 ]; then
    say "[+] no installed command found for '$COMMAND_NAME' (looked in: $(launcher_candidates | tr '\n' ' '))"
fi

if [ "$PURGE_VENV" -eq 1 ]; then
    say ""
    purge_venv || true
else
    say ""
    say "[i] virtual environment kept: $VENV_DIR"
    say "    remove it with: ./uninstall.sh --purge-venv --yes"
fi

if [ "$PURGE_CACHES" -eq 1 ]; then
    say ""
    purge_caches || true
else
    say "[i] caches kept (__pycache__, .api_cache, .pytest_cache, test_reports)"
    say "    remove them with: ./uninstall.sh --purge-caches --yes"
fi

if [ "$PURGE_RUNTIME" -eq 1 ]; then
    say ""
    purge_runtime || true
else
    say "[i] runtime state kept (logs/, exported_reports/, data/vulnerabilities.db, data/api_tasks/)"
    say "    remove it with: ./uninstall.sh --purge-runtime --yes"
fi

if [ "$PURGE_RESULTS" -eq 1 ]; then
    say ""
    purge_results || true
else
    say "[i] analysis output kept (results/, reports/) — these also contain upstream sample reports"
    say "    remove it with: ./uninstall.sh --purge-results --yes"
fi

say ""
say "[i] Never touched by design: project sources, samples/, system packages,"
say "    radare2, and PATH lines you added to ~/.bashrc or ~/.zshrc yourself."
say ""

if [ "$DRY_RUN" -eq 1 ]; then
    say "[+] dry-run complete — nothing was changed"
    exit 0
fi

if [ "$FAILED_ITEMS" -gt 0 ]; then
    say "[!] Uninstall INCOMPLETE: $FAILED_ITEMS item(s) could not be removed (see errors above)"
    exit 1
fi

if [ "$SKIPPED_ITEMS" -gt 0 ]; then
    say "[!] Uninstall incomplete: $SKIPPED_ITEMS item(s) were skipped (you answered 'no')"
    exit 1
fi

say "[+] Uninstall complete (removed $REMOVED_ITEMS item(s))"
if [ "$PURGE_VENV" -eq 1 ] && [ "$PURGE_CACHES" -eq 1 ]; then
    say "    Clean state — ready to re-test: ./install.sh --user"
fi
exit 0
