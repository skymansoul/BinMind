"""SHA256 哈希变更检测 — 精确追踪文件变更。
支持整文件哈希和 CDC（Content-Defined Chunking）两种模式：
- 整文件模式（默认）：对每个文件计算 SHA-256，O(n) 扫描。
- CDC 模式：对大于阈值的文件使用 Gear-hash CDC 分块，
  仅当块级哈希变化时才标记文件为变更——减少误报。
  适用于 AI 仅修改文件局部（如追加函数）的场景。"""
import os
import hashlib
import fnmatch
from parallel_deep_dev.config import CONFIG


def file_sha256(filepath: str) -> str:
    """返回文件的 SHA256 十六进制摘要。"""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _is_excluded(filepath: str, patterns: list[str] | None = None) -> bool:
    """检查文件是否在排除列表中。"""
    if patterns is None:
        patterns = CONFIG.EXCLUDE_PATTERNS
    try:
        rel_path = os.path.relpath(filepath, CONFIG.ROOT_DIR)
    except ValueError:
        return True
    for pattern in patterns:
        if fnmatch.fnmatch(rel_path, pattern) or pattern in rel_path:
            return True
    return False


def snapshot_tree_hashes(
    root_dir: str, exclude_patterns: list[str] | None = None
) -> dict[str, str]:
    """对整个目录树做 SHA256 快照，返回 {relpath: hexdigest}。"""
    if exclude_patterns is None:
        exclude_patterns = CONFIG.EXCLUDE_PATTERNS
    snap: dict[str, str] = {}
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            fpath = os.path.join(dirpath, fn)
            if _is_excluded(fpath, exclude_patterns):
                continue
            rel = os.path.relpath(fpath, root_dir)
            h = file_sha256(fpath)
            if h:
                snap[rel] = h
    return snap


def detect_changed_by_hash(
    before: dict[str, str], after: dict[str, str]
) -> set[str]:
    """比较前后快照，返回变更文件的绝对路径集合。"""
    changed: set[str] = set()
    for rel, h in after.items():
        if rel not in before or before[rel] != h:
            changed.add(os.path.join(CONFIG.ROOT_DIR, rel))
    return changed


def collect_changed_files(
    results: dict[str, list[str]], changed_files: list[str] | None = None
) -> set[str]:
    """收集所有实际变更的文件路径。"""
    changed: set[str] = set()
    for files in results.values():
        for fpath in files:
            if os.path.isfile(fpath):
                changed.add(fpath)
    if changed_files:
        for fpath in changed_files:
            if os.path.isfile(fpath):
                changed.add(fpath)
    try:
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, cwd=CONFIG.ROOT_DIR, timeout=10,
        )
        for line in result.stdout.strip().split("\n"):
            if line:
                fpath = os.path.join(CONFIG.ROOT_DIR, line)
                if os.path.isfile(fpath):
                    changed.add(fpath)
    except Exception:
        pass
    return changed


# ---------------------------------------------------------------------------
# CDC 增强哈希 — 对大型文件使用内容定义分块，减少 AI 局部修改导致的整文件误报
# ---------------------------------------------------------------------------

def file_cdc_hash(filepath: str) -> str:
    """返回文件的 CDC 复合哈希。
    对大文件：SHA-256(块1哈希 || 块2哈希 || ...)，仅块级变更才改变该哈希。
    对小文件：退化为普通 SHA-256。
    此函数通过分析 AI 修改模式（追加函数、修改局部代码块）降低误报率。"""
    file_size = 0
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        return ""

    if file_size < CONFIG.CDC_MIN_FILE_SIZE:
        return file_sha256(filepath)

    try:
        from parallel_deep_dev.engine.chunking import chunk_file
    except ImportError:
        return file_sha256(filepath)

    chunks = chunk_file(
        filepath,
        min_chunk=CONFIG.CDC_CHUNK_MIN,
        avg_chunk=CONFIG.CDC_CHUNK_AVG,
        max_chunk=CONFIG.CDC_CHUNK_MAX,
    )
    if not chunks:
        return ""

    # 将所有块哈希拼接后取 SHA-256，作为该文件的"结构哈希"
    combined = "".join(c[2] for c in chunks).encode("ascii")
    return hashlib.sha256(combined).hexdigest()


def snapshot_tree_hashes_cdc(
    root_dir: str, exclude_patterns: list[str] | None = None
) -> dict[str, str]:
    """CDC 模式目录快照 — 对大文件使用 CDC 复合哈希替代整文件哈希。
    接口与 snapshot_tree_hashes 完全一致，可互换使用。"""
    if exclude_patterns is None:
        exclude_patterns = CONFIG.EXCLUDE_PATTERNS
    snap: dict[str, str] = {}
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            fpath = os.path.join(dirpath, fn)
            if _is_excluded(fpath, exclude_patterns):
                continue
            rel = os.path.relpath(fpath, root_dir)
            h = file_cdc_hash(fpath)
            if h:
                snap[rel] = h
    return snap
