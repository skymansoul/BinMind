# 2026-07-30
# 安全文件系统操作: 原子写入、安全文件名清理、临时文件、目录遍历安全约束
# 二进制分析管线常需写入中间结果（反编译输出、特征缓存、补丁文件）——
# 原子写入确保崩溃中断时不产生半写文件。
# 符号链接遍历防护参考 OWASP 路径遍历缓解指南。
import os
import re
import tempfile
import shutil
import hashlib
from contextlib import contextmanager
from typing import Optional, Iterator, List

# 原子写入 ------------------------------------------------------------

def atomic_write(filepath: str, data: bytes, *, mode: int = 0o644,
                 sync: bool = True) -> int:
    """原子写入: 先写同名临时文件，fsync 后 rename。
    在 POSIX 上保证 rename 的原子性；Windows 上若目标存在则替换。
    sync=True 时先 fsync 数据到磁盘再重命名。
    返回写入的字节数。"""
    dirname = os.path.dirname(filepath) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirname, suffix=".tmp")
    try:
        written = os.write(fd, data)
        if sync:
            os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, filepath)
    return written

def atomic_write_text(filepath: str, text: str, encoding: str = "utf-8",
                      **kwargs) -> int:
    """原子写入文本文件。kwargs 传递到 atomic_write。"""
    return atomic_write(filepath, text.encode(encoding), **kwargs)

# ---- 安全的文件名 --------------------------------------------------------

# Windows/Linux 通用不安全的文件名字符
_UNSAFE_FILENAME = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
# 仅允许字母数字、连字符、下划线、点、空格（首尾去空格）
_SAFE_FILENAME = re.compile(r'[^a-zA-Z0-9._\- ]')

def sanitize_filename(name: str, replacement: str = "_",
                      max_length: int = 255) -> str:
    """清理文件名中的危险字符。
    去除路径分隔符、控制字符和 Windows 保留名。
    max_length: 截断到最大长度（不含扩展名截断逻辑）。"""
    # 去除前导和尾部空格/点（Windows 不允许）
    name = name.strip(" .")
    # 替换不安全字符
    name = _SAFE_FILENAME.sub(replacement, name)
    # 限制长度
    if len(name) > max_length:
        name = name[:max_length].rstrip(" .")
    # 空文件名兜底
    if not name:
        name = "unnamed"
    return name

# ---- 路径安全验证 --------------------------------------------------------

def is_safe_path(base_dir: str, target_path: str) -> bool:
    """验证 target_path 是否在 base_dir 子树内（防目录遍历）。
    解析真实路径后做前缀比较。"""
    try:
        base_real = os.path.realpath(base_dir)
        target_real = os.path.realpath(os.path.join(base_dir, target_path))
        return os.path.commonpath([base_real, target_real]) == base_real
    except (ValueError, OSError):
        return False

def safe_join(base_dir: str, *components: str) -> Optional[str]:
    """安全路径拼接。若结果不在 base_dir 内则返回 None。"""
    joined = os.path.normpath(os.path.join(base_dir, *components))
    if is_safe_path(base_dir, joined):
        return joined
    return None

# ---- 临时文件/目录 上下文管理器 -----------------------------------------

@contextmanager
def temp_file(suffix: str = "", prefix: str = "binmind_",
              dir: Optional[str] = None, delete: bool = True):
    """创建临时文件上下文管理器。退出时自动删除。
    Yields the file path (str). 调用方自行 open。"""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
    os.close(fd)
    try:
        yield path
    finally:
        if delete and os.path.exists(path):
            try:
                os.unlink(path)
            except OSError:
                pass

@contextmanager
def temp_dir(suffix: str = "", prefix: str = "binmind_",
             dir: Optional[str] = None, delete: bool = True):
    """创建临时目录上下文管理器。退出时递归删除。"""
    path = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)
    try:
        yield path
    finally:
        if delete and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)

# ---- 目录遍历 ------------------------------------------------------------

def walk_files(root_dir: str, extensions: Optional[List[str]] = None,
               max_size: Optional[int] = None) -> Iterator[str]:
    """安全遍历目录树下的所有文件。
    extensions: 如 ['.py', '.so', '.dll']。大小写不敏感。
    max_size: 跳过超过此字节限制的文件。"""
    exts_lower = {e.lower() for e in extensions} if extensions else None
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # 跳过隐藏目录
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fn in filenames:
            if fn.startswith('.'):
                continue
            full = os.path.join(dirpath, fn)
            if exts_lower:
                if os.path.splitext(fn)[1].lower() not in exts_lower:
                    continue
            if max_size is not None:
                try:
                    if os.path.getsize(full) > max_size:
                        continue
                except OSError:
                    continue
            yield full

# ---- 文件校验辅助 --------------------------------------------------------

def file_checksum_sha256(filepath: str, chunk_size: int = 8192) -> str:
    """流式计算文件 SHA-256，适用于大文件。"""
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_dir(filepath: str) -> str:
    """确保文件路径的父目录存在。类似于 mkdir -p $(dirname filepath)。
    返回文件路径本身。"""
    parent = os.path.dirname(filepath)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    return filepath
