"""
样本管理器 —— 常量定义与辅助函数。

将样本路径常量、目录结构模板及格式/漏洞类型推断逻辑集中管理，
供 CRUD 和批量操作模块复用。
"""


import os
from typing import List

# 默认样本库路径
DEFAULT_SAMPLE_DB = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'data', 'samples.json'
)

# 样本库目录结构模板
SAMPLE_DIRS = {
    'ctf': 'CTF 竞赛样本',
    'teaching': '教学演示样本',
    'cve': '公开 CVE 漏洞样本',
}


def find_binaries(directory: str, recursive: bool) -> List[str]:
    """发现目录中的可执行二进制文件。"""
    binaries = []
    from core.binary_info import detect_format

    for root, dirs, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.isfile(fpath) and not fname.endswith(
                ('.py', '.c', '.cpp', '.h', '.txt', '.md', '.json', '.log')
            ):
                if detect_format(fpath) != 'unknown':
                    binaries.append(fpath)
        if not recursive:
            break

    return binaries


def guess_format(path: str) -> str:
    """快速猜测文件格式。"""
    try:
        from core.binary_info import detect_format
        return detect_format(path)
    except Exception:
        return 'unknown'


def infer_vuln_type(path: str) -> str:
    """从文件名推断漏洞类型。"""
    name = os.path.basename(path).lower()
    if 'stack' in name or 'bof' in name or 'overflow' in name:
        return 'stack-overflow'
    if 'fmt' in name or 'format' in name or 'fsb' in name:
        return 'format-string'
    if 'heap' in name or 'uaf' in name:
        return 'heap-corruption'
    if 'rop' in name:
        return 'code-reuse'
    if 'shellcode' in name:
        return 'shellcode-injection'
    return ''
