"""样本管理辅助函数：二进制发现、格式猜测、漏洞类型推断、目录初始化。"""

import os
from typing import Dict, List


# 样本库目录结构模板
SAMPLE_DIRS = {
    'ctf': 'CTF 竞赛样本',
    'teaching': '教学演示样本',
    'cve': '公开 CVE 漏洞样本',
}


def _find_binaries(directory: str, recursive: bool) -> List[str]:
    """发现目录中的可执行二进制文件。"""
    binaries: List[str] = []
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


def _guess_format(path: str) -> str:
    """快速猜测文件格式。"""
    try:
        from core.binary_info import detect_format
        return detect_format(path)
    except Exception:
        return 'unknown'


def _infer_vuln_type(path: str) -> str:
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


def init_sample_directories(base_dir: str) -> Dict[str, str]:
    """初始化样本库目录结构。"""
    created: Dict[str, str] = {}
    for dirname, description in SAMPLE_DIRS.items():
        dirpath = os.path.join(base_dir, dirname)
        os.makedirs(dirpath, exist_ok=True)
        readme_path = os.path.join(dirpath, 'README.md')
        if not os.path.exists(readme_path):
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(f'# {description}\n\n放置 {description} 的二进制文件。\n')
        created[dirname] = dirpath
    return created
