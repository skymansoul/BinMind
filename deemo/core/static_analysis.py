"""
静态二进制分析 — 危险函数检测、字符串扫描、导入表审查。
无需外部反汇编器, 基于原始字节与 radare2 输出。
"""

import logging
import re
import subprocess
from typing import Dict, List

from config import R2_PATH, SUBPROCESS_TIMEOUT
from core.detection_shared import DANGEROUS_FUNCTIONS, normalize_import_name

logger = logging.getLogger(__name__)

def scan_imports(binary_path: str) -> List[Dict]:
    """通过 r2 扫描二进制导入表中的危险函数。"""
    raw = _radare2_cmd(binary_path, ['iE'], timeout=60)
    found = []

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        name = normalize_import_name(line)
        meta = DANGEROUS_FUNCTIONS.get(name)
        if meta:
            vuln_type, severity, cwe, _confidence = meta
            found.append({
                'function': line,
                'normalized_function': name,
                'vuln_type': vuln_type,
                'severity': severity,
                'cwe': cwe,
                'description': f'Imports {name} — potential {vuln_type}',
            })
    return found


def scan_strings(binary_path: str) -> List[str]:
    """提取二进制中的可打印字符串, 查找可疑模式。"""
    raw = _radare2_cmd(binary_path, ['izz'], timeout=60)
    strings = []
    for line in raw.splitlines():
        # izz 输出: 地址 长度 编码 字符串
        parts = line.split(None, 3)
        if len(parts) >= 4:
            s = parts[3]
            # 过滤不可打印字符
            if s.isprintable() and len(s) >= 4:
                strings.append(s)
    return strings


def find_suspicious_strings(strings: List[str]) -> List[Dict]:
    """标记有分析价值的可疑字符串。"""
    patterns = {
        'hardcoded-password': r'(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]',
        'shell-command': r'(?i)(/bin/(ba)?sh|cmd\.exe|/bin/bash)',
        'url': r'https?://[^\s]+',
        'file-path': r'(?i)(/etc/(passwd|shadow)|C:\\Windows\\)',
        'stack-canary': r'(?i)(__stack_chk|stack.*canary)',
    }

    findings = []
    for s in strings:
        for category, pat in patterns.items():
            if re.search(pat, s):
                findings.append({'string': s[:120], 'category': category})
    return findings


def _radare2_cmd(path: str, cmds: List[str], timeout: int = 300) -> str:
    cmd = [R2_PATH, '-q', '-e', 'io.color=false']
    for c in cmds:
        cmd.extend(['-c', c])
    cmd.append(path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout
    except FileNotFoundError:
        return ''
    except subprocess.TimeoutExpired:
        return ''
