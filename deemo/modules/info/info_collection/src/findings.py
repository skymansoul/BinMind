# findings — 危险函数发现、评分、去重
# 按语言分层的危险函数库，评分 = severity × confidence × context_multiplier
# 去重用 (type, normalized_description) 模糊匹配

import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from itertools import accumulate

# ===== 危险函数库：语言 → {函数名: 基础严重度} =====
DANGEROUS_FUNCTIONS: Dict[str, Dict[str, int]] = {
    "c": {
        "system": 9, "popen": 8, "execve": 9, "execvp": 9, "execl": 9,
        "execle": 9, "execlp": 9, "strcpy": 7, "strcat": 6, "gets": 9,
        "sprintf": 6, "vsprintf": 6, "scanf": 5, "realpath": 5, "getopt": 4,
        "CreateProcess": 8, "CreateProcessA": 8, "CreateProcessW": 8,
        "WinExec": 8, "ShellExecute": 8, "ShellExecuteA": 8, "ShellExecuteW": 8,
        "LoadLibrary": 6, "LoadLibraryA": 6, "LoadLibraryW": 6,
        "dlopen": 6, "VirtualAlloc": 7, "VirtualProtect": 8,
        "WriteProcessMemory": 8, "CreateRemoteThread": 9,
        "mmap": 5, "mprotect": 7, "ptrace": 6,
        "malloc": 3, "free": 3, "realloc": 3,
    },
    "python": {
        "eval": 8, "exec": 9, "compile": 7, "__import__": 7,
        "os.system": 8, "os.popen": 8, "subprocess.call": 7,
        "subprocess.Popen": 7, "subprocess.run": 6,
        "pickle.loads": 8, "pickle.load": 8, "marshal.loads": 7,
        "ctypes.CFUNCTYPE": 7, "ctypes.cdll": 6,
        "input": 5, "raw_input": 4, "file": 5,
    },
    "js": {
        "eval": 9, "Function": 9, "setTimeout": 6, "setInterval": 6,
        "document.write": 6, "document.writeln": 6,
        "innerHTML": 7, "outerHTML": 6, "postMessage": 5,
        "localStorage.setItem": 4, "sessionStorage.setItem": 4,
        "WebSocket": 5, "XMLHttpRequest": 4,
        "fetch": 4, "require": 4, "import": 4,
        "process.exec": 8, "child_process.exec": 8,
        "child_process.spawn": 8, "child_process.fork": 7,
    },
    "kernel": {
        "copy_from_user": 8, "copy_to_user": 8,
        "__get_free_pages": 5, "kmalloc": 3,
        "kfree": 3, "capable": 5,
        "sprintf": 7, "strcpy": 8, "strncpy": 5,
        "memcpy": 5, "ioremap": 6,
        "request_irq": 5, "module_init": 3,
        "smp_call_function": 5, "call_usermodehelper": 8,
    },
}

class Severity(Enum):
  CRITICAL = "CRITICAL"
  HIGH = "HIGH"
  MEDIUM = "MEDIUM"
  LOW = "LOW"
  INFO = "INFO"

_SEVERITY_WEIGHT = {
  Severity.CRITICAL: 100,
  Severity.HIGH: 75,
  Severity.MEDIUM: 50,
  Severity.LOW: 25,
  Severity.INFO: 10,
}

@dataclass
class Finding:
    type: str
    description: str
    severity: Severity
    confidence: float
    location: str = ""

    def __hash__(self):
        return hash((self.type, self.description.lower()))


def _score_to_severity(score: int) -> Severity:
    for _s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if score >= _SEVERITY_WEIGHT[_s]:
            return _s
    return Severity.INFO


def _search_in_strings(strings: list, pattern: str) -> list:
    _r = []
    _pat = re.compile(pattern, re.IGNORECASE)
    for _s in strings:
        _text = _s[1] if isinstance(_s, tuple) else _s
        if _pat.search(_text):
            _r.append(_text)
    return _r


def _search_in_imports(imports: dict, pattern: str) -> list:
    _r = []
    _pat = re.compile(pattern, re.IGNORECASE)
    for _dll, _funcs in imports.items():
        for _f in _funcs:
            if _pat.search(_f):
                _r.append(f"{_dll}:{_f}")
    return _r


def extract_findings(binary_info: dict, strings: list = None, imports: dict = None) -> List[Finding]:
    """从二进制信息/字符串/导入表提取危险发现。
    评分公式：base_score * 10 * confidence * multiplier。
    imported 函数 multiplier=0.6（可能只是库链接），字符串中出现 multiplier=1.0。
    """
    _findings: List[Finding] = []
    _strs = strings or binary_info.get("strings", [])
    _imps = imports or binary_info.get("imports", {})

    _c_funcs = DANGEROUS_FUNCTIONS["c"]
    for _fn, _base_score in _c_funcs.items():
        _pattern = re.compile(r'\b' + re.escape(_fn) + r'\b', re.IGNORECASE)
        _imported = []
        for _dll, _funcs in _imps.items():
            for _f in _funcs:
                if _pattern.search(_f):
                    _imported.append((_dll, _f))

        _in_strings = _search_in_strings(_strs, r'\b' + re.escape(_fn) + r'\b')

        if _imported:
            _conf = 0.85
            _score = int(_base_score * 10 * _conf * 0.6)
            for _dll, _f in _imported:
                _findings.append(Finding(
                    type="dangerous_function",
                    description=f"Imported dangerous C function: {_f} from {_dll}",
                    severity=_score_to_severity(_score),
                    confidence=_conf,
                    location=f"import:{_dll}",
                ))

        if _in_strings:
            _conf = 0.7
            _score = int(_base_score * 10 * _conf * 1.0)
            for _s_text in _in_strings[:5]:
                _findings.append(Finding(
                    type="dangerous_function",
                    description=f"String reference to dangerous function: {_s_text}",
                    severity=_score_to_severity(_score),
                    confidence=_conf,
                    location="strings",
                ))

    for _fn, _base_score in DANGEROUS_FUNCTIONS["python"].items():
        _in_strs = _search_in_strings(_strs, re.escape(_fn))
        if _in_strs:
            _conf = 0.75
            _score = int(_base_score * 10 * _conf)
            _findings.append(Finding(
                type="dangerous_function",
                description=f"Python dangerous pattern: {_fn}",
                severity=_score_to_severity(_score),
                confidence=_conf,
                location="strings",
            ))

    for _fn, _base_score in DANGEROUS_FUNCTIONS["js"].items():
        _in_strs = _search_in_strings(_strs, re.escape(_fn))
        if _in_strs:
            _conf = 0.75
            _score = int(_base_score * 10 * _conf)
            _findings.append(Finding(
                type="dangerous_function",
                description=f"JavaScript dangerous pattern: {_fn}",
                severity=_score_to_severity(_score),
                confidence=_conf,
                location="strings",
            ))

    for _fn, _base_score in DANGEROUS_FUNCTIONS["kernel"].items():
        _in_strs = _search_in_strings(_strs, re.escape(_fn))
        if _in_strs:
            _conf = 0.8
            _score = int(_base_score * 10 * _conf)
            _findings.append(Finding(
                type="dangerous_function",
                description=f"Kernel dangerous function: {_fn}",
                severity=_score_to_severity(_score),
                confidence=_conf,
                location="strings",
            ))

    _high_entropy = _search_in_strings(_strs, r'(?:encrypt|decrypt|crypt|aes|rsa|des|blowfish|chacha|rc4)')
    if len(_high_entropy) >= 3:
        _findings.append(Finding(
            type="crypto_detected",
            description=f"Cryptographic strings detected ({len(_high_entropy)} matches)",
            severity=Severity.MEDIUM,
            confidence=0.6,
            location="strings",
        ))

    _anti_patterns = _search_in_strings(_strs,
        r'(?:VMware|VirtualBox|vbox|qemu|xen|sandboxie|'
        r'isDebugger|isDebug|is_vm|cpuid|rdtsc|'
        r'ollydbg|ida\s*pro|x64dbg|windbg|procmon)'
    )
    if _anti_patterns:
        _findings.append(Finding(
            type="anti_analysis",
            description=f"Anti-analysis strings detected: {_anti_patterns[:3]}",
            severity=Severity.HIGH,
            confidence=0.65,
            location="strings",
        ))

    return _findings


def dedup_findings(findings: List[Finding]) -> List[Finding]:
    """按 (type, normalized_desc) 去重，相同描述取置信度最高项。
    归一化策略：引号/括号内容替换为占位符，抹除变量特异性。
    """
    if not findings:
        return []
    _result: List[Finding] = []
    _seen_keys = set()

    def _normalize(desc: str) -> str:
        _s = desc.lower()
        _s = re.sub(r'"[^"]*"', '"..."', _s)
        _s = re.sub(r"'[^']*'", "'...'", _s)
        _s = re.sub(r'from\s+\S+', 'from ...', _s)
        return _s

    for _f in sorted(findings, key=lambda x: _SEVERITY_WEIGHT.get(x.severity, 0), reverse=True):
        _key = (_f.type, _normalize(_f.description))
        if _key not in _seen_keys:
            _seen_keys.add(_key)
            _result.append(_f)

    return _result
