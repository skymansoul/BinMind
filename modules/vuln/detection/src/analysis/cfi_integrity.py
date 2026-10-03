# — CFI完整性分析器
# 检测clang CFI/kCFI/Spectre CFI/MSVC CFG控制流完整性保护机制

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
import os

from deemo.modules.vuln.detection.src.logger import get_logger

_log = get_logger("vuln_detection.cfi_integrity")


@dataclass
class CFIResult:
    binary_path: str = ""
    cfi_type: str = "none"
    is_enabled: bool = False
    coverage: float = 0.0
    protected_functions: int = 0
    total_functions: int = 0
    details: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if not self.is_enabled:
            return "unprotected"
        if self.coverage >= 0.9:
            return "fully_protected"
        if self.coverage >= 0.5:
            return "partially_protected"
        return "minimally_protected"


CFI_TYPES = {
    "clang_cfi": {"pattern": b"__cfi_check", "desc": "Clang Forward-Edge CFI"},
    "clang_cfi_cross_dso": {"pattern": b"__cfi_check_fail", "desc": "Clang CFI cross-DSO"},
    "msvc_cfg": {"pattern": b"___guard_check_icall", "desc": "MSVC Control Flow Guard"},
    "msvc_cet": {"pattern": b"__cet_proc", "desc": "MSVC CET Shadow Stack"},
    "gcc_vtv": {"pattern": b"_ZTV", "desc": "GCC Vtable Verification"},
    "android_kcfi": {"pattern": b"kcfi_check", "desc": "Android kCFI"},
    "spectre_retpoline": {"pattern": b"__x86_indirect_thunk", "desc": "Spectre Retpoline"},
    "pauth": {"pattern": b"__ptrauth", "desc": "ARM Pointer Authentication"},
    "bti": {"pattern": b"hint #3", "desc": "ARM Branch Target Identification"},
}


class CFIIntegrityAnalyzer:
    """控制流完整性保护检测。
    检测编译器注入的CFI运行时桩代码，覆盖clang CFI/kCFI/
    MSVC CFG-CET/ARM PA-BTI方案。
    基于符号存在性与函数覆盖率判定保护强度。
    """

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self._patterns_found: Dict[str, bool] = {}
        self._function_count: int = 0

    def analyze(self) -> CFIResult:
        result = CFIResult(binary_path=self.binary_path)

        if not self.binary_path or not os.path.isfile(self.binary_path):
            result.details["error"] = "binary not found"
            return result

        try:
            with open(self.binary_path, "rb") as f:
                data = f.read(16 * 1024 * 1024)
        except Exception:
            result.details["error"] = "read failed"
            return result

        for cfi_type, info in CFI_TYPES.items():
            found = info["pattern"] in data
            self._patterns_found[cfi_type] = found
            result.details[cfi_type] = {"detected": found, "description": info["desc"]}

        self._detect_cfi_type(result)
        self._estimate_coverage(data, result)
        self._check_warnings(result)

        _log.info("CFI analysis complete: %s -> %s (coverage=%.1f%%)",
                  self.binary_path, result.cfi_type, result.coverage * 100)
        return result

    def _detect_cfi_type(self, result: CFIResult) -> None:
        priority = [
            ("clang_cfi_cross_dso", "clang_cfi_cross_dso"),
            ("clang_cfi", "clang_cfi"),
            ("android_kcfi", "android_kcfi"),
            ("msvc_cfg", "msvc_cfg"),
            ("msvc_cet", "msvc_cet"),
            ("gcc_vtv", "gcc_vtv"),
            ("spectre_retpoline", "spectre_retpoline"),
            ("pauth", "pauth"),
            ("bti", "bti"),
        ]
        for name, display in priority:
            if self._patterns_found.get(name):
                result.cfi_type = display
                result.is_enabled = True
                break
        if not result.is_enabled:
            result.cfi_type = "none"

    def _estimate_coverage(self, data: bytes, result: CFIResult) -> None:
        import re
        try:
            text = data.decode("ascii", errors="replace")
            funcs = set(re.findall(r'_Z\w+', text))
            result.total_functions = len(funcs) if funcs else 1

            if result.cfi_type == "clang_cfi":
                protected = len(re.findall(rb'__cfi_check', data))
                result.protected_functions = min(protected * 10, result.total_functions)
            elif result.cfi_type in ("msvc_cfg", "msvc_cet"):
                protected = data.count(b"\xff\x15")  # 间接调用thunk
                result.protected_functions = min(protected, result.total_functions)
            elif result.cfi_type == "spectre_retpoline":
                result.protected_functions = result.total_functions
            else:
                result.protected_functions = 0

            result.coverage = (result.protected_functions / result.total_functions
                               if result.total_functions > 0 else 0.0)
        except Exception:
            result.coverage = 0.0

    def _check_warnings(self, result: CFIResult) -> None:
        if result.is_enabled:
            if result.coverage < 0.5:
                result.warnings.append(
                    "low CFI coverage (<50%): many indirect calls unprotected")
            if result.cfi_type == "msvc_cfg" and not self._patterns_found.get("msvc_cet"):
                result.warnings.append(
                    "MSVC CFG without CET: backward-edge not protected")
            if result.cfi_type == "clang_cfi" and not self._patterns_found.get("clang_cfi_cross_dso"):
                result.warnings.append(
                    "clang CFI without cross-DSO support: shared library calls unprotected")
        else:
            result.warnings.append("no CFI protection detected")


def cfi_check(binary_path: str) -> CFIResult:
    """快速CFI检测快捷入口。"""
    analyzer = CFIIntegrityAnalyzer(binary_path)
    return analyzer.analyze()
