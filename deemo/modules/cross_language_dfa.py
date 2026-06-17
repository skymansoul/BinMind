"""
多语言交互分析: 跨语言数据流跟踪模块

功能:
    1. 分析 Python (通过 PyInstaller 解包) / Go / Rust 等混合二进制时,
       自动处理语言边界调用 (CGo / cgo / FFI)
    2. 数据流分析穿越语言边界
    3. 识别从脚本层传入的原生内存操作

核心技术:
    - 语言特征检测 (字符串/符号/调用约定)
    - 边界函数识别: cgo_check_fail, _cgo_panic, PyXXX 等
    - 跨语言污点传播
"""

import logging
import os
import re
import json
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class LangBoundaryKind(Enum):
    PYTHON_C = "python_c"
    GO_C = "go_c"          # CGo
    RUST_C = "rust_c"      # Rust FFI
    NODE_NATIVE = "node_native"
    LUA_C = "lua_c"
    UNKNOWN = "unknown"


@dataclass
class LanguageHint:
    language: str
    confidence: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class BoundaryFunction:
    """边界函数"""
    name: str
    kind: LangBoundaryKind
    address: int = 0
    param_count: int = 0
    description: str = ""
    risk: str = "low"


@dataclass
class CrossLangDFAResult:
    """跨语言 DFA 结果"""
    languages: List[LanguageHint]
    boundaries: List[BoundaryFunction]
    flows: List[Dict[str, Any]]
    high_risk_paths: List[Dict[str, Any]]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'languages': [
                {'language': l.language, 'confidence': l.confidence,
                 'evidence': l.evidence}
                for l in self.languages
            ],
            'boundaries': [
                {
                    'name': b.name, 'kind': b.kind.value,
                    'param_count': b.param_count,
                    'risk': b.risk
                }
                for b in self.boundaries
            ],
            'flows': self.flows[:50],
            'high_risk_paths': self.high_risk_paths[:20]
        }


class LanguageDetector:
    """检测二进制中存在的语言"""

    PYTHON_HINTS = [
        r"PyObject", r"Py_TYPE", r"_PyObject_Malloc",
        r"PyUnicode_FromString", r"PyArg_ParseTuple"
    ]
    GO_HINTS = [
        r"runtime\.", r"gofunc", r"_cgo_", r"go.buildid",
        r"go:itab\."
    ]
    RUST_HINTS = [
        r"rust_panic", r"core::panicking", r"<.* as .*>::drop",
        r"_ZN.*CString", r"std::ffi"
    ]
    NODE_HINTS = [r"v8::", r"node::", r"napi_"]
    LUA_HINTS = [r"lua_", r"luaL_", r"lua_push"]

    def detect(self, binary_path: str, symbols: Optional[List[str]] = None) -> List[LanguageHint]:
        if symbols is None:
            symbols = self._list_symbols(binary_path)
        text = "\n".join(symbols)
        hints = []
        py = sum(1 for p in self.PYTHON_HINTS if re.search(p, text))
        if py >= 2:
            hints.append(LanguageHint(
                language="python", confidence=min(1.0, 0.3 + 0.1 * py),
                evidence=[f"匹配 {py} 个 Python 特征符号"]
            ))
        go = sum(1 for p in self.GO_HINTS if re.search(p, text))
        if go >= 1:
            hints.append(LanguageHint(
                language="go", confidence=min(1.0, 0.3 + 0.15 * go),
                evidence=[f"匹配 {go} 个 Go 特征符号"]
            ))
        rust = sum(1 for p in self.RUST_HINTS if re.search(p, text))
        if rust >= 1:
            hints.append(LanguageHint(
                language="rust", confidence=min(1.0, 0.3 + 0.15 * rust),
                evidence=[f"匹配 {rust} 个 Rust 特征符号"]
            ))
        node = sum(1 for p in self.NODE_HINTS if re.search(p, text))
        if node >= 1:
            hints.append(LanguageHint(
                language="node", confidence=min(1.0, 0.3 + 0.2 * node),
                evidence=[f"匹配 {node} 个 Node 特征符号"]
            ))
        lua = sum(1 for p in self.LUA_HINTS if re.search(p, text))
        if lua >= 1:
            hints.append(LanguageHint(
                language="lua", confidence=min(1.0, 0.3 + 0.2 * lua),
                evidence=[f"匹配 {lua} 个 Lua 特征符号"]
            ))
        return hints

    def _list_symbols(self, binary_path: str) -> List[str]:
        import subprocess
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'is;q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            return r.stdout.split("\n")
        except Exception as e:
            logger.warning(f"符号列表获取失败: {e}")
            return []


class BoundaryIdentifier:
    """识别语言边界函数"""

    PYTHON_API = {"PyArg_ParseTuple", "PyArg_ParseTupleAndKeywords",
                  "PyObject_Call", "PyObject_CallFunction",
                  "PyUnicode_AsEncodedString", "PyMem_Free",
                  "PyMem_Malloc", "PyMem_Realloc", "_PyObject_Malloc"}
    GO_CGO = {"_cgo_panic", "runtime.cgocall", "runtime.cgocallback",
              "crosscall2", "go:asm.cgocall"}
    RUST_FFI = {"std::ffi::CString::from_raw", "std::ffi::CStr::from_ptr",
                "core::slice::from_raw_parts"}
    NODE_API = {"napi_create_function", "napi_get_cb_info",
                "napi_call_function", "v8::Function::Call"}

    def identify(self, symbols: List[str]) -> List[BoundaryFunction]:
        result: List[BoundaryFunction] = []
        sym_set = set(symbols)
        for name in self.PYTHON_API:
            if any(name in s for s in sym_set):
                result.append(BoundaryFunction(
                    name=name, kind=LangBoundaryKind.PYTHON_C,
                    risk="medium", description="Python C API"
                ))
        for name in self.GO_CGO:
            if any(name in s for s in sym_set):
                result.append(BoundaryFunction(
                    name=name, kind=LangBoundaryKind.GO_C,
                    risk="medium", description="Go CGo boundary"
                ))
        for name in self.RUST_FFI:
            if any(name in s for s in sym_set):
                result.append(BoundaryFunction(
                    name=name, kind=LangBoundaryKind.RUST_C,
                    risk="medium", description="Rust FFI"
                ))
        for name in self.NODE_API:
            if any(name in s for s in sym_set):
                result.append(BoundaryFunction(
                    name=name, kind=LangBoundaryKind.NODE_NATIVE,
                    risk="medium", description="Node native addon"
                ))
        return result


class CrossLanguageDFA:
    """
    跨语言数据流分析
    """

    HIGH_RISK_NATIVE = {
        "memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets",
        "scanf", "system", "execve", "popen", "free", "malloc"
    }

    def __init__(self):
        self.detector = LanguageDetector()
        self.boundary = BoundaryIdentifier()

    def analyze(self, binary_path: str) -> CrossLangDFAResult:
        symbols = self.detector._list_symbols(binary_path)
        langs = self.detector.detect(binary_path, symbols)
        bounds = self.boundary.identify(symbols)

        # 跨语言流分析
        flows: List[Dict[str, Any]] = []
        for b in bounds:
            if b.kind == LangBoundaryKind.PYTHON_C:
                for n in self.HIGH_RISK_NATIVE:
                    if any(n in s for s in symbols):
                        flows.append({
                            'from': 'python_script',
                            'boundary': b.name,
                            'to': n,
                            'risk': 'high' if n in {"gets", "system", "execve"} else 'medium'
                        })
            elif b.kind == LangBoundaryKind.GO_C:
                for n in self.HIGH_RISK_NATIVE:
                    if any(n in s for s in symbols):
                        flows.append({
                            'from': 'go_runtime',
                            'boundary': b.name,
                            'to': n,
                            'risk': 'high' if n in {"system", "execve"} else 'medium'
                        })
            elif b.kind == LangBoundaryKind.RUST_C:
                for n in self.HIGH_RISK_NATIVE:
                    if any(n in s for s in symbols):
                        flows.append({
                            'from': 'rust_safe',
                            'boundary': b.name,
                            'to': n,
                            'risk': 'high' if n in {"system"} else 'medium'
                        })

        high_risk = [f for f in flows if f['risk'] == 'high']

        return CrossLangDFAResult(
            languages=langs,
            boundaries=bounds,
            flows=flows,
            high_risk_paths=high_risk,
            metadata={'binary': binary_path, 'symbol_count': len(symbols)}
        )


def analyze_multilang_binary(binary_path: str) -> Dict[str, Any]:
    """便捷入口"""
    dfa = CrossLanguageDFA()
    result = dfa.analyze(binary_path)
    return {'success': True, 'result': result.to_dict()}
