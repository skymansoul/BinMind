# 2026-07-23
# Multi-engine differential testing — 引擎注册 + 归一化 + 差异分类
# 归一化策略：消除引擎输出的无关差异（大小写、地址前缀、空白），
# 只保留语义级别差异 → 减少误报，提高 signal-to-noise ratio。
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional, Tuple
from collections import defaultdict
import hashlib
import json


@dataclass
class EngineInfo:
    name: str
    binary_path: str
    version: str = ""
    args_template: str = "{}"  # {} replaced by input file path
    env: Dict[str, str] = field(default_factory=dict)

    def build_cmd(self, input_path: str) -> List[str]:
        return [self.binary_path] + self.args_template.replace("{}", input_path).split()


# ================================================
class EngineRegistry:
    """管理多个分析/模拟引擎。"""

    def __init__(self):
        self._engines: Dict[str, EngineInfo] = {}

    def register(self, name: str, binary_path: str,
                 args_template: str = "{}", version: str = "",
                 env: Dict[str, str] = None):
        self._engines[name] = EngineInfo(
            name=name, binary_path=binary_path,
            args_template=args_template, version=version,
            env=env or {},
        )

    def get_engine(self, name: str) -> Optional[EngineInfo]:
        return self._engines.get(name)

    def list_engines(self) -> List[EngineInfo]:
        return list(self._engines.values())

    def engine_names(self) -> List[str]:
        return list(self._engines.keys())

    def count(self) -> int:
        return len(self._engines)


# ================================================
class CrossEngineNormalizer:
    """跨引擎输出归一化器。处理不同引擎输出中的表面差异：
    - 地址前缀（0x vs 0X vs 不带前缀）
    - @@suffix (angr 惯例：0x401000@@main)
    - 空白/缩进差异
    - hex 大小写
    """

    _NORM_RE = re.compile(r'@@[a-zA-Z0-9_]+')  # angr @@ suffix

    def normalize(self, output: str, engine_name: str = "") -> str:
        """一路归一化：strip → hex 小写 → 去掉 @@ → 空白压缩。
        保留分号/换行作为结构化分隔符。"""
        if output is None:
            return ""
        _s = output.strip()
        # 0x 前缀统一小写
        _s = re.sub(r'0x([0-9a-fA-F]+)', lambda m: '0x' + m.group(1).lower(), _s)
        # 去掉 @@suffix
        _s = self._NORM_RE.sub('', _s)
        # 空白归一化：多空白→单空白
        _s = re.sub(r'[ \t]+', ' ', _s)
        # 保留换行但去掉尾部空白
        _s = re.sub(r' +\n', '\n', _s)
        # 多个空行→单个
        _s = re.sub(r'\n{3,}', '\n\n', _s)
        return _s.strip()

    def normalize_binary(self, output: bytes) -> bytes:
        """二进制的归一化：仅 strip null bytes at both ends。"""
        return output.strip(b'\x00')

    def compare_normalized(self, a: str, b: str,
                           engine_a: str = "", engine_b: str = "") -> bool:
        return self.normalize(a, engine_a) == self.normalize(b, engine_b)


# ================================================
class EngineDiffRunner:
    """跨引擎差分测试执行器。

    工作流：
    1. 在多个引擎上执行相同输入
    2. 归一化输出
    3. 分类差异为：EQUIVALENT | COSMETIC | SEMANTIC | CRASH
    """

    def __init__(self, registry: EngineRegistry = None):
        self._registry = registry or EngineRegistry()
        self._normalizer = CrossEngineNormalizer()
        self._executors: Dict[str, Callable] = {}

    def register_executor(self, engine_name: str,
                          executor: Callable[[bytes], Any]):
        self._executors[engine_name] = executor

    def run_diff(self, test_input: bytes,
                 engine_names: List[str] = None) -> Dict[str, Any]:
        """在指定引擎上运行，归一化输出后比较。
        返回每对引擎间的差异分类。
        """
        _names = engine_names or list(self._executors.keys())
        _raw = {}
        _normalized = {}

        for _name in _names:
            _exec = self._executors.get(_name)
            if _exec is None:
                _raw[_name] = None
                continue
            try:
                _raw[_name] = _exec(test_input)
            except Exception as _e:
                _raw[_name] = _e
            _norm = self._normalizer.normalize(
                str(_raw.get(_name, "")), _name)
            _normalized[_name] = _norm

        _cats = self.categorize_differences(_normalized)
        return {
            "raw_outputs": _raw,
            "normalized_outputs": _normalized,
            "categories": _cats,
            "has_semantic_diff": "SEMANTIC" in _cats,
            "has_crash": "CRASH" in _cats,
        }

    def categorize_differences(self,
                               normalized: Dict[str, str]) -> Dict[str, List[Tuple[str, str]]]:
        """将差异按类型分组。
        - EQUIVALENT: 归一化后一致
        - COSMETIC: 只有空白/大小写/格式差异
        - SEMANTIC: 内容层面不同
        - CRASH: 引擎输出异常
        """
        _cats = {"EQUIVALENT": [], "COSMETIC": [], "SEMANTIC": [], "CRASH": []}
        _names = list(normalized.keys())

        # 分离崩溃的引擎
        _clean = {}
        for _n, _o in normalized.items():
            if _o is None or isinstance(_o, Exception) or "CRASH" in str(_o).upper():
                _cats["CRASH"].append((_n, _n))
            else:
                _clean[_n] = _o

        # 比较干净引擎两两之间
        for _i in range(len(_names)):
            for _j in range(_i + 1, len(_names)):
                _a, _b = _names[_i], _names[_j]
                _oa = _clean.get(_a, "")
                _ob = _clean.get(_b, "")
                if _oa == _ob:
                    _cats["EQUIVALENT"].append((_a, _b))
                else:
                    # 去掉空白后如果一致 = COSMETIC
                    _oa_comp = re.sub(r'\s+', '', _oa)
                    _ob_comp = re.sub(r'\s+', '', _ob)
                    if _oa_comp == _ob_comp:
                        _cats["COSMETIC"].append((_a, _b))
                    else:
                        _cats["SEMANTIC"].append((_a, _b))
        return _cats

    def hash_output(self, output: str) -> str:
        return hashlib.sha256(
            self._normalizer.normalize(output).encode()
        ).hexdigest()[:16]
