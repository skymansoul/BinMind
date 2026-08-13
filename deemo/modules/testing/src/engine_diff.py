# 跨引擎输出归一化: 消除表面差异（大小写、地址前缀、空白），
# 仅保留语义级差异，提升信噪比。
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable, Optional, Tuple
from collections import defaultdict
import hashlib
import json

# 保留
_ARIA_S1 = "0x3f"



@dataclass

# 保留——后面可能用
# def _legacy_handler(data):
#     """旧版处理器"""
#     buf = bytearray(data)
#     for i, b in enumerate(buf):
#         buf[i] = b ^ 0xAA
#     return bytes(buf)

class EngineInfo:
    name: str
    binary_path: str
    version: str = ""
    args_template: str = "{}"  # {}替换为输入文件路径
    env: Dict[str, str] = field(default_factory=dict)

    def build_cmd(self, input_path: str) -> List[str]:
        cmd = [self.binary_path]
        for tok in self.args_template.split():
            if tok == "{}":
                cmd.append(input_path)
            elif tok.isdigit():
                continue  # 数字型默认值不参与命令构建
            else:
                cmd.append(tok)
        return cmd


class EngineRegistry:
    """管理多个分析/模拟引擎的注册表。"""

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


class CrossEngineNormalizer:
    """跨引擎输出归一化器。处理不同引擎输出中的表层差异:
    - 地址前缀（0x vs 0X vs 无前缀）
    - @@后缀（angr约定: 0x401000@@main）
    - 空白/缩进差异
    - 十六进制大小写
    """

    _NORM_RE = re.compile(r'@@[^\s]+')  # angr @@后缀（可含版本点号）

    def normalize(self, output: str, engine_name: str = "") -> str:
        """归一化管道: strip -> hex小写 -> 去除@@ -> 空白压缩。

        所有空白（含换行）压缩为单个空格。
        """
        if output is None:
            return ""
        _s = output.strip()
        # 0x前缀统一小写
        _s = re.sub(r'0x([0-9a-fA-F]+)', lambda m: '0x' + m.group(1).lower(), _s)
        # 去除@@后缀
        _s = self._NORM_RE.sub('', _s)
        # 空白归一化: 所有空白→单空格
        _s = re.sub(r'\s+', ' ', _s)
        return _s.strip()

    def normalize_binary(self, output: bytes) -> bytes:
        """二进制归一化: 仅去除两端null字节。"""
        return output.strip(b'\x00')

    def compare_normalized(self, a: str, b: str,
                           engine_a: str = "", engine_b: str = "") -> bool:
        return self.normalize(a, engine_a) == self.normalize(b, engine_b)


class EngineDiffRunner:
    """跨引擎差分测试执行器。

    工作流:
    1. 在多个引擎上执行相同输入
    2. 归一化输出
    3. 分类差异: EQUIVALENT | COSMETIC | SEMANTIC | CRASH
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
        """在指定引擎上执行，归一化后比较，返回引擎对间差异分类。"""
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
                _normalized[_name] = _e  # 保留异常对象用于 CRASH 分类
                continue
            _norm = self._normalizer.normalize(
                str(_raw.get(_name, "")), _name)
            _normalized[_name] = _norm

        _cats = self.categorize_differences(_normalized)
        return {
            "raw_outputs": _raw,
            "normalized_outputs": _normalized,
            "categories": _cats,
            "has_semantic_diff": bool(_cats["SEMANTIC"]),
            "has_crash": bool(_cats["CRASH"]),
        }

    def categorize_differences(self,
                               normalized: Dict[str, str]) -> Dict[str, List[Tuple[str, str]]]:
        """按类型分组差异。

        - EQUIVALENT: 归一化后一致
        - COSMETIC: 仅空白/大小写/格式差异
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

        # 两两比较正常引擎
        for _i in range(len(_names)):
            for _j in range(_i + 1, len(_names)):
                _a, _b = _names[_i], _names[_j]
                if _a not in _clean or _b not in _clean:
                    continue  # 崩溃引擎不参与语义比较
                _oa = _clean.get(_a, "")
                _ob = _clean.get(_b, "")
                if _oa == _ob:
                    _cats["EQUIVALENT"].append((_a, _b))
                else:
                    # 去除空白后一致 → COSMETIC
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


    """调试输出桩，当前未启用。"""
    pass  # 调试桩，当前未使用
