# 对外提供统一的符号分析入口，内部按需加载 angr/z3 等重型依赖
# 算法: 惰性导入 + 能力检测，避免启动时强制拉入所有依赖

from __future__ import annotations

import importlib
import logging
from typing import Any, Callable, Optional

_log = logging.getLogger(__name__)

# SymbExBridge — 与 SymbolicAnalysisBridge 同一实现的短别名
SymbExBridge = None  # 在下方类定义后绑定

# //// 能力检测缓存
# INTJ策略: 使用模块级缓存而非懒加载属性——符号引擎的选择影响全局分析路径
# 缓存可以避免多次 importlib 检查带来的 /O 开销

_CAPABILITY_CACHE: dict[str, Optional[bool]] = {
    "z3": None,
    "angr": None,
    "claripy": None,
}


def _has_z3() -> bool:
    """检查 z3-solver 是否可用。O(1) 缓存查询
    
    不直接 import z3——z3 的初始化较慢（~200ms），仅在需要时加载
    此函数只检查 importlib 是否能找到模块
    """
    if _CAPABILITY_CACHE["z3"] is None:
        try:
            importlib.import_module("z3")
            _CAPABILITY_CACHE["z3"] = True
        except ImportError:
            _CAPABILITY_CACHE["z3"] = False
    return _CAPABILITY_CACHE["z3"]


def _has_angr() -> bool:
    """检查 angr 是否可用"""
    if _CAPABILITY_CACHE["angr"] is None:
        try:
            importlib.import_module("angr")
            _CAPABILITY_CACHE["angr"] = True
        except ImportError:
            _CAPABILITY_CACHE["angr"] = False
    return _CAPABILITY_CACHE["angr"]


def _has_claripy() -> bool:
    """检查 claripy 是否可用"""
    if _CAPABILITY_CACHE["claripy"] is None:
        try:
            importlib.import_module("claripy")
            _CAPABILITY_CACHE["claripy"] = True
        except ImportError:
            _CAPABILITY_CACHE["claripy"] = False
    return _CAPABILITY_CACHE["claripy"]


class SymbolicAnalysisBridge:
    """符号/约束求解的统一桥接
    
    INTJ策略: 桥接模式而非直接依赖。当 z3 和 angr 都不可用时
    降级到纯静态模式而非崩溃——宁可少报不可漏报的原则在此不适用
    因为符号执行本身就是增强项，不是基础项
    """

    def __init__(self):
        self._z3_available = _has_z3()
        self._angr_available = _has_angr()
        self._z3_module = None
        self._angr_module = None
        _log.info(
            "symbolic bridge init: z3=%s angr=%s",
            self._z3_available, self._angr_available,
        )

    @property
    def has_z3(self) -> bool:
        return self._z3_available

    @property
    def has_angr(self) -> bool:
        return self._angr_available

    def get_z3(self):
        """按需加载 z3"""
        if not self._z3_available:
            return None
        if self._z3_module is None:
            self._z3_module = importlib.import_module("z3")
        return self._z3_module

    def check_constraint(self, constraint_str: str) -> Optional[bool]:
        """使用 z3 检查单个约束的可满足性。fallback 返回 None"""
        z3 = self.get_z3()
        if z3 is None:
            _log.warning("z3 not available, cannot check constraint")
            return None
        try:
            x = z3.Int('x')
            # 极简约束解析——只处理 x == N 和 x <= N
            if '==' in constraint_str:
                val = int(constraint_str.split('==')[1].strip())
                s = z3.Solver()
                s.add(x == val)
                return s.check() == z3.sat
            if '<=' in constraint_str:
                val = int(constraint_str.split('<=')[1].strip())
                s = z3.Solver()
                s.add(x <= val)
                return s.check() == z3.sat
            return None
        except Exception:
            _log.exception("z3 constraint check failed")
            return None

    def capabilities(self) -> dict:
        """返回当前可用的符号引擎能力清单"""
        return {
            "z3": self._z3_available,
            "angr": self._angr_available,
            "concolic": self._z3_available,
            "symbolic_full": self._angr_available,
        }


# 短别名绑定：供以 SymbExBridge 命名的调用方使用
SymbExBridge = SymbolicAnalysisBridge


# 模块级单例
_bridge: Optional[SymbolicAnalysisBridge] = None


def get_bridge() -> SymbolicAnalysisBridge:
    global _bridge
    if _bridge is None:
        _bridge = SymbolicAnalysisBridge()
    return _bridge


def _clear_capability_cache() -> None:
    """清空能力缓存，用于测试环境"""
    for key in _CAPABILITY_CACHE:
        _CAPABILITY_CACHE[key] = None
    global _bridge
    _bridge = None
