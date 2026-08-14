# 过程内稀疏常量传播 — 区分 printf(const) 与 printf(variable)。
# format_string_detector 的正则把所有 printf(user_var) 标记为漏洞 (含安全的 printf("hello"));
# 在反编译代码的 SSA 形式上做格传播 (top/const/bottom), printf 首参数 meet 后为 const 即安全。

from typing import Dict, Optional, Set, Tuple
from enum import Enum

class LatticeValue(Enum):
    TOP = 1       # 未知
    CONSTANT = 2  # 确定常量
    BOTTOM = 3    # 非常量（多路径冲突）

class ConstPropagator:
    def __init__(self):
        self._values: Dict[str, Tuple[LatticeValue, Optional[str]]] = {}

    def set_constant(self, var: str, value: str):
        self._values[var] = (LatticeValue.CONSTANT, value)

    def set_bottom(self, var: str):
        self._values[var] = (LatticeValue.BOTTOM, None)

    def meet(self, var: str, new_val: Tuple[LatticeValue, Optional[str]]):
        if var not in self._values:
            self._values[var] = new_val
            return
        old = self._values[var]
        if old[0] == LatticeValue.TOP:
            self._values[var] = new_val
        elif new_val[0] == LatticeValue.TOP:
            pass
        elif old[0] == LatticeValue.CONSTANT and new_val[0] == LatticeValue.CONSTANT:
            if old[1] != new_val[1]:
                self._values[var] = (LatticeValue.BOTTOM, None)
        else:
            self._values[var] = (LatticeValue.BOTTOM, None)

    def is_constant(self, var: str) -> Optional[str]:
        v = self._values.get(var)
        if v and v[0] == LatticeValue.CONSTANT:
            return v[1]
        return None

def propagate_constants(decompiled_code: str, target_func: str) -> ConstPropagator:
    cp = ConstPropagator()
    import re
    lines = decompiled_code.splitlines()
    in_func = False
    for line in lines:
        if target_func in line and '{' in line:
            in_func = True; continue
        if in_func and '}' in line and line.strip() == '}':
            break
        if not in_func: continue
        m = re.match(r'\s*(\w+)\s*=\s*"([^"]*)"\s*;', line)
        if m: cp.set_constant(m.group(1), m.group(2)); continue
        m = re.match(r'\s*(\w+)\s*=\s*(\w+)\s*;', line)
        if m:
            src = m.group(2)
            if cp.is_constant(src) is not None:
                cp.set_constant(m.group(1), cp.is_constant(src))
            continue
    return cp

def is_format_arg_constant(decompiled_code: str, func_name: str,
                           call_line: str) -> bool:
    cp = propagate_constants(decompiled_code, func_name)
    import re
    m = re.match(r'.*(printf|fprintf|sprintf|snprintf)\s*\(\s*(\w+)', call_line)
    if m:
        arg_var = m.group(2)
        return cp.is_constant(arg_var) is not None
    return False


class SparseConstantPropagation:
    """稀疏常量传播 — 判定反编译代码中变量是否为编译期常量。

    包装 ConstPropagator, 对外提供变量格值查询, 供误报过滤器
    判断危险调用的参数是否来自常量字符串。
    """

    def __init__(self):
        self._propagator = ConstPropagator()

    def set_constant(self, var: str, value: str) -> None:
        self._propagator.set_constant(var, value)

    def set_bottom(self, var: str) -> None:
        self._propagator.set_bottom(var)

    def meet(self, var: str, value) -> None:
        self._propagator.meet(var, value)

    def is_constant(self, var: str):
        """返回变量的常量值; 非常量或未知返回 None。"""
        return self._propagator.is_constant(var)

    def analyze(self, ir, func_name: str = ''):
        """从 IR 行收集常量赋值。

        识别两种赋值: var = "const" 与 var = other_var(常量传递)。
        返回 self 供链式调用。
        """
        import re as _re
        propagator = ConstPropagator()
        for line in (ir or []):
            m = _re.match(r'\s*(\w+)\s*=\s*"([^"]*)"\s*;?', line)
            if m:
                propagator.set_constant(m.group(1), m.group(2))
                continue
            m = _re.match(r'\s*(\w+)\s*=\s*(\w+)\s*;?', line)
            if m:
                src_val = propagator.is_constant(m.group(2))
                if src_val is not None:
                    propagator.set_constant(m.group(1), src_val)
        self._propagator = propagator
        return self
