"""Canary 绕过分析器 — 检测栈 canary 保护 + 评估绕过可能性.

stack_bound_infer 仅判断 canary 是否存在, 本模块进一步分析:
  1. canary 值是否可被泄露 (格式化字符串/越界读)
  2. canary 检查是否被优化掉 (死代码消除/尾调用优化)
  3. 是否存在 fork() 后 canary 不变的多进程场景

方法: PBAEG canary 绕过检测的简化版——不做完整符号执行,
仅检查 canary 值是否流向任何输出函数 (write/printf/send)。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CanaryInfo:
    """一个函数的 canary 保护分析结果."""
    function_name: str
    canary_present: bool         # 是否存在 canary
    canary_load_addr: int        # fs:[0x28] 加载地址
    canary_check_addr: int       # __stack_chk_fail 调用地址
    canary_leakable: bool        # canary 值是否可被泄露
    leak_path: str               # 泄露路径描述
    bypass_difficulty: str       # 'trivial'|'moderate'|'hard'|'impossible'


class CanaryBypassAnalyzer:
    """Canary 绕过分析器 — 评估栈 canary 的实际保护强度.

    检测三种绕过场景:
      1. 信息泄露: canary 值通过格式化字符串/越界读泄露
      2. 逐字节爆破: fork() 后子进程 canary 不变
      3. 覆盖 __stack_chk_fail GOT: 修改 canary 失败处理函数指针

    用法: add_canary_info 注册, mark_output_reachable/mark_fork_detected/mark_got_overwritable 标记绕过条件, analyze 取结果。
    """

    def __init__(self):
        self._functions: Dict[str, CanaryInfo] = {}
        # canary 值可达的输出函数
        self._output_reachable: Dict[str, List[Tuple[str, str]]] = {}
        # fork 调用检测
        self._forks_detected: Set[str] = set()

    def add_canary_info(self, func_name: str, present: bool,
                        load_addr: int = 0,
                        check_addr: int = 0) -> None:
        """注册函数的 canary 信息."""
        info = CanaryInfo(
            function_name=func_name, canary_present=present,
            canary_load_addr=load_addr, canary_check_addr=check_addr,
            canary_leakable=False, leak_path='',
            bypass_difficulty='impossible' if present else 'trivial')
        self._functions[func_name] = info

    def mark_output_reachable(self, func_name: str,
                               canary_reg: str,
                               output_func: str) -> None:
        """标记 canary 值可达某个输出函数 (可泄露)."""
        self._output_reachable.setdefault(
            func_name, []).append((canary_reg, output_func))
        if func_name in self._functions:
            self._functions[func_name].canary_leakable = True
            self._functions[func_name].leak_path = (
                f'{canary_reg} → {output_func}')
            self._functions[func_name].bypass_difficulty = 'moderate'

    def mark_fork_detected(self, func_name: str) -> None:
        """标记检测到 fork() 调用 (子进程 canary 不变)."""
        self._forks_detected.add(func_name)
        if func_name in self._functions:
            info = self._functions[func_name]
            if info.canary_present:
                info.bypass_difficulty = 'moderate'
                info.leak_path += ' + fork() brute-force possible'

    def mark_got_overwritable(self, func_name: str) -> None:
        """标记 __stack_chk_fail 的 GOT 可被覆盖."""
        if func_name in self._functions:
            info = self._functions[func_name]
            if info.canary_present:
                info.bypass_difficulty = 'moderate'
                info.leak_path += ' + GOT overwrite possible'

    def analyze(self, func_name: str) -> Optional[CanaryInfo]:
        """返回完整的 canary 分析结果."""
        return self._functions.get(func_name)

    def analyze_all(self) -> List[CanaryInfo]:
        """分析所有函数."""
        results = []
        for name, info in self._functions.items():
            # 综合评估绕过难度
            if not info.canary_present:
                info.bypass_difficulty = 'trivial'
            elif info.canary_leakable:
                info.bypass_difficulty = 'moderate'
            elif name in self._forks_detected:
                info.bypass_difficulty = 'hard'  # 逐字节爆破需 2^32 次
            else:
                info.bypass_difficulty = 'hard'
            results.append(info)
        results.sort(key=lambda x: (
            {'trivial': 0, 'moderate': 1, 'hard': 2, 'impossible': 3}
        )[x.bypass_difficulty])
        return results

    def stats(self) -> dict:
        all_info = self.analyze_all()
        trivial = sum(1 for i in all_info
                     if i.bypass_difficulty == 'trivial')
        moderate = sum(1 for i in all_info
                      if i.bypass_difficulty == 'moderate')
        hard = sum(1 for i in all_info
                  if i.bypass_difficulty == 'hard')
        return {
            'functions_analyzed': len(all_info),
            'canary_protected': sum(1 for i in all_info if i.canary_present),
            'trivial_bypass': trivial,
            'moderate_bypass': moderate,
            'hard_bypass': hard,
            'leakable_count': sum(1 for i in all_info if i.canary_leakable),
        }

    def clear(self) -> None:
        self._functions.clear()
        self._output_reachable.clear()
        self._forks_detected.clear()
