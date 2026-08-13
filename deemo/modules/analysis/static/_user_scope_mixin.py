# -*- coding: utf-8 -*-
"""用户代码范围判定 mixin.

决策:
  多个检测器共用同一套用户函数范围判定: set_user_func_ranges 记录
  用户函数地址区间, _is_user_code 判定指令地址是否落在用户代码内.
  CRT/库代码通过该判定排除, 避免库内危险调用污染检测结果.

创建: 2024-03-12
"""

from typing import List, Tuple


class UserScopeMixin:
    """用户代码范围判定, 由各检测器继承."""

    def set_user_func_ranges(self, ranges: List[Tuple[int, int]]):
        self._user_func_ranges = sorted(ranges, key=lambda r: r[0])

    def _is_user_code(self, addr: int) -> bool:
        if not self._user_func_ranges:
            return True
        for lo, hi in self._user_func_ranges:
            if lo <= addr < hi:
                return True
        return False


__all__ = ["UserScopeMixin"]
