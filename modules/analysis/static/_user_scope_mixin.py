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
