"""FP过滤阶段通用访问器 — 各阶段文件共享, 避免逐文件重复."""

from typing import Any


def _get_alloc_size(integrator: Any, c: Any) -> int:
    return integrator._get_alloc_size(c)


def _get_alloc_var(integrator: Any, c: Any) -> str:
    return integrator._get_alloc_var(c)


def _get_size_var(integrator: Any, c: Any) -> str:
    return integrator._get_size_var(c)


def _get_write_offset(integrator: Any, c: Any) -> int:
    return integrator._get_write_offset(c)


def _get_write_size(integrator: Any, c: Any) -> int:
    return integrator._get_write_size(c)


def _get_store_pc(integrator: Any, c: Any) -> int:
    return integrator._get_store_pc(c)


def _get_base_var(integrator: Any, c: Any) -> str:
    return integrator._get_base_var(c)


def _try_parse_int(s: str) -> tuple:
    try:
        return True, int(s)
    except (ValueError, TypeError):
        pass
    try:
        return True, int(s, 16)
    except (ValueError, TypeError):
        pass
    return False, -1
