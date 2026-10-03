# _heap_call_handlers — 实现已并入 heap_overflow_detect.py, 此处仅为兼容重导出.
from .heap_overflow_detect import HeapCallHandlerMixin  # noqa: F401

__all__ = ['HeapCallHandlerMixin']
