# 每调用点参数语义表 (Per-Call Argument Semantics Table)
#
# 核心决策:
#   堆溢出检测误报/漏报的隐蔽来源: 对所有写入函数用统一的参数索引
#   提取size. memcpy(dst,src,n)的size在index2, 而snprintf(dst,n,fmt)
#   的size在index1, fread(ptr,size,nmemb,stream)的实际写量为
#   size*nmemb. 统一取index2会拿到snprintf的fmt指针(误报数据流),
#   取index1会低估fread写入量(漏报). 本表为每个调用点建立
#   函数→参数角色的精确映射, 消除该类系统性误差.
#
#   参数角色: 0=dst指针, 1=src/格式串, 2=size/数量, ...
#   索引语义统一为"第k个实参", 由调用方映射到实际ABI寄存器.
#
# 理论依据:
#   CodeQL 的 ExternalFlowSources/SummaryModels 同样依赖按函数签名
#   建模参数语义; 静态分析精度首先取决于调用点参数角色的正确性.
#

from typing import Dict, Optional, Tuple


# 按函数名索引的写入size实参位置.
# 值为int(单个实参)或tuple(多个实参相乘, 如fread的size*nmemb).
_WRITE_SIZE_ARG: Dict[str, object] = {
    "memcpy": 2, "memmove": 2, "mempcpy": 2, "memccpy": 2,
    "memset": 2, "strncpy": 2, "strncat": 2, "stpncpy": 2,
    "snprintf": 1, "vsnprintf": 1, "vsnprintf_s": 1,
    "read": 2, "pread": 2, "recv": 2, "recvfrom": 2, "recvmsg": 2,
    "fread": (1, 2), "fwrite": (1, 2),
    "bcopy": 2, "bzero": 1, "explicit_bzero": 1,
    "gets_s": 0,  # 受限gets: 实际size为第二个参数, 此处保守不启用
}

# dst指针实参位置 (写入目标).
_WRITE_DST_ARG: Dict[str, int] = {
    "memcpy": 0, "memmove": 0, "mempcpy": 0, "memccpy": 0,
    "memset": 0, "strncpy": 0, "strncat": 0, "stpncpy": 0,
    "snprintf": 0, "vsnprintf": 0,
    "read": 1, "pread": 1, "recv": 1, "recvfrom": 1, "recvmsg": 1,
    "fread": 0, "fwrite": 0,
    "bcopy": 0, "bzero": 0, "explicit_bzero": 0,
}

# 无界写入: 写尺寸由源字符串长度决定, 无法从参数直接提取.
# 交由BWR模块恢复有界上界.
_UNSIZED_WRITES: Dict[str, int] = {
    "strcpy": 1, "stpcpy": 1, "strcat": 1, "sprintf": 1,
    "vsprintf": 1, "gets": 0,
}

# 分配函数 → size实参位置 (malloc=index0, calloc=(count,size), realloc=index1).
_ALLOC_SIZE_ARG: Dict[str, object] = {
    "malloc": 0, "_Znwm": 0, "_Znam": 0, "g_malloc": 0,
    "g_try_malloc": 0, "kzalloc": 0, "kmalloc": 0, "vmalloc": 0,
    "calloc": (0, 1), "g_malloc0": (0, 1),
    "realloc": 1, "g_realloc": 1, "ExAllocatePoolWithTag": 1,
}

# 释放函数.
_FREE_FUNCS: Dict[str, None] = {
    "free": None, "_ZdlPv": None, "g_free": None, "ExFreePool": None,
    "kfree": None,
}


def write_size_index(func: str) -> Optional[object]:
    """返回写入函数的size实参位置, 无界写入或无写入返回None."""
    if func in _UNSIZED_WRITES:
        return None
    return _WRITE_SIZE_ARG.get(func)


def write_dst_index(func: str) -> Optional[int]:
    """返回写入函数的dst实参位置.

    无界写 (strcpy/sprintf/gets) 的 dst 恒为第0实参.
    """
    if func in _UNSIZED_WRITES:
        return 0
    return _WRITE_DST_ARG.get(func, 0)


def is_sized_write(func: str) -> bool:
    """是否显式携带size参数的有界写入."""
    return func in _WRITE_SIZE_ARG


def is_unsized_write(func: str) -> bool:
    """是否由源字符串长度决定写量的无界写入."""
    return func in _UNSIZED_WRITES


def is_write_func(func: str) -> bool:
    """是否任一写入函数."""
    return func in _WRITE_SIZE_ARG or func in _UNSIZED_WRITES


def is_alloc_func(func: str) -> bool:
    return func in _ALLOC_SIZE_ARG


def alloc_size_indices(func: str) -> Optional[object]:
    return _ALLOC_SIZE_ARG.get(func)


def is_free_func(func: str) -> bool:
    return func in _FREE_FUNCS


__all__ = [
    "write_size_index", "write_dst_index",
    "is_sized_write", "is_unsized_write", "is_write_func",
    "is_alloc_func", "alloc_size_indices", "is_free_func",
]
