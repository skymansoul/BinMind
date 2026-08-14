"""
堆分配点追踪 — 从反编译代码或原始指令中提取 malloc 类函数的分配大小并向前传播。
建立"分配点→分配大小"映射, 为同一函数内后续内存操作提供数值约束以过滤误报;
间接计算的大小仅部分追踪, 跨函数分配-使用对不做传播。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AllocSite:
    """一个堆分配点。"""
    address: int = 0              # 调用地址
    alloc_func: str = ""          # malloc / calloc / realloc
    size_known: bool = False      # 分配大小是否可静态确定
    size_value: int = 0           # 已知的分配大小(字节)
    size_expr: str = ""           # 大小表达式(如"rdi"表示从rdi读取)
    dest_reg: str = ""            # 返回值存放的寄存器(通常rax)
    dest_var: str = ""            # 返回值赋给的变量名(反编译代码中)


@dataclass
class MemAccess:
    """一个堆内存访问点(memcpy/sprintf/strcpy等)。"""
    address: int = 0
    access_func: str = ""         # memcpy / memset / strcpy / sprintf
    dest_expr: str = ""           # 目标地址表达式
    size_known: bool = False
    size_value: int = 0           # 写入大小(字节)
    size_expr: str = ""           # 大小表达式


def extract_alloc_sites(decompiled_text: str, func_offset: int = 0
                         ) -> List[AllocSite]:
    """从反编译文本中提取所有堆分配点, 匹配 malloc/calloc/realloc 赋值模式。"""
    sites: List[AllocSite] = []

    patterns = [
        # var = malloc(size)
        (r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*malloc\s*\(\s*(\d+|0x[0-9a-fA-F]+|\w+)\s*\)',
         'malloc', 1),
        # var = calloc(n, size)
        (r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*calloc\s*\(\s*(\d+|\w+)\s*,\s*(\d+)\s*\)',
         'calloc', 1),
        # var = realloc(ptr, size)
        (r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*realloc\s*\(\s*\w+\s*,\s*(\d+|0x[0-9a-fA-F]+|\w+)\s*\)',
         'realloc', 1),
    ]

    for pattern, func_name, size_group in patterns:
        for m in re.finditer(pattern, decompiled_text):
            var_name = m.group(1)
            size_str = m.group(size_group)
            site = AllocSite(
                alloc_func=func_name, dest_var=var_name,
                size_expr=size_str)

            try:
                if size_str.startswith('0x'):
                    site.size_value = int(size_str, 16)
                else:
                    site.size_value = int(size_str)
                site.size_known = True
            except ValueError:
                site.size_known = False
                # 变量参数 — 保留表达式供后续反向追踪

            if func_name == 'calloc':
                count_str = m.group(2)
                size_str2 = m.group(3)
                try:
                    site.size_value = int(count_str) * int(size_str2)
                    site.size_known = True
                except ValueError:
                    site.size_known = False

            sites.append(site)

    return sites


def extract_mem_accesses(decompiled_text: str) -> List[MemAccess]:
    """从反编译文本中提取所有堆内存写入操作 (memcpy/strcpy/sprintf 等)。"""
    accesses: List[MemAccess] = []

    patterns = [
        # memcpy(dest, src, size)
        (r'memcpy\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+|\w+)\s*\)', 'memcpy'),
        # memset(dest, val, size)
        (r'memset\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\d+|\w+)\s*\)', 'memset'),
        # strcpy(dest, src)
        (r'strcpy\s*\(\s*(\w+)\s*,\s*\w+\s*\)', 'strcpy'),
        # sprintf(dest, fmt, ...)
        (r'sprintf\s*\(\s*(\w+)\s*,\s*"[^"]*"', 'sprintf'),
    ]

    for pattern, func_name in patterns:
        for m in re.finditer(pattern, decompiled_text):
            dest = m.group(1)
            acc = MemAccess(access_func=func_name, dest_expr=dest)
            if func_name in ('memcpy', 'memset'):
                size_str = m.group(2)
                try:
                    acc.size_value = int(size_str)
                    acc.size_known = True
                except ValueError:
                    acc.size_known = False
                    acc.size_expr = size_str
            elif func_name == 'strcpy':
                # strcpy无显式大小 → 保守标记为未知
                acc.size_known = False
                acc.size_expr = 'strlen(src)'
            accesses.append(acc)

    return accesses


def match_alloc_to_access(sites: List[AllocSite],
                           accesses: List[MemAccess]
                           ) -> List[Tuple[AllocSite, MemAccess, str]]:
    """将分配点与内存访问配对, 判定每次写入是否安全。

    双方大小已知时按数值比较得 SAFE/UNSAFE, 任一方未知得 UNCERTAIN。
    返回 [(alloc, access, verdict), ...]。
    """
    pairs: List[Tuple[AllocSite, MemAccess, str]] = []

    for site in sites:
        for acc in accesses:
            # 简化配对: 同一函数内的所有alloc-access配对
            # 生产级实现应做变量名匹配(同一dest_var)
            if site.size_known and acc.size_known:
                if acc.size_value <= site.size_value:
                    verdict = 'SAFE'
                else:
                    verdict = 'UNSAFE'
            else:
                verdict = 'UNCERTAIN'
            pairs.append((site, acc, verdict))

    return pairs
