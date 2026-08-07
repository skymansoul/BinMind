"""
Binary hardening detection — shared constants and logger.

ELF/PE/Mach-O 硬化检测的公共常量集中管理，避免解析器与检测器重复定义。
"""


import logging

_log = logging.getLogger(__name__)

# ELF magic 与类别标识
ELFMAG = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2

# Program Header 类型
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552

# Dynamic section 标签
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_SYMTAB = 6
DT_FLAGS = 30
DT_FLAGS_1 = 0x6ffffffb
DT_GNU_HASH = 0x6ffffef5

# DT_FLAGS / DT_FLAGS_1 中的绑定标志
DF_BIND_NOW = 8
DF_1_NOW = 1

# Segment 权限位
PF_X = 1
PF_W = 2
PF_R = 4

# Canary 候选符号名，用于导入表扫描回退
CANARY_SYMBOLS = {'__stack_chk_fail', '__stack_chk_guard', '__stack_smash_handler'}
