# src/disasm/ - 二进制反汇编与结构化提取
# 为检测管线提供: 指令列表、基本块边界、CFG边
# 基于objdump -d输出, 无需调试符号

from .objdump_parser import (
    ObjdumpParser, FunctionInfo, CFGEdge, EdgeType)
