# coding: utf-8
#
"""
程序切片启发式-无完整PDG时的轻量级漏洞函数代码范围定位。

应用场景:
  限定git blame的行范围-全文件blame引入过多噪声提交。
  本模块识别漏洞函数的精确行范围，将追溯限定在真正相关的代码区。

方法:
  C/C++: 函数签名定位 + 大括号深度跟踪
  Python: def行定位 + 缩进层级跟踪
  危险操作标记: 在切片内标记memcpy/system等调用行-这些行需更精确的逐行追溯。

局限性:
  无数据流/控制流分析-仅行范围，非语句级切片。
  完整PDG切片由外部静态分析插件提供（可替换本模块）。
"""

import os
import re
import logging
from dataclasses import dataclass
from typing import List, Optional

_log = logging.getLogger(__name__)


@dataclass
class SliceRegion:
    """程序切片区域-漏洞相关代码行范围（1-based, inclusive）"""
    file_path: str
    start_line: int
    end_line: int
    function_name: str = ""
    slice_type: str = "heuristic"
    confidence: float = 0.7


# 高危操作模式-标记为需要逐行精确追溯
_DANGEROUS_PATTERNS = [
    r'\b(memcpy|strcpy|strcat|sprintf|gets|scanf)\s*\(',
    r'\b(system|exec|popen|fork|spawn)\s*\(',
    r'\b(malloc|free|realloc|alloca)\s*\(',
    r'\b(read|write|send|recv|mmap)\s*\(',
    r'\[.*\].*=',                          # 数组写入
    r'pointer.*cast|reinterpret_cast',      # 类型强制转换
]


class HeuristicSlicer:
    """启发式函数定位器-识别C/C++/Python函数边界。

    实现策略:
      C/C++: 计大括号深度，深度归零时函数结束
      Python: 计缩进层级，缩进回归def级时函数结束
      多行函数签名: 跟踪括号匹配直至开大括号/冒号
    """

    def locate_function(self, file_path: str,
                         function_name: str) -> Optional[SliceRegion]:
        """在源文件中定位指定函数-返回行号范围。"""
        if not os.path.isfile(file_path):
            return None
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            return None

        func_start = None
        brace_depth = 0
        in_func = False
        is_py = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not in_func:
                if function_name not in stripped:
                    continue
                is_py = (stripped.startswith('def ') and
                         function_name in stripped.split('(')[0])
                is_c = (function_name in stripped and '(' in stripped and
                        not stripped.startswith('//') and not stripped.startswith('#') and
                        not stripped.startswith('/*') and not stripped.endswith(';'))
                if is_py or is_c:
                    func_start = i
                    in_func = True
                    is_py = is_py or stripped.endswith(':')
                continue

            if is_py:
                if i > func_start:
                    cur_indent = len(line) - len(line.lstrip())
                    def_indent = len(lines[func_start]) - len(lines[func_start].lstrip())
                    if stripped and cur_indent <= def_indent:
                        return SliceRegion(file_path=file_path,
                                           start_line=func_start + 1,
                                           end_line=i, function_name=function_name)
            else:
                brace_depth += stripped.count('{') - stripped.count('}')
                if brace_depth <= 0 and i > func_start:
                    return SliceRegion(file_path=file_path,
                                       start_line=func_start + 1,
                                       end_line=i + 1, function_name=function_name)

        if in_func:
            return SliceRegion(file_path=file_path, start_line=func_start + 1,
                               end_line=len(lines), function_name=function_name)
        return None

    def find_dangerous_lines(self, region: SliceRegion) -> List[int]:
        """在切片区域内标记包含高危操作的行号（1-based）。

        这些行是漏洞利用的直接载体-需要更精确的逐行追溯。
        """
        dangerous = []
        try:
            with open(region.file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            return dangerous
        for i in range(region.start_line - 1, min(region.end_line, len(lines))):
            stripped = lines[i].strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('#'):
                continue
            for pat in _DANGEROUS_PATTERNS:
                if re.search(pat, lines[i], re.IGNORECASE):
                    dangerous.append(i + 1)
                    break
        return dangerous


__all__ = ["SliceRegion", "HeuristicSlicer"]
