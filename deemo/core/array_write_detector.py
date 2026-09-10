"""数组下标写入检测器 — 识别 buf[expr] = val 模式的堆写入。"""

import re
from typing import Dict, List

from .symbolic_range import AffineInterval, PathCondition
from .cfg_parser import BasicBlock
from .heap_expr_parser import parse_size_expr

_RE_MEMCPY = re.compile(
    r'(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|memset|'
    r'read|fread|recv|scanf|fscanf|sscanf|gets|fgets|bcopy)\s*\(')
_RE_ARRAY_WRITE = re.compile(r'(\w+)\s*\[([^\]]+)\]\s*=(?!=)\s*')


def detect_array_writes(
    block: BasicBlock, bid: int, pc: PathCondition,
    env: Dict[str, AffineInterval], write_sites: List,
):
    """检测数组下标写入 buf[expr] = val, 提取为 WriteSite。

    下标值即写入偏移, 实际访问范围 [0, idx], 需 idx+1 字节可访问。
    跳过已由 memcpy 等函数调用写入覆盖的行。
    """
    from .path_sensitive_vrf import WriteSite  # 延迟导入避免循环依赖
    for line in block.lines:
        for aw in _RE_ARRAY_WRITE.finditer(line):
            dst = aw.group(1)
            idx_expr = aw.group(2).strip()
            if _RE_MEMCPY.search(line):
                continue
            ws = parse_size_expr(idx_expr, env)
            # 常量折叠: 仿射表达式中所有符号变量都是常量时, 折叠为常量
            if ws.const_val is None and ws.coef:
                all_const = all(env.get(s) and env[s].const_val is not None
                                for s in ws.coef)
                if all_const:
                    val = ws.base
                    for s, c in ws.coef.items():
                        val += c * env[s].const_val
                    ws = AffineInterval.constant(val)
            if ws.const_val is not None:
                ws = AffineInterval.constant(ws.const_val + 1)
            else:
                ws = AffineInterval(
                    lo=ws.lo + 1 if ws.lo >= 0 else 1,
                    hi=ws.hi + 1 if ws.hi < 2**31 - 1 else 2**31 - 1)
            write_sites.append(WriteSite(
                var_name=dst, write_size=ws,
                write_call='array_index', path_cond=pc.clone(),
                block_id=bid, lineno=block.start_lineno,
            ))
