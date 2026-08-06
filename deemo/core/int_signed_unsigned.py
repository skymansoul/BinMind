# 有符号/无符号混淆检测 —— 搜索movsx/movzx类型转换+后续比较的模式。
# C语言中最隐蔽的整数漏洞: signed int与unsigned size_t比较时,
# 负数被转为巨大的无符号数→绕过边界检查→溢出。
# 例: if (len < MAX) memcpy(buf, src, len); 若len为signed=-1→转为size_t=0xFFFFFFFF。
# 本模块搜索movsx(符号扩展)→cmp/test→条件跳转的模式链。

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SignConfusion:
    """有符号/无符号混淆候选"""
    convert_addr: int        # movsx/movzx指令地址
    from_type: str           # "s8"/"s16"/"s32"/"u8"/"u16"
    to_reg: str              # 目标寄存器
    cmp_addr: int            # 后续比较指令地址
    jmp_addr: int            # 条件跳转地址
    confidence: float
    evidence: str = ""


# 符号扩展/零扩展指令模式
_CONVERT_PATTERNS = [
    (r'movsx\s+(\w+),\s*(?:byte|word|dword)\s+\[', 's'),  # movsx reg, byte [...]
    (r'movzx\s+(\w+),\s*(?:byte|word)\s+\[', 'u'),         # movzx reg, byte [...]
    (r'movsxd?\s+(\w+),\s*(\w+)', 's32'),                   # movsxd r64, r32
    (r'mov\s+(\w+),\s*(\w+)', 'r2r'),                       # mov r32, r32 (隐式零扩展)
]


def detect_sign_confusion(
    disasm_lines: List[str],
    func_name: str = "",
) -> List[SignConfusion]:
    """检测有符号/无符号混淆: 符号扩展后立即做无符号比较的模式。"""
    results: List[SignConfusion] = []

    for i, line in enumerate(disasm_lines):
        stripped = line.strip().lower()
        if not stripped or stripped.startswith(';'):
            continue

        # 步骤1: 找到符号扩展指令
        convert_type = ""
        to_reg = ""
        for pattern, ctype in _CONVERT_PATTERNS:
            m = re.search(pattern, stripped)
            if m:
                convert_type = ctype
                to_reg = m.group(1)
                break
        if not convert_type or 's' not in convert_type:
            continue  # 仅追踪符号扩展(有符号→大寄存器的转换)

        # 步骤2: 搜索后续cmp/test + jcc(使用同一寄存器)
        for j in range(i + 1, min(len(disasm_lines), i + 10)):
            dl = disasm_lines[j].strip().lower()
            if not dl:
                continue
            # cmp reg, imm
            m = re.search(rf'cmp\s+{to_reg},\s*(0x[0-9a-fA-F]+|\d+)', dl)
            if not m:
                # test reg, reg
                m = re.search(rf'test\s+{to_reg},\s*{to_reg}', dl)
            if not m:
                continue

            # 步骤3: 搜索后续条件跳转(jg/jge/jbe——可能是无符号比较)
            for k in range(j + 1, min(len(disasm_lines), j + 5)):
                el = disasm_lines[k].strip().lower()
                m = re.search(r'(j[abgl]|j[ln]?[abege])', el)
                if m:
                    jcc = m.group(1)
                    # 若是有符号和无符号混用→混淆嫌疑
                    results.append(SignConfusion(
                        convert_addr=i, from_type=convert_type,
                        to_reg=to_reg, cmp_addr=j, jmp_addr=k,
                        confidence=0.55 if jcc in ('ja','jb','jbe','jae') else 0.35,
                        evidence=(f"符号扩展{convert_type}→{to_reg}@"
                                 f"{hex(i)}→cmp@{hex(j)}→{jcc}@{hex(k)}"),
                    ))
                    break
            break

    results.sort(key=lambda r: -r.confidence)
    return results[:20]


__all__ = ["SignConfusion", "detect_sign_confusion"]
