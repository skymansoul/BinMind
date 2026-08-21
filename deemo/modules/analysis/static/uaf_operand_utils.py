# UAF 操作数解析辅助.
#
# 提供内存访问模式判定和立即数解析,
# 供 uaf_detect 的指针追踪模块使用.
#

import re
from typing import Optional

_KNOWN_REGS = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
               "r8","r9","r10","r11","r12","r13","r14","r15"}


def is_indexed_access(op: str) -> bool:
    """判断内存操作数是否为base+index*scale的数组索引访问.

    结构体字段 [rax+0x8] 只含一个寄存器 → False
    数组索引 [rdx+rax*1] 含两个寄存器 → True
    """
    s = op.strip().lower()
    if "[" not in s or "]" not in s:
        return False
    inner = s[s.find("[")+1:s.rfind("]")]
    regs = re.findall(r'[a-z]+', inner)
    count = sum(1 for r in regs if r in _KNOWN_REGS)
    return count >= 2


def parse_immediate(op: str) -> Optional[int]:
    """解析立即数操作数, 返回int或None."""
    o = op.strip().lower().lstrip("%").replace("$","")
    if "#" in o: o = o.split("#")[0].strip()
    if o.startswith("0x"):
        try: return int(o, 16)
        except ValueError: return None
    try: return int(o)
    except ValueError: return None


__all__ = ["is_indexed_access", "parse_immediate"]
