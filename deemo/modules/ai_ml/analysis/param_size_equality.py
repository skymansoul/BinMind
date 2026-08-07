# 参数来源等式检测——证明alloc_size与copy_size恒等则拷贝必然安全
# 误报根源: 同函数参数len同时流向malloc(len)与memcpy(buf,in,len),
#   值流引擎因跨栈槽写回链断裂解析为TOP, 落入"未知→保守保留"分支→FP
# 解决: 溯源到同一函数参数索引/同一栈槽/同一常量→copy≡alloc→不溢出
#
# 与value_flow_engine.is_same_source的区别:
#   该模块只看STACK_SLOT/REGISTER/CONSTANT三类来源且依赖其正则解析
#   本模块: (1)按调用约定枚举双ABI候选寄存器 (2)解析AT&T/Intel双语法
#   (3)区分"纯mov链"/"算术变换"(变换后不判等, 保留召回)
#
# 安全边界: 仅当纯mov链(cdqe/movsxd视为纯宽化)且无算术改动时判等;
#   alloc=n, copy=n+16之类经add/sub/imul改动的场景返回DIFFERENT→保守保留

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)

_REG_ALIAS = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx',
              'esi':'rsi','edi':'rdi','r8d':'r8','r9d':'r9',
              'r10d':'r10','r11d':'r11','ax':'rax','cx':'rcx',
              'dx':'rdx'}
_PARAM_IDX = {'rdi':0,'rsi':1,'rdx':2,'rcx':3,'r8':4,'r9':5}
_NON_REG = {'qword','dword','word','byte','ptr','xmmword','rip','eip'}

# 各危险函数size参数寄存器——按ABI分开, 避免Linux寄存器在Windows二进制中误命中
_LINUX_SIZE_REG: Dict[str, str] = {
    'malloc':'rdi','calloc':'rsi','realloc':'rsi','alloca':'rdi',
    'memcpy':'rdx','memmove':'rdx','strncpy':'rdx','snprintf':'rsi',
    'read':'rdx','recv':'rdx','fread':'rsi',
}
_WIN_SIZE_REG: Dict[str, str] = {
    'malloc':'rcx','calloc':'rdx','realloc':'rdx','alloca':'rcx',
    'memcpy':'r8','memmove':'r8','strncpy':'r8','snprintf':'rdx',
    'read':'r8','recv':'r8','fread':'rdx',
}


class EqualityKind(Enum):
    SAME_PARAM = 'same_param'     # 同一函数参数索引→恒等
    SAME_SLOT = 'same_slot'       # 同一栈槽→恒等
    SAME_CONST = 'same_const'     # 同一常量→恒等
    DIFFERENT = 'different'       # 来源不同/算术变换→保守
    UNKNOWN = 'unknown'           # 无法解析→保守


@dataclass
class SizeOrigin:
    """size参数的来源签名——签名相等即值恒等"""
    kind: str                     # slot|param|imm|zero|transformed|external|unknown
    sig: str = ""                 # 签名: 栈槽/参数索引/常量值
    traced: bool = False

    def signature(self) -> str:
        return f"{self.kind}:{self.sig}"


@dataclass
class ParamEqualityReport:
    kind: EqualityKind
    alloc_origin: SizeOrigin
    copy_origin: SizeOrigin
    evidence: str = ""


class ParamSizeEquality:
    """参数来源等式检测器——alloc/copy大小同源→判安全"""

    def __init__(self, max_trace_depth: int = 12):
        self._max_depth = max_trace_depth

    def check(self, instructions: List[str], alloc_idx: int,
              alloc_func: str, copy_idx: int, copy_func: str
              ) -> ParamEqualityReport:
        """检测alloc_size与copy_size是否恒等。
        仅能证明相等→返回SAME_*; 其余一律DIFFERENT/UNKNOWN, 不误杀真漏洞
        """
        abi = self._detect_abi(instructions, alloc_idx)
        size_regs = _WIN_SIZE_REG if abi == 'win' else _LINUX_SIZE_REG
        a_reg = size_regs.get(alloc_func, 'rdi')
        c_reg = size_regs.get(copy_func, 'rdx')

        a_origin = self._trace_reg(instructions, alloc_idx, a_reg)
        c_origin = self._trace_reg(instructions, copy_idx, c_reg)

        if (a_origin.traced and c_origin.traced
                and a_origin.signature() == c_origin.signature()):
            if a_origin.kind == 'param':
                kind = EqualityKind.SAME_PARAM
            elif a_origin.kind == 'slot':
                kind = EqualityKind.SAME_SLOT
            elif a_origin.kind == 'imm':
                kind = EqualityKind.SAME_CONST
            else:
                kind = EqualityKind.DIFFERENT
            ev = (f"same_size_origin[{abi}]: alloc[{alloc_func}]="
                  f"{a_origin.signature()}≡copy[{copy_func}]="
                  f"{c_origin.signature()}→copy≤alloc恒成立")
            return ParamEqualityReport(kind, a_origin, c_origin, ev)

        ev = (f"size_origin[{abi}]: alloc={a_origin.signature() or '?'},"
              f" copy={c_origin.signature() or '?'}")
        if a_origin.kind == 'unknown' or c_origin.kind == 'unknown':
            return ParamEqualityReport(EqualityKind.UNKNOWN, a_origin, c_origin, ev)
        return ParamEqualityReport(EqualityKind.DIFFERENT, a_origin, c_origin, ev)

    def _detect_abi(self, instructions: List[str], alloc_idx: int) -> str:
        """从malloc调用前的实参装载判定ABI——rcx装载→win, rdi装载→linux
        AT&T用%前缀; Intel裸寄存器, 用mov dst格式区分"""
        for j in range(alloc_idx - 1, max(-1, alloc_idx - 4), -1):
            il = instructions[j].strip().lower()
            if not il or il.startswith((';', '.')):
                continue
            if re.search(r'(?:mov|movsx|movsxd|lea)\s+.*?%r(cx|8|9|dx)\b', il):
                return 'win'
            if re.search(r'(?:mov|movsx|movsxd|lea)\s+.*?%r(di|si)\b', il):
                return 'linux'
            # Intel: 第一操作数=目标寄存器
            if re.search(r'\b(?:mov|movsx|movsxd|lea)\s+(?:r|e)(cx|dx|8d|9d)\b', il):
                return 'win'
            if re.search(r'\b(?:mov|movsx|movsxd|lea)\s+(?:r|e)(di|si)\b', il):
                return 'linux'
        win = linux = 0
        for il in instructions:
            il_l = il.strip().lower()
            if 'mov' not in il_l:
                continue
            if re.search(r'%r(cx|8|9|dx)\b', il_l):
                win += 1
            elif re.search(r'%r(di|si)\b', il_l):
                linux += 1
            elif re.search(r'\bmov\s+(?:r|e)(cx|dx|8d|9d)\b', il_l):
                win += 1
            elif re.search(r'\bmov\s+(?:r|e)(di|si)\b', il_l):
                linux += 1
        return 'win' if win >= linux else 'linux'

    def _best_origin(self, instructions: List[str], call_idx: int,
                     cands: Tuple[str, ...]) -> SizeOrigin:
        """遍历候选寄存器取最优来源——优先级: 非unknown且非transformed"""
        best = SizeOrigin(kind='unknown')
        for reg in cands:
            o = self._trace_reg(instructions, call_idx, reg)
            if o.kind in ('slot', 'param', 'imm', 'zero') and o.traced:
                return o
            if o.traced and not best.traced:
                best = o
        return best

    def _trace_reg(self, instructions: List[str], call_idx: int,
                   start_reg: str) -> SizeOrigin:
        """沿纯mov链反向溯源——终止于栈槽/参数/常量/算术/调用"""
        cur = self._norm(start_reg)
        for i in range(call_idx - 1, max(-1, call_idx - self._max_depth), -1):
            if i < 0:
                break
            il = instructions[i].strip().lower()
            if not il or il.startswith((';', '.')):
                continue

            # 立即数赋值——双语法: AT&T mov $imm,%reg / Intel mov reg,imm
            m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', il)
            if m and self._norm(m.group(2)) == cur:
                return SizeOrigin(kind='imm', sig=m.group(1), traced=True)
            m = re.match(r'mov\s+%?(\w+),\s*(0x[0-9a-f]+|\d+)', il)
            if m and self._norm(m.group(1)) == cur and m.group(1) not in _NON_REG:
                return SizeOrigin(kind='imm', sig=m.group(2), traced=True)

            # 栈槽读取——双语法: AT&T mov off(%rbp),%reg / Intel mov reg,[rbp+off]
            m = re.match(r'mov\s+([+\-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*%?(rbp|rsp)\s*\)\s*,\s*%?(\w+)', il)
            if m and self._norm(m.group(3)) == cur:
                return SizeOrigin(kind='slot', sig=f"{m.group(2)}{m.group(1)}",
                                  traced=True)
            m = re.match(rf'mov(?:sx|sxd|zx)?\s+%?{cur}\s*,\s*(?:\w+\s+ptr\s+)?\[(rbp|rsp)([+\-]\w+)\]', il)
            if m:
                return SizeOrigin(kind='slot', sig=f"{m.group(1)}{m.group(2)}",
                                  traced=True)

            # 寄存器间mov/movsx/movzx/movsxd/movslq——语法感知的DST判定
            # AT&T: mov %src,%dst(第二操作数是dst); Intel: mov dst,src(第一操作数dst)
            m = re.match(r'mov(?:sx|sxd|zx|slq|sbq|swq|zbq|zwq|sq|zq)?\s+(\S+),\s*(\S+)', il)
            if m:
                r1, r2 = self._norm(m.group(1)), self._norm(m.group(2))
                if '%' in il:
                    if r2 == cur and r1 not in _NON_REG and not r1.startswith(('$', '0x')):
                        cur = r1
                        continue
                elif r1 == cur and r2 not in _NON_REG:
                    cur = r2
                    continue

            # lea写当前寄存器——地址/值计算→变换, 不判等
            m = re.match(r'lea\s+(\S+)', il)
            if m:
                dst = m.group(1).lstrip('%')
                if self._norm(dst) == cur:
                    return SizeOrigin(kind='transformed', sig=dst, traced=True)

            # cdqe/cltq——eax→rax纯宽化, 值来源为eax的低32位
            if cur == 'rax' and il in ('cdqe', 'cltq'):
                cur = 'rax'
                continue

            # xor reg,reg → 恒零
            m = re.match(r'xor\s+%?(\w+),\s*%?\1\b', il)
            if m and self._norm(m.group(1)) == cur:
                return SizeOrigin(kind='zero', sig='0', traced=True)

            # 算术改动→值已变换, 不判等
            if re.match(r'(add|sub|imul|shl|shr|and|or|neg|not)\s+', il) and re.search(
                    rf'(?:%?{cur}\b)', il):
                return SizeOrigin(kind='transformed', sig=cur, traced=True)

            # 内存间接读取→无法解析值
            if re.search(rf'\bmov\b.*,.*%?{cur}\b', il) and re.search(r'\[', il):
                return SizeOrigin(kind='external', sig=cur, traced=True)

            # 调用截断——停止回溯; 循环结束由参数寄存器判定兜底
            if 'call' in il:
                break

        # 循环结束——cur若是参数寄存器(函数入口未定义)→参数来源
        if cur in _PARAM_IDX:
            return SizeOrigin(kind='param', sig=str(_PARAM_IDX[cur]), traced=True)
        return SizeOrigin(kind='unknown', sig=cur, traced=False)

    @staticmethod
    def _norm(r: str) -> str:
        clean = r.lstrip('%').lower()
        return _REG_ALIAS.get(clean, clean)
