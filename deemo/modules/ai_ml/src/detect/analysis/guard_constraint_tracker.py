# 路径守卫约束追踪器——从分支条件提取安全守卫对栈槽/寄存器的约束
# 解决HEAP-FP-002型FP: cmp+jcc→return守卫在trace_backward的栈加载之前,
# 导致值范围传播丢失守卫约束信息
# 方法: 扫描cmp+jcc→exit/return模式 → 记录{slot:OFF: upper_bound}约束 →
#   在copy size估计时应用约束收缩
# 理论: 轻量路径条件推理——不执行完整符号执行, 仅提取守卫比较的数值边界
import re, logging
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)

# 条件跳转→约束方向: 'jg'/'ja'→≤bound / 'jl'/'jb'→≥bound
_GUARD_UPPER = {'jg', 'ja', 'jge', 'jae'}   # jg: greater→ ≤
_GUARD_LOWER = {'jl', 'jb', 'jle', 'jbe'}   # jl: less→ ≥
# Intel→AT&T寄存器映射
_REG32 = {'rax':'eax','rbx':'ebx','rcx':'ecx','rdx':'edx','rsi':'esi',
          'rdi':'edi','r8':'r8d','r9':'r9d','r10':'r10d','r11':'r11d'}
_REG64 = {v:k for k,v in _REG32.items()}
_NON_REG = {'qword','dword','word','byte','ptr','xmmword'}


@dataclass
class GuardConstraint:
    """单个守卫约束——cmp reg/slot, N 后 jcc→exit的含义"""
    slot: str = ""          # 栈槽 'rbp+0x18' 或寄存器 'eax'
    is_slot: bool = True    # True=栈槽, False=寄存器
    upper_bound: Optional[int] = None   # 上界 (jle/jg守卫)
    lower_bound: Optional[int] = None   # 下界 (jge/jl守卫)
    guard_idx: int = 0      # cmp指令索引

    def constrain(self, lo: int, hi: int) -> Tuple[int, int]:
        """应用此约束收缩值范围 [lo, hi]"""
        if self.upper_bound is not None:
            hi = min(hi, self.upper_bound)
        if self.lower_bound is not None:
            lo = max(lo, self.lower_bound)
        return (lo, hi)

    def __repr__(self) -> str:
        parts = []
        if self.upper_bound is not None: parts.append(f"≤{self.upper_bound}")
        if self.lower_bound is not None: parts.append(f"≥{self.lower_bound}")
        return f"Guard({self.slot}: {', '.join(parts)})"


class GuardConstraintTracker:
    """守卫约束追踪器——收集cmp+jcc→exit模式, 为值范围提供约束"""
    # 双ABI参数寄存器: (linux32, linux64, win32, win64)
    _PARAM_REGS = {
        0: ('edi','rdi','ecx','rcx'), 1: ('esi','rsi','edx','rdx'),
        2: ('edx','rdx','r8d','r8'), 3: ('ecx','rcx','r9d','r9'),
    }

    def collect_guards(self, instructions: List[str]) -> List[GuardConstraint]:
        """扫描指令序列, 收集所有cmp+jcc模式的守卫约束
        不要求jcc目标必须是exit——slot匹配本身就是强过滤器"""
        guards = []
        for i, il in enumerate(instructions):
            il_s = il.strip().lower()
            if not il_s or 'cmp' not in il_s: continue
            # 解析cmp操作数 (兼容带字节码前缀的objdump输出)
            # 跳过字节码部分: 取\t后的指令文本
            instr_text = il_s.split('\t')[-1].strip() if '\t' in il_s else il_s
            slot, bound = self._parse_cmp(instr_text if 'cmp' in instr_text else il_s)
            if slot is None or bound is None: continue
            if bound > 0x10000: continue
            # 查找紧随的jcc (guard类型)
            jcc_type = self._next_jcc_guard(instructions, i)
            if not jcc_type: continue
            g = GuardConstraint(slot=slot, is_slot=slot.startswith('rbp'),
                               guard_idx=i)
            if jcc_type in _GUARD_UPPER:
                g.upper_bound = bound
            elif jcc_type in _GUARD_LOWER:
                g.lower_bound = bound
            else:
                continue
            if g.upper_bound is not None or g.lower_bound is not None:
                guards.append(g)
        return guards

    @staticmethod
    def _find_exit_targets(instructions: List[str]) -> Set[int]:
        """找到所有exit/return目标的索引——ret指令及其前导jmp"""
        exits = set()
        for i, il in enumerate(instructions):
            il_s = il.strip().lower()
            # 匹配 'ret', 'retn', 'retf' (可能带地址前缀)
            if re.search(r'\bret\b', il_s):
                exits.add(i)
        return exits

    @staticmethod
    def _next_jcc_guard(instructions: List[str], ci: int) -> Optional[str]:
        """cmp后3条指令内找guard型jcc→返回jcc类型(jg/ja/jge等)
        兼容objdump带字节码前缀的格式: '7f XX  \tjg  50 <exit>'"""
        for j in range(ci + 1, min(ci + 4, len(instructions))):
            il = instructions[j].strip().lower()
            if not il or il.startswith(';'): continue
            m = re.search(r'\b(j[a-z]{1,3})\b', il)
            if m:
                jcc = m.group(1)
                if jcc in _GUARD_UPPER or jcc in _GUARD_LOWER:
                    return jcc
                return None
            if 'ret' in il or 'call' in il: break
        return None

    @staticmethod
    def _parse_cmp(il: str) -> Tuple[Optional[str], Optional[int]]:
        """解析cmp操作数→(栈槽/寄存器, 比较值)
        cmp [rbp+0x18], 0x40 → ('rbp+0x18', 64)
        cmp eax, 0x40 → ('eax', 64)
        cmp DWORD PTR [rbp+0x18], 0x40 → ('rbp+0x18', 64)"""
        # cmp mem, imm — Intel: cmp DWORD PTR [rbp+OFF], IMM
        m = re.search(r'cmp\s+(?:dword|qword|word|byte)?\s*(?:ptr\s+)?'
                      r'\[(rbp[+\-]0x[0-9a-f]+)\]\s*,\s*(0x[0-9a-f]+|\d+)', il)
        if m:
            slot = m.group(1).strip()
            return (slot, _parse_hex(m.group(2)))
        # cmp imm, mem — AT&T
        m = re.search(r'cmp\s+\$?(0x[0-9a-f]+|\d+)\s*,\s*'
                      r'(?:qword|dword|word|byte)?\s*(?:ptr\s+)?'
                      r'\[(rbp[+\-]0x[0-9a-f]+)\]', il)
        if m:
            slot = m.group(2).strip()
            return (slot, _parse_hex(m.group(1)))
        # cmp reg, imm
        m = re.search(r'cmp\s+%?(\w+)\s*,\s*\$?(0x[0-9a-f]+|\d+)', il)
        if m and m.group(1) not in _NON_REG:
            return (m.group(1), _parse_hex(m.group(2)))
        # cmp imm, reg — AT&T
        m = re.search(r'cmp\s+\$?(0x[0-9a-f]+|\d+)\s*,\s*%?(\w+)', il)
        if m and m.group(2) not in _NON_REG:
            return (m.group(2), _parse_hex(m.group(1)))
        return (None, None)

    def constrain_copy_size(self,
                            instructions: List[str],
                            copy_idx: int,
                            size_param_idx: int,
                            guards: List[GuardConstraint]
                            ) -> Tuple[int, int]:
        """给定copy调用点, 应用守卫约束收缩size范围
        返回 (lo, hi)——收缩后的区间"""
        if size_param_idx < 0:
            return (0, 0xFFFFFFFF)
        targets = self._PARAM_REGS.get(size_param_idx, ())
        if not targets:
            return (0, 0xFFFFFFFF)

        # 追踪copy site的size寄存器到其源
        traced_slot = self._trace_to_slot(instructions, copy_idx, targets)
        if not traced_slot:
            return (0, 0xFFFFFFFF)

        # 对匹配的守卫约束应用收缩
        lo, hi = 0, 0xFFFFFFFF
        for g in guards:
            if self._slots_match(traced_slot, g.slot):
                lo, hi = g.constrain(lo, hi)
        return (lo, hi)

    def _trace_to_slot(self, instructions: List[str], call_idx: int,
                       targets: Tuple[str, ...]) -> Optional[str]:
        """从call向上追踪size参数寄存器→寄存器链→栈槽或常量源
        返回 'rbp+0x18' 或 None (立即数源/未找到)"""
        # 语法检测
        is_att = any('%r' in il or '%e' in il
                    for il in instructions[max(0,call_idx-10):call_idx])

        cur = None
        found_at = call_idx  # 追踪起点——从此索引向前搜索
        # 阶段1: 找到size参数寄存器在call前的最近赋值源
        for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
            il = instructions[j].strip().lower()
            if not il or il.startswith(';'): continue
            for t in targets:
                # 立即数源→不需要守卫
                if re.search(rf'mov\s+%?{t}\s*,\s*\$?(?:0x[0-9a-f]+|\d+)', il):
                    return None
                # 栈加载→直接返回栈槽
                m = re.search(rf'(?:mov|movsxd)\s+%?{t}\s*,\s*(?:dword|qword|word)?\s*'
                             r'(?:ptr\s+)?\[(rbp[+\-]0x[0-9a-f]+)\]', il)
                if m: return m.group(1).strip()
                # AT&T栈加载
                m = re.search(rf'mov\s+([+\-]?0x[0-9a-f]+)\(%rbp\)\s*,\s*%{t}', il)
                if m: return f'rbp{m.group(1)}'
                # 寄存器源: Intel=t作为DST(mov t,src) / AT&T=t作为DST(mov src,t)
                if is_att:
                    m = re.match(rf'mov\s+%?(\w+)\s*,\s*%?{t}', il)
                else:
                    m = re.match(rf'mov\s+%?{t}\s*,\s*%?(\w+)', il)
                if m and m.group(1) not in _NON_REG:
                    cur = m.group(1); found_at = j; break
                # movsxd
                m = re.match(rf'movsxd\s+%?{t}\s*,\s*%?(\w+)', il)
                if m and m.group(1) not in _NON_REG:
                    cur = m.group(1); found_at = j; break
            if cur: break
        if not cur: return None

        # 阶段2: 沿寄存器链追踪直到栈槽
        # 关键: 搜索从上次找到cur的位置向前, 避免跨越不同用途的寄存器重定义
        search_from = found_at
        for _ in range(6):
            found = False
            for j in range(search_from - 1, max(-1, search_from - 15), -1):
                il = instructions[j].strip().lower()
                if not il or il.startswith(';'): continue
                # 栈加载→找到源
                m = re.search(rf'(?:mov|movsxd)\s+%?{cur}\s*,\s*(?:dword|qword|word)?\s*'
                             r'(?:ptr\s+)?\[(rbp[+\-]0x[0-9a-f]+)\]', il)
                if m: return m.group(1).strip()
                # AT&T栈加载
                m = re.search(rf'mov\s+([+\-]?0x[0-9a-f]+)\(%rbp\)\s*,\s*%{cur}', il)
                if m: return f'rbp{m.group(1)}'
                # 立即数赋值→不需要守卫
                if re.search(rf'mov\s+%?{cur}\s*,\s*\$?(?:0x[0-9a-f]+|\d+)', il):
                    return None
                # cdqe (eax→rax符号扩展)
                if cur == 'rax' and 'cdqe' in il:
                    cur = 'eax'; found = True; search_from = j; break
                # 寄存器mov链: 语法感知的DEF追踪 (cur作为DST)
                if is_att:
                    m = re.match(rf'mov\s+%?(\w+)\s*,\s*%?{cur}', il)
                else:
                    m = re.match(rf'mov\s+%?{cur}\s*,\s*%?(\w+)', il)
                if m and m.group(1) not in _NON_REG:
                    cur = m.group(1); found = True; search_from = j; break
                # movsxd cur, src32
                m = re.match(rf'movsxd\s+%?{cur}\s*,\s*%?(\w+)', il)
                if m and m.group(1) not in _NON_REG:
                    cur = m.group(1); found = True; search_from = j; break
                # AT&T movsxd src, %cur
                if is_att:
                    m = re.match(rf'movsxd\s+%?(\w+)\s*,\s*%?{cur}', il)
                    if m and m.group(1) not in _NON_REG:
                        cur = m.group(1); found = True; search_from = j; break
            if not found: break
        return None

    @staticmethod
    def _slots_match(traced: str, guard_slot: str) -> bool:
        """比较两个栈槽引用是否指同一位置
        'rbp+0x18' == 'rbp+0x18' / 'rbp+0x18' ≈ 'rbp+0x18'"""
        if traced == guard_slot: return True
        # 规范化: 去除空格, 统一大小写
        t = traced.strip().lower().replace(' ', '')
        g = guard_slot.strip().lower().replace(' ', '')
        return t == g


def _parse_hex(s: str) -> int:
    return int(s, 16) if '0x' in s.lower() else int(s)
