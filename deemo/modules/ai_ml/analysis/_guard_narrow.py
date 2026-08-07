# L5守卫约束收缩——cmp+jcc→exit模式收窄copy size上界
# 解决HEAP-FP-002: malloc(N); if(len>N)return; memcpy(buf,in,len)
# 独立内联模块, 避免跨包导入guard_constraint_tracker
import re
from typing import List

_NON_REG = {'qword','dword','word','byte','ptr','xmmword'}

_PARAM_REGS = {
    0: ('edi','rdi','ecx','rcx'), 1: ('esi','rsi','edx','rdx'),
    2: ('edx','rdx','r8d','r8'), 3: ('ecx','rcx','r9d','r9'),
}

_COPY_SIZE_PARAM = {
    'memcpy':2,'memmove':2,'strncpy':2,'read':2,'recv':2,
    'fread':1,'snprintf':1,
}

_GUARD_UPPER = {'jg','ja','jge','jae'}
# AT&T符号扩展助记符: movslq(long→quad)=Intel movsxd, movswq(word→quad), movsbq(byte→quad)
_SEXT_ATT = {'movslq','movswq','movsbq','movsbw','movswl','movzbl','movzwl','movzbq','movzwq'}


def _instr_text(il: str) -> str:
    """从objdump行提取纯指令文本(去除地址/字节码前缀)"""
    s = il.strip()
    if '\t' in s:
        parts = s.split('\t')
        for p in reversed(parts):
            p = p.strip()
            if p and not p.startswith('0x') and not re.match(r'^[0-9a-f ]+$', p):
                return p.lower()
    return s.lower()


def _norm_offset(offs: str) -> str:
    """规范化栈偏移: '0x18'→'rbp+0x18', '-0x8'→'rbp-0x8'"""
    o = offs.strip()
    if o.startswith('rbp'):
        return o.lower()
    if o.startswith('-'):
        return f'rbp{o}'
    return f'rbp+{o}'


def guard_narrow_copy_size(instructions: List[str], copy_idx: int,
                           copy_func: str) -> int:
    """扫描守卫约束并收缩copy size上界。
    返回收窄后的上界值(0xFFFFFFFF表示未找到守卫约束)。"""
    size_param = _COPY_SIZE_PARAM.get(copy_func, 2)
    targets = _PARAM_REGS.get(size_param, ('edx','rdx','r8d','r8'))
    slot = _trace_size_to_slot(instructions, copy_idx, targets)
    if not slot:
        return 0xFFFFFFFF
    return _find_guard_bound(instructions, copy_idx, slot)


def _trace_size_to_slot(instructions, call_idx, targets):
    """从call向上追踪size参数寄存器→栈槽或立即数src"""
    is_att = any('%r' in il or '%e' in il
                for il in instructions[max(0,call_idx-10):call_idx])
    cur, found_at = None, call_idx
    # 阶段1: size参数寄存器的最近DEF
    for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
        il = instructions[j]
        instr = _instr_text(il)
        if not instr or instr.startswith(';'): continue
        for t in targets:
            # 立即数源→无需守卫
            if re.search(rf'mov\s+%?{t}\s*,\s*\$?(?:0x[0-9a-f]+|\d+)', instr):
                return None
            # 直接栈加载 (Intel: mov r8, [rbp+0x18] / AT&T: mov 0x18(%rbp),%r8)
            m = re.search(
                rf'(?:mov|movsxd|movslq)\s+%?{t}\s*,'
                r'\s*(?:dword|qword|word)?\s*(?:ptr\s+)?'
                r'\[(rbp[+\-]0x[0-9a-f]+)\]', instr)
            if m: return _norm_offset(m.group(1))
            m = re.search(rf'mov\s+([+\-]?0x[0-9a-f]+)\(%rbp\)\s*,\s*%{t}', instr)
            if m: return _norm_offset(m.group(1))
            # 寄存器追源 (AT&T: mov src, t / Intel: mov t, src)
            if is_att:
                m = re.match(rf'mov\s+%?(\w+)\s*,\s*%?{t}', instr)
            else:
                m = re.match(rf'mov\s+%?{t}\s*,\s*%?(\w+)', instr)
            if m and m.group(1) not in _NON_REG: cur = m.group(1); found_at = j; break
            # 符号扩展 (Intel: movsxd t, src / AT&T: movslq src, t)
            if is_att:
                m = re.match(rf'(?:movs[lwb]q|movz[bwl][lq]?)\s+%?(\w+)\s*,\s*%?{t}', instr)
            else:
                m = re.match(rf'movsxd\s+%?{t}\s*,\s*%?(\w+)', instr)
            if m and m.group(1) not in _NON_REG: cur = m.group(1); found_at = j; break
        if cur: break
    if not cur: return None

    # 阶段2: 寄存器链→栈槽 (search_from避免跨越重定义)
    search_from = found_at
    for _ in range(6):
        found = False
        for j in range(search_from - 1, max(-1, search_from - 15), -1):
            il = instructions[j]
            instr = _instr_text(il)
            if not instr or instr.startswith(';'): continue
            # 栈加载→找到源
            m = re.search(rf'(?:mov|movsxd|movslq)\s+%?{cur}\s*,'
                         r'\s*(?:dword|qword|word)?\s*(?:ptr\s+)?'
                         r'\[(rbp[+\-]0x[0-9a-f]+)\]', instr)
            if m: return _norm_offset(m.group(1))
            m = re.search(rf'mov\s+([+\-]?0x[0-9a-f]+)\(%rbp\)\s*,\s*%{cur}', instr)
            if m: return _norm_offset(m.group(1))
            # 立即数赋值→无需守卫
            if re.search(rf'mov\s+%?{cur}\s*,\s*\$?(?:0x[0-9a-f]+|\d+)', instr):
                return None
            # cdqe (eax→rax符号扩展)
            if cur == 'rax' and 'cdqe' in instr:
                cur = 'eax'; found = True; search_from = j; break
            # 寄存器mov链
            if is_att:
                m = re.match(rf'mov\s+%?(\w+)\s*,\s*%?{cur}', instr)
            else:
                m = re.match(rf'mov\s+%?{cur}\s*,\s*%?(\w+)', instr)
            if m and m.group(1) not in _NON_REG:
                cur = m.group(1); found = True; search_from = j; break
            # 符号扩展链
            if is_att:
                m = re.match(rf'(?:movs[lwb]q|movz[bwl][lq]?)\s+%?(\w+)\s*,\s*%?{cur}', instr)
            else:
                m = re.match(rf'movsxd\s+%?{cur}\s*,\s*%?(\w+)', instr)
            if m and m.group(1) not in _NON_REG:
                cur = m.group(1); found = True; search_from = j; break
        if not found: break
    return None


def _find_guard_bound(instructions, copy_idx, slot: str) -> int:
    """从copy_idx向上扫描, 找cmp slot,N → jg/jge/jae模式 → 返回上界N
    支持双语法: Intel cmp [rbp+0x18], 0x40 / AT&T cmpl $0x40, 0x18(%rbp)"""
    slot = slot.strip().lower()
    for i in range(copy_idx - 1, max(-1, copy_idx - 30), -1):
        il = instructions[i]
        instr = _instr_text(il)
        if not instr or 'cmp' not in instr: continue
        slot2, val = _parse_cmp(instr)
        if slot2 is None or val is None: continue
        if slot2 != slot: continue
        for j in range(i + 1, min(i + 4, len(instructions))):
            j_instr = _instr_text(instructions[j])
            jm = re.search(r'\b(j[a-z]{1,3})\b', j_instr)
            if not jm: continue
            return val if jm.group(1) in _GUARD_UPPER else 0xFFFFFFFF
        return 0xFFFFFFFF
    return 0xFFFFFFFF


def _parse_cmp(instr: str):
    """解析cmp指令→(栈槽, 比较值)。双语法支持。
    Intel: cmp [rbp+0x18], 0x40 → ('rbp+0x18', 64)
    AT&T:  cmpl $0x40, 0x18(%rbp) → ('rbp+0x18', 64)"""
    # Intel: cmp [rbp+OFF], IMM
    m = re.search(r'cmp[lq]?\s+(?:dword|qword|word|byte)?\s*(?:ptr\s+)?'
                  r'\[(rbp[+\-]0x[0-9a-f]+)\]\s*,\s*(0x[0-9a-f]+|\d+)', instr)
    if m:
        return (_norm_offset(m.group(1)), _pint(m.group(2)))
    # AT&T: cmp[lq] $IMM, OFF(%rbp)
    m = re.search(r'cmp[lq]?\s+\$?(0x[0-9a-f]+|\d+)\s*,\s*'
                  r'([+\-]?0x[0-9a-f]+)\(%rbp\)', instr)
    if m:
        return (_norm_offset(m.group(2)), _pint(m.group(1)))
    # AT&T reversed: sometimes cmp[lq] OFF(%rbp), $IMM
    m = re.search(r'cmp[lq]?\s+([+\-]?0x[0-9a-f]+)\(%rbp\)\s*,\s*'
                  r'\$?(0x[0-9a-f]+|\d+)', instr)
    if m:
        return (_norm_offset(m.group(1)), _pint(m.group(2)))
    return (None, None)


def _pint(s: str) -> int:
    return int(s, 16) if '0x' in s.lower() else int(s)
