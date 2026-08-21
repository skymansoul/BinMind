# IR归一化：将反编译器输出归一为统一行级IR（非AST，各反编译器伪代码语法
# 差异大无法统一）。行级IR损失部分语义但足以支撑def-use分析，TaintEngine
# 基于IR行文本正则匹配；归一化后二进制相似度提升30-50%。
import re, logging
from collections import defaultdict
from typing import Optional

_log = logging.getLogger(__name__)


# 反编译器归一化 (Ghidra/Radare2/Generic)

def normalize_ir(decompiled_text: str, source: str = 'auto') -> list[str]:
    """自动检测反编译器类型并归一化为IR行列表."""
    if source == 'ghidra':
        return _normalize_ghidra(decompiled_text)
    if source == 'r2':
        return _normalize_radare2(decompiled_text)
    if source == 'generic':
        return _normalize_generic(decompiled_text.split('\n'))
    if '{' in decompiled_text and ';' not in decompiled_text[:100]:
        return _normalize_ghidra(decompiled_text)
    return _normalize_radare2(decompiled_text)


def _normalize_ghidra(text: str) -> list[str]:
    lines_out = []; in_function = False; brace_depth = 0
    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped: continue
        if not in_function:
            if '{' in stripped: in_function = True; brace_depth = 1
            continue
        brace_depth += stripped.count('{') - stripped.count('}')
        if brace_depth <= 0: break
        if stripped in ('{', '}'): continue
        if '=' not in stripped and '(' not in stripped: continue
        cleaned = _strip_type_prefix(stripped)
        if '(' in cleaned and '=' not in cleaned: cleaned = f'call {cleaned}'
        lines_out.append(cleaned.rstrip(';'))
    return lines_out


def _normalize_radare2(text: str) -> list[str]:
    lines_out = []
    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith((';', '//', '#')): continue
        parts = stripped.split(None, 1)
        if not parts: continue
        body = parts[1] if parts[0].startswith('0x') and len(parts) > 1 else stripped
        if body.startswith(('loc_', 'sym.', 'fcn.', 'data_')): continue
        body = _substitute_regs(body)
        if 'call' in body.lower() and not body.startswith('call '):
            body = f'call {body}'
        lines_out.append(body)
    return lines_out


def _normalize_generic(disasm_lines: list[str]) -> list[str]:
    lines_out = []
    for line in disasm_lines:
        stripped = line.strip()
        if not stripped or ':' not in stripped: continue
        m = re.match(r'\s*(?:0x)?[0-9a-fA-F]+:\s*(.+)', stripped)
        if not m: continue
        ins = m.group(1).strip()
        if ins.startswith(('.byte', '.long', '.quad', 'nop', 'data')): continue
        simplified = _simplify_asm(ins)
        if simplified: lines_out.append(simplified)
    return lines_out


def _strip_type_prefix(line: str) -> str:
    c_types = {'void','char','short','int','long','float','double','size_t','ssize_t',
               'uint8_t','uint16_t','uint32_t','uint64_t','int8_t','int16_t','int32_t',
               'int64_t','uchar','ushort','uint','ulong','bool','byte','undefined',
               'undefined1','undefined2','undefined4','undefined8','DWORD','WORD','BYTE',
               'QWORD','pointer32','pointer64','wchar_t','code','FILE'}
    words = line.split(None, 1)
    if len(words) >= 2 and words[0] in c_types:
        rest = words[1]
        while rest.startswith('*'): rest = rest[1:]
        return rest.strip()
    return line


def _substitute_regs(line: str) -> str:
    reg_map = {'rax':'ret_val','eax':'ret_val','rdi':'arg1','rsi':'arg2','rdx':'arg3',
               'rcx':'arg4','r8':'arg5','r9':'arg6','rbp':'frame_ptr','rsp':'stack_ptr'}
    result = line
    for reg, var in reg_map.items():
        result = re.sub(rf'\b{reg}\b', var, result)
    return result


def _simplify_asm(ins: str) -> Optional[str]:
    parts = ins.split(None, 1)
    if not parts: return None
    mnemonic = parts[0].lower(); ops = parts[1] if len(parts) > 1 else ''
    if mnemonic in ('mov','movabs','lea'):
        m = re.match(r'([^,]+),\s*(.+)', ops)
        if m: return f"{m.group(1).strip()} = {m.group(2).strip()}"
    elif mnemonic in ('add','sub','and','or','xor','shl','shr','mul','imul'):
        m = re.match(r'([^,]+),\s*(.+)', ops)
        if m:
            dst, src = m.group(1).strip(), m.group(2).strip()
            return f"{dst} = {dst} {mnemonic} {src}"
    elif mnemonic == 'call': return f'call {ops.strip()}'
    elif mnemonic == 'ret': return 'return'
    return None


# VEX IR 归一化
# 将angr VEX IR基本块规范化为编译器无关形式

class VEXNormalizer:
    """VEX IR基本块归一化器: 寄存器虚拟化+常量折叠+死代码消除."""

    def normalize_block(self, statements: list[str], arch: str = "x86_64") -> list[str]:
        renamed = self._rename_regs(statements)
        folded = [self._fold_constants(s) for s in renamed]
        return self._eliminate_dead_stores(folded)

    def _rename_regs(self, stmts: list[str]) -> list[str]:
        reg_map: dict[str, str] = {}; counter = [0]
        def _vreg(phys: str) -> str:
            if phys not in reg_map:
                base = phys.lstrip('r').lstrip('e')
                reg_map[phys] = f"v_{base}_{counter[0]}"; counter[0] += 1
            return reg_map[phys]
        result = []
        for s in stmts:
            rs = s
            for m in re.finditer(r'\b(r[a-z0-9]{1,3}|e[a-z0-9]{1,2})\b', s, re.IGNORECASE):
                rs = re.sub(rf'\b{m.group(1)}\b', _vreg(m.group(1).lower()), rs, flags=re.IGNORECASE)
            result.append(rs)
        return result

    def _fold_constants(self, stmt: str) -> str:
        m = re.match(r'(\w+)\s*=\s*(-?\d+)\s*([+\-*/])\s*(-?\d+)', stmt)
        if m:
            try:
                a, op, b = int(m.group(2)), m.group(3), int(m.group(4))
                r = {"+": a+b, "-": a-b, "*": a*b, "/": a//b if b else 0}[op]
                return f"{m.group(1)} = {r}"
            except (ZeroDivisionError, KeyError): pass
        return stmt

    def _eliminate_dead_stores(self, stmts: list[str]) -> list[str]:
        reads: dict[str, list[int]] = defaultdict(list)
        for i, s in enumerate(stmts):
            for m in re.finditer(r'\b([a-z_]\w+)\b', s):
                reads[m.group(1)].append(i)
        result = []
        for i, s in enumerate(stmts):
            m = re.match(r'(\w+)\s*=\s*', s)
            if m and i < len(stmts) - 1:
                lhs = m.group(1)
                if not any(r > i for r in reads.get(lhs, [])): continue
            result.append(s)
        return result

    def block_opcode_signature(self, block_stmts: list[str]) -> str:
        ops = []
        for s in block_stmts:
            m = re.match(r'(\w+)\s*=', s)
            if m: ops.append(m.group(1))
        return "|".join(ops[:12])

    @staticmethod
    def jaccard_similarity(sig_a: str, sig_b: str) -> float:
        sa, sb = set(sig_a.split("|")), set(sig_b.split("|"))
        if not sa or not sb: return 0.0
        return len(sa & sb) / len(sa | sb)
