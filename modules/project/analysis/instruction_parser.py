# 指令解析器 — x86-64 Intel语法汇编指令行解析
# 职责: parse_line, 寄存器工具函数, lea/mem解析,
#   parse_mem_slot (栈槽位解析), trace_reg_to_source_slot (寄存器→栈槽溯源)
import re
from typing import Dict, List, Optional, Set, Tuple

class InstructionParser:
    """x86-64 指令流解析器 (Intel语法, objdump -M intel输出)."""

    # Intel语法的大小前缀模式
    _SIZE_PREFIX_RE = re.compile(
        r'\b(BYTE|WORD|DWORD|QWORD|XMMWORD|YMMWORD|OWORD)\s+PTR\s+',
        re.IGNORECASE)

    @staticmethod
    def parse_line(line: str) -> Optional[Tuple[str, List[str]]]:
        """解析单行指令. 返回 (操作码, [操作数...]) 或 None.

        对call指令, 若目标包含<name>格式, 将函数名替换为操作数.
        """
        line = line.strip()
        if not line or line[0] in '#;.':
            return None
        # 去除标签 (label:)
        if ':' in line[:30] and not line.startswith(' '):
            line = line.split(':', 1)[1].strip()
            if not line:
                return None
        # 去除Intel大小前缀 (QWORD PTR 等)
        # 保留原始行用于call解析
        clean_line = InstructionParser._SIZE_PREFIX_RE.sub('', line)
        # 分词: 替换逗号为空格后分割
        parts = clean_line.replace(',', ' ').split()
        if not parts:
            return None
        op = parts[0]
        operands = parts[1:]
        # call指令的目标解析: 提取<name>中的函数名作为操作数
        # objdump Intel格式: call ADDR <name> 或 call <name>
        if op == 'call' and operands:
            # 在所有操作数中搜索<name>模式
            fn_name = None
            for j, operand in enumerate(operands):
                m = re.search(r'<([\w@.]+)>', operand)
                if m:
                    fn_name = m.group(1)
                    if '@' in fn_name:
                        fn_name = fn_name.split('@')[0]
                    break
            if fn_name is not None:
                operands = [fn_name]
            else:
                # 无<name>标记: 检查是否是"address  <name>"分两个token的情况
                for j in range(len(operands)):
                    if operands[j].startswith('<') and operands[j].endswith('>'):
                        inner = operands[j][1:-1]
                        operands = [inner.split('@')[0]]
                        break
        return op, operands

    # 32→64位寄存器映射: mov r8d,imm 实际影响整个r8
    _REG32_TO_64 = {
        'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx',
        'esi':'rsi','edi':'rdi','esp':'rsp','ebp':'rbp',
        'r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11',
        'r12d':'r12','r13d':'r13','r14d':'r14','r15d':'r15',
    }

    @staticmethod
    def is_reg(s: str) -> bool:
        s = s.strip()
        if s in InstructionParser._REG32_TO_64:
            return True
        return bool(re.match(
            r'^(r[abcd]x|r[sd]i|r[bs]p|r\d+[d]?|e[abcd]x|e[sd]i|e[bs]p)$',
            s))

    @staticmethod
    def clean_reg(s: str) -> str:
        return s.strip().strip('[]').strip()

    @staticmethod
    def normalize_reg64(s: str) -> str:
        """将32位寄存器名映射为64位 (mov r8d, 0x100 影响 r8)."""
        s = s.strip()
        return InstructionParser._REG32_TO_64.get(s, s)

    @staticmethod
    def reg_bit_width(reg: str) -> int:
        """返回寄存器位宽: rax→64, eax→32, ax→16, al→8, r8d→32."""
        r = reg.lower().strip()
        if re.match(r'^r([abcd]x|[sd]i|[bs]p|8|9|1[0-5])$', r):
            return 64       # rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15
        if re.match(r'^(e[abcd]x|e[sd]i|e[bs]p|r\d+d)$', r):
            return 32       # eax, ebx, ecx, edx, esi, edi, ebp, esp, r8d-r15d
        if re.match(r'^([abcd]x|[bs]p|[sd]i|r\d+w)$', r):
            return 16       # ax, bx, cx, dx, bp, sp, si, di, r8w-r15w
        if re.match(r'^([abcd][lh]|[bs]pl|[sd]il|r\d+b)$', r):
            return 8        # al, ah, bl, bh, cl, ch, dl, dh, spl, bpl, sil, dil, r8b-r15b
        return 0

    @staticmethod
    def parse_immediate(s: str) -> Optional[int]:
        s = s.strip()
        try:
            return int(s, 16) if s.startswith('0x') else int(s)
        except ValueError:
            return None

    # [DEPRECATED] _locate 已迁移至 loop_trip_extractors.locate_operand
    # (本会话新增后即迁移, 待确认删除)

    @staticmethod
    def parse_mem(s: str) -> Tuple[str, int]:
        """解析 [base+offset] 返回 (base, offset)."""
        s = s.strip()
        if s.startswith('[') and s.endswith(']'):
            inner = s[1:-1]
            m = re.match(r'(\w+)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)', inner)
            if m:
                base = m.group(1)
                sign = 1 if m.group(2) == '+' else -1
                off = m.group(3)
                return base, sign * (
                    int(off, 16) if off.startswith('0x') else int(off))
            m = re.match(r'(\w+)', inner)
            if m:
                return m.group(1), 0
        return "", 0

    # 内存写入大小前缀映射
    _MEM_WRITE_SIZES = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8}

    @staticmethod
    def parse_mem_write(line: str) -> Optional[Tuple[int, str]]:
        """检测内存写入指令并提取写大小和目标基址寄存器.

        识别模式:
          mov [BYTE/WORD/DWORD/QWORD] PTR [base+...], val
        返回 (write_size_bytes, base_register) 或 None.
        """
        line = line.strip()
        if not line.startswith('mov '):
            return None
        # 检查是否有大小前缀
        size_m = re.match(
            r'mov\s+(BYTE|WORD|DWORD|QWORD)\s+PTR\s+',
            line, re.IGNORECASE)
        if not size_m:
            # 检查是否是 [reg+...] 格式的目标 (无显式大小前缀)
            # mov [rax+rdx], dl — 无显式PTR前缀, 但目标是内存
            m2 = re.match(r'mov\s+\[(\w+)', line, re.IGNORECASE)
            if m2:
                # 根据源操作数大小推断
                parts = line.replace(',', ' ').split()
                if len(parts) >= 3:
                    src = parts[-1]
                    if len(src) <= 3:  # al, dl, cl, bl, sil, dil等
                        return (1, m2.group(1))
                    elif len(src) == 3 and src[1] == 'l':
                        return (1, m2.group(1))
                    elif len(src) <= 4:
                        return (2, m2.group(1))
                    elif len(src) <= 5 and 'e' in src:
                        return (4, m2.group(1))
                    else:
                        return (8, m2.group(1))
            return None
        size_name = size_m.group(1).upper()
        write_size = InstructionParser._MEM_WRITE_SIZES.get(size_name)
        if write_size is None:
            return None
        # 提取目标操作数: mov SIZE PTR [base+...], val 中的 [base+...]
        rest = line[size_m.end():]
        # 找到逗号前的内容 (目标操作数)
        comma_pos = rest.find(',')
        if comma_pos < 0:
            # 可能逗号在方括号内, 找到最后的不在[]内的逗号
            depth = 0
            for i, ch in enumerate(rest):
                if ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    comma_pos = i
                    break
        dst_str = rest[:comma_pos].strip() if comma_pos >= 0 else rest.strip()
        # 去除方括号
        if dst_str.startswith('[') and dst_str.endswith(']'):
            dst_str = dst_str[1:-1]
        # 提取第一个寄存器作为基址
        m = re.match(r'(\w+)', dst_str)
        if m:
            base = m.group(1)
            # 验证是否是寄存器
            if InstructionParser.is_reg(base) or re.match(
                    r'^(r[abcd]x|r[sd]i|r[bs]p|r\d+[d]?|e[abcd]x|e[sd]i|e[bs]p)$',
                    base):
                return (write_size, base)
        return None

    @staticmethod
    def parse_lea_src(s: str) -> Tuple[str, int, str, int]:
        """解析 lea 源操作数 [base + idx*scale + offset].

        Repair: 原先只提取base寄存器, 完全忽略了offset部分.
        对于lea rcx,[rax+0x4]这种关键模式, offset=0x4被丢弃,
        导致07_struct_field等结构体字段偏移无法追踪.
        """
        s = s.strip()
        if s.startswith('[') and s.endswith(']'):
            inner = s[1:-1]
            base, off, idx, scale = "", 0, "", 1
            parts = re.split(r'([+\-])', inner)
            if not parts:
                return "", 0, "", 1
            # 处理第一个token: base或index*scale
            first = parts[0].strip()
            if '*' in first:
                # 格式: index*scale
                idx_scale = first.split('*')
                idx = idx_scale[0].strip()
                try:
                    scale = int(idx_scale[1].strip())
                except (ValueError, IndexError):
                    scale = 1
            else:
                m = re.match(r'(\w+)', first)
                if m:
                    base = m.group(1)
            # 处理 sign + offset 对
            i = 1
            while i + 1 < len(parts):
                sign_str = parts[i].strip()
                val_str = parts[i + 1].strip()
                sign = 1 if sign_str == '+' else -1
                try:
                    val = int(val_str, 16) if val_str.startswith('0x') else int(val_str)
                    off += sign * val
                except ValueError:
                    pass
                i += 2
            return base, off, idx, scale
        return "", 0, "", 1

    @staticmethod
    def parse_mem_slot(text: str) -> Optional[int]:
        """解析 [rbp±offset] 模式, 返回偏移值或None."""
        m = re.search(
            r'\[rbp\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)\]',
            text, re.IGNORECASE)
        if m:
            sign = 1 if m.group(1) == '+' else -1
            val_str = m.group(2)
            val = (int(val_str, 16) if 'x' in val_str.lower()
                   else int(val_str))
            return sign * val
        # clean_reg剥离方括号后的 rbp±X 形式
        m = re.search(r'\brbp\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)\b', text, re.IGNORECASE)
        if m:
            sign = 1 if m.group(1) == '+' else -1
            val_str = m.group(2)
            return sign * (int(val_str, 16) if 'x' in val_str.lower() else int(val_str))
        return None

    @staticmethod
    def trace_reg_to_source_slot(write_idx: int,
                                  instructions: List[str],
                                  reg: str) -> Optional[int]:
        """反向追踪寄存器→源栈槽位.

        从write_idx向前扫描mov/movsxd链, 直到找到[rbp±slot]加载.
        返回栈槽偏移或None.
        """
        current_reg = reg
        scan_end = max(0, write_idx - 15)
        for i in range(write_idx - 1, scan_end - 1, -1):
            parsed = InstructionParser.parse_line(instructions[i])
            if parsed is None:
                continue
            op, ops = parsed
            if op in ('mov', 'movsxd') and len(ops) >= 2:
                dst64 = InstructionParser.normalize_reg64(
                    InstructionParser.clean_reg(ops[0].strip()))
                if dst64 == current_reg:
                    src_raw = ops[1].strip()
                    slot = InstructionParser.parse_mem_slot(src_raw)
                    if slot is not None:
                        return slot
                    if InstructionParser.is_reg(src_raw):
                        current_reg = InstructionParser.normalize_reg64(
                            InstructionParser.clean_reg(src_raw))
                        continue
                    return None
        return None


from .propagation_coordinator import PropagationCoordinator  # noqa: F401
