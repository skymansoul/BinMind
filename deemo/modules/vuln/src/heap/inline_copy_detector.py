"""内联拷贝循环检测 — 识别func_analyzer遗漏的堆写入 (字节循环/sprintf).

创建: 2026-06-10  自包含 — 接收指令+全局malloc列表, 返回memcpy兼容dict.
"""
from typing import Dict, List, Optional, Set, Tuple
from insn_parser import Instruction, extract_register


class InlineCopyDetector:
    """内联堆拷贝检测 — 栈追踪+跨函数感知."""

    MIN_LOOP_INSNS = 3

    def scan(self, insns: List[Instruction],
             global_mallocs: List[dict],
             function_name: str = "") -> List[dict]:
        """主入口 — global_mallocs为跨函数合并的malloc列表."""
        if not global_mallocs:
            return []
        self._heap_regs, self._stack_ptrs = self._track_heap_ptrs(
            insns, global_mallocs)
        if not self._heap_regs and not self._stack_ptrs:
            return []
        findings = []
        for loop in self._find_loops(insns):
            r = self._analyze_loop_body(insns, loop, function_name)
            if r:
                findings.append(r)
        findings.extend(self._detect_sprintf(insns, function_name))
        return findings

# malloc→寄存器/栈 追踪

    def _track_heap_ptrs(self, insns: List[Instruction],
                         mallocs: List[dict]) -> Tuple[Dict[str, int],
                                                       Dict[str, int]]:
        """追踪malloc返回值 → 寄存器 + 栈位置 (含跨函数入口参数)."""
        heap_regs: Dict[str, int] = {}
        stack_map: Dict[str, int] = {}
        malloc_addrs = {m['addr'] for m in mallocs}
        for i, insn in enumerate(insns):
            if insn.addr not in malloc_addrs:
                continue
            for j in range(i + 1, min(i + 6, len(insns))):
                nxt = insns[j]
                if nxt.mnemonic not in ('mov', 'movsxd'):
                    continue
                parts = nxt.operands.split(',')
                dst = parts[0].strip(); src = parts[-1].strip()
                if extract_register(src) != 'rax':
                    continue
                dst_r = extract_register(dst)
                if dst_r and '[' not in dst:
                    heap_regs[dst_r] = insn.addr
                elif '[' in dst:
                    off = self._stack_offset(dst)
                    if off is not None:
                        stack_map[off] = insn.addr
                break
        # 无本地malloc时追踪函数入口参数 (跨函数堆指针传播)
        if not heap_regs and not stack_map and mallocs:
            self._track_entry_params(insns, mallocs, heap_regs, stack_map)
        self._propagate_stack_reloads(insns, heap_regs, stack_map)
        self._propagate_regs(insns, heap_regs)
        return heap_regs, stack_map

    def _track_entry_params(self, insns: List[Instruction],
                             mallocs: List[dict],
                             heap_regs: Dict[str, int],
                             stack_map: Dict[str, int]) -> None:
        """函数入口参数追踪 — rcx/rdx/r8/r9→栈保存, 匹配全局malloc."""
        seen = set()
        for insn in insns[:15]:
            if insn.mnemonic not in ('mov', 'movsxd'):
                continue
            parts = insn.operands.split(',')
            dst, src = parts[0].strip(), parts[-1].strip()
            src_r = extract_register(src)
            if src_r not in ('rcx', 'rdx', 'r8', 'r9'):
                continue
            off = self._stack_offset(dst)
            if not off or 'rbp' not in off or off in seen:
                continue
            # 使用首个全局malloc为源 (跨函数时无法精确匹配, 取优先)
            stack_map[off] = mallocs[0]['addr']
            seen.add(off)

    def _propagate_stack_reloads(self, insns: List[Instruction],
                                  heap_regs: Dict[str, int],
                                  stack_map: Dict[str, int]) -> None:
        """mov reg, [rbp-offset] → 若offset在stack_map中则继承堆指针."""
        for insn in insns:
            if insn.mnemonic not in ('mov', 'movsxd'):
                continue
            parts = insn.operands.split(',')
            dst_r = extract_register(parts[0].strip())
            if not dst_r or '[' not in parts[-1].strip():
                continue
            off = self._stack_offset(parts[-1].strip())
            if off and off in stack_map and dst_r not in heap_regs:
                heap_regs[dst_r] = stack_map[off]

    def _propagate_regs(self, insns: List[Instruction],
                        heap_regs: Dict[str, int]) -> None:
        """mov/add传播堆寄存器别名."""
        for insn in insns:
            if insn.mnemonic not in ('mov', 'movsxd', 'add'):
                continue
            parts = insn.operands.split(',')
            dst_r = extract_register(parts[0].strip())
            src_r = extract_register(parts[-1].strip())
            if (dst_r and src_r and dst_r not in heap_regs
                    and src_r in heap_regs and '[' not in parts[0].strip()):
                heap_regs[dst_r] = heap_regs[src_r]

# 循环检测

    def _find_loops(self, insns: List[Instruction]) -> List[dict]:
        addr_idx = {insn.addr: i for i, insn in enumerate(insns)}
        loops = []
        for i, insn in enumerate(insns):
            if not insn.mnemonic.startswith('j') or insn.mnemonic == 'jmp':
                continue
            t = self._parse_int(insn.operands)
            if t is None or t >= insn.addr or t not in addr_idx:
                continue
            j = addr_idx[t]
            if i - j >= self.MIN_LOOP_INSNS:
                loops.append({
                    'header': t, 'header_idx': j, 'tail_idx': i,
                    'jcc': insn.mnemonic, 'body_range': (j, i + 1),
                })
        return loops

    def _analyze_loop_body(self, insns: List[Instruction],
                            loop: dict, fn_name: str) -> Optional[dict]:
        body = insns[loop['body_range'][0]:loop['body_range'][1]]
        heap_writes = self._find_heap_writes(body)
        if not heap_writes:
            return None
        hw = heap_writes[0]
        bound_val, bound_reg, idx_reg = self._extract_bound(body, loop)
        return {
            'addr': loop['header'], 'dst_reg': hw['base_reg'],
            'dst_val': f"malloc@{hw['malloc_addr']:x}",
            'size_reg': bound_reg or idx_reg or '',
            'size_val': bound_val, 'type': 'byte_loop',
            'function': fn_name,
            'off_by_one': loop.get('jcc', '') in ('jbe', 'jae'),
            'loop_jcc': loop.get('jcc', ''),
        }

    def _find_heap_writes(self, body: List[Instruction]) -> List[dict]:
        """在循环体中找堆写入 — mov [heap_reg+idx], ..."""
        derived = dict(self._heap_regs)
        for insn in body:
            if insn.mnemonic == 'add':
                parts = insn.operands.split(',')
                d_r = extract_register(parts[0].strip())
                s_r = extract_register(parts[-1].strip())
                if d_r and s_r and s_r in derived and d_r not in derived:
                    derived[d_r] = derived[s_r]
        writes = []
        for insn in body:
            if (insn.mnemonic != 'mov' or 'PTR' not in insn.operands
                    or '[' not in insn.operands):
                continue
            base = self._extract_base_reg(insn.operands.split(',')[0].strip())
            if base and base in derived:
                writes.append({'insn': insn, 'base_reg': base,
                               'malloc_addr': derived[base]})
        return writes

    def _extract_bound(self, body: List[Instruction],
                       loop: dict) -> Tuple[Optional[int], str, str]:
        bound_val, bound_reg, idx_reg = None, "", ""
        for insn in reversed(body):
            if insn.mnemonic == 'cmp':
                parts = insn.operands.replace(',', ' ').split()
                if len(parts) >= 2:
                    idx_reg = extract_register(parts[0]) or parts[0].strip()
                    try:
                        bound_val = int(parts[1], 0)
                    except ValueError:
                        bound_reg = extract_register(parts[1]) or parts[1].strip()
            elif insn.mnemonic == 'add' and not idx_reg:
                parts = insn.operands.split(',')
                try:
                    int(parts[-1].strip(), 0)
                    idx_reg = extract_register(parts[0].strip()) or ''
                except ValueError:
                    pass
        return bound_val, bound_reg, idx_reg

# IO写检测 (sprintf/fread/fgets → 堆缓冲区)

    _IO_WRITE_TARGETS = ('sprintf', 'snprintf', 'vsprintf',
                         'fread', 'fgets', 'fscanf', 'recv')

    def _detect_sprintf(self, insns: List[Instruction],
                        fn_name: str) -> List[dict]:
        findings = []
        rcx_heap = None
        for insn in insns:
            if insn.mnemonic == 'call':
                if rcx_heap is not None:
                    target = insn.operands.strip().lower()
                    if any(t in target for t in self._IO_WRITE_TARGETS):
                        findings.append({
                            'addr': insn.addr, 'dst_reg': 'rcx',
                            'dst_val': f"malloc@{rcx_heap:x}",
                            'size_reg': '', 'size_val': None,
                            'type': 'sprintf', 'function': fn_name,
                        })
                rcx_heap = None
                continue
            if insn.mnemonic in ('mov', 'movsxd', 'lea'):
                parts = insn.operands.split(',')
                if extract_register(parts[0].strip()) != 'rcx':
                    continue
                src = parts[-1].strip() if len(parts) > 1 else ''
                src_r = extract_register(src)
                if src_r and src_r in self._heap_regs:
                    rcx_heap = self._heap_regs[src_r]
                elif '[' in src:
                    off = self._stack_offset(src)
                    rcx_heap = self._stack_ptrs.get(off) if off else None
                else:
                    rcx_heap = None
            elif insn.mnemonic in ('add', 'sub', 'xor'):
                rcx_heap = None
        return findings

# 工具

    @staticmethod
    def _extract_base_reg(mem_op: str) -> Optional[str]:
        s = _strip_size_prefix(mem_op)
        if not (s.startswith('[') and ']' in s):
            return None
        inner = s[s.index('[') + 1:s.index(']')]
        for p in inner.replace('+', ' ').replace('-', ' ').split():
            r = extract_register(p)
            if r:
                return r
        return extract_register(inner)

    @staticmethod
    def _stack_offset(mem_op: str) -> Optional[str]:
        s = _strip_size_prefix(mem_op)
        if not (s.startswith('[') and ']' in s):
            return None
        inner = s[s.index('[') + 1:s.index(']')]
        parts = inner.replace('+', ' +').replace('-', ' -').split()
        for i, p in enumerate(parts):
            r = extract_register(p.strip())
            if r not in ('rbp', 'rsp'):
                continue
            for j, adj in enumerate(parts):
                if j == i:
                    continue
                adj = adj.strip()
                if adj.startswith(('+', '-', '0x')) or adj.lstrip('-').isdigit():
                    return f"{r}{adj}"
            return f"{r}+0x0"
        return None

    @staticmethod
    def _parse_int(s: str) -> Optional[int]:
        token = s.strip().split()[0]
        if len(token) >= 5 and all(c in '0123456789abcdefABCDEF' for c in token):
            try:
                return int(token, 16)
            except (ValueError, TypeError):
                pass
        try:
            return int(token, 0)
        except (ValueError, TypeError):
            return None


def _strip_size_prefix(s: str) -> str:
    """去除objdump尺寸前缀 — QWORD PTR [rbp-0x8] → [rbp-0x8]."""
    s = s.strip()
    for prefix in ('QWORD PTR ', 'DWORD PTR ', 'WORD PTR ', 'BYTE PTR ',
                   'XMMWORD PTR ', 'OWORD PTR '):
        if s.startswith(prefix):
            return s[len(prefix):]
    return s
