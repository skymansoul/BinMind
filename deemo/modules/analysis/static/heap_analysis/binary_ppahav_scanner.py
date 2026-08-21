"""二进制级 PPA-HAV 扫描器 - objdump 反汇编 → 五层过滤管线.

管线: 指令解析 → malloc识别 → 寄存器溯源 → 对象结构学习 → 三维验证 → 过滤
输入: objdump -d -M intel 文本
输出: (real_vulnerabilities, filtered_false_positives, stats)

设计决策:
  - 仅依赖 objdump, 不读源码/符号/调试信息
  - 保守: 无法确定寄存器来源 → 保留告警, 不冒险过滤
  - 跨函数限制为单函数内 (调用图分析留待后续)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from .provenance_aware_filter import ProvenanceAwareFilter


# 堆分配函数
_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_Znwm', '_Znam',
                'g_malloc', 'g_malloc0', 'g_try_malloc'}
# 危险写入函数
_DANGEROUS_CALLS = {'memcpy', 'memmove', 'strcpy', 'strncpy', 'sprintf',
                    'snprintf', 'gets', 'read', 'fread', 'recv',
                    '__memcpy_chk', '__strcpy_chk'}

# x86_64 调用约定寄存器映射 (arg_n → 寄存器名)
# System V AMD64 (Linux): arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
# Microsoft x64 (Windows):  arg0=rcx, arg1=rdx, arg2=r8,  arg3=r9
_CC_SYSV   = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
_CC_WIN64  = ['rcx', 'rdx', 'r8',  'r9']
# 需要检查 arg0 (大小) 的分配函数
# 对于 malloc(size): Linux → rdi, Windows → rcx
# 对于 calloc(nmemb, size): Linux → rdi/rsi, Windows → rcx/rdx


@dataclass
class BinaryScanResult:
    sample_name: str
    total_instructions: int = 0
    mallocs_found: int = 0
    heap_writes_found: int = 0
    dangerous_calls_found: int = 0
    real_vulnerabilities: List[dict] = field(default_factory=list)
    filtered_false_positives: List[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str = ""


class BinaryPpahavScanner:
    """二进制 PPA-HAV 五层扫描器 - 从 objdump 输出执行完整管线."""

    def __init__(self):
        self._ppa = ProvenanceAwareFilter()
        self._insns: List[ParsedInstruction] = []
        self._alloc_sizes: Dict[int, int] = {}       # addr → size
        self._heap_writes: List[Tuple[int, int, int]] = []  # (addr, off, sz)
        self._danger_sites: List[Tuple[int, str, str, int]] = []  # (addr,fn,reg,sz)

    def scan(self, objdump_output: str,
             sample_name: str = "",
             user_code_only: bool = True,
             functions: Optional[List[str]] = None) -> BinaryScanResult:
        import time
        t0 = time.perf_counter()
        try:
            all_insns = InstructionParser.parse(objdump_output)
        except Exception as e:
            return BinaryScanResult(sample_name=sample_name, error=str(e))
        if not all_insns:
            return BinaryScanResult(sample_name=sample_name,
                                    error="no instructions")

        # 过滤到指定函数 或 用户函数
        if functions:
            funcs = InstructionParser.parse_functions(objdump_output)
            func_addrs = sorted(funcs.keys())
            ranges = []
            for i, start_addr in enumerate(func_addrs):
                if funcs[start_addr] in functions:
                    end_addr = (func_addrs[i + 1] if i + 1 < len(func_addrs)
                                else 0xFFFFFFFFFFFFFFFF)
                    ranges.append((start_addr, end_addr))
            if ranges:
                self._insns = [ins for ins in all_insns
                               if any(s <= ins.address < e for s, e in ranges)]
            else:
                self._insns = all_insns
        elif user_code_only:
            funcs = InstructionParser.parse_functions(objdump_output)
            self._insns = InstructionParser.filter_user_instructions(
                all_insns, funcs)
            if not self._insns:
                self._insns = all_insns
        else:
            self._insns = all_insns

        self._find_allocs()
        self._find_writes_and_dangers()
        self._track_reg_flow()
        self._learn_structure()
        self._ppa.finalize_analysis()
        real, filtered = self._validate()

        return BinaryScanResult(
            sample_name=sample_name,
            total_instructions=len(self._insns),
            mallocs_found=len(self._alloc_sizes),
            heap_writes_found=len(self._heap_writes),
            dangerous_calls_found=len(self._danger_sites),
            real_vulnerabilities=real,
            filtered_false_positives=filtered,
            stats=self._ppa.stats(),
            elapsed_ms=(time.perf_counter() - t0) * 1000)

    # Layer 1: 分配点识别

    def _find_allocs(self):
        for i, ins in enumerate(self._insns):
            if ins.mnemonic != "call":
                continue
            callee = InstructionParser.extract_callee(ins)
            if callee not in _ALLOC_FUNCS:
                continue
            # 尝试两种调用约定 (Linux sysv: rdi, Windows x64: rcx)
            size = (self._prev_imm(i, {'rdi', 'edi'})
                 or self._prev_imm(i, {'rcx', 'ecx'}) or 0)
            is_calloc = 'calloc' in callee
            self._alloc_sizes[ins.address] = size
            # 直接设置 rax 为返回值 (而非通过 track_malloc 的 ptr_reg 参数)
            self._ppa._prov_tracker.register_malloc(
                ins.address, callee, "rax", size, is_calloc=is_calloc)
            self._ppa._obj_model.create_object(
                f"alloc@{hex(ins.address)}", alloc_size=size,
                usable_size=self._ppa._compute_usable(size))

    # Layer 2: 危险调用 + 堆写入识别

    def _find_writes_and_dangers(self):
        for i, ins in enumerate(self._insns):
            if ins.mnemonic == "call":
                callee = InstructionParser.extract_callee(ins)
                if callee in _DANGEROUS_CALLS:
                    # dest: Linux arg0=rdi / Windows arg0=rcx
                    dest = (self._arg_reg(i, 0, _CC_SYSV)
                         or self._arg_reg(i, 0, _CC_WIN64) or "rdi")
                    # size: Linux arg2=rdx / Windows arg2=r8
                    size_val = (self._arg_imm(i, 2, _CC_SYSV)
                             or self._arg_imm(i, 2, _CC_WIN64) or 0)
                    self._danger_sites.append(
                        (ins.address, callee, dest, size_val))
                continue

            if ins.mnemonic != "mov" or len(ins.operands) < 2:
                continue
            dest_op = ins.operands[0]
            reg, offset = InstructionParser.parse_memory_operand(dest_op)
            if reg is None:
                continue
            sz = InstructionParser.infer_access_size(ins)
            self._heap_writes.append((ins.address, offset, sz))

    # Layer 3: 寄存器传播追踪

    def _track_reg_flow(self):
        for ins in self._insns:
            mn, ops = ins.mnemonic, ins.operands
            if mn == "mov" and len(ops) >= 2:
                dst = InstructionParser.normalize_reg(ops[0])
                src = InstructionParser.normalize_reg(ops[1])
                if dst and src and dst != src:
                    if not InstructionParser.is_immediate(ops[1]):
                        self._ppa.track_assign(ins.address, dst, src)
            elif mn == "lea" and len(ops) >= 2:
                dst = InstructionParser.normalize_reg(ops[0])
                base, off = InstructionParser.parse_memory_operand(ops[1])
                if dst and base and off != 0:
                    self._ppa.track_arithmetic(ins.address, dst, base, off)
            elif mn in ("add", "sub") and len(ops) >= 2:
                dst = InstructionParser.normalize_reg(ops[0])
                if dst and InstructionParser.is_immediate(ops[1]):
                    val = int(ops[1].strip(), 0) * (-1 if mn == "sub" else 1)
                    self._ppa.track_arithmetic(ins.address, dst, dst, val)
            elif mn == "push" and ops:
                r = InstructionParser.normalize_reg(ops[0])
                if r:
                    self._ppa._prov_tracker.track_stack_save(ins.address, r)
            elif mn == "pop" and ops:
                r = InstructionParser.normalize_reg(ops[0])
                if r:
                    self._ppa._prov_tracker.track_stack_restore(ins.address, r)

    # Layer 4: 对象结构学习

    def _learn_structure(self):
        for addr, offset, size in self._heap_writes:
            self._ppa.track_field_access(addr, "rax", offset, size, "write")

    # Layer 5: 验证 + 过滤

    def _validate(self) -> Tuple[List[dict], List[dict]]:
        real, filtered = [], []
        for addr, func, dest_reg, size_val in self._danger_sites:
            alloc_size, usable = self._nearest_alloc(addr)
            if alloc_size is None:
                real.append(self._mk_finding(addr, func, dest_reg, size_val,
                                             0, 0, "no nearby malloc", 0.40))
                continue
            if size_val > 0 and size_val <= usable:
                filtered.append(self._mk_finding(addr, func, dest_reg,
                    size_val, alloc_size, usable,
                    f"write({size_val}) <= usable({usable})", 0.0, True))
                continue
            conf = 0.85 if size_val > usable else 0.50
            real.append(self._mk_finding(addr, func, dest_reg, size_val,
                alloc_size, usable,
                f"{func} write({size_val}) vs alloc({alloc_size})", conf))
        return real, filtered

    # 辅助

    def _prev_imm(self, idx: int, regs: Set[str]) -> Optional[int]:
        for j in range(idx - 1, max(0, idx - 10), -1):
            p = self._insns[j]
            if p.mnemonic not in ("mov", "movabs") or len(p.operands) < 2:
                continue
            if InstructionParser.normalize_reg(p.operands[0]) in regs:
                try:
                    return int(p.operands[1].strip(), 0)
                except ValueError:
                    return None
        return None

    def _arg_reg(self, idx: int, arg_n: int,
                 regs: Optional[List[str]] = None) -> Optional[str]:
        if regs is None:
            regs = _CC_SYSV
        if arg_n >= len(regs):
            return None
        target = regs[arg_n]
        for j in range(idx - 1, max(0, idx - 20), -1):
            p = self._insns[j]
            if p.mnemonic not in ("mov", "movabs", "lea") or len(p.operands) < 2:
                continue
            if InstructionParser.normalize_reg(p.operands[0]) == target:
                src = p.operands[1].strip()
                r = InstructionParser.normalize_reg(src)
                if r:
                    return r
                br, _ = InstructionParser.parse_memory_operand(src)
                if br:
                    return br
        return None

    def _arg_imm(self, idx: int, arg_n: int,
                 regs: Optional[List[str]] = None) -> Optional[int]:
        if regs is None:
            regs = _CC_SYSV
        if arg_n >= len(regs):
            return None
        target = regs[arg_n]
        # 首先直接查找 imm 值
        for j in range(idx - 1, max(0, idx - 20), -1):
            p = self._insns[j]
            if p.mnemonic not in ("mov", "movabs") or len(p.operands) < 2:
                continue
            if InstructionParser.normalize_reg(p.operands[0]) == target:
                try:
                    return int(p.operands[1].strip(), 0)
                except ValueError:
                    break  # 找到了寄存器赋值, 尝试链式追踪
        # 链式追踪: 穿越寄存器赋值查找 imm 源头
        return self._chain_find_imm(idx, target)

    def _chain_find_imm(self, call_idx: int, target: str, max_hops: int = 5) -> Optional[int]:
        """沿寄存器赋值链反向追踪, 查找立即数源头. 最多 max_hops 跳."""
        seen = {target}
        current_target = target
        start = call_idx - 1
        for _ in range(max_hops):
            found = False
            for j in range(start, max(0, start - 50), -1):
                p = self._insns[j]
                if p.mnemonic not in ("mov", "movabs") or len(p.operands) < 2:
                    continue
                if InstructionParser.normalize_reg(p.operands[0]) == current_target:
                    src = p.operands[1].strip()
                    try:
                        return int(src, 0)
                    except ValueError:
                        next_reg = InstructionParser.normalize_reg(src)
                        if next_reg and next_reg not in seen:
                            seen.add(next_reg)
                            current_target = next_reg
                            start = j - 1
                            found = True
                            break
                        # 内存操作数或已见寄存器 → 无法继续追踪, 放弃
                        return None
            if not found:
                break
        return None

    def _nearest_alloc(self, addr: int) -> Tuple[Optional[int], int]:
        best_addr, best_sz = None, None
        for a, sz in sorted(self._alloc_sizes.items()):
            if a < addr:
                best_addr, best_sz = a, sz
            else:
                break
        if best_addr is None:
            return None, 0
        return best_sz, self._ppa._compute_usable(best_sz or 0)

    @staticmethod
    def _mk_finding(addr, func, reg, write_sz, alloc_sz, usable,
                    reason, conf, filtered=False):
        return {
            "type": "heap_overflow", "subtype": "binary_ppahav",
            "insn_addr": addr, "function": func,
            "ptr_register": reg, "write_size": write_sz,
            "alloc_size": alloc_sz, "usable_size": usable,
            "overflow_by": max(0, write_sz - usable),
            "reason": reason, "confidence": conf, "filtered": filtered,
        }


# smoke test
def _check():
    asm = """
    1000:       48 c7 c7 40 00 00 00    mov    rdi,0x40
    1007:       e8 f4 fe ff ff          call   1000 <malloc@plt>
    100c:       48 89 c3                mov    rbx,rax
    100f:       48 c7 c2 00 01 00 00    mov    rdx,0x100
    1016:       48 89 df                mov    rdi,rbx
    1019:       e8 e2 fe ff ff          call   1000 <memcpy@plt>
    """
    s = BinaryPpahavScanner()
    r = s.scan(asm, "test")
    assert r.mallocs_found >= 1, f"malloc: {r.mallocs_found}"
    assert r.dangerous_calls_found >= 1, f"dangers: {r.dangerous_calls_found}"
    print(f"[OK] binary_ppahav_scanner: insns={r.total_instructions} "
          f"mallocs={r.mallocs_found} dangers={r.dangerous_calls_found} "
          f"real={len(r.real_vulnerabilities)} filtered={len(r.filtered_false_positives)}")


if __name__ == "__main__":
    _check()
