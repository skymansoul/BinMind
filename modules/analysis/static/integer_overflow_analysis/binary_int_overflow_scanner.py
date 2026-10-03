"""二进制级整数溢出扫描器 - objdump → imul/shl 追踪 → malloc 欠分配检测.

I-GUARD: 二进制级检测 imul/shl 结果无 overflow check 直接流入 malloc,
导致分配大小远小于预期 → 后续 memcpy 堆溢出.
检测: imul/shl→mov chain→call malloc | 栈暂存传播 | add/sub 链
方法: I-GUARD 符号性追踪 - imul/shl 结果流入分配函数的欠分配判定.
创建: 2024-07-02
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ..heap_analysis.instruction_parser import InstructionParser, ParsedInstruction
from .cross_func_int_overflow_tracker import CrossFuncIntOverflowTracker


@dataclass
class IntOverflowFinding:
    insn_addr: int          # call malloc 的地址
    alloc_func: str         # 分配函数名
    overflow_kind: str      # "imul" | "shl" | "add_chain"
    reg_at_alloc: str       # 分配时的参数寄存器
    reason: str
    confidence: float


class BinaryIntOverflowScanner:
    """二进制级整数溢出扫描器 - I-GUARD 引擎.

    使用方式:
      scanner = BinaryIntOverflowScanner()
      findings = scanner.scan(objdump_text)
    """

    ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'reallocarray',
                   '_Znwm', '_Znam', 'g_malloc', 'ExAllocatePoolWithTag'}
    OVERFLOW_OPS = {'imul', 'mul', 'shl', 'sal'}
    CHAIN_OPS = {'add', 'sub'}

    def __init__(self):
        self._findings: List[IntOverflowFinding] = []
        self._insns: List[ParsedInstruction] = []
        self._reg_taint: Dict[str, Tuple[str, int]] = {}
        self._stack_taint: Dict[str, Tuple[str, int]] = {}
        self._cross_tracker = CrossFuncIntOverflowTracker()
        self._tainted_returns: Set[str] = set()

    def scan(self, objdump_output: str, sample_name: str = "",
             user_code_only: bool = True,
             functions: Optional[Dict[int, str]] = None) -> List[dict]:
        self._findings.clear()
        self._reg_taint.clear()
        self._stack_taint.clear()

        insns = InstructionParser.parse(objdump_output)
        if not insns:
            return []

        if user_code_only:
            if functions is None:
                functions = InstructionParser.parse_functions(objdump_output)
            insns = InstructionParser.filter_user_instructions(insns, functions)

        self._insns = insns

        # 跨函数分析: 检测哪些函数通过 rax 返回 imul/shl 结果
        if functions is None:
            functions = InstructionParser.parse_functions(objdump_output)
        self._cross_tracker.analyze_functions(
            insns, functions, self.OVERFLOW_OPS)
        self._tainted_returns = self._cross_tracker._tainted_returns

        for ins in insns:
            self._step(ins)

        return [f.__dict__ for f in self._findings]

    def _step(self, ins: ParsedInstruction):
        mn = ins.mnemonic
        if mn == "call":
            self._step_call(ins)
        elif mn in self.OVERFLOW_OPS:
            self._step_overflow_op(ins)
        elif mn in self.CHAIN_OPS:
            self._step_chain_op(ins)
        elif mn in ("mov", "movabs") and len(ins.operands) >= 2:
            self._step_mov(ins)
        elif mn == "lea" and len(ins.operands) >= 2:
            self._step_lea(ins)
        elif mn == "xor" and len(ins.operands) >= 2:
            if ins.operands[0].strip() == ins.operands[1].strip():
                dst = InstructionParser.normalize_reg(ins.operands[0])
                if dst:
                    self._reg_taint.pop(dst, None)
        elif mn == "ret":
            self._reg_taint.clear()
            self._stack_taint.clear()

    def _step_overflow_op(self, ins: ParsedInstruction):
        dst = InstructionParser.normalize_reg(ins.operands[0])
        if dst:
            self._reg_taint[dst] = (ins.mnemonic, ins.address)

    def _step_chain_op(self, ins: ParsedInstruction):
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        if not dst: return
        src_reg = InstructionParser.normalize_reg(ops[1].strip())
        if src_reg and src_reg in self._reg_taint:
            kind, addr = self._reg_taint[src_reg]
            self._reg_taint[dst] = (f"{kind}_chain", addr)

    def _step_mov(self, ins: ParsedInstruction):
        ops = ins.operands
        dst_reg = InstructionParser.normalize_reg(ops[0])
        src = ops[1].strip()
        src_reg = InstructionParser.normalize_reg(src)

        # 立即数 → 清除溢出标记
        if src_reg is None:
            try:
                int(src, 0)
                if dst_reg:
                    self._reg_taint.pop(dst_reg, None)
            except ValueError:
                pass

        # 寄存器→寄存器: 传播溢出标记
        if dst_reg and src_reg and src_reg in self._reg_taint:
            kind, addr = self._reg_taint[src_reg]
            self._reg_taint[dst_reg] = (kind, addr)

        # 寄存器→栈槽: mov [rbp-0x8], reg
        dst_slot = self._extract_stack_slot(ops[0])
        if dst_slot and src_reg and src_reg in self._reg_taint:
            kind, addr = self._reg_taint[src_reg]
            self._stack_taint[dst_slot] = (kind, addr)
        # 清除: mov [rbp-0x8], imm → 不传播立即数给栈槽
        elif dst_slot and src_reg is None:
            try:
                int(src, 0)
                self._stack_taint.pop(dst_slot, None)
            except ValueError:
                pass

        # 栈槽→寄存器: mov reg, [rbp-0x8]
        if dst_reg:
            src_slot = self._extract_stack_slot(ops[1])
            if src_slot and src_slot in self._stack_taint:
                kind, addr = self._stack_taint[src_slot]
                self._reg_taint[dst_reg] = (kind, addr)
            elif src_slot:
                self._reg_taint.pop(dst_reg, None)

    def _step_lea(self, ins: ParsedInstruction):
        dst = InstructionParser.normalize_reg(ins.operands[0])
        if dst:
            self._reg_taint.pop(dst, None)

    def _step_call(self, ins: ParsedInstruction):
        callee = InstructionParser.extract_callee(ins)
        # 跨函数: callee 返回 tainted rax → 标记调用者 rax
        if callee and callee in self._tainted_returns:
            self._reg_taint['rax'] = ('cross_func_result', ins.address)

        if callee not in self.ALLOC_FUNCS:
            return

        # 检测 arg0 (rcx/rdi) 是否来自溢出源
        for r in ('rcx', 'rdi'):
            if r in self._reg_taint:
                kind, src_addr = self._reg_taint[r]
                # 检查是否有溢出保护 (最近的 cmp/jcc 在 imul 和 call 之间)
                has_check = self._has_overflow_check(src_addr, ins.address)
                sev = "critical" if not has_check else "medium"
                self._findings.append(IntOverflowFinding(
                    insn_addr=ins.address, alloc_func=callee,
                    overflow_kind=kind,
                    reg_at_alloc=r,
                    reason=f"{kind}@0x{src_addr:x} flows to {callee}() "
                           f"via {r} (overflow check: {'yes' if has_check else 'no'})",
                    confidence=0.50 if has_check else 0.80))
                break

    def _has_overflow_check(self, overflow_addr: int, call_addr: int) -> bool:
        in_range = False
        for ins in self._insns:
            if ins.address == overflow_addr: in_range = True; continue
            if ins.address == call_addr: break
            if not in_range: continue
            if ins.mnemonic in ('cmp', 'test', 'jo'):
                return True
        return False

# call: 检测溢出结果流入分配函数

    @staticmethod
    def _extract_stack_slot(operand: str) -> Optional[str]:
        """从操作数提取栈槽: [rbp-0x8] → 'rbp-0x8'."""
        o = operand.strip().lower()
        if '[' not in o or ']' not in o:
            return None
        inner = o[o.index('[') + 1:o.rindex(']')]
        inner = inner.replace('*', '').strip()
        # 检查基址寄存器
        if 'rbp' in inner or 'rsp' in inner:
            # 标准化格式
            inner = inner.replace(' ', '')
            return inner
        return None


# smoke test
def _check():
    # 场景1: imul → mov rcx → call malloc (无溢出检查)
    asm_io = """
    1000:       55                      push   rbp
    1001:       48 89 e5                mov    rbp,rsp
    1004:       48 8b 45 10             mov    rax,QWORD PTR [rbp+0x10]
    1008:       48 0f af 45 18          imul   rax,QWORD PTR [rbp+0x18]
    100d:       48 89 c1                mov    rcx,rax
    1010:       e8 eb fe ff ff          call   malloc
    """
    s = BinaryIntOverflowScanner()
    r = s.scan(asm_io, user_code_only=False)
    assert len(r) >= 1, f"expected int overflow finding, got {len(r)}"
    assert r[0]['confidence'] >= 0.70, f"expected high conf, got {r[0]['confidence']}"

    # 场景2: 无 imul → call malloc (安全)
    asm_safe = """
    2000:       55                      push   rbp
    2001:       48 89 e5                mov    rbp,rsp
    2004:       b9 40 00 00 00          mov    rcx,0x40
    2009:       e8 f2 fe ff ff          call   malloc
    """
    s2 = BinaryIntOverflowScanner()
    r2 = s2.scan(asm_safe, user_code_only=False)
    assert len(r2) == 0, f"expected no findings, got {len(r2)}"

    # 场景3: shl → call malloc
    asm_shl = """
    3000:       55                      push   rbp
    3001:       48 89 e5                mov    rbp,rsp
    3004:       8b 45 10                mov    eax,DWORD PTR [rbp+0x10]
    3007:       48 c1 e0 02             shl    rax,0x2
    300b:       48 89 c1                mov    rcx,rax
    300e:       e8 ed fe ff ff          call   malloc
    """
    s3 = BinaryIntOverflowScanner()
    r3 = s3.scan(asm_shl, user_code_only=False)
    assert len(r3) >= 1, f"expected shl finding, got {len(r3)}"
    assert r3[0]['overflow_kind'] == 'shl'

    # 场景4: 有溢出检查 → 低置信度
    asm_checked = """
    4000:       55                      push   rbp
    4001:       48 89 e5                mov    rbp,rsp
    4004:       48 8b 45 10             mov    rax,QWORD PTR [rbp+0x10]
    4008:       48 0f af 45 18          imul   rax,QWORD PTR [rbp+0x18]
    400d:       48 3d 00 00 01 00       cmp    rax,0x10000
    4013:       76 08                   jbe    401d
    4015:       48 89 c1                mov    rcx,rax
    4018:       e8 e3 fe ff ff          call   malloc
    """
    s4 = BinaryIntOverflowScanner()
    r4 = s4.scan(asm_checked, user_code_only=False)
    if len(r4) > 0:
        assert r4[0]['confidence'] <= 0.60, \
            f"checked case should have low conf, got {r4[0]['confidence']}"

    print("[OK] binary_int_overflow_scanner")


if __name__ == "__main__":
    _check()
