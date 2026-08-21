"""二进制级格式化字符串检测 - objdump 反汇编 → printf(user_input) 识别.

v2.0: .rdata 交叉引用 - 读取二进制中实际格式字符串,
  分类危险说明符 (%n/%s/%x/%p) 并计算 CVSS 风格评分.

理论: Scut / team teso "Exploiting Format String Vulnerabilities"
算法 (二进制级):
  1. 识别所有 printf/fprintf/sprintf/snprintf 调用
  2. 检测格式字符串参数 (rcx/rdi = arg0)
  3. 若来自 lea reg, [rip+off] → .rdata 字面量 → 读取实际字符串
     a. 含 %n → 写原语危险 (confidence 0.85+)
     b. 含 %s → 信息泄露 (confidence 0.60+)
     c. 仅安全说明符 → 无风险 (confidence 0.0)
  4. 若来自栈加载 → 用户控制格式字符串 → 漏洞
  5. 计算 FSCS (Format String CVSS Score) 0-10 评分
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ..heap_analysis.instruction_parser import InstructionParser, ParsedInstruction


@dataclass
class FmtFinding:
    insn_addr: int
    callee: str
    reason: str
    confidence: float
    specifiers: str = ""      # 检测到的危险说明符
    fmt_string: str = ""      # 实际格式字符串 (前64字符)
    fscs_score: float = 0.0   # Format String CVSS Score


class BinaryFmtScanner:
    """二进制格式字符串漏洞扫描器 - objdump + 可选 .rdata 交叉引用.

    使用方式:
      scanner = BinaryFmtScanner()
      findings = scanner.scan(objdump_text)                    # 仅 objdump
      findings = scanner.scan(objdump_text, binary_path=exe)  # + .rdata 交叉引用
    """

    _FMT_FUNCS = {'printf', 'fprintf', 'sprintf', 'snprintf',
                  '__mingw_printf', '__printf_chk', 'printf'}

    def __init__(self):
        self._findings: List[FmtFinding] = []
        self._literal_regs: Dict[str, bool] = {}
        self._stack_sourced: Dict[str, bool] = {}
        self._rip_offsets: Dict[str, int] = {}   # reg → rip_offset (用于 .rdata 查找)
        self._rdata_reader = None

    def scan(self, objdump_output: str, sample_name: str = "",
             user_code_only: bool = True,
             functions: Optional[Dict[int, str]] = None,
             binary_path: Optional[str] = None) -> List[dict]:
        self._findings.clear()
        self._literal_regs.clear()
        self._stack_sourced.clear()
        self._rip_offsets.clear()
        self._rdata_reader = None

        if binary_path and os.path.isfile(binary_path):
            try:
                from .rdata_reader import RdataReader
                self._rdata_reader = RdataReader(binary_path)
            except Exception:
                pass

        insns = InstructionParser.parse(objdump_output)
        if not insns:
            return []

        if user_code_only:
            if functions is None:
                functions = InstructionParser.parse_functions(objdump_output)
            insns = InstructionParser.filter_user_instructions(insns, functions)

        for ins in insns:
            self._step(ins)

        return [f.__dict__ for f in self._findings]

    def _step(self, ins: ParsedInstruction):
        mn = ins.mnemonic
        if mn == "call":
            self._step_call(ins)
        elif mn == "lea" and len(ins.operands) >= 2:
            self._step_lea(ins)
        elif mn in ("mov", "movabs") and len(ins.operands) >= 2:
            self._step_mov(ins)

    def _step_lea(self, ins: ParsedInstruction):
        """追踪 lea reg, [rip+off] → 记录目标 VA 用于 .rdata 查找."""
        dst = InstructionParser.normalize_reg(ins.operands[0])
        if not dst:
            return
        src = ins.operands[1].strip().lower()
        if 'rip' in src:
            self._literal_regs[dst] = True
            # 提取 rip 偏移: lea rcx, [rip+0x9830] → 0x9830
            import re
            m = re.search(r'[+-]0x([0-9a-f]+)', src)
            if m:
                rip_off = int(m.group(1), 16)
                if src.find('-') >= 0:
                    rip_off = -rip_off
                # 计算目标 VA: ins.address + ins_len + rip_offset
                ins_len = self._compute_insn_len(ins)
                target_va = ins.address + ins_len + rip_off
                self._rip_offsets[dst] = target_va

    @staticmethod
    def _compute_insn_len(ins: ParsedInstruction) -> int:
        """从 raw_line 中的 hex 字节计算指令长度."""
        import re
        m = re.search(r':\s+((?:[0-9a-f]{2}\s)+)\s{2,}', ins.raw_line)
        if m:
            return len(m.group(1).strip().split())
        return 7  # lea r, [rip+...] 默认 7 字节

    def _step_mov(self, ins: ParsedInstruction):
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        if not dst:
            return
        src_op = ops[1].strip()
        src_reg = InstructionParser.normalize_reg(src_op)

        if src_reg and src_reg in self._literal_regs:
            self._literal_regs[dst] = True
            if src_reg in self._rip_offsets:
                self._rip_offsets[dst] = self._rip_offsets[src_reg]
        elif src_reg and src_reg in self._stack_sourced:
            self._stack_sourced[dst] = True
        else:
            base, off = InstructionParser.parse_memory_operand(src_op)
            if base in ('rbp', 'rsp'):
                self._stack_sourced[dst] = True

    def _step_call(self, ins: ParsedInstruction):
        callee = InstructionParser.extract_callee(ins)
        if callee not in self._FMT_FUNCS:
            self._literal_regs.clear()
            self._stack_sourced.clear()
            return

        fmt_reg = None
        for r in ('rcx', 'rdi'):
            if r in self._literal_regs or r in self._stack_sourced:
                fmt_reg = r
                break

        if fmt_reg and fmt_reg in self._literal_regs:
            # .rdata 来源 → 读取实际格式字符串确认安全性
            # 决策: .rdata 中仅有 %n 是真正危险的 (写原语, 无论来源均可疑)
            #       %s/%x/%p 在常量格式字符串中属正常行为, 不报告
            if self._rdata_reader and self._rdata_reader.is_loaded:
                target_va = self._rip_offsets.get(fmt_reg, 0)
                if target_va:
                    fmt_str = self._rdata_reader.read_string_at_va(target_va)
                    if fmt_str:
                        spec = self._rdata_reader.classify_specifiers(fmt_str)
                        if spec["write"]:
                            score = self._rdata_reader.danger_score(fmt_str)
                            self._findings.append(FmtFinding(
                                insn_addr=ins.address, callee=callee,
                                reason=f".rdata fmt '{fmt_str[:48]}' "
                                       f"contains %n write primitive",
                                confidence=0.85 + score * 0.1,
                                specifiers=str(spec),
                                fmt_string=fmt_str[:64],
                                fscs_score=score * 10.0))
                        # .rdata 中的 %s/%x/%p → 正常格式化, 不报告
                        return
            # 无 .rdata reader → .rdata 常量视为安全
            return

        if fmt_reg and fmt_reg in self._stack_sourced:
            self._findings.append(FmtFinding(
                insn_addr=ins.address, callee=callee,
                reason=f"{callee} format string from stack variable "
                       f"(loaded from [rbp/rsp])",
                confidence=0.45, fscs_score=6.0))
            return

        # 无法确定来源 → 保守检测
        has_extra_args = False
        for r in ('rdx', 'r8'):
            if r in self._literal_regs or r in self._stack_sourced:
                has_extra_args = True
                break

        if not has_extra_args:
            self._findings.append(FmtFinding(
                insn_addr=ins.address, callee=callee,
                reason=f"{callee} possibly user-controlled fmt "
                       f"(no .rdata literal for rcx)",
                confidence=0.35, fscs_score=3.5))


# smoke test
def _check():
    # 危险: printf(user_input) - rcx 来自栈
    asm_danger = """
    1000:       55                      push   rbp
    1001:       48 89 e5                mov    rbp,rsp
    1004:       48 8b 4d 10             mov    rcx,QWORD PTR [rbp+0x10]
    1008:       e8 f3 fe ff ff          call   1000 <printf>
    """
    scanner = BinaryFmtScanner()
    findings = scanner.scan(asm_danger, user_code_only=False)
    assert len(findings) >= 1, f"expected finding, got {len(findings)}"
    assert findings[0]['confidence'] >= 0.30

    # 安全: printf("hello") - rcx 来自 lea rcx, [rip+...]
    asm_safe = """
    1000:       55                      push   rbp
    1001:       48 89 e5                mov    rbp,rsp
    1004:       48 8d 0d 30 98 00 00    lea    rcx,[rip+0x9830]
    100b:       e8 f0 fe ff ff          call   1000 <printf>
    """
    scanner2 = BinaryFmtScanner()
    findings2 = scanner2.scan(asm_safe, user_code_only=False)
    assert len(findings2) == 0, \
        f"expected no findings for safe printf, got {len(findings2)}"

    print(f"[OK] binary_fmt_scanner")


if __name__ == "__main__":
    _check()
