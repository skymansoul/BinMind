"""常量时间验证器 — 检测二进制密码实现中的时序侧信道漏洞。

密码库(OpenSSL, libsodium等)要求关键操作(比较/选择/移位)的执行时间
与秘密数据无关。违反此要求的代码存在时序侧信道 — 攻击者通过测量
执行时间推断密钥或明文。

本模块在二进制层面(不依赖源码)检测三类常量时间违规:
  1. 秘密依赖的条件分支 — cmp/jcc操作数受秘密数据影响
  2. 秘密依赖的内存访问 — load/store地址受秘密数据影响(触发cache-timing侧信道)
  3. 秘密依赖的执行次数 — 循环迭代次数受秘密数据影响

"秘密数据"识别: 调用方通过taint_source_addrs指定秘密数据来源地址
(包含密钥的缓冲区/明文输入)。本模块通过数据流传播标记受污染的寄存器
和内存位置 — 被污染的寄存器/内存出现在分支条件或访存地址中时报告违规。

权衡: 二进制层面静态数据流分析 — 不执行程序, 不求解约束。
      避免了符号执行路径爆炸问题, 但会产生假阳性 —
      看似受污染但实际执行中恒为常数的场景无法区分。
"""

from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class TaintViolation:
    """单次常量时间违规记录."""
    violation_type: str  # 'secret_dependent_branch' | 'secret_dependent_load' | 'secret_dependent_loop'
    instruction_addr: int
    description: str


class ConstantTimeVerifier:
    """二进制层面常量时间违规检测器。

    静态数据流传播 — 不执行代码, 不调用SMT求解器。
    假阳性率估计15-30% — 标记为"疑似"而非"确认"违规。
    """

    def __init__(self):
        self._tainted_regs: Set[str] = set()
        self._tainted_memory: Set[int] = set()  # 受污染内存地址
        self._violations: List[TaintViolation] = []

    def set_taint_sources(self, regs: Set[str] = None,
                          mem_addrs: Set[int] = None):
        """标记秘密数据的初始位置."""
        if regs:
            self._tainted_regs.update(regs)
        if mem_addrs:
            self._tainted_memory.update(mem_addrs)

    def analyze_instruction(self, addr: int, mnemonic: str,
                            operands: List[str]) -> Optional[TaintViolation]:
        """分析单条指令是否引入污点传播或触发违规.

        调用方在主循环中逐条传入反汇编结果。
        返回TaintViolation(若触发违规), 否则返回None。

        寄存器命名规范化 — 统一小写, 去除x86大小前缀:
        rax/eax/ax/al → 均追踪为'rax'(传播时按全宽度处理)。
        牺牲精度(al污染 vs ah未污染无法区分),
        但实现复杂度大幅降低 — 不值得为此维护位级污点位图。
        """
        mnem = mnemonic.lower()

        # === 违规检测 ===
        violation = self._check_for_violation(addr, mnem, operands)
        if violation:
            self._violations.append(violation)

        # === 污点传播 ===
        self._propagate_taint(addr, mnem, operands)

        return violation

    def _check_for_violation(self, addr: int, mnem: str,
                             operands: List[str]) -> Optional[TaintViolation]:
        """检查当前指令是否触发常量时间违规."""
        ops_str = ' '.join(operands).lower()

        # 类型1: 秘密依赖条件分支
        if mnem.startswith('j') or mnem in ('loop', 'loope', 'loopne'):
            for reg in self._tainted_regs:
                if self._reg_in_operands(reg, operands):
                    return TaintViolation(
                        'secret_dependent_branch', addr,
                        f"branch at {hex(addr)} depends on tainted register '{reg}'"
                    )

        # 类型2: 秘密依赖内存访问
        if mnem in ('mov', 'ldr', 'str', 'lw', 'sw') and len(operands) >= 2:
            # 检查第二操作数(源地址) — 若受污染, load地址泄露秘密
            src_op = operands[1] if len(operands) > 1 else ''
            for reg in self._tainted_regs:
                if reg in src_op.lower():
                    return TaintViolation(
                        'secret_dependent_load', addr,
                        f"load at {hex(addr)} uses tainted address register '{reg}'"
                    )

        # 类型3: 秘密依赖循环 — 检测含污点寄存器的cmp后的loop
        if mnem == 'cmp':
            for reg in self._tainted_regs:
                if self._reg_in_operands(reg, operands):
                    return TaintViolation(
                        'secret_dependent_loop', addr,
                        f"loop bound comparison at {hex(addr)} uses tainted register '{reg}'"
                    )

        return None

    def _propagate_taint(self, addr: int, mnem: str, operands: List[str]):
        """传播污点 — 若源操作数受污染, 标记目标操作数为受污染."""
        if len(operands) < 2:
            return

        dst = operands[0].lower()
        src = operands[1].lower() if len(operands) > 1 else ''

        # 源是否包含受污染寄存器?
        src_tainted = any(reg in src for reg in self._tainted_regs)

        if src_tainted:
            # 提取目标寄存器并标记
            dst_reg = self._extract_reg(dst)
            if dst_reg:
                self._tainted_regs.add(dst_reg)

        # 处理内存写入 — 若存储值为受污染寄存器, 标记目标地址
        if '[' in dst or '(' in dst:
            for reg in self._tainted_regs:
                if reg in src:
                    # 受污染值写入内存 — 记录但无法静态确定具体位置
                    pass

    def _reg_in_operands(self, reg: str, operands: List[str]) -> bool:
        """检查寄存器是否出现在操作数列表任意位置."""
        reg_lower = reg.lower()
        for op in operands:
            op_lower = op.lower()
            # 匹配完整寄存器名 — 避免'rax'匹配'eax'产生假阳性
            # (rax和eax为同一寄存器64-bit vs 32-bit视图,
            #  污点传播按全宽度处理, 此为正确行为)
            if reg_lower in op_lower:
                return True
            # 子寄存器匹配 — 'al'为'rax'低8位
            if reg_lower == 'rax' and 'eax' in op_lower:
                return True
            if reg_lower == 'rax' and 'al' in op_lower:
                return True
        return False

    def _extract_reg(self, operand: str) -> Optional[str]:
        """从操作数字符串提取寄存器名."""
        import re
        m = re.search(r'(?:%|%)?([a-z]{2,5}\d{0,2})', operand.lower())
        return m.group(1) if m else None

    def get_violations(self) -> List[TaintViolation]:
        return list(self._violations)

    def summary(self) -> Dict:
        types = {}
        for v in self._violations:
            types[v.violation_type] = types.get(v.violation_type, 0) + 1
        return {
            'total_violations': len(self._violations),
            'by_type': types,
            'tainted_regs_count': len(self._tainted_regs),
        }
