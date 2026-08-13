"""
汇编翻译器 — 条件/扩展类指令 handler.

符号/零扩展与守卫提取的语义要点:
  - cdqe/movsxd/movzx: 别名/常量保持, 未知置 None
  - cmp reg, imm + jcc: 输出 guard 伪 IR (上界/下界/相等),
    仅当寄存器绑定伪变量 (vN) 时输出
"""

from .asm_regex import (_RE_CMP_IMM, _RE_JCC_EQ, _RE_JCC_GT, _RE_JCC_LT,
                        norm_reg)


def handle_extend(self, mnem: str, operands: str) -> None:
    """符号/零扩展与 movzx: 常量保持, 变量保持, 未知置 None."""
    parts = [p.strip() for p in operands.split(',')]
    if not operands or not parts or not parts[0]:
        # cdqe/cdq 等零操作数指令: 低32位即rax本身 (别名统一)
        return
    if mnem == 'movsxd':
        if len(parts) == 2:
            dst, src = norm_reg(parts[0]), norm_reg(parts[1])
            self.regs[dst] = self.regs.get(src)
        return
    dst = norm_reg(parts[0])
    if len(parts) >= 2:
        src = norm_reg(parts[1])
        self.regs[dst] = self.regs.get(src)


def handle_cmp(self, operands: str) -> None:
    m = _RE_CMP_IMM.match(operands)
    if m:
        self._pending_cmp = (norm_reg(m.group(1)), int(m.group(2), 0))


def handle_jcc(self, mnem: str) -> None:
    """jcc 配对上一条 cmp, 输出 guard 伪 IR 行.

    Intel 语义: cmp reg, imm; jge target → reg >= imm 时跳转,
    fall-through 是 reg < imm → 上界收窄 (guard reg < imm).
    反之 jl 的 fall-through 是 reg >= imm → 无上界, 不下界
    抑制. reg 若绑定伪变量 (vN) 则输出变量名; 若为常量则无
    窄化价值, 跳过.
    """
    if self._pending_cmp is None:
        return
    reg, imm = self._pending_cmp
    self._pending_cmp = None
    val = self.regs.get(reg)
    var = val if isinstance(val, str) and val.startswith('v') else None
    if var is None:
        return
    if mnem in ('jge', 'jae', 'jg', 'ja'):
        self.ir.append(f'guard {var} < {imm}')
    elif mnem in ('jle', 'jbe', 'jl', 'jb'):
        self.ir.append(f'guard {var} > {imm}')
    elif mnem in ('je', 'jz'):
        self.ir.append(f'guard {var} == {imm}')