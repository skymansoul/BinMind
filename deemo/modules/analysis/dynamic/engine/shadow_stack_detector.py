import logging as _logging
import os as _os
import re as _re
import subprocess as _sp
import struct

__dbg = _logging.getLogger(__name__)


class ReturnViolation:
    """返回-address integrity violation record"""
    __slots__ = ('addr', 'expected', 'actual', 'sev')

    def __init__(self, addr, expected=0, actual=0, sev='HIGH'):
        self.addr     = int(addr) if addr is not None else 0
        self.expected = int(expected) if expected is not None else 0
        self.actual   = int(actual) if actual is not None else 0
        self.sev      = str(sev) if sev else 'HIGH'

# 舍入 5: ROP构件 catalog
# 影子栈检测的基础上增加ROP gadget分类和利用难度评估
# Gadget按功能分为: 栈操作 (pop;ret), 寄存器加载, 内存写入 (mov [reg];ret)
# 系统调用 (系统调用;ret), 间接跳转 (jmp [reg]) 五类
# 分类结果指示攻击者可用的原语丰富度，辅助ROP防护策略选择

class ROPGadget:
    __slots__ = ('address', 'instructions', 'category', 'regs_modified', 'side_effects')

    def __init__(self, address=0, instructions="", category="unknown",
                 regs_modified=None, side_effects=""):
        self.address = int(address) if address else 0
        self.instructions = str(instructions)
        self.category = str(category)         # 栈_op | reg_load | mem_write | 系统调用 | indirect_jmp
        self.regs_modified = list(regs_modified) if regs_modified else []
        self.side_effects = str(side_effects)  # e.g. "clobbers rax, 读取 [rdi]"

_GADGET_PATTERNS = [
    # (regex, category, typical_use)
    (r'pop\s+r\w+\s*\n\s*ret', 'stack_op', 'Stack pivot / register load'),
    (r'mov\s+r\w+,\s*\[r\w+.*\]\s*\n.*ret', 'reg_load', 'Memory-to-register load'),
    (r'mov\s+\[r\w+.*\],\s*r\w+\s*\n.*ret', 'mem_write', 'Arbitrary write primitive'),
    (r'syscall\s*\n.*ret', 'syscall', 'Direct syscall invocation'),
    (r'jmp\s+r\w+', 'indirect_jmp', 'Indirect control transfer'),
    (r'xchg\s+r\w+,\s*r\w+\s*\n.*ret', 'stack_op', 'Register swap gadget'),
    (r'xor\s+r\w+,\s*r\w+\s*\n.*ret', 'reg_load', 'Register zeroing gadget'),
]

class ShadowStackDetector:
    """返回-address overwrite detector via 反汇编 pattern matching
    
    Scans 反汇编 for 栈-relative 写入 (rbp/rsp displacement)
    检查 whether a RET follows next four instructions. A hit
    indicates a likely 返回-address clobber — a ROP or 栈-smash signal
    
    舍入 5: Added ROP构件 cataloging for 漏洞利用原语 assessment
    """

    _kRetPats = (
        r'\bret\b',
        r'\bretn?\b',
        r'\bpop\s+r\w+\s*\n\s*jmp',
    )

    _kStackWrites = (
        (r'mov\s+(?:qword\s+)?\[rbp\s*[-+]\s*\d+\]\s*,\s*r\w+', 'rbp_write'),
        (r'mov\s+(?:qword\s+)?\[rsp\s*[-+]\s*\d+\]\s*,\s*r\w+', 'rsp_write'),
        (r'push\s+r\w+', 'push'),
    )

    def __init__(self, f_binpath):
        if f_binpath is None:
            raise ValueError("binary path required")
        self.__path = _os.path.abspath(f_binpath)
        self._gadgets: list[ROPGadget] = []

    def find_violations(self):
        """Pattern-match 栈 写入 followed RET; 返回 violation list"""
        viols = []
        try:
            cmd = ['r2', '-q', '-c', 'aaaa; pD $SS @ $S; q', self.__path]
            r = _sp.run(cmd, capture_output=True, text=True,
                        timeout=120, encoding='utf-8', errors='replace')
            lines = r.stdout.split('\n')
            n = len(lines)
            li = 0
            while li < n:
                line = lines[li]
                wi = 0
                wn = len(self._kStackWrites)
                while wi < wn:
                    pat, vtype = self._kStackWrites[wi]
                    if _re.search(pat, line, _re.IGNORECASE):
                        am = _re.match(r'\s*0x([0-9a-f]+)', line)
                        addr = int(am.group(1), 16) if am else li
                        ctx_end = li + 4
                        if ctx_end > n:
                            ctx_end = n
                        ctx = '\n'.join(lines[li:ctx_end])
                        has_ret = False
                        ri = 0
                        while ri < len(self._kRetPats):
                            if _re.search(self._kRetPats[ri], ctx, _re.IGNORECASE):
                                has_ret = True
                                break
                            ri += 1
                        if has_ret:
                            viols.append(ReturnViolation(addr, sev='HIGH'))
                    wi += 1
                li += 1
        except Exception as _e:
            __dbg.warning(f"shadow stack detection failed: {_e}")
        return viols

    def assess_rop(self):
        """Score ROP resilience: 启动 100, subtract 15 per violation"""
        viols = self.find_violations()
        score = 100 - len(viols) * 15
        if score < 0:
            score = 0
        return {
            'success': True,
            'violations': len(viols),
            'rop_resilience_score': score,
            'recommendation': (
                'enable CET/Shadow Stack'
                if score < 70
                else 'baseline secure'
            ),
        }

# 舍入 5: ROP构件 cataloging
    def catalog_gadgets(self, gadget_count: int = 50) -> List[ROPGadget]:
        """从二进制中提取并分类ROP gadget。使用radare2的/R命令搜索
        ret-terminated指令序列，然后按功能分类（栈操作/寄存器加载/
        内存写入/系统调用/间接跳转）
        
        分类结果用于评估ROP利用难度：若存在syscall gadget+寄存
        器加载gadget，那么实现execve("/bin/sh")的难度显著降低"""
        gadgets = []
        try:
            # 使用radare2搜索ret-terminated序列
            cmd = ['r2', '-q', '-c',
                   f'aaaa; /R pop r; /R mov r; /R syscall; q',
                   self.__path]
            r = _sp.run(cmd, capture_output=True, text=True,
                        timeout=120, encoding='utf-8', errors='replace')
            disasm_text = r.stdout

            for pat_re, category, typical_use in _GADGET_PATTERNS:
                for m in _re.finditer(pat_re, disasm_text, _re.IGNORECASE):
                    # 尝试从上下文中提取地址
                    addr_match = _re.search(r'0x([0-9a-f]+)', disasm_text[max(0, m.start()-40):m.start()])
                    addr = int(addr_match.group(1), 16) if addr_match else m.start()

                    # 识别修改的寄存器
                    regs = _re.findall(r'[re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|r\d+', m.group(0))

                    gadgets.append(ROPGadget(
                        address=addr,
                        instructions=m.group(0).strip(),
                        category=category,
                        regs_modified=list(set(regs)),
                        side_effects=typical_use,
                    ))

                    if len(gadgets) >= gadget_count:
                        break
                if len(gadgets) >= gadget_count:
                    break
        except Exception as e:
            __dbg.warning(f"ROP gadget cataloging failed: {e}")

        self._gadgets = gadgets
        return gadgets

    def gadget_summary(self) -> Dict[str, Any]:
        """生成ROP gadget分类摘要。统计每类gadget的数量并评估利用可行性"""
        if not self._gadgets:
            self.catalog_gadgets()

        by_category = {}
        for g in self._gadgets:
            by_category.setdefault(g.category, []).append(g)

        # 利用可行性评估
        has_stack_op = 'stack_op' in by_category
        has_syscall = 'syscall' in by_category
        has_mem_write = 'mem_write' in by_category
        exploitability = 'LOW'
        if has_stack_op and has_mem_write:
            exploitability = 'MEDIUM'
        if has_stack_op and has_syscall:
            exploitability = 'HIGH'
        if has_stack_op and has_mem_write and has_syscall:
            exploitability = 'CRITICAL'

        return {
            'total_gadgets': len(self._gadgets),
            'by_category': {c: len(gs) for c, gs in by_category.items()},
            'exploitability_assessment': exploitability,
            'top_gadgets': [
                {'addr': hex(g.address), 'category': g.category,
                 'insn': g.instructions[:60], 'regs': g.regs_modified}
                for g in self._gadgets[:10]
            ],
        }

    def detect_stack_canary(self) -> Dict[str, Any]:
        """检测栈金丝雀保护机制"""
        canary_symbols = ['__stack_chk_fail', '___stack_chk_guard',
                          '__security_check_cookie', '__GSHandlerCheck',
                          '__stack_chk_guard']
        found = []
        try:
            with open(self.__path, 'rb') as fh:
                raw = fh.read().decode('latin-1', errors='ignore')
            for sym in canary_symbols:
                if sym in raw:
                    found.append(sym)
        except Exception:
            pass
        return {'has_canary': len(found) > 0, 'symbols_found': found,
                'severity_if_missing': 'high'}

    def assess_cet_compatibility(self) -> Dict[str, Any]:
        """检测CET (Control-flow Enforcement Technology) 兼容性"""
        endbr64_count = 0
        try:
            with open(self.__path, 'rb') as fh:
                raw = fh.read()
            endbr64_count = raw.count(b'\xf3\x0f\x1e\xfa')
            rdsspq_count = raw.count(b'\xf3\x0f\x1e\xfb')
        except Exception:
            pass
        total_ibt = endbr64_count
        has_shstk = rdsspq_count > 0
        return {
            'ibt_landing_pads': total_ibt,
            'shadow_stack_instructions': rdsspq_count,
            'is_ibt_compatible': total_ibt > 2,
            'is_shstk_compatible': has_shstk,
        }

    def export_report(self) -> str:
        """生成完整的Markdown审计报告"""
        rop = self.assess_rop()
        canary = self.detect_stack_canary()
        cet = self.assess_cet_compatibility()
        gadget_summary = self.gadget_summary()

        lines = [
            "# Shadow Stack & ROP Audit Report",
            "",
            "## ROP Resilience",
            f"- Violations detected: {rop['violations']}",
            f"- Resilience score: {rop['rop_resilience_score']}/100",
            f"- Recommendation: {rop['recommendation']}",
            "",
            "## Stack Canary",
            f"- Present: {canary['has_canary']}",
            f"- Symbols: {', '.join(canary['symbols_found']) if canary['symbols_found'] else 'none'}",
            "",
            "## CET Compatibility",
            f"- IBT landing pads (endbr64): {cet['ibt_landing_pads']}",
            f"- Shadow stack instructions (rdsspq): {cet['shadow_stack_instructions']}",
            "",
            "## ROP Gadget Catalog",
            f"- Total gadgets found: {gadget_summary['total_gadgets']}",
            f"- Exploitability: {gadget_summary['exploitability_assessment']}",
            f"- By category: {gadget_summary['by_category']}",
            "",
            "| Address | Category | Instructions | Registers |",
            "|---------|----------|-------------|-----------|",
        ]
        for g in gadget_summary['top_gadgets']:
            lines.append(f"| {g['addr']} | {g['category']} | {g['insn']} | {', '.join(g['regs'])} |")

        return "\n".join(lines)


def detect_shadow_stack_violations(f_binpath):
    """Single-call entry: scan binary 返回 ROP resilience assessment"""
    det = ShadowStackDetector(f_binpath)
    return det.assess_rop()
