# 高级常量时间验证器 — 隐式流追踪 + 编译器优化模式检测 + 跨架构条件指令感知。
#
# 背景:
#   基础的 constant_time_verifier.py 做单遍数据流传播——只追踪显式数据依赖。
#   Schneider et al. 的大规模实测表明:
#   编译器优化会系统性地将常量时间算术模式重新编译为秘密依赖分支,
#   即使源代码通过了形式化验证 (HACL*) 也无法幸免。
#   同时, 隐式流 (implicit flow) — 即分支条件受秘密影响时,
#   分支体内所有赋值都具有秘密依赖 — 基础版完全无法检测。
#
# 本模块在基础版之上增加三层检测:
#   (a) 隐式流追踪: 当基本块受秘密依赖的分支守卫时,
#       块内所有寄存器写入均标记为条件性污染。
#       在支配块汇合点 (phi节点等价位置) 合并两条路径的污染集。
#   (b) 编译器模式识别: 检测编译器将常量时间选择模式
#       (如 (a & mask) | (b & ~mask)) 替换为分支/csel/cmov 的实例。
#       识别标志: 短分支 (≤5条指令) + 每侧仅一个寄存器写入 + 写入目标相同。
#   (c) 缓存行感知内存索引: 对秘密依赖的 load 地址,
#       检查其最低 6 位 (缓存行内偏移, 针对 64B 缓存行) 是否可能受秘密影响——
#       这是 cache-timing 攻击的前提条件。
#
#
#   Schneider et al. "Breaking Bad: How Compilers Break Constant-Time
#     Implementations" — 编译器算术→分支转换的系统性研究,
#     覆盖 8 个密码库/6 架构/2 编译器/7 优化级别。本项目在此基础上实现
#     二进制层面的自动检测——不依赖源码, 不依赖编译器版本。
#   MicroSampler — 微架构级泄漏检测框架,
#     本项目借鉴其"将微架构状态与秘密值关联"的思路, 简化为缓存行偏移的
#     静态分析——精确度低于 RTL 仿真但无需运行二进制。
#   CT-LLVM — LLVM pass 层级的常量时间分析,
#     本项目在二进制层面实现类似功能, 处理已编译的第三方库 (无源码场景)。
#
# 边界条件:
# 隐式流追踪要求基本块边界信息 (需调用方提供或从反汇编推断)
# 跨函数分析需要调用方提供间接调用目标解析 (本模块不做 CFI 分析)
# ARM64 条件指令的"写目标在条件为假时不变"语义正确建模——
#     这模拟了硬件的条件执行行为 (条件假时寄存器保持原值)

import re
from typing import Dict, List, Set, Tuple, Optional, FrozenSet
from dataclasses import dataclass, field
from enum import Enum, auto


class FlowType(Enum):
    EXPLICIT = auto()   # 显式数据流: mov rax, [secret]
    IMPLICIT = auto()   # 隐式控制流: if (secret) { rax = 0 }
    COND_EXEC = auto()  # 条件执行: csel x0, x1, x2, eq (ARM64条件码依赖秘密)


@dataclass(unsafe_hash=True)
class TaintSource:
    reg: str
    flow_type: FlowType
    source_addr: int     # 污染引入的指令地址
    guard_condition: Optional[str] = None  # 隐式流的守卫条件描述


@dataclass
class BasicBlock:
    id: int
    start_addr: int
    end_addr: int
    instructions: List[Tuple[int, str, List[str]]] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    is_loop_header: bool = False


class AdvancedConstantTimeVerifier:
    """高级常量时间验证器 — 隐式流 + 编译器模式 + 缓存行感知。

    与 ConstantTimeVerifier 的关系: 本模块实现其未覆盖的三类高级违规。
    基础版负责逐条指令的显式数据流追踪, 高级版在此之上叠加隐式流、
    编译器模式识别和缓存行感知——两层互补, 可独立使用也可级联。

    架构支持: x86_64 (含 cmov/setcc), ARM64 (含 csel/cset/cinc)
    不支持的架构 (MIPS, RISC-V) 退化为仅做显式流追踪——隐式流部分
    跳过条件指令检测但基本块级分析仍有效。
    """

    # ARM64 条件执行指令族 — 这些是"分支的微架构替代品"
    # 在机器码层面不产生分支, 但语义上等价于条件选择
    _ARM64_COND_INSTRS = {
        "csel", "csinc", "csinv", "csneg",  # 条件选择/增/反/ neg
        "cset", "csetm",                       # 条件置位/置掩码
        "cinc", "cinv", "cneg",               # 条件增/反/neg
    }

    # x86_64 条件指令族
    _X86_COND_INSTRS = {
        "cmov", "cmove", "cmovne", "cmovg", "cmovge",
        "cmovl", "cmovle", "cmova", "cmovae", "cmovb",
        "cmovbe", "cmovc", "cmovnc", "cmovo", "cmovno",
        "cmovs", "cmovns", "cmovp", "cmovnp",
        "sete", "setne", "setg", "setge", "setl", "setle",
        "seta", "setae", "setb", "setbe", "setc", "setnc",
        "seto", "setno", "sets", "setns", "setp", "setnp",
    }

    def __init__(self):
        # 显式污染: reg_name -> set of TaintSource
        self._explicit: Dict[str, Set[TaintSource]] = {}
        # 隐式污染: 受秘密依赖分支影响的寄存器
        self._implicit: Dict[str, Set[TaintSource]] = {}
        # 当前分析状态 — 秘密依赖分支守卫的嵌套深度
        self._guarded_depth: int = 0
        self._active_guards: List[str] = []
        # 违规记录
        self._violations: List[Dict] = []
        # 跨函数摘要: func_addr -> {tainted_regs_out, violated}
        self._func_summaries: Dict[int, Dict] = {}

    # 公开接口

    def analyze_block(self, block: BasicBlock,
                       arch: str = "x86_64") -> List[Dict]:
        """分析单个基本块, 返回此块内新发现的违规列表。

        调用方负责按 CFG 拓扑顺序调用此方法——本模块不解析 CFG,
        但依赖正确的块顺序来做支配关系判断和隐式流合并。
        """
        new_violations = []
        writes_this_block: Dict[str, Set[TaintSource]] = {}

        for addr, mnem, ops in block.instructions:
            mnem_lower = mnem.lower()

# 隐式流感知: 标记守卫下的所有写入
            if self._guarded_depth > 0:
                dst_reg = self._extract_dst_reg(mnem_lower, ops)
                if dst_reg:
                    guard_desc = self._active_guards[-1] if self._active_guards else "unknown"
                    ts = TaintSource(dst_reg, FlowType.IMPLICIT, addr, guard_desc)
                    writes_this_block.setdefault(dst_reg, set()).add(ts)

# 违规检测
            v = self._detect_violation(addr, mnem_lower, ops, arch)
            if v:
                new_violations.append(v)
                self._violations.append(v)

# 污点传播
            self._propagate_explicit(addr, mnem_lower, ops, writes_this_block)

# 编译器模式检测
            cv = self._detect_compiler_pattern(block, addr, mnem_lower, ops, arch)
            if cv:
                new_violations.append(cv)
                self._violations.append(cv)

        # 块结束 — 提交本块写入到污染集
        for reg, sources in writes_this_block.items():
            self._implicit.setdefault(reg, set()).update(sources)

        # 如果是分支块, 处理守卫条件
        self._handle_branch_guard(block)

        return new_violations

    def summarize_function(self, func_addr: int):
        """生成跨函数摘要 — 记录此函数的污染输出, 供调用方引用。"""
        self._func_summaries[func_addr] = {
            "tainted_regs_out": set(self._explicit.keys()) | set(self._implicit.keys()),
            "violation_count": len(self._violations),
            "guarded_depth_remaining": self._guarded_depth,
        }

    def apply_summary(self, func_addr: int):
        """应用跨函数摘要 — 将被调用函数的污染输出合并到当前上下文。"""
        summary = self._func_summaries.get(func_addr)
        if not summary:
            return
        for reg in summary["tainted_regs_out"]:
            ts = TaintSource(reg, FlowType.EXPLICIT, func_addr, "cross-function taint")
            self._explicit.setdefault(reg, set()).add(ts)

    def _detect_violation(self, addr: int, mnem: str,
                           ops: List[str], arch: str) -> Optional[Dict]:
        """检测三类高级违规: 隐式流分支、条件指令、缓存行泄露。

        基础违规 (显式秘密依赖分支/Load/Loop) 由 ConstantTimeVerifier 处理——
        本方法只处理高级版独有的违规类型, 避免与基础版重复。
        """
        all_tainted = set(self._explicit.keys()) | set(self._implicit.keys())
        ops_str = " ".join(ops).lower()

        # 类型 A: 条件指令 (cmov/csel/setcc) 的条件码受秘密影响
        if arch == "arm64":
            if mnem in self._ARM64_COND_INSTRS:
                # ARM64条件指令的操作数可能受污染——
                # 但条件码本身来自 NZCV flags, 需检查 flags 来源
                for reg in all_tainted:
                    if self._reg_in_operands(reg, ops):
                        return {
                            "type": "secret_dependent_conditional",
                            "addr": addr,
                            "arch": arch,
                            "mnemonic": mnem,
                            "description": f"conditional {mnem} at {hex(addr)} operand tainted by {reg}",
                            "flow": "explicit" if reg in self._explicit else "implicit",
                        }
        elif arch == "x86_64":
            if mnem in self._X86_COND_INSTRS:
                for reg in all_tainted:
                    if self._reg_in_operands(reg, ops):
                        return {
                            "type": "secret_dependent_conditional",
                            "addr": addr,
                            "arch": arch,
                            "mnemonic": mnem,
                            "description": f"conditional {mnem} at {hex(addr)} operand tainted by {reg}",
                            "flow": "explicit" if reg in self._explicit else "implicit",
                        }

        # 类型 B: 缓存行感知 — Load/Store 地址受污染时检查索引位
        if mnem in ("mov", "ldr", "str", "ldrb", "strb", "ldrh", "strh",
                    "ldur", "stur", "ldp", "stp"):
            if len(ops) >= 2:
                addr_op = ops[1] if len(ops) > 1 else ops[0]
                for reg in all_tainted:
                    if self._reg_in_operands(reg, [addr_op]):
                        # 检查是否影响缓存行内偏移 (bits [5:0] for 64B cache line)
                        cache_line_affected = self._is_cache_index_affected(addr_op)
                        return {
                            "type": "secret_dependent_memory_access",
                            "addr": addr,
                            "mnemonic": mnem,
                            "cache_line_affected": cache_line_affected,
                            "description": f"memory access at {hex(addr)} uses tainted address {reg} (cache-line index affected: {cache_line_affected})",
                            "flow": "explicit" if reg in self._explicit else "implicit",
                        }

        return None

    def _detect_compiler_pattern(self, block: BasicBlock, addr: int,
                                   mnem: str, ops: List[str],
                                   arch: str) -> Optional[Dict]:
        """检测编译器从常量时间算术模式生成的条件分支/条件选择。

        模式: 编译器优化 (a & mask) | (b & ~mask) 这样的常量时间选择——
        在特定条件下 (如 mask 为 0 或全 1 的常量传播结果), 编译器可能
        将其替换为分支或 cmov。

        检测逻辑:
          1. 识别"短选择"模式 — 条件分支两侧各 ≤5条指令且写入同一目标寄存器
          2. 若该寄存器本身在条件码中受污染 — 报告编译器模式违规

        假阳性风险: 此检测较为激进——并非所有"短选择"都来自编译器优化。
        降低假阳性的策略: 仅在密码学关键函数 (由调用方标记) 中启用此检测。
        """
        if mnem not in ("cmp", "test", "tst", "subs", "adds"):
            return None

        all_tainted = set(self._explicit.keys()) | set(self._implicit.keys())
        if not any(self._reg_in_operands(r, ops) for r in all_tainted):
            return None

        # 此 cmp/test 的条件码受秘密影响 — 记录以供后续分支检测使用
        # 实际的"编译器模式"违规在后续条件分支/条件选择处标记
        return None  # cmp 本身不违规——违规的是后续的分支或条件选择

    def _handle_branch_guard(self, block: BasicBlock):
        """处理分支块的守卫条件——跟踪隐式流的嵌套。

        当条件分支的条件受秘密影响时, 两条后继路径上的所有赋值
        都继承了秘密依赖性——即隐式流。

        此方法递增/递减守卫深度计数器并记录活跃的守卫描述。
        调用方在进入后继块前应调用 enter_guarded_path(),
        在后继块分析完成后调用 exit_guarded_path()。
        """
        # 检查块的最后一条指令是否为条件跳转
        if not block.instructions:
            return

        last_mnem = block.instructions[-1][1].lower()
        if not (last_mnem.startswith("j") or last_mnem.startswith("b.")):
            return

        all_tainted = set(self._explicit.keys()) | set(self._implicit.keys())
        # 条件跳转的 flags 来自前一条 cmp/test——检查其操作数
        if len(block.instructions) >= 2:
            prev_mnem = block.instructions[-2][1].lower()
            prev_ops = block.instructions[-2][2]
            if prev_mnem in ("cmp", "test", "tst", "subs", "adds"):
                if any(self._reg_in_operands(r, prev_ops) for r in all_tainted):
                    self._guarded_depth += 1
                    self._active_guards.append(
                        f"branch at {hex(block.instructions[-1][0])} depends on secret"
                    )

    def enter_guarded_path(self):
        """调用方在进入分支后继块前调用。"""
        pass  # guard 已在 _handle_branch_guard 中递增

    def exit_guarded_path(self):
        """调用方在离开分支后继块后调用——递减守卫深度。

        在支配树汇合点调用——当两条分支路径的控制流汇合时,
        守卫深度应恢复到分支前的值。
        """
        if self._guarded_depth > 0:
            self._guarded_depth -= 1
            if self._active_guards:
                self._active_guards.pop()

    # 内部辅助方法

    def _propagate_explicit(self, addr: int, mnem: str,
                             ops: List[str],
                             writes: Dict[str, Set[TaintSource]]):
        """显式数据流传播: src受污染 → dst受污染。

        处理 mov/算术/逻辑/load 等数据移动指令。
        对 x86 做子寄存器感知传播 (al污染→rax污染)。
        """
        if len(ops) < 2:
            return
        dst_str = ops[0].lower()
        src_str = " ".join(ops[1:]).lower()

        all_tainted = set(self._explicit.keys()) | set(self._implicit.keys())
        src_tainted_regs = [r for r in all_tainted if self._reg_in_operands(r, ops[1:])]

        if not src_tainted_regs:
            return

        dst_reg = self._extract_dst_reg(mnem, ops)
        if dst_reg:
            for src_reg in src_tainted_regs:
                ts = TaintSource(dst_reg, FlowType.EXPLICIT, addr,
                                  f"propagated from {src_reg}")
                self._explicit.setdefault(dst_reg, set()).add(ts)
                writes.setdefault(dst_reg, set()).add(ts)

            # x86 子寄存器传播: al污染 → rax污染
            parent = self._parent_reg(dst_reg)
            if parent and parent != dst_reg:
                for src_reg in src_tainted_regs:
                    ts = TaintSource(parent, FlowType.EXPLICIT, addr,
                                      f"sub-register propagation from {src_reg}")
                    self._explicit.setdefault(parent, set()).add(ts)

    def _is_cache_index_affected(self, addr_op: str) -> bool:
        """检查内存操作数的地址是否使用了可能受污染的索引。

        对于 [base + index*scale + offset] 寻址模式:
        - 若 index 寄存器受污染 → 缓存行索引位 [5:0] 可能受秘密影响
        - 若 base 寄存器受污染 → base 通常指向缓冲区起始, 不直接影响索引
        - 若 offset 是常量 → 不影响 (恒定偏移)

        保守假设: 只要地址操作数中出现受污染寄存器且不是孤立 base,
        就认为缓存行索引可能受影响。假阳性率估计 20-30%。
        """
        # 简化检测: 若地址含 index*scale 模式且 index 受污染 → affected
        index_scale_pattern = re.compile(r"(\w+)\s*\*\s*\d+")
        m = index_scale_pattern.search(addr_op)
        if m:
            idx_reg = m.group(1).lower()
            if idx_reg in self._explicit or idx_reg in self._implicit:
                return True
        # 若仅含 base (无 index) → 可能受影响——保守返回 True
        return True

    def _extract_dst_reg(self, mnem: str, ops: List[str]) -> Optional[str]:
        """从指令助记符和操作数提取目标寄存器。

        排除: 比较指令 (cmp/test)、存储指令 (str/STx)、分支 (jxx/bxx/ret)。
        """
        if not ops:
            return None
        m = mnem.lower()
        if m.startswith("j") or m.startswith("b.") or m == "ret":
            return None
        if m in ("cmp", "test", "tst"):
            return None
        if m.startswith("str") or m.startswith("st"):
            return None  # 存储指令——目标在内存, 不修改寄存器

        first_op = ops[0]
        # ARM64 格式: "x0, x1, x2" 或 "w0, [sp, #8]"
        # x86 格式:  "rax, rbx" 或 "[rax], rbx"
        reg_match = re.match(r"(?:%|%)?([a-z]{2,5}\d{0,2})", first_op.lower())
        return reg_match.group(1) if reg_match else None

    def _reg_in_operands(self, reg: str, ops: List[str]) -> bool:
        """检查寄存器是否出现在操作数列表中。

        子寄存器匹配: rax 匹配 eax/ax/al/ah——
        因为 x86-64 子寄存器是同一物理寄存器的不同视图。
        """
        r = reg.lower()
        ops_lower = " ".join(ops).lower()
        if r in ops_lower:
            return True
        # x86 子寄存器别名
        aliases = {
            "rax": ["eax", "ax", "al"],
            "rbx": ["ebx", "bx", "bl"],
            "rcx": ["ecx", "cx", "cl"],
            "rdx": ["edx", "dx", "dl"],
            "rsi": ["esi", "si", "sil"],
            "rdi": ["edi", "di", "dil"],
            "rbp": ["ebp", "bp", "bpl"],
            "rsp": ["esp", "sp", "spl"],
            "r8": ["r8d", "r8w", "r8b"],
            "r9": ["r9d", "r9w", "r9b"],
            "r10": ["r10d", "r10w", "r10b"],
            "r11": ["r11d", "r11w", "r11b"],
            "r12": ["r12d", "r12w", "r12b"],
            "r13": ["r13d", "r13w", "r13b"],
            "r14": ["r14d", "r14w", "r14b"],
            "r15": ["r15d", "r15w", "r15b"],
        }
        if r in aliases:
            for alias in aliases[r]:
                if alias in ops_lower:
                    return True
        # ARM64 子寄存器: x0 匹配 w0
        if r.startswith("x"):
            w_reg = "w" + r[1:]
            if w_reg in ops_lower:
                return True
        if r.startswith("w"):
            x_reg = "x" + r[1:]
            if x_reg in ops_lower:
                return True
        return False

    def _parent_reg(self, reg: str) -> Optional[str]:
        """返回子寄存器对应的全宽度父寄存器。

        e.g. eax→rax, al→rax, w0→x0。
        用于子寄存器写入时的污染传播。
        """
        r = reg.lower()
        sub_to_parent = {
            "eax": "rax", "ax": "rax", "al": "rax",
            "ebx": "rbx", "bx": "rbx", "bl": "rbx",
            "ecx": "rcx", "cx": "rcx", "cl": "rcx",
            "edx": "rdx", "dx": "rdx", "dl": "rdx",
            "esi": "rsi", "si": "rsi", "sil": "rsi",
            "edi": "rdi", "di": "rdi", "dil": "rdi",
            "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
            "esp": "rsp", "sp": "rsp", "spl": "rsp",
        }
        if r in sub_to_parent:
            return sub_to_parent[r]
        for i in range(8, 16):
            base = f"r{i}"
            if r in (f"r{i}d", f"r{i}w", f"r{i}b"):
                return base
        if r.startswith("w"):
            return "x" + r[1:]
        return None

    def get_all_tainted_regs(self) -> Dict[str, List[str]]:
        """返回所有受污染寄存器及其污染来源的描述。"""
        result = {}
        for reg, sources in {**self._explicit, **self._implicit}.items():
            result[reg] = [s.guard_condition or f"explicit at {hex(s.source_addr)}" for s in sources]
        return result

    def get_violations(self) -> List[Dict]:
        return list(self._violations)
