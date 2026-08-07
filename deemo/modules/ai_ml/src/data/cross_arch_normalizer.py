#
# 跨架构指令语义归一化器 — 将不同 ISA 的汇编指令映射到统一的 IR 操作类型。
#
# 同一 C 源码编译到 x86_64 和 ARM32 产生的汇编在指令层面完全不同：
# x86: cmp eax, 0x41; je 0x401000
# ARM: CMP r0, #0x41; BEQ 0x1000
# 但它们的 IR 语义是相同的--都是一次比较 + 一次条件跳转。
#
# 本模块不替代反汇编器（Capstone 仍负责将机器码→助记符）。
# 它在反汇编器的输出之上做一层归一化--将各架构的助记符映射到
# 统一的 IR 操作类型（arith/logic/mem/branch/call/other），
# 供 graph_builder.py 的 12 维特征提取使用。
#
# 归一化后的操作类型分布在不同架构的同一源码函数上应高度一致--
# 这是跨架构 GNN 匹配的前提。没有这层归一化，ARM 条件执行指令
# （ADDNE, MOVCS 等）会被 graph_builder 分类为"arith"和"mem"，
# 而它们在 x86 上的等价位（cmp+jcc+add/mov）会被分类为"branch"+各自类型
# 导致同一函数的不同架构版本在 GNN 特征空间中偏离。

from typing import Dict, Set, Tuple, Optional

# x86_64 指令 → IR 操作类型
_X86_IR_MAP: Dict[str, str] = {
    # 数据移动
    'mov': 'mem', 'movsx': 'mem', 'movzx': 'mem', 'cmov': 'mem',
    'cmove': 'mem', 'cmovne': 'mem', 'cmovg': 'mem', 'cmovl': 'mem',
    'cmovge': 'mem', 'cmovle': 'mem', 'push': 'mem', 'pop': 'mem',
    'lea': 'arith', 'xchg': 'mem', 'xadd': 'arith',
    # 算术
    'add': 'arith', 'sub': 'arith', 'mul': 'arith', 'imul': 'arith',
    'div': 'arith', 'idiv': 'arith', 'inc': 'arith', 'dec': 'arith',
    'neg': 'arith', 'adc': 'arith', 'sbb': 'arith',
    # 逻辑/位运算
    'and': 'logic', 'or': 'logic', 'xor': 'logic', 'not': 'logic',
    'test': 'logic', 'shl': 'logic', 'shr': 'logic', 'sar': 'logic',
    'rol': 'logic', 'ror': 'logic', 'bt': 'logic', 'bts': 'logic',
    'btr': 'logic', 'bsf': 'logic', 'bsr': 'logic',
    # 控制流
    'cmp': 'branch', 'jmp': 'branch', 'je': 'branch', 'jne': 'branch',
    'jg': 'branch', 'jge': 'branch', 'jl': 'branch', 'jle': 'branch',
    'ja': 'branch', 'jae': 'branch', 'jb': 'branch', 'jbe': 'branch',
    'jo': 'branch', 'jno': 'branch', 'js': 'branch', 'jns': 'branch',
    'jcxz': 'branch', 'jecxz': 'branch', 'loop': 'branch',
    'loope': 'branch', 'loopne': 'branch',
    # 调用
    'call': 'call', 'syscall': 'call', 'int': 'call', 'sysenter': 'call',
    'ret': 'branch', 'iret': 'branch',
}

# ARM32 指令 → IR 操作类型
# ARM 条件执行（ADDEQ, MOVNE 等后缀）的归一化策略：
# 条件后缀被视为独立的"条件检查"--即每个条件执行指令等价于
# (cmp + op) 的组合。在 IR 分类时，条件后缀指令同时标记为 'branch'
# 和其基础操作类型。这使得 ARM 的 CFG 分支结构与 x86 的显式 cmp+jcc
# 在特征空间中趋于一致。
# 例如 ADDEQ r0, r1, r2 → 同时计为 arith 和 branch。
_ARM_COND_SUFFIXES = {'eq', 'ne', 'cs', 'cc', 'mi', 'pl', 'vs', 'vc',
                       'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al'}

_ARM_IR_MAP: Dict[str, str] = {
    # 数据移动
    'mov': 'mem', 'movw': 'mem', 'movt': 'mem', 'ldr': 'mem',
    'str': 'mem', 'ldrb': 'mem', 'strb': 'mem', 'ldrh': 'mem',
    'strh': 'mem', 'push': 'mem', 'pop': 'mem', 'adr': 'arith',
    # 算术
    'add': 'arith', 'sub': 'arith', 'mul': 'arith', 'sdiv': 'arith',
    'udiv': 'arith', 'mla': 'arith', 'mls': 'arith',
    # 逻辑
    'and': 'logic', 'orr': 'logic', 'eor': 'logic', 'orn': 'logic',
    'bic': 'logic', 'lsl': 'logic', 'lsr': 'logic', 'asr': 'logic',
    'ror': 'logic', 'clz': 'logic',
    # 比较/分支
    'cmp': 'branch', 'cmn': 'branch', 'tst': 'logic',
    'b': 'branch', 'bl': 'branch', 'bx': 'branch', 'blx': 'branch',
    'beq': 'branch', 'bne': 'branch', 'bgt': 'branch', 'blt': 'branch',
    'cbz': 'branch', 'cbnz': 'branch',
    # 调用
    'bl': 'call', 'svc': 'call',
}

# MIPS32 指令 → IR 操作类型
# MIPS 延迟槽 (delay slot) 指令的归一化：
# 分支指令后的延迟槽指令在原始 CFG 中产生一条额外的"延迟边"--
# 该边不对应程序逻辑的控制流，纯粹是 ISA artifact。
# 归一化策略：延迟槽指令合并到其所属基本块的末尾，不生成独立的基本块。
# 这由调用方（CFG 构建器）在基本块划分阶段处理，本模块仅负责指令分类。
_MIPS_IR_MAP: Dict[str, str] = {
    # 数据移动
    'lw': 'mem', 'sw': 'mem', 'lh': 'mem', 'sh': 'mem',
    'lb': 'mem', 'sb': 'mem', 'lui': 'mem', 'move': 'mem',
    # 算术
    'add': 'arith', 'addu': 'arith', 'sub': 'arith', 'subu': 'arith',
    'mul': 'arith', 'mult': 'arith', 'div': 'arith', 'divu': 'arith',
    'addi': 'arith', 'addiu': 'arith',
    # 逻辑
    'and': 'logic', 'or': 'logic', 'xor': 'logic', 'nor': 'logic',
    'andi': 'logic', 'ori': 'logic', 'xori': 'logic',
    'sll': 'logic', 'srl': 'logic', 'sra': 'logic',
    # 比较/分支
    'slt': 'branch', 'sltu': 'branch', 'slti': 'branch', 'sltiu': 'branch',
    'beq': 'branch', 'bne': 'branch', 'bgtz': 'branch', 'blez': 'branch',
    'b': 'branch', 'j': 'branch', 'jr': 'branch',
    # 调用
    'jal': 'call', 'jalr': 'call', 'syscall': 'call',
}

# AArch64 (ARM64) 指令 → IR 操作类型 — 2025-07-28 新增
#
# AArch64 与 ARM32 的关键差异（影响归一化策略）：
# (a) 无条件执行--AArch64 取消了条件执行后缀，条件分支仅通过 B.cond。
# 因此无需双重分类--每条指令恰好映射到一种 IR 类型。
# (b) 零寄存器 XZR/WZR--语义是"硬零"而非异或清零，归入 arith。
# (c) CSEL/CSINC 等条件选择--通用寄存器承载条件码，等价于 x86 cmov。
# (d) 位域操作 BFI/UBFM/SBFM--AArch64 特有，在 Z3 约束中对应 extract/concat，
# 归入 logic 是合理的--它们本质是位向量切片/拼接。
# (e) LDXR/STXR 独占加载/存储--原子操作，ir 分类暂不区分原子性，归入 mem。
_AARCH64_IR_MAP: Dict[str, str] = {
    # 数据移动
    'mov': 'mem', 'movz': 'mem', 'movk': 'mem', 'movn': 'mem',
    'ldr': 'mem', 'str': 'mem', 'ldrb': 'mem', 'strb': 'mem',
    'ldrh': 'mem', 'strh': 'mem', 'ldrsb': 'mem', 'ldrsh': 'mem',
    'ldrsw': 'mem', 'ldp': 'mem', 'stp': 'mem', 'ldnp': 'mem', 'stnp': 'mem',
    'adr': 'arith', 'adrp': 'arith',
    # 条件选择（AArch64 的 cmov 等价物）
    'csel': 'mem', 'csinc': 'mem', 'csinv': 'mem', 'csneg': 'mem',
    'cset': 'mem', 'csetm': 'mem',
    # 算术
    'add': 'arith', 'sub': 'arith', 'mul': 'arith', 'madd': 'arith',
    'msub': 'arith', 'sdiv': 'arith', 'udiv': 'arith', 'neg': 'arith',
    'mneg': 'arith', 'smaddl': 'arith', 'smsubl': 'arith',
    'umaddl': 'arith', 'umsubl': 'arith',
    # 逻辑/位运算
    'and': 'logic', 'orr': 'logic', 'eor': 'logic', 'orn': 'logic',
    'bic': 'logic', 'eon': 'logic', 'mvn': 'logic',
    'lsl': 'logic', 'lsr': 'logic', 'asr': 'logic', 'ror': 'logic',
    'sxtb': 'logic', 'sxth': 'logic', 'sxtw': 'logic',
    'uxtb': 'logic', 'uxth': 'logic',
    'bfi': 'logic', 'bfm': 'logic', 'bfxil': 'logic',
    'ubfm': 'logic', 'sbfm': 'logic', 'ubfiz': 'logic',
    # 比较/分支
    'cmp': 'branch', 'cmn': 'branch', 'tst': 'logic',
    'b': 'branch', 'br': 'branch', 'blr': 'branch',
    'b.eq': 'branch', 'b.ne': 'branch',
    'b.gt': 'branch', 'b.lt': 'branch', 'b.ge': 'branch', 'b.le': 'branch',
    'b.hi': 'branch', 'b.ls': 'branch', 'b.cs': 'branch', 'b.cc': 'branch',
    'b.mi': 'branch', 'b.pl': 'branch', 'b.vs': 'branch', 'b.vc': 'branch',
    'cbz': 'branch', 'cbnz': 'branch', 'tbz': 'branch', 'tbnz': 'branch',
    'ret': 'branch',
    # 调用
    'bl': 'call', 'blr': 'call', 'svc': 'call',
}

# RISC-V (RV64GC) 指令 → IR 操作类型 — 2025-08-01 新增
#
# RISC-V 归一化的特殊处理：
# (a) 零寄存器 x0--add rd, rs1, x0 等价于 x86 mov，按 arith 处理。
# 在分类时无法区分 "真正加法" vs "mov via x0"--两者都落入 arith。
# (b) 压缩指令 (C extension)--c.add, c.li 等 16-bit 形式与 32-bit
# 基础形式语义相同。normalize_mnemonic 在查表前剥离 c. 前缀。
# (c) AUIPC--RISC-V 的 PIC 基址指令，无 x86/ARM 直接等价，归入 arith。
# (d) FENCE/SFENCE.VMA--内存屏障，对漏洞检测特征无贡献，归入 other。
# (e) SLT/SLTU--条件设置指令，将比较结果写入目标寄存器（而非标志位）。
# 这与 x86 cmp+setXX 模式等价，分类为 branch。
_RISCV64_IR_MAP: Dict[str, str] = {
    # 数据移动（RISC-V 无独立 MOV--通过 addi rd, x0, imm 或 lw 实现）
    'lw': 'mem', 'sw': 'mem', 'lh': 'mem', 'sh': 'mem',
    'lb': 'mem', 'sb': 'mem', 'lhu': 'mem', 'lbu': 'mem',
    'ld': 'mem', 'sd': 'mem', 'lwu': 'mem',
    'lui': 'arith', 'auipc': 'arith', 'la': 'arith',
    # 算术
    'add': 'arith', 'addi': 'arith', 'sub': 'arith',
    'mul': 'arith', 'mulh': 'arith', 'mulhu': 'arith', 'mulhsu': 'arith',
    'div': 'arith', 'divu': 'arith', 'rem': 'arith', 'remu': 'arith',
    'addw': 'arith', 'addiw': 'arith', 'subw': 'arith',
    'mulw': 'arith', 'divw': 'arith', 'divuw': 'arith',
    # 逻辑/位运算
    'and': 'logic', 'andi': 'logic', 'or': 'logic', 'ori': 'logic',
    'xor': 'logic', 'xori': 'logic', 'not': 'logic',
    'sll': 'logic', 'slli': 'logic', 'srl': 'logic', 'srli': 'logic',
    'sra': 'logic', 'srai': 'logic',
    'sllw': 'logic', 'slliw': 'logic', 'srlw': 'logic',
    'srliw': 'logic', 'sraw': 'logic', 'sraiw': 'logic',
    # 条件设置（RISC-V 无标志寄存器--通过 SLT/SLTU 配合分支使用）
    'slt': 'branch', 'slti': 'branch', 'sltu': 'branch', 'sltiu': 'branch',
    # 分支
    'beq': 'branch', 'bne': 'branch', 'blt': 'branch', 'bge': 'branch',
    'bltu': 'branch', 'bgeu': 'branch', 'beqz': 'branch', 'bnez': 'branch',
    'j': 'branch', 'jr': 'branch', 'ret': 'branch',
    # 调用
    'jal': 'call', 'jalr': 'call', 'ecall': 'call',
    # 原子操作--涉及内存，但语义含义高于普通 load/store
    'lr.w': 'mem', 'sc.w': 'mem', 'lr.d': 'mem', 'sc.d': 'mem',
    'amoadd.w': 'arith', 'amoswap.w': 'mem',
    # CSR
    'csrr': 'mem', 'csrw': 'mem', 'csrs': 'mem', 'csrc': 'mem',
    'csrrw': 'mem', 'csrrs': 'mem', 'csrrc': 'mem',
}

# 架构名 → 映射表的统一查找
_ARCH_MAPS = {'x86': _X86_IR_MAP, 'x86_64': _X86_IR_MAP,
              'arm': _ARM_IR_MAP, 'arm32': _ARM_IR_MAP,
              'arm64': _AARCH64_IR_MAP, 'aarch64': _AARCH64_IR_MAP,
              'mips': _MIPS_IR_MAP, 'mips32': _MIPS_IR_MAP,
              'riscv': _RISCV64_IR_MAP, 'riscv64': _RISCV64_IR_MAP,
              'rv64gc': _RISCV64_IR_MAP}


def normalize_mnemonic(mnemonic: str, arch: str) -> str:
    """将架构特定的汇编助记符归一化为通用 IR 操作类型。

    返回: 'arith' | 'logic' | 'mem' | 'branch' | 'call' | 'other'
    """
    ir_map = _ARCH_MAPS.get(arch.lower(), {})
    mnem_lower = mnemonic.lower().strip()

    # RISC-V 压缩指令前缀剥离--c.add → add
    if arch.lower().startswith('riscv') or arch.lower() == 'rv64gc':
        if mnem_lower.startswith('c.') and len(mnem_lower) > 2:
            base = mnem_lower[2:]
            if base in ir_map:
                return ir_map[base]

    if mnem_lower in ir_map:
        return ir_map[mnem_lower]

    # ARM 条件后缀处理--如 'addeq' → 基础操作 'add' + 条件标志
    if arch.lower().startswith('arm') and not arch.lower().startswith('arm64'):
        for suffix in sorted(_ARM_COND_SUFFIXES, key=len, reverse=True):
            if mnem_lower.endswith(suffix) and len(mnem_lower) > len(suffix):
                base = mnem_lower[:-len(suffix)]
                if base in _ARM_IR_MAP:
                    return _ARM_IR_MAP[base]
        # ARM 的 's' 后缀（如 adds, subs）不影响操作类型
        if mnem_lower.endswith('s') and len(mnem_lower) > 1:
            base = mnem_lower[:-1]
            if base in _ARM_IR_MAP:
                return _ARM_IR_MAP[base]

    return 'other'


def get_arm_has_implicit_branch(mnemonic: str) -> bool:
    """判断 ARM 指令是否携带条件执行后缀（隐含条件分支语义）。

    此函数供调用方在特征提取时使用——携带条件后缀的指令应同时
    在 'branch' 类别中计数，以补偿 ARM 缺少显式 cmp+jcc 的架构差异。
    """
    if not mnemonic.lower().startswith(('b', 'bl', 'bx', 'cbz', 'cbnz')):
        for suffix in _ARM_COND_SUFFIXES:
            if mnemonic.lower().endswith(suffix):
                return True
    return False
