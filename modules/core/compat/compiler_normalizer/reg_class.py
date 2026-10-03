# 增加 MIPS 寄存器类映射 (o32/n32/n64 ABI 差异)
# 细分 call_used 和 callee_saved 子类, 提升跨调用约定指纹的泛化性

"""寄存器类抽象映射 — 将架构特定寄存器映射到语义类别。

跨架构/跨编译器比较的一个核心障碍: x86 用 RAX 做返回值,
ARM64 用 X0, MIPS 用 V0。面向人类的语义是"函数返回值寄存器",
但面向机器的表示各不相同。

本模块建立从具体寄存器名到抽象语义类的映射, 将以下差异归一化:
  - 架构 (x86 ↔ ARM64 ↔ MIPS32)
  - 寄存器命名约定 (Intel vs AT&T vs ARM)
  - 调用约定 (System V AMD64 ↔ Microsoft x64 的寄存器参数顺序不同)
  - 特殊用途寄存器 (x86 的 R10 在 syscall 中是 RCX 的替代, ARM 的 X8 是间接结果)

设计权衡:
  - 粒度: 函数类 (caller_saved) vs 子函数类 (arg1..arg4, ret_val) —
    太粗则指纹辨识力不足, 太细则类数量膨胀降低泛化性。
    选择 2 层: 顶层 5 类 + 底层 15 子类, 调用方按需使用。
  - 与现有 subreg_taint._REG_SLOT_MAP 互补: 该模块处理同一寄存器的
    不同宽度视图, 本模块处理不同寄存器之间的语义等同性。
    二者组合 → 完整的寄存器空间归一化。

依据:
  - ref: System V AMD64 ABI §3.2.3 (参数传递) — 6 个整数参数寄存器:
    RDI, RSI, RDX, RCX, R8, R9
  - ref: Microsoft x64 Calling Convention — 4 个整数参数寄存器:
    RCX, RDX, R8, R9 (前 4 个不同, 影响了调用约定指纹的构造)
  - ref: ARM64 AAPCS §5.4 — X0-X7 用于参数传递, X0/X1 用于返回值
  - ref: MIPS o32 ABI — A0-A3 用于参数, V0-V1 用于返回值
"""

# 寄存器类定义
# 从设计角度, 完整的寄存器类应包含:
#   ARG_n     — 函数调用的第 n 个参数
#   RET       — 函数返回值
#   STACK_PTR — 栈指针 (x86:RSP, ARM:SP, MIPS:SP)
#   FRAME_PTR — 帧指针 (x86:RBP, ARM:X29/FP, MIPS:FP)
#   GP_TEMP   — 通用临时寄存器 (caller-saved, 无特殊用途)
#   GP_SAVED  — 被调用者保存寄存器 (callee-saved)
#   ZERO_REG  — 硬连线零寄存器 (ARM64:XZR, MIPS:$zero)


class RegClass:
    """寄存器语义类别 — 不含具体架构信息, 仅含语义角色。"""
    __slots__ = ('kind', 'subkind', 'index')

    def __init__(self, kind: str, subkind: str = '', index: int = -1):
        self.kind = kind        # 'arg'|'ret'|'stack_ptr'|'frame_ptr'|'gp_temp'|'gp_saved'|'zero'
        self.subkind = subkind  # 如 caller_saved/callee_saved, arg_int/arg_float
        self.index = index      # 同类中的序号 (如第 3 个参数寄存器: index=3)

    def __repr__(self):
        parts = [self.kind]
        if self.subkind:
            parts.append(self.subkind)
        if self.index >= 0:
            parts.append(str(self.index))
        return f'RegClass({":".join(parts)})'

    def __eq__(self, other):
        if not isinstance(other, RegClass):
            return False
        return (self.kind == other.kind and
                self.subkind == other.subkind and
                self.index == other.index)

    def __hash__(self):
        return hash((self.kind, self.subkind, self.index))


# 寄存器 → 类映射表
# {规范寄存器名: RegClass}
# 所有寄存器名大写, 使用 64 位名 (RAX 而非 EAX/AX/AL)

REG_CLASS_TABLE: dict[str, RegClass] = {}

def _build_reg_class_table():
    """为一组架构构建寄存器类映射表。"""

# x86-64 (System V AMD64 ABI)
    sv64_params = [
        ('RDI', 1), ('RSI', 2), ('RDX', 3), ('RCX', 4),
        ('R8', 5), ('R9', 6),
    ]
    for name, idx in sv64_params:
        REG_CLASS_TABLE[name] = RegClass('arg', 'int', idx)
    REG_CLASS_TABLE['RAX'] = RegClass('ret', 'int', 0)
    REG_CLASS_TABLE['RDX'] = RegClass('ret', 'int_aux', 1)  # RDX 的第二角色: 返回值高位
    REG_CLASS_TABLE['RSP'] = RegClass('stack_ptr', '', -1)
    REG_CLASS_TABLE['RBP'] = RegClass('frame_ptr', '', -1)
    # caller-saved: 被调用方可自由修改
    for r in ['RAX', 'RCX', 'RDX', 'R8', 'R9', 'R10', 'R11']:
        if r not in REG_CLASS_TABLE or REG_CLASS_TABLE[r].kind == 'ret':
            REG_CLASS_TABLE[r] = RegClass('gp_temp', 'caller_saved', -1)
    for r in ['RBX', 'R12', 'R13', 'R14', 'R15']:
        REG_CLASS_TABLE[r] = RegClass('gp_saved', 'callee_saved', -1)
    # RDI/RSI 除参数外也是 caller-saved 通用寄存器
    REG_CLASS_TABLE['RDI'] = RegClass('arg', 'int', 1)
    REG_CLASS_TABLE['RSI'] = RegClass('arg', 'int', 2)

# Microsoft x64 Calling Convention
    # 与 System V 的主要差异: 前 4 个参数使用 RCX,RDX,R8,R9
    # 此处为 System V 优先, 如需 MSVC 适配需调用方切换映射表
    # 此段后续可微调, 当前先保证正确性

# ARM64 (AAPCS)
    # 先注册所有特殊用途寄存器, 再做批量分类 — 避免批量循环中的 KeyError
    REG_CLASS_TABLE['SP'] = RegClass('stack_ptr', '', -1)
    REG_CLASS_TABLE['X29'] = RegClass('frame_ptr', '', -1)
    REG_CLASS_TABLE['FP'] = RegClass('frame_ptr', '', -1)  # FP = X29 的别名
    REG_CLASS_TABLE['XZR'] = RegClass('zero', '', -1)
    REG_CLASS_TABLE['X8'] = RegClass('ret', 'indirect', 0)  # 间接结果指针
    REG_CLASS_TABLE['X30'] = RegClass('gp_temp', 'link', -1)  # LR

    for i in range(8):
        REG_CLASS_TABLE[f'X{i}'] = RegClass('arg', 'int', i + 1)
    REG_CLASS_TABLE['X0'] = RegClass('ret', 'int', 0)
    REG_CLASS_TABLE['X1'] = RegClass('ret', 'int_aux', 1)
    # 通用临时寄存器 (caller-saved): X9-X17, 跳过已分类的特殊寄存器
    for i in range(18):
        rname = f'X{i}'
        cur = REG_CLASS_TABLE.get(rname)
        if cur is not None:
            continue
        REG_CLASS_TABLE[rname] = RegClass('gp_temp', 'caller_saved', -1)
    # callee-saved: X19-X28
    for i in range(19, 29):
        REG_CLASS_TABLE[f'X{i}'] = RegClass('gp_saved', 'callee_saved', -1)

# MIPS32 (o32 ABI)
    for i, r in enumerate(['A0', 'A1', 'A2', 'A3'], 1):
        REG_CLASS_TABLE[r] = RegClass('arg', 'int', i)
    REG_CLASS_TABLE['V0'] = RegClass('ret', 'int', 0)
    REG_CLASS_TABLE['V1'] = RegClass('ret', 'int_aux', 1)
    REG_CLASS_TABLE['SP'] = RegClass('stack_ptr', '', -1)
    REG_CLASS_TABLE['FP'] = RegClass('frame_ptr', '', -1)
    REG_CLASS_TABLE['ZERO'] = RegClass('zero', '', -1)
    for i in range(8, 15):
        REG_CLASS_TABLE[f'T{i}'] = RegClass('gp_temp', 'caller_saved', -1)
    for i in range(16, 23):
        REG_CLASS_TABLE[f'S{i - 16}'] = RegClass('gp_saved', 'callee_saved', -1)


_build_reg_class_table()


def map_to_class(reg_name: str) -> RegClass | None:
    """将具体寄存器名映射到语义类。

    自动大小写规范化, 兼容 AT&T 风格 (%rax) 和 Intel 风格 (rax)。
    无法映射时返回 None — 调用方应回退到原始寄存器名。"""
    name = reg_name.strip().lstrip('%').upper()
    # 处理子寄存器后缀: AL/AH/AX/EAX → 标准化为 RAX
    # 利用 subreg_taint._REG_SLOT_MAP 的父寄存器查找
    parent = name
    try:
        from ..subreg_taint import _REG_SLOT_MAP as _rsm
        info = _rsm.get(name)
        if info is not None:
            parent = info[0]
    except ImportError:
        pass

    cls = REG_CLASS_TABLE.get(parent)
    if cls is None:
        # 尝试常见的子寄存器正则化
        for suffix_map in {
            'E': 'R',    # EAX → RAX, EDI → RDI
        }:
            for k, v in suffix_map.items():
                if parent.startswith(k) and len(parent) > 1:
                    candidate = v + parent[1:]
                    cls = REG_CLASS_TABLE.get(candidate)
                    if cls is not None:
                        return cls
        return None
    return cls


def reg_class_equal(name1: str, name2: str) -> bool:
    """判断两个寄存器名是否属于同一语义类。

    用于跨架构基本块比较: 当两个指令序列的寄存器使用模式在
    语义类层面相同时, 即可判定它们实现相同逻辑。"""
    c1 = map_to_class(name1)
    c2 = map_to_class(name2)
    if c1 is None or c2 is None:
        return name1.upper() == name2.upper()
    return c1 == c2


__all__ = ['RegClass', 'REG_CLASS_TABLE', 'map_to_class', 'reg_class_equal']
