# 签名.py：组合约束的函数签名恢复（Cross-Architecture 签名 Recovery）
#
# 对应论文:
# Recover Function 签名 Combined Constraints - ACM CCS 2025
# Binary2vec: Cross-architecture binary embeddings global
# attention-enhanced graph neural 网络s - Array 2025
#
# 设计意图:
#   跨架构识别要求签名不依赖具体指令集。本模块把来自多个独立约束源的
#   证据合并，恢复 (参数个数, 返回类型) 并给出置信度:
#     约束 A - 反编译签名行的显式形参列表（最可靠）
#     约束 B - 函数体内"未先赋值即被读取"的标识符（隐式参数候选）
#     约束 C - 反汇编文本中参数寄存器的读取模式（若无反汇编则缺失）
#     约束 D - return 语句形态推断返回类型（void/int/指针启发式）
#   每类约束是弱信号，合并后按加权投票给出高置信签名；缺失的约束源
# 不参与投票（视为中性），保证跨架构场景下仍可输出部分签名
#
# 边界条件:
#   伪代码无类型信息时默认按 int 处理；寄存器约束仅在提供反汇编
# 文本片段时生效；返回指针的判定依赖 & / -> / * 运算出现

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 调用约定表：参数寄存器顺序（从前向后）、栈传递起点

_CALLING_CONVENTIONS: Dict[str, Dict[str, Any]] = {
    'x86_64': {
        'name': 'sysv_amd64',
        'family': 'x86_64',
        'regs': ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'],
        'stack_passing_after': 6,
    },
    'x86_64_windows': {
        'name': 'microsoft_x64',
        'family': 'x86_64',
        'regs': ['rcx', 'rdx', 'r8', 'r9'],
        'stack_passing_after': 4,
    },
    'x86': {
        'name': 'cdecl',
        'family': 'x86',
        'regs': [],
        'stack_passing_after': 0,
    },
    'arm64': {
        'name': 'aapcs64',
        'family': 'arm64',
        'regs': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
        'stack_passing_after': 8,
    },
    'arm': {
        'name': 'aapcs',
        'family': 'arm',
        'regs': ['r0', 'r1', 'r2', 'r3'],
        'stack_passing_after': 4,
    },
    'mips': {
        'name': 'o32',
        'family': 'mips',
        'regs': ['$a0', '$a1', '$a2', '$a3'],
        'stack_passing_after': 4,
    },
    'riscv64': {
        'name': 'riscv',
        'family': 'riscv64',
        'regs': ['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'],
        'stack_passing_after': 8,
    },
    'ppc64': {
        'name': 'sysv_ppc64',
        'family': 'ppc64',
        'regs': ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'],
        'stack_passing_after': 8,
    },
}

# 返回类型大类：用于跨架构兼容性比较
_RETURN_CLASS = {
    'void': 'void',
    'int': 'int',
    'unsigned': 'int',
    'size_t': 'int',
    'char': 'int',
    'long': 'int',
    'pointer': 'pointer',
    'bool': 'int',
}

# 常见指针返回值命名启发式：str*/mem*/alloc 类前缀
_POINTER_NAME_HINTS = re.compile(
    r'^(str|mem|alloc|get|find|lookup|new|create|make|parse|read|open|realloc|calloc|malloc|free)',
    re.IGNORECASE,
)


@dataclass
class RecoveredSignature:
    """组合约束恢复出的函数签名"""
    param_count: int = 0
    param_names: List[str] = field(default_factory=list)
    return_type: str = 'int'                 # void / int / 指针 / unsigned
    return_class: str = 'int'                # 抽象大类，用于跨架构比较
    arch: str = 'x86_64'
    confidence: float = 0.0                  # [0,1]
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'param_count': self.param_count,
            'param_names': self.param_names,
            'return_type': self.return_type,
            'return_class': self.return_class,
            'arch': self.arch,
            'confidence': round(self.confidence, 4),
            'evidence': self.evidence,
        }


def _param_count_from_signature_line(code: str) -> Tuple[int, List[str], float]:
    """约束 A：解析反编译签名行的显式形参"""
    match = re.search(r'\(([^)]*)\)\s*\{', code, re.DOTALL)
    if not match:
        return -1, [], 0.0
    inner = match.group(1).strip()
    if inner == 'void' or inner == '':
        return 0, [], 1.0
    parts = [p.strip() for p in inner.split(',') if p.strip()]
    names: List[str] = []
    for part in parts:
        ids = re.findall(r'[A-Za-z_]\w*', part)
        # 形如 "int a" / "char *buf" - 最后标识符是变量名
        if ids:
            names.append(ids[-1])
    return len(names), names, 1.0


def _implicit_args_from_body(code: str) -> List[str]:
    """约束 B：未先赋值即被读取的标识符（隐式参数候选）

    算法: 收集形如 `\bname\b` 且非关键字、非类型名的标识符；
    排除形如 `name =` 的写入位置（粗粒度近似数据流）
    """
    declared = set(re.findall(
        r'\b(?:int|char|void|long|short|unsigned|signed|float|double|size_t|bool)\s+'
        r'[*\s]*\b([A-Za-z_]\w*)\b', code))
    written = set(re.findall(r'\b([A-Za-z_]\w*)\s*=(?!=)', code))
    read = set(re.findall(r'\b([A-Za-z_]\w*)\b', code))
    keywords = {'if', 'else', 'while', 'for', 'switch', 'case', 'return',
                'sizeof', 'do', 'goto', 'continue', 'break', 'struct',
                'union', 'enum', 'typedef', 'default', 'static', 'const',
                'int', 'char', 'void', 'long', 'short', 'unsigned', 'signed',
                'float', 'double', 'size_t', 'bool'}
    candidates = [v for v in read
                  if v not in keywords and v not in declared and v not in written]
    return candidates


def _return_type_from_body(code: str) -> Tuple[str, str, float]:
    """约束 D：依据 return 语句形态推断返回类型"""
    returns = re.findall(r'\breturn\s*([^;]*)', code)
    if not returns:
        # 无 return：可能 void，也可能主函数隐含 0
        if re.search(r'\bvoid\s+[A-Za-z_]\w*\s*\(', code):
            return 'void', 'void', 0.8
        return 'void', 'void', 0.4
    has_value = False
    has_pointer_op = False
    for expr in returns:
        expr = expr.strip()
        if not expr:
            continue
        has_value = True
        if re.search(r'[&*]->|malloc|calloc|realloc|strdup|memchr|strchr', expr):
            has_pointer_op = True
        if re.search(r'\b\d+\b', expr) and not has_pointer_op:
            pass
    if not has_value:
        return 'void', 'void', 0.8
    if has_pointer_op:
        return 'pointer', 'pointer', 0.6
    return 'int', 'int', 0.5


def _register_arg_count_from_asm(asm_text: str, convention: Dict[str, Any]) -> Optional[int]:
    """约束 C：从反汇编文本推断参数寄存器读取数"""
    if not asm_text:
        return None
    regs = convention.get('regs', [])
    if not regs:
        # 全栈传参约定无法从寄存器推断
        return None
    used: List[str] = []
    for reg in regs:
        # 匹配作为源操作数的寄存器（粗略：出现次数 >= 2 视为被使用）
        count = len(re.findall(r'\b' + re.escape(reg) + r'\b', asm_text, re.IGNORECASE))
        if count >= 2:
            used.append(reg)
    if not used:
        return None
    # 参数寄存器按约定顺序连续使用：取最长前缀
    k = 0
    for reg in regs:
        if reg in used:
            k += 1
        else:
            break
    return k


class SignatureRecoverer:
    """从组合约束恢复函数签名

    对应论文: CCS 2025 (combined constraints)；Array 2025 (跨架构视角)
    约束 A 权重最高；B/C 作为交叉验证；D 决定返回类型
    """

    def __init__(self):
        self.conventions = _CALLING_CONVENTIONS

    def recover(self, pseudocode: str, arch: str = 'x86_64',
                asm_text: Optional[str] = None,
                function_name: str = '') -> RecoveredSignature:
        convention = self.conventions.get(arch) or self.conventions['x86_64']
        evidence: List[str] = []
        code = pseudocode or ''

        # 约束 A：显式形参
        a_count, a_names, a_conf = _param_count_from_signature_line(code)
        if a_count >= 0:
            evidence.append(f'签名行显式形参 {a_count} 个: {a_names}')

        # 约束 B：隐式参数
        b_candidates = _implicit_args_from_body(code)
        if b_candidates:
            evidence.append(f'未先赋值即读取的标识符 {len(b_candidates)} 个: '
                            f'{b_candidates[:6]}')

        # 约束 C：寄存器
        c_count = _register_arg_count_from_asm(asm_text, convention) \
            if asm_text else None
        if c_count is not None:
            evidence.append(f'参数寄存器读取前缀 {c_count} 个')
        elif asm_text is not None:
            evidence.append('寄存器约束缺失（无参数寄存器使用）')

        # 约束 D：返回类型
        ret_type, ret_class, ret_conf = _return_type_from_body(code)
        evidence.append(f'返回类型推断: {ret_type} (置信度 {ret_conf:.2f})')

# 加权投票
        if a_count >= 0:
            param_count = a_count
            param_names = a_names
            conf = 0.5 * a_conf + 0.3 * ret_conf
        else:
            # 无显式签名：用寄存器 + 隐式参数折中
            est = c_count if c_count is not None else len(b_candidates)
            param_count = max(0, est if est is not None else 0)
            param_names = b_candidates[:param_count] if param_count else []
            conf = 0.3 * ret_conf
            if c_count is not None:
                conf += 0.3
            elif b_candidates:
                conf += 0.15

        # 隐式/寄存器约束与显式约束交叉验证：不一致时略微降置信度
        if c_count is not None and a_count >= 0 and c_count != a_count:
            conf -= 0.1
        if b_candidates and a_count >= 0 and len(b_candidates) > a_count + 2:
            conf -= 0.05

        conf = max(0.0, min(1.0, conf))

        # 名称启发式增强返回类型：无指针运算但函数名像字符串处理 → 指针
        if ret_type == 'int' and function_name and _POINTER_NAME_HINTS.match(function_name):
            ret_type, ret_class = 'pointer', 'pointer'
            evidence.append(f'函数名 {function_name} 暗示指针返回值')

        return RecoveredSignature(
            param_count=param_count,
            param_names=param_names,
            return_type=ret_type,
            return_class=ret_class,
            arch=arch,
            confidence=conf,
            evidence=evidence,
        )

    def cross_arch_compatible(self, sig_a: RecoveredSignature,
                              sig_b: RecoveredSignature,
                              arch_b: str = 'x86_64') -> Tuple[bool, List[str]]:
        """判断两个不同架构下恢复的签名是否兼容

        兼容判据: 参数个数一致 且 返回类型大类一致（void/int/pointer）
        仅比较抽象大类，规避具体类型名在跨架构反编译中的差异
        """
        notes: List[str] = []
        ok = True
        if sig_a.param_count != sig_b.param_count:
            ok = False
            notes.append(f'参数个数不一致: {sig_a.param_count} vs {sig_b.param_count}')
        else:
            notes.append(f'参数个数一致: {sig_a.param_count}')
        if sig_a.return_class != sig_b.return_class:
            ok = False
            notes.append(f'返回类型大类不一致: {sig_a.return_class} vs {sig_b.return_class}')
        else:
            notes.append(f'返回类型大类一致: {sig_a.return_class}')
        if ok:
            notes.append(f'签名跨架构兼容 ({sig_a.arch} <-> {arch_b})')
        return ok, notes


def normalize_arch(arch: str) -> str:
    """把常见别名映射到约定表键名"""
    a = arch.lower().replace('-', '_')
    mapping = {
        'x64': 'x86_64', 'amd64': 'x86_64', 'x86_64': 'x86_64',
        'win64': 'x86_64_windows', 'x86_64_windows': 'x86_64_windows',
        'i386': 'x86', 'x86': 'x86', 'i686': 'x86',
        'aarch64': 'arm64', 'arm64': 'arm64',
        'arm': 'arm', 'armhf': 'arm',
        'mips': 'mips', 'mipsel': 'mips',
        'riscv64': 'riscv64', 'riscv32': 'riscv64',
        'ppc64': 'ppc64', 'powerpc64': 'ppc64',
    }
    return mapping.get(a, a)


__all__ = [
    'RecoveredSignature',
    'SignatureRecoverer',
    'normalize_arch',
    '_CALLING_CONVENTIONS',
]
