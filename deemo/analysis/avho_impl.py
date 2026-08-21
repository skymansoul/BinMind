# AVHO-G — 二进制级堆溢出检测核心管线 (objdump 反汇编).
#
# 决策逻辑:
#   反汇编 → 指令解析 (用户函数过滤) → 单函数寄存器追踪
#   (Win x64 ABI: rcx=dst/rdx=src/r8=size) → 三类发现:
#     1. direct_write: mov [malloc_ptr+off], val
#     2. memcpy: 偏移经 'malloc@addr+off+off2' 累积提取
#     3. loop_accumulate: 循环内 memcpy 累积写入
#         (后向跳转+cmp+归纳变量 → trip_count×stride)
#   oversize malloc 回退: size>0x1000000 或 None → 128 (保守上界).
#   分类 (BOUND_CHECK): usable = ptmalloc2 model_alloc(alloc).usable_size,
#     offset+size > usable 才判 vuln (分配器 padding 合法访问不过滤).
#   本文件实现 AVHO-G 核心链; CAORN proof 与 DP-TVRA 阶段属其他品牌
#   (offset_proof_filter / heap_fp_filter_v2), 保留在原管线.
#
# 本文件为 AVHO 独立实现, 合并 modules/vuln/src/heap/ 的
# insn_parser.py + func_analyzer.py + allocator_model.py +
# loop_accum_detector.py + _heap_orch_helpers.py 的 AVHO 核心部分
# (剔除 HeapBoundInferrer/OffsetProofFilter/HeapFPFilterV2 依赖),
# 仅标准库.

import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_DEFAULT_ALLOC = 128


# ================= 指令解析 (原 insn_parser) =================

_ASM_LINE_RE = re.compile(
    r'^\s*([0-9a-fA-F]+):\s+'
    r'((?:[0-9a-fA-F]{2}\s)+)\s+'
    r'(.+)$')

_REG_ALIASES = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
    'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
    'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
    'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
    'r12': 'r12', 'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
    'r13': 'r13', 'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
    'r14': 'r14', 'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
    'r15': 'r15', 'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp',
}


@dataclass
class Instruction:
    """一条反汇编指令."""
    addr: int
    mnemonic: str
    operands: str
    raw: str


def is_user_function(name: str, n_insns: int = 999) -> bool:
    """排除CRT/系统/IAT函数, 只分析用户代码."""
    if not name:
        return False
    skip_prefixes = (
        '__', '_', '.', 'memset', 'memcpy', 'memmove',
        'strlen', 'strcpy', 'strcat', 'printf', 'scanf',
        'malloc', 'calloc', 'realloc', 'free', 'fflush',
        'abort', 'exit', 'atexit', 'setvbuf', 'setjmp',
        'longjmp', 'signal', 'raise', 'perror',
    )
    skip_contains = (
        '_msvc', 'mingw_', 'DllMain', 'WinMain',
        'register_frame', 'deregister_frame',
        'duplicate_pp', 'pseudo_reloc',
        'mark_section', 'restore_modified',
        '_pei386', '__tmain', 'wcsnlen', 'strnlen',
        'wcrtomb', 'mbrtowc', 'bitstob',
        'dtoa_lock', 'dtoa_unlock',
        'init_fpreg', 'fallback_IsDBCS',
        'CRTStartup', 'pei386',
    )
    if name.startswith(skip_prefixes):
        return False
    if any(s in name for s in skip_contains):
        return False
    # 短函数: ≤4条指令且满足IAT stub特征 → 过滤
    if n_insns <= 4:
        if (_is_iat_stub_like(name)):
            return False
    return True


def _is_iat_stub_like(name: str) -> bool:
    """检查函数名是否像导入表桩 (Windows API/CRT wrapper)."""
    if name[0].isupper() and any(c.islower() for c in name):
        return True
    if (name.islower() and '_' not in name
            and len(name) <= 12 and name.isalpha()):
        return True
    return False


def parse_instructions(asm_text: str) -> List[Tuple[str, List[Instruction]]]:
    """解析objdump输出为按函数分组的指令列表."""
    functions: List[Tuple[str, List[Instruction]]] = []
    current_fn = ""
    current_insns: List[Instruction] = []
    fn_header_re = re.compile(r'^[0-9a-fA-F]+\s+<([^>]+)>:\s*$')

    for line in asm_text.split('\n'):
        line = line.rstrip()
        fn_match = fn_header_re.match(line)
        if fn_match:
            if current_insns and is_user_function(current_fn,
                                                  len(current_insns)):
                functions.append((current_fn, current_insns))
            current_fn = fn_match.group(1)
            current_insns = []
            continue

        m = _ASM_LINE_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            raw_insn = m.group(3).strip()
            if ' ' in raw_insn:
                parts = raw_insn.split(None, 1)
                mnemonic = parts[0].lower()
                operands = parts[1] if len(parts) > 1 else ''
            else:
                mnemonic = raw_insn.lower()
                operands = ''
            current_insns.append(Instruction(
                addr=addr, mnemonic=mnemonic, operands=operands,
                raw=raw_insn))

    if current_insns and is_user_function(current_fn, len(current_insns)):
        functions.append((current_fn, current_insns))
    return functions


def is_call_to(insn: Instruction, target: str) -> bool:
    """检查call目标是否含指定符号名."""
    return insn.mnemonic == 'call' and target in insn.operands.lower()


def extract_register(operand: str) -> Optional[str]:
    """提取操作数中的寄存器, 返回规范名."""
    m = re.search(
        r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p|[er]?ip)\b',
        operand, re.IGNORECASE)
    if m:
        return _REG_ALIASES.get(m.group(1).lower(), m.group(1).lower())
    return None


def extract_constant(operand: str) -> Optional[int]:
    """提取操作数中的立即数 (hex: 0xNNN, dec: NNN, mem: [reg+NNN])."""
    m = re.search(r'0x([0-9a-fA-F]+)', operand)
    if m:
        return int(m.group(1), 16)
    m = re.search(r'\[[^]]*[+]\s*(0x[0-9a-fA-F]+|\d+)', operand)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    m = re.search(r'(?<![0-9a-fA-Fx])(\d+)(?![0-9a-fA-Fx])', operand)
    if m:
        val = int(m.group(1))
        if val < 0x100000:
            return val
    return None


def extract_mem_offset(operand: str) -> Tuple[Optional[str], Optional[int]]:
    """从内存操作数 [reg+offset] 提取 (reg, offset)."""
    m = re.search(r'\[([^\]]+)\]', operand)
    if not m:
        return None, None
    inner = m.group(1).strip()
    reg = extract_register(inner)
    const = extract_constant(inner)
    if reg is None and re.match(r'^[a-z][a-z0-9]+$', inner):
        reg = _REG_ALIASES.get(inner.lower(), inner.lower())
    return reg, const


def infer_access_size(mem_operand: str, raw_insn: str) -> int:
    """从内存操作数/指令文本推断访问大小 (字节)."""
    raw_lower = raw_insn.lower()
    if 'byte ptr' in raw_lower:
        return 1
    if 'word ptr' in raw_lower:
        return 2
    if 'dword ptr' in raw_lower:
        return 4
    if 'qword ptr' in raw_lower:
        return 8
    if 'xmmword' in raw_lower:
        return 16
    if 'movzx' in raw_lower or 'movsx' in raw_lower:
        if 'byte' in raw_lower:
            return 1
        if 'word' in raw_lower:
            return 2
    return 4


def extract_malloc_addr(val_str: str) -> Optional[int]:
    """从 'malloc@0x1400017fa' 中提取十六进制地址."""
    for prefix in ('malloc@', 'calloc@', 'realloc@', 'strdup@'):
        m = re.search(rf'{re.escape(prefix)}([0-9a-fA-F]+)', val_str)
        if m:
            return int(m.group(1), 16)
    return None


# ================= 函数分析 (原 func_analyzer) =================

@dataclass
class FunctionAnalysis:
    """单个函数内的堆操作分析结果."""
    name: str = ""
    n_insns: int = 0
    mallocs: List[dict] = field(default_factory=list)
    frees: List[dict] = field(default_factory=list)
    writes: List[dict] = field(default_factory=list)
    memcpys: List[dict] = field(default_factory=list)
    violations: int = 0


_CALLER_SAVED = {'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}


def _clear_caller_saved(reg_val: Dict[str, object]) -> None:
    for r in _CALLER_SAVED:
        reg_val.pop(r, None)


def _handle_mov(insn: Instruction,
                reg_val: Dict[str, object],
                mem_val: Dict[str, object],
                fa: FunctionAnalysis,
                fn_name: str) -> None:
    """处理 mov 及其变体指令."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''

    dst_reg = extract_register(dst)
    src_reg = extract_register(src)
    src_const = extract_constant(src) if '[' not in src else None

    # 内存写入: mov [reg+offset], val
    if '[' in dst:
        base_reg, base_off = extract_mem_offset(dst)
        if base_reg:
            base_val = reg_val.get(base_reg)
            if isinstance(base_val, str) and 'malloc' in str(base_val):
                fa.writes.append({
                    'addr': insn.addr,
                    'base_reg': base_reg,
                    'base_val': base_val,
                    'offset': base_off or 0,
                    'access_size': infer_access_size(dst, insn.raw),
                    'src_val': src_const,
                    'function': fn_name,
                })
        mem_key = f"mem@{dst}"
        if src_reg and src_reg in reg_val:
            mem_val[mem_key] = reg_val[src_reg]
        elif src_const is not None:
            mem_val[mem_key] = src_const
        return

    # 寄存器赋值
    if dst_reg:
        if src_reg and src_reg in reg_val:
            reg_val[dst_reg] = reg_val[src_reg]
        elif '[' in src:
            base_reg, _ = extract_mem_offset(src)
            mem_key = f"mem@{src}"
            if mem_key in mem_val:
                reg_val[dst_reg] = mem_val[mem_key]
            elif base_reg and base_reg in reg_val:
                reg_val[dst_reg] = reg_val[base_reg]
        elif src_const is not None:
            reg_val[dst_reg] = src_const
        else:
            reg_val.pop(dst_reg, None)


def _handle_add(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """add reg, const → 更新已知常量或指针偏移."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    src_const = extract_constant(src)

    if dst_reg and src_const is not None:
        cur = reg_val.get(dst_reg)
        if isinstance(cur, int):
            reg_val[dst_reg] = cur + src_const
        elif isinstance(cur, str) and 'malloc' in str(cur):
            reg_val[dst_reg] = f"{cur}+{src_const}"


def _handle_sub(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """sub reg, const → 减量更新, 下界为0."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    src_const = extract_constant(src)

    if dst_reg and src_const is not None:
        cur = reg_val.get(dst_reg)
        if isinstance(cur, int):
            reg_val[dst_reg] = max(0, cur - src_const)


def _handle_lea(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """lea dst, [base+offset] → 地址传播."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)

    if not dst_reg:
        return

    if '[' in src:
        base_reg, base_off = extract_mem_offset(src)
        off = base_off or 0
        if base_reg and base_reg in reg_val:
            base_val = reg_val[base_reg]
            if isinstance(base_val, str) and 'malloc' in str(base_val):
                reg_val[dst_reg] = f"{base_val}+{off}"
                return
            elif isinstance(base_val, int):
                reg_val[dst_reg] = base_val + off
                return
            elif isinstance(base_val, str) and base_val.startswith('arg'):
                reg_val[dst_reg] = f"{base_val}+{off}"
                return

    # lea 产生指针, 无法追踪为简单值
    reg_val.pop(dst_reg, None)


def _handle_xor(insn: Instruction, reg_val: Dict[str, object]) -> None:
    """xor reg, reg → reg = 0."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    src_reg = extract_register(src)
    if dst_reg and src_reg and dst_reg == src_reg:
        reg_val[dst_reg] = 0


def _handle_shift(insn: Instruction,
                  reg_val: Dict[str, object],
                  direction: str) -> None:
    """shl/sal/shr/sar reg, const → 更新 reg 值为移位结果."""
    op = insn.operands
    dst = op.split(',')[0].strip() if ',' in op else ''
    src = op.split(',')[-1].strip() if ',' in op else ''
    dst_reg = extract_register(dst)
    amount = extract_constant(src)

    if not dst_reg or amount is None:
        return
    cur = reg_val.get(dst_reg)
    if not isinstance(cur, int):
        return
    is_32bit = dst.rstrip(',') in ('eax', 'ecx', 'edx', 'ebx', 'esi', 'edi',
                                    'r8d', 'r9d', 'r10d', 'r11d')
    if direction in ('shl', 'sal'):
        result = cur << amount
        if is_32bit and result > 0xFFFFFFFF:
            result = result & 0xFFFFFFFF
    else:
        result = cur >> amount
    reg_val[dst_reg] = result


def analyze_function(name: str,
                     insns: List[Instruction]) -> FunctionAnalysis:
    """在单个函数内追踪寄存器以提取 malloc→write/memcpy 数据流.

    Windows x64 calling convention (MinGW):
      rcx = arg1 (malloc: size; memcpy: dst)
      rdx = arg2 (memcpy: src)
      r8  = arg3 (memcpy: size)
      rax = return value
    """
    fa = FunctionAnalysis(name=name, n_insns=len(insns))
    reg_val: Dict[str, object] = {}
    mem_val: Dict[str, object] = {}
    malloc_records: Dict[int, dict] = {}
    for i, reg in enumerate(['rcx', 'rdx', 'r8', 'r9'], 1):
        reg_val[reg] = f"arg{i}"

    for insn in insns:
        op = insn.operands
        mn = insn.mnemonic

        if is_call_to(insn, 'malloc'):
            size_val = reg_val.get('rcx')
            malloc_records[insn.addr] = {
                'addr': insn.addr,
                'size_reg': 'rcx',
                'size_val': size_val if isinstance(size_val, int) else None,
            }
            reg_val['rax'] = f"malloc@{insn.addr:x}"
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'calloc'):
            reg_val['rax'] = f"calloc@{insn.addr:x}"
            malloc_records[insn.addr] = {
                'addr': insn.addr, 'size_reg': 'rcx',
            }
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'realloc'):
            # Win x64: rdx=arg2=new_size. ptr in rcx.
            size_val = reg_val.get('rdx')
            reg_val['rax'] = f"realloc@{insn.addr:x}"
            malloc_records[insn.addr] = {
                'addr': insn.addr, 'size_reg': 'rdx',
                'size_val': size_val if isinstance(size_val, int) else None,
            }
            _clear_caller_saved(reg_val)
            continue

        if (is_call_to(insn, 'memcpy')
                or is_call_to(insn, 'memmove')
                or is_call_to(insn, 'memset')):
            dst_val = reg_val.get('rcx')
            size_val = reg_val.get('r8')
            fa.memcpys.append({
                'addr': insn.addr,
                'dst_reg': 'rcx', 'dst_val': dst_val,
                'size_reg': 'r8',
                'size_val': size_val if isinstance(size_val, int) else None,
            })
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'strcpy') or is_call_to(insn, 'strcat'):
            dst_val = reg_val.get('rcx')
            fa.memcpys.append({
                'addr': insn.addr,
                'dst_reg': 'rcx', 'dst_val': dst_val,
                'size_reg': '', 'size_val': None,
                'type': 'strcpy',
            })
            _clear_caller_saved(reg_val)
            continue

        if is_call_to(insn, 'free'):
            ptr_val = reg_val.get('rcx')
            fa.frees.append({
                'addr': insn.addr,
                'ptr_reg': 'rcx',
                'ptr_val': ptr_val,
                'function': name,
            })
            _clear_caller_saved(reg_val)
            continue

        if mn == 'call':
            _clear_caller_saved(reg_val)
            continue

        if mn in ('mov', 'movsxd', 'movzx', 'movsx'):
            _handle_mov(insn, reg_val, mem_val, fa, name)
            continue

        if mn == 'add':
            _handle_add(insn, reg_val)
            continue

        if mn == 'sub':
            _handle_sub(insn, reg_val)
            continue

        if mn == 'lea':
            _handle_lea(insn, reg_val)
            continue

        if mn in ('xor', 'pxor'):
            _handle_xor(insn, reg_val)
            continue

        if mn in ('shl', 'sal'):
            _handle_shift(insn, reg_val, 'shl')
            continue

        if mn in ('shr', 'sar'):
            _handle_shift(insn, reg_val, 'shr')
            continue

    fa.mallocs = list(malloc_records.values())
    return fa


# ================= ptmalloc2 模型 (原 allocator_model) =================

MIN_CHUNK_SIZE = 32
MALLOC_ALIGNMENT = 16
SIZE_SZ = 8
MIN_LARGE_SIZE = 512
DEFAULT_MMAP_THRESHOLD = 128 * 1024
MAX_FAST_SIZE = 80


@dataclass
class AllocatorConstraint:
    """一次 malloc 调用的分配器约束."""
    requested_size: int          # 用户请求的大小
    actual_chunk_size: int       # 分配器分配的实际块大小 (含 header)
    usable_size: int             # 用户可用的字节数 (actual - 2*SIZE_SZ)
    aligned: bool = True         # 是否满足对齐要求
    is_mmap: bool = False        # 是否通过 mmap 分配


class Ptmalloc2Model:
    """ptmalloc2 分配器内部约束模型.

    将用户请求的 malloc(n) 映射为分配器实际分配的大小.
    """

    def __init__(self):
        self._cache: Dict[int, AllocatorConstraint] = {}

    def model_alloc(self, requested_size: int) -> AllocatorConstraint:
        """将用户请求大小映射为分配器实际分配的约束."""
        if requested_size in self._cache:
            return self._cache[requested_size]

        size = max(requested_size, 0)

        # mmap 路径: 超过阈值 → mmap, 页面对齐
        if size >= DEFAULT_MMAP_THRESHOLD:
            actual = self._round_up(size + 2 * SIZE_SZ, 4096)
            usable = actual - 2 * SIZE_SZ
            constraint = AllocatorConstraint(
                requested_size=size, actual_chunk_size=actual,
                usable_size=usable, is_mmap=True)
            self._cache[requested_size] = constraint
            return constraint

        # 常规路径: 最小块 + 对齐 + 舍入
        min_data_size = max(size, MIN_CHUNK_SIZE - 2 * SIZE_SZ)
        chunk_size = self._round_up(
            min_data_size + 2 * SIZE_SZ, MALLOC_ALIGNMENT)
        chunk_size = max(MIN_CHUNK_SIZE, chunk_size)
        usable = chunk_size - 2 * SIZE_SZ

        constraint = AllocatorConstraint(
            requested_size=size, actual_chunk_size=chunk_size,
            usable_size=usable, aligned=True, is_mmap=False)
        self._cache[requested_size] = constraint
        return constraint

    def is_within_usable_bounds(self, requested_size: int,
                                 offset: int,
                                 access_size: int = 1) -> bool:
        """检查 offset + access_size 是否在分配器的可用范围内."""
        constraint = self.model_alloc(requested_size)
        return (offset >= 0
                and offset + access_size <= constraint.usable_size)

    def safe_padding_range(self, requested_size: int) -> int:
        """返回因分配器舍入而多出的安全 padding 字节数."""
        constraint = self.model_alloc(requested_size)
        return max(0, constraint.usable_size - requested_size)

    def size_to_bin_category(self, requested_size: int) -> str:
        """返回尺寸对应的 bin 类别."""
        constraint = self.model_alloc(requested_size)
        cs = constraint.actual_chunk_size
        if cs <= MAX_FAST_SIZE:
            return 'fastbin'
        if cs < MIN_LARGE_SIZE:
            return 'smallbin'
        if constraint.is_mmap:
            return 'mmap'
        return 'largebin'

    @staticmethod
    def _round_up(val: int, align: int) -> int:
        """向上对齐."""
        return (val + align - 1) & ~(align - 1)

    def stats(self) -> dict:
        return {
            'min_chunk_size': MIN_CHUNK_SIZE,
            'alignment': MALLOC_ALIGNMENT,
            'max_fast_size': MAX_FAST_SIZE,
            'mmap_threshold': DEFAULT_MMAP_THRESHOLD,
            'modeled_allocs': len(self._cache),
        }

    def clear(self) -> None:
        self._cache.clear()


# ================= 循环累积检测 (原 loop_accum_detector) =================

def detect_loop_accumulated(insns: List[Instruction],
                            memcpys: List[dict],
                            mallocs: List[dict]) -> List[dict]:
    """识别循环内 memcpy 的累积写入, 返回增强后的 finding 列表.

    策略: 扫描后向跳转 (jle/jne/jl/jg/...), 向前找到 cmp 和循环变量,
          向后扫描循环体内的 add 归纳变量和 memset 调用,
          计算 trip_count * per_iter_size 累积溢出.
    """
    if len(insns) < 6:
        return []

    extra = []
    mc_by_addr = {}
    for mc in memcpys:
        mc_by_addr[mc.get('addr', 0)] = mc

    for idx, insn in enumerate(insns):
        mn = insn.mnemonic
        if mn not in ('jle', 'jl', 'jne', 'jbe', 'jb', 'jge', 'jg', 'jae', 'ja'):
            continue
        target = _parse_jump_target(insn.operands)
        if target is None or target >= insn.addr:
            continue  # 前向跳转, 不是循环回边

        cmp_idx = _find_prev_cmp(insns, idx)
        if cmp_idx is None:
            continue

        cmp_insn = insns[cmp_idx]
        cmp_reg = _cmp_register(cmp_insn)
        cmp_const = _cmp_constant(cmp_insn)
        if cmp_reg is None:
            continue

        init_reg, init_val = _find_init(insns, cmp_idx, cmp_reg)
        if init_reg is None:
            continue

        trip_count = _trip_count(mn, cmp_const, init_val)
        if trip_count is None or trip_count <= 1:
            continue

        loop_start = target
        loop_end = insn.addr

        loop_insns = [i for i in insns if loop_start <= i.addr <= loop_end]

        iv_reg, iv_stride, iv_mem = _find_iv(loop_insns, cmp_reg)

        for li in loop_insns:
            if li.mnemonic != 'call':
                continue
            mc = mc_by_addr.get(li.addr)
            if mc is None:
                continue

            initial_offset = mc.get('offset', 0)
            per_iter_size = mc.get('size_val', 0)
            if not isinstance(per_iter_size, int) or per_iter_size <= 0:
                continue

            if iv_stride is not None and iv_stride > 0:
                max_offset = initial_offset + (trip_count - 1) * iv_stride
            else:
                max_offset = initial_offset

            cumulative_size = max_offset + per_iter_size

            dst_val = str(mc.get('dst_val', ''))
            for m in mallocs:
                m_addr = m.get('addr', 0)
                if f'malloc@{m_addr:x}' in dst_val \
                        or f'calloc@{m_addr:x}' in dst_val:
                    alloc_sz = m.get('size_val', 128)
                    if not isinstance(alloc_sz, int) or alloc_sz <= 0:
                        alloc_sz = 128
                    if cumulative_size > alloc_sz:
                        extra.append({
                            'type': 'loop_accumulate',
                            'function': mc.get('function', ''),
                            'insn_addr': mc.get('addr', 0),
                            'alloc_size': alloc_sz,
                            'real_alloc_size': alloc_sz,
                            'offset': max_offset,
                            'access_size': per_iter_size,
                            'malloc_addr': m_addr,
                            'cumulative_size': cumulative_size,
                            'trip_count': trip_count,
                            'iv_stride': iv_stride,
                            'per_iter_size': per_iter_size,
                            'initial_offset': initial_offset,
                            'loop_back_edge': loop_end,
                            'phase': 'LOOP_ACCUM',
                        })
                    break

    return extra


def _parse_jump_target(op_str: str) -> Optional[int]:
    """从跳转操作数提取目标地址."""
    m = re.search(r'([0-9a-fA-F]+)\b', op_str)
    return int(m.group(1), 16) if m else None


def _find_prev_cmp(insns: List[Instruction], jmp_idx: int) -> Optional[int]:
    """从跳转指令向前找最近的 cmp 指令 (向后扫描 ≤8条)."""
    for i in range(jmp_idx - 1, max(jmp_idx - 9, -1), -1):
        if insns[i].mnemonic == 'cmp':
            return i
    return None


def _cmp_register(insn: Instruction) -> Optional[str]:
    """cmp [mem], const 或 cmp reg, const → 返回被比较的寄存器/内存."""
    op = insn.operands
    left = op.split(',')[0].strip()
    reg = extract_register(left)
    if '[' in left:
        m = re.search(r'\[(rbp[+-]0x[0-9a-fA-F]+)\]', left)
        if m:
            return m.group(1)
    return reg


def _cmp_constant(insn: Instruction) -> Optional[int]:
    """cmp ..., const → 返回常量值."""
    op = insn.operands
    if ',' not in op:
        return None
    right = op.split(',')[-1].strip()
    return extract_constant(right)


def _find_init(insns: List[Instruction], cmp_idx: int,
               cmp_reg: str) -> Tuple[Optional[str], Optional[int]]:
    """从 cmp 向前找循环变量初始化 (mov reg, 0 或 mov [mem], 0)."""
    for i in range(cmp_idx - 1, max(cmp_idx - 20, -1), -1):
        insn = insns[i]
        if insn.mnemonic not in ('mov', 'movsxd', 'xor', 'pxor'):
            continue
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip() if ',' in op else ''

        if '[' in dst and cmp_reg.startswith('rbp'):
            if dst == cmp_reg or cmp_reg in dst:
                c = extract_constant(src)
                if src_reg := extract_register(src):
                    continue  # mov from reg, not const init
                if insn.mnemonic in ('xor', 'pxor'):
                    src_reg2 = extract_register(src)
                    if src_reg2 and dst == src or src_reg2 == extract_register(dst):
                        return (dst, 0)
                return (dst, c if c is not None else 0)

        dst_reg = extract_register(dst)
        if dst_reg and dst_reg == cmp_reg:
            if insn.mnemonic in ('xor', 'pxor'):
                src_reg = extract_register(src)
                if src_reg and dst_reg == src_reg:
                    return (dst_reg, 0)
            c = extract_constant(src)
            return (dst_reg, c if c is not None else 0)

    return (None, None)


def _trip_count(jcc: str, cmp_const: Optional[int],
                init_val: Optional[int]) -> Optional[int]:
    """根据跳转类型和比较常量计算循环次数.

    jle:    i <= N → trip = N+1 (i:0..N)
    jl:     i < N  → trip = N
    jne:    i != N → trip = N (假设 i:0→N-1))
    jbe/jb: 同上用无符号比较.
    """
    if cmp_const is None or init_val is None:
        return None
    if jcc in ('jle', 'jbe'):
        return max(0, cmp_const - init_val + 1)
    elif jcc in ('jl', 'jb'):
        return max(0, cmp_const - init_val)
    elif jcc in ('jne',):
        return max(0, cmp_const - init_val + 1)  # 保守: 假设全遍历
    elif jcc in ('jge', 'jae'):
        return max(0, init_val - cmp_const + 1)
    elif jcc in ('jg', 'ja'):
        return max(0, init_val - cmp_const)
    return None


def _find_iv(loop_insns: List[Instruction],
             cmp_target: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """在循环体内找归纳变量: add [mem], const 或 add reg, const.
    返回 (reg_name, stride, mem_target_or_None)."""
    for insn in loop_insns:
        if insn.mnemonic != 'add':
            continue
        op = insn.operands
        dst = op.split(',')[0].strip()
        src = op.split(',')[-1].strip() if ',' in op else ''

        if '[' in dst:
            m = re.search(r'\[(rbp[+-]0x[0-9a-fA-F]+)\]', dst)
            if m:
                mem_target = m.group(1)
                stride = extract_constant(src)
                if stride is not None:
                    return (mem_target, stride, mem_target)
        else:
            dst_reg = extract_register(dst)
            stride = extract_constant(src)
            if dst_reg and stride is not None:
                return (dst_reg, stride, None)

    return (None, None, None)


# ================= AVHO 发现收集与分类 (核心链) =================

def register_mallocs(mallocs: List[dict],
                     seen: Dict[int, Tuple[str, int]],
                     fn_name: str = '') -> None:
    """注册malloc分配点 — oversize (>0x1000000) 或 None → 128 回退."""
    for m in mallocs:
        size = m.get('size_val')
        addr = m.get('addr', 0)
        if isinstance(size, int) and 0 < size <= 0x1000000:
            seen[addr] = (fn_name, size)
        elif isinstance(size, int):
            seen[addr] = (fn_name, _DEFAULT_ALLOC)
        elif size is None:
            seen[addr] = (fn_name, _DEFAULT_ALLOC)


def _extract_malloc_offset(dst_val: str) -> int:
    """从 'malloc@0x140001772+96+256' 提取累积偏移量."""
    total = 0
    for m in re.finditer(r'\+(\d+)', str(dst_val)):
        try:
            total += int(m.group(1))
        except ValueError:
            pass
    return total


def _collect_one_memcpy(mc: dict, seen: Dict[int, Tuple[str, int]],
                        findings: List[dict], fn_name: str = '') -> None:
    """单个memcpy记录→发现."""
    dst_val = str(mc.get('dst_val', ''))
    m_addr = extract_malloc_addr(dst_val)
    if not m_addr or m_addr not in seen:
        return
    _, alloc_sz = seen[m_addr]
    effective = alloc_sz if alloc_sz > 0 else _DEFAULT_ALLOC
    mc_offset = _extract_malloc_offset(dst_val)
    size_val = mc.get('size_val')
    size_bounded = isinstance(size_val, int) and size_val > 0
    access_size = size_val if size_bounded else effective + 1024
    findings.append({
        'type': 'memcpy', 'function': mc.get('function', fn_name),
        'insn_addr': mc['addr'], 'alloc_size': effective,
        'real_alloc_size': alloc_sz, 'offset': mc_offset,
        'access_size': access_size, 'size_bounded': size_bounded,
        'size_unknown': not size_bounded})


def collect_findings(writes: List[dict], memcpys: List[dict],
                     seen: Dict[int, Tuple[str, int]],
                     fn_name: str = '',
                     mallocs: List[dict] = None) -> List[dict]:
    """从write/memcpy列表收集发现."""
    findings: List[dict] = []
    for w in writes:
        m_addr = extract_malloc_addr(str(w.get('base_val', '')))
        if m_addr and m_addr in seen:
            _, alloc_sz = seen[m_addr]
            findings.append({
                'type': 'direct_write',
                'function': w.get('function', fn_name),
                'insn_addr': w['addr'], 'alloc_size': alloc_sz,
                'offset': w.get('offset', 0),
                'access_size': w.get('access_size', 4)})
    for mc in memcpys:
        _collect_one_memcpy(mc, seen, findings, fn_name)
    return findings


def classify_findings_avho(findings: List[dict]) -> List[dict]:
    """AVHO 分类 (BOUND_CHECK): ptmalloc2 usable_size 判定.

    offset+size > usable → vuln; 否则 safe (分配器 padding 合法访问).
    """
    alloc_model = Ptmalloc2Model()
    out = []
    for f in findings:
        alloc_sz = f.get('alloc_size', _DEFAULT_ALLOC)
        access_sz = f.get('access_size', 4)
        size_unknown = f.get('size_unknown', False)
        offset = f.get('offset', 0)
        if f.get('type') == 'loop_accumulate':
            # 循环累积: 直接用 cumulative_size 与分配比较
            cum = f.get('cumulative_size', offset + access_sz)
            if cum > alloc_sz:
                out.append({**f, 'decision': 'vuln',
                            'phase': 'LOOP_ACCUM',
                            'reasoning': (f'loop accumulated write {cum}'
                                          f' > alloc {alloc_sz}'),
                            'fp_probability': 0.05})
            else:
                out.append({**f, 'decision': 'safe',
                            'phase': 'LOOP_ACCUM',
                            'reasoning': (f'loop accumulated write {cum}'
                                          f' ≤ alloc {alloc_sz}'),
                            'fp_probability': 0.95})
            continue
        if not size_unknown:
            usable = alloc_model.model_alloc(alloc_sz).usable_size
            effective_limit = max(alloc_sz, usable)
            if offset + access_sz > effective_limit:
                out.append({**f, 'decision': 'vuln', 'phase': 'BOUND_CHECK',
                            'reasoning': (f'Overflow: offset {offset} + '
                                          f'size {access_sz} > usable '
                                          f'{effective_limit} (alloc '
                                          f'{alloc_sz})'),
                            'fp_probability': 0.05})
            else:
                out.append({**f, 'decision': 'safe', 'phase': 'BOUND_CHECK',
                            'reasoning': (f'offset {offset} + size '
                                          f'{access_sz} ≤ usable '
                                          f'{effective_limit}'),
                            'fp_probability': 0.95})
        else:
            out.append({**f, 'decision': 'likely', 'phase': 'BOUND_CHECK',
                        'reasoning': (f'Unbounded copy into buffer of '
                                      f'{alloc_sz}B'),
                        'fp_probability': 0.20})
    return out


@dataclass
class AvhoReport:
    """AVHO-G 分析报告."""
    binary_path: str = ""
    raw_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    filtered_fp: int = 0
    fp_reduction_pct: float = 0.0
    n_functions: int = 0
    findings: List[dict] = field(default_factory=list)


def analyze_heap_avho(binary_path: str, timeout_s: int = 60) -> AvhoReport:
    """AVHO-G 核心管线: 反汇编→解析→函数分析→循环累积→分类."""
    report = AvhoReport(binary_path=binary_path)
    asm_text = _disassemble(binary_path)
    if not asm_text:
        return report

    functions = parse_instructions(asm_text)
    report.n_functions = len(functions)
    seen: Dict[int, Tuple[str, int]] = {}
    all_findings: List[dict] = []
    all_mallocs: List[dict] = []
    mc_all: List[dict] = []

    for fn_name, insns in functions:
        if len(insns) < 3:
            continue
        fa = analyze_function(fn_name, insns)
        register_mallocs(fa.mallocs, seen, fn_name=fa.name)
        all_findings.extend(collect_findings(
            fa.writes, fa.memcpys, seen,
            fn_name=fa.name, mallocs=fa.mallocs))
        mc_all.extend(fa.memcpys)
        all_mallocs.extend({'addr': m['addr'], 'size_val': m['size_val'],
                            'function': fn_name} for m in fa.mallocs)

    # 循环累积写入检测
    for fn_name, insns in functions:
        if len(insns) < 6:
            continue
        loop_extra = detect_loop_accumulated(insns, mc_all, all_mallocs)
        all_findings.extend(loop_extra)

    report.raw_findings = len(all_findings)
    classified = classify_findings_avho(all_findings)
    for f in classified:
        if f['decision'] == 'vuln':
            report.confirmed += 1
        elif f['decision'] == 'likely':
            report.likely += 1
        else:
            report.filtered_fp += 1
        report.findings.append(f)
    total = max(1, report.raw_findings)
    report.fp_reduction_pct = round(report.filtered_fp / total * 100, 1)
    return report


def _disassemble(elf_path: str) -> str:
    """反汇编二进制 (objdump 优先, 回退 llvm-objdump)."""
    for tool in ['objdump', 'llvm-objdump']:
        try:
            proc = subprocess.run(
                [tool, '-d', '-M', 'intel', elf_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


__all__ = [
    "Instruction", "parse_instructions", "is_user_function",
    "extract_register", "extract_constant", "extract_mem_offset",
    "infer_access_size", "extract_malloc_addr",
    "FunctionAnalysis", "analyze_function",
    "AllocatorConstraint", "Pmalloc2Model",
    "detect_loop_accumulated",
    "register_mallocs", "collect_findings", "classify_findings_avho",
    "AvhoReport", "analyze_heap_avho",
]
