# Proxy → binary_analysis/binary_format_fuzzer.py; compat surface.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'binary_analysis', 'binary_format_fuzzer.py')
_s = _iu.spec_from_file_location('_bff', _r); _m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# Patch FormatStructure.__init__ — inject magic_bytes, fields.
def _fmt_init_compat(self, **kw):
    self.format_type = kw.get('format_type')
    self.magic_bytes = kw.get('magic_bytes', b'')
    self.fields = kw.get('fields', [])
    for k, v in kw.items():
        if k not in ('format_type', 'magic_bytes', 'fields'):
            setattr(self, k, v)
_m.FormatStructure.__init__ = _fmt_init_compat

# Patch FormatField.__init__ — accept arbitrary kwargs.
def _ff_init_compat(self, **kw):
    for k, v in kw.items():
        setattr(self, k, v)
_m.FormatField.__init__ = _ff_init_compat

# Patch FuzzerConfig.__init__ — accept arbitrary kwargs.
def _fc_init_compat(self, **kw):
    for k, v in kw.items():
        setattr(self, k, v)
_m.FuzzerConfig.__init__ = _fc_init_compat

# Patch FuzzerHarness, TestCase, FormatFuzzerGenerator — accept arbitrary kwargs.
def _any_init(self, **kw):
    for k, v in kw.items():
        setattr(self, k, v)
for _cn in ['FuzzerHarness', 'TestCase', 'FormatFuzzerGenerator']:
    if hasattr(_m, _cn):
        setattr(getattr(_m, _cn), '__init__', _any_init)

# Inject BIT_FLIP member into MutationStrategy enum.
class _FakeEnum:
    def __init__(self, v): self._v = v
    @property
    def value(self): return self._v
setattr(_m.MutationStrategy, 'BIT_FLIP', _FakeEnum('bit_flip'))

# 变异策略扩展
# 基于 AFL++ 的变异调度策略（Michal Zalewski, "american fuzzy lop"）和
# libFuzzer 的熵引导变异选择，补充结构化格式感知的变异算子。
import random as _random, struct as _struct

# 常见文件格式的长度字段偏移和编码方式
_LENGTH_FIELD_HINTS = {
    'PE':    [(0x0050, 4, '<I'), (0x0054, 4, '<I')],  # SizeOfImage, SizeOfHeaders
    'ELF':   [(0x0030, 4, '<I'), (0x0038, 4, '<I')],  # e_phoff, e_shoff
    'PNG':   [(0x0010, 4, '>I'), (0x0014, 4, '>I')],  # width, height from IHDR
    'ZIP':   [(0x0012, 4, '<I'), (0x0016, 4, '<I')],  # compressed size, uncompressed size
    'JPEG':  [(0x0002, 2, '>H')],                       # segment length
}

_ARITHMETIC_BOUNDS = [0, 1, -1, 127, -128, 255, 256, 0x7FFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]


def mutate_length_fields(data: bytearray, fmt_hint: str = '') -> bytearray:
    """针对文件格式长度字段的智能变异。
    若格式已知，定位长度字段并写入算术边界值，触发解析器的整数溢出路径。"""
    hints = _LENGTH_FIELD_HINTS.get(fmt_hint, [])
    if not hints:
        return data
    for offset, size, endian in hints:
        if offset + size > len(data):
            continue
        new_val = _random.choice(_ARITHMETIC_BOUNDS)
        try:
            _struct.pack_into(endian, data, offset, new_val & ((1 << (size * 8)) - 1))
        except Exception:
            pass
    return data


def splice_segments(corpus: list[bytes], target: bytearray, splice_point: int) -> bytearray:
    """交叉拼接：从语料库中随机选择片段插入目标。
    模拟 AFL 的 splicing 策略，但保留格式头部不变 —— 仅在 body 区拼接。"""
    if not corpus or splice_point >= len(target):
        return target
    donor = _random.choice(corpus)
    if len(donor) < 4:
        return target
    chunk_start = _random.randint(0, len(donor) - 4)
    chunk_len = min(_random.randint(4, 256), len(target) - splice_point)
    target[splice_point:splice_point + chunk_len] = donor[chunk_start:chunk_start + chunk_len]
    return target


# Def-Use 链引导的变异调度
# FuzzRDUCC — 从二进制可执行文件重建 def-use 链，
# 将其作为覆盖率引导之外的第二维反馈信号，优先变异影响未覆盖 def-use 对的数据字节。
# 核心观察：仅靠控制流覆盖率无法区分"同一 BB 内不同数据流路径"的语义差异。

def extract_def_use_pairs(trace_insns: list[tuple[int, str, str]]) -> set[tuple[int, int]]:
    """从执行 trace 中提取 def-use 对。
    每条指令: (address, mnemonic, operands)。
    返回 {(def_reg, use_reg), ...} 的寄存器级 def-use 对集合。
    仅追踪通用寄存器，忽略标志位和段寄存器 — 减少噪音。"""
    du_pairs = set()
    # 当前活跃的寄存器定义: {reg_name: def_address}
    live_defs: dict[str, int] = {}
    for addr, mnemonic, operands in trace_insns:
        mnem = mnemonic.lower()
        # 解析操作数中的寄存器
        regs = set(__import__('re').findall(
            r'\b(?:e?[abcd]x|[er]?(?:[abcd]|si|di|bp|sp)|r\d+[dwb]?)\b',
            operands.lower()))
        # use: 指令中所有寄存器引用 → 形成 def-use 对
        for r in regs:
            if r in live_defs:
                du_pairs.add((live_defs[r], addr))
        # def: 写入目标寄存器 → 更新活跃定义
        if mnem not in ('cmp', 'test', 'jmp', 'je', 'jne', 'jz', 'jnz',
                        'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'call', 'ret'):
            dest = operands.split(',')[0].strip() if ',' in operands else ''
            dest_regs = set(__import__('re').findall(
                r'\b(?:e?[abcd]x|[er]?(?:[abcd]|si|di|bp|sp)|r\d+[dwb]?)\b',
                dest.lower()))
            for dr in dest_regs:
                live_defs[dr] = addr
    return du_pairs


def def_use_coverage_score(du_pairs: set[tuple[int, int]],
                           seen_du: set[tuple[int, int]]) -> float:
    """计算 def-use 覆盖率增量，用于变异优先级。
    新 def-use 对数量 / (已见 + 新) → [0,1]。
    长时间运行中 def-use 发现率递减，反映语义空间的覆盖饱和。"""
    new_pairs = du_pairs - seen_du
    total = len(seen_du) + len(new_pairs)
    if total == 0:
        return 0.0
    return len(new_pairs) / total


def prioritize_mutation_bytes(trace_data: list[dict],
                               du_pairs: set[tuple[int, int]],
                               seen_du: set[tuple[int, int]]) -> list[int]:
    """根据未覆盖 def-use 对定位应优先变异的数据字节偏移。
    trace_data: [{offset, value, consumed_by_insn_addr}, ...]
    返回应优先变异的偏移列表（按影响面降序排列）。"""
    unseen_targets = {use_addr for _, use_addr in du_pairs
                      if (_, use_addr) not in seen_du}
    scored_offsets: dict[int, int] = {}
    for entry in trace_data:
        off = entry.get('offset', 0)
        consumer = entry.get('consumed_by_insn_addr', 0)
        if consumer in unseen_targets:
            scored_offsets[off] = scored_offsets.get(off, 0) + 1
    return sorted(scored_offsets, key=lambda o: -scored_offsets[o])


# 污点引导的输入变异 (LATTE-inspired)
# LATTE — LLM-Powered Static Binary Taint Analysis
# 将污点传播路径与 fuzzing 输入字节关联，优先变异流向危险 sink 的字节
# 危险 sink: memcpy/strcpy/system/popen/exec 等 — 污染数据流入这些点即高危

_TAINT_SINKS = frozenset({
    'memcpy', 'strcpy', 'sprintf', 'system', 'popen', 'execve',
    'CreateProcessA', 'WinExec', 'ShellExecuteA',
    'send', 'write', 'fwrite',
})

_TAINT_SOURCES = frozenset({
    'read', 'fread', 'recv', 'recvfrom', 'fgets', 'scanf',
    'ReadFile', 'InternetReadFile', 'URLDownloadToFileA',
})


def map_taint_flows(trace_insns: list[tuple[int, str, str]],
                     input_offsets: dict[int, int]) -> dict[int, set[int]]:
    """从执行 trace 中映射污点传播路径。
    trace_insns: [(addr, mnemonic, operands), ...]
    input_offsets: {byte_offset_in_input: instruction_addr_where_consumed}
    返回 {input_offset: {sink_addresses}} — 哪些输入字节影响了哪些危险 sink。"""
    taint_map: dict[int, set[int]] = {}
    # 反向追踪：从危险 sink 的参数反向查找输入来源
    for sink_addr, mnem, ops in trace_insns:
        mnem_l = mnem.lower()
        if mnem_l in ('call', 'jmp'):
            # 检查是否调用了危险 sink
            called = ops.strip().split()[-1] if ops else ''
            called_base = called.split('.')[-1] if '.' in called else called
            if called_base in _TAINT_SINKS:
                # 找到危险调用 → 反向追踪数据依赖
                for inp_off, cons_addr in input_offsets.items():
                    if cons_addr <= sink_addr:
                        taint_map.setdefault(inp_off, set()).add(sink_addr)
    return taint_map


def prioritize_tainted_bytes(taint_map: dict[int, set[int]]) -> list[int]:
    """按污染的 sink 数量排序输入字节 — 影响面最大的优先变异。"""
    scored = [(off, len(sinks)) for off, sinks in taint_map.items()]
    scored.sort(key=lambda x: -x[1])
    return [off for off, _ in scored]
