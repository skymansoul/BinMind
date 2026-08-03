"""ROP/JOP gadget 链分析 —— 借鉴 ARCANIST [USENIX Security 2025]。

ARCANIST 实现跨栈/堆/寄存器的多样化 gadget 链合成。
本模块沿用其 gadget 分类与可达性分析思路，对二进制中的
ROP/JOP gadget 进行分类、评分、链式可达性评估。

覆盖 x86_64 / ARM64 常见 gadget 类型。
"""

import re, struct, logging, os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


class GadgetKind:
    """Gadget 类型常量 —— 参考 ARCANIST 第三节分类法。"""
    RET = "ret"               # ret 结尾 (ROP)
    CALL_REG = "call_reg"     # call reg 结尾 (JOP)
    JMP_REG = "jmp_reg"       # jmp reg 结尾 (JOP dispatcher)
    POP_RET = "pop_ret"       # pop + ret
    POP_POP_RET = "pop_pop_ret"  # pop n + ret
    PUSH_RET = "push_ret"     # push + ret
    SYSCALL = "syscall"       # syscall/sysenter (SROP)
    LEAVE_RET = "leave_ret"   # leave; ret (stack pivot)
    INT80 = "int80"           # int 0x80
    INDIRECT_JMP = "indirect_jmp"  # jmp [reg]
    PAC_RET = "pac_ret"       # ARM64 PAC + ret
    UNKNOWN = "unknown"


@dataclass
class Gadget:
    """单个 gadget 元数据。"""
    offset: int
    size: int
    kind: str
    bytes: bytes = b""
    disasm: str = ""
    useful_regs: Set[str] = field(default_factory=set)
    clobber_regs: Set[str] = field(default_factory=set)
    side_effects: str = ""     # "stack_pivot", "write_to_mem", "read_from_mem" 等
    usefulness_score: float = 0.0  # 0..1, 越高对 exploit 越有利
    pac_protected: bool = False  # ARM64 PAC 保护令 gadget 难以利用


@dataclass
class GadgetChainAnalysis:
    """Gadget 链可达性分析结果。"""
    binary_path: str = ""
    total_gadgets: int = 0
    rop_gadgets: int = 0
    jop_gadgets: int = 0
    syscall_gadgets: int = 0
    pac_protected_count: int = 0
    chainable_pairs: List[Tuple[int, int]] = field(default_factory=list)
    longest_chain: int = 0
    defense_score: float = 0.0  # 0..1, 越高越安全
    critical_gadgets: List[Gadget] = field(default_factory=list)
    stack_pivot_gadgets: List[Gadget] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'binary_path': self.binary_path,
            'total_gadgets': self.total_gadgets,
            'rop_gadgets': self.rop_gadgets,
            'jop_gadgets': self.jop_gadgets,
            'syscall_gadgets': self.syscall_gadgets,
            'pac_protected': self.pac_protected_count,
            'longest_chain': self.longest_chain,
            'defense_score': round(self.defense_score, 4),
            'critical_gadgets': [
                {
                    'offset': hex(_g.offset),
                    'kind': _g.kind,
                    'usefulness': round(_g.usefulness_score, 3),
                    'side_effects': _g.side_effects,
                }
                for _g in self.critical_gadgets[:30]
            ],
            'stack_pivot_gadgets': [
                {
                    'offset': hex(_g.offset),
                    'kind': _g.kind,
                    'disasm': _g.disasm[:60],
                }
                for _g in self.stack_pivot_gadgets[:10]
            ],
        }


# ── Gadget 终结束码查找表 ──────────────────────────────────────────
# 每个 opcode 序列 → (类型, 有用寄存器集合, 是否栈 pivot)

_GADGET_TERMINATORS_X86 = {
    # opcode: (kind, useful_regs_set, is_stack_pivot)
    b'\xc3':       (GadgetKind.RET,          set(), False),               # ret
    b'\xc2':       (GadgetKind.RET,          set(), False),               # ret imm16
    b'\xcb':       (GadgetKind.RET,          set(), False),               # retf (far return)
    b'\xca':       (GadgetKind.RET,          set(), False),               # retf imm16
    b'\xc9':       (GadgetKind.LEAVE_RET,    set(), True),                # leave (stack pivot)
    b'\xff':       (GadgetKind.UNKNOWN,      set(), False),               # jmp/call [mem]——看 ModRM
    b'\xcd\x80':   (GadgetKind.INT80,        set(), False),               # int 0x80
    b'\x0f\x05':   (GadgetKind.SYSCALL,      set(), False),               # syscall
    b'\x0f\x34':   (GadgetKind.SYSCALL,      set(), False),               # sysenter
    b'\x0f\x07':   (GadgetKind.SYSCALL,      set(), False),               # sysexit
}

_GADGET_TERMINATORS_ARM64 = {
    b'\xc0\x03\x5f\xd6': (GadgetKind.RET,     set(), False),              # ret
    b'\xd6\x5f\x03\xc0': (GadgetKind.RET,     set(), False),              # ret (big-endian)
    b'\xc0\x03\x1f\xd6': (GadgetKind.PAC_RET, set(), False),              # retaa (PAC)
    b'\xff\x0f\x1f\xd6': (GadgetKind.PAC_RET, set(), False),              # retab
    b'\x3f\x23\x03\xd5': (GadgetKind.PAC_RET, set(), False),              # paciasp
    b'\xff\x23\x03\xd5': (GadgetKind.PAC_RET, set(), False),              # autiasp
}

# ModRM 间接调用/跳转 opcode
_MODRM_INDIRECT_CALL = [0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7]  # call reg
_MODRM_INDIRECT_JMP  = [0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7]  # jmp reg

_REG_NAMES_INDIRECT = {
    0: 'rax', 1: 'rcx', 2: 'rdx', 3: 'rbx',
    4: 'rsp', 5: 'rbp', 6: 'rsi', 7: 'rdi',
}


class GadgetChainAnalyzer:
    """ARCANIST 风格 gadget 链分析器。

    扫描二进制 ROP/JOP gadget 并评估利用价值。
    不合成完整 exploit chain，仅做分类与风险评分。
    """

    def __init__(self, arch: str = "x86_64"):
        self._arch = arch.lower()
        self._terminators = _GADGET_TERMINATORS_X86
        if 'arm' in self._arch or 'aarch' in self._arch:
            self._terminators = _GADGET_TERMINATORS_ARM64

    # ============================================================
    # 主入口
    # ============================================================
    def analyze(self, binary_path: str,
                code_sections: Optional[List[Tuple[int, int]]] = None) -> GadgetChainAnalysis:
        """扫描二进制 gadget 并进行链式分析。"""
        _rpt = GadgetChainAnalysis(binary_path=binary_path)

        _data = self._load_binary(binary_path)
        if _data is None:
            return _rpt

        # 确定扫描区间
        if code_sections is None:
            code_sections = self._guess_code_sections(_data)

        # 收集全部 gadget
        _all = []
        for _start, _end in code_sections:
            _section_data = _data[_start:_end]
            _gadgets = self._scan_gadgets(_section_data, _start)
            _all.extend(_gadgets)

        _rpt.total_gadgets = len(_all)

        # 按类型统计
        for _g in _all:
            _k = _g.kind
            if _k in (GadgetKind.RET, GadgetKind.POP_RET, GadgetKind.POP_POP_RET,
                      GadgetKind.PUSH_RET, GadgetKind.LEAVE_RET, GadgetKind.PAC_RET):
                _rpt.rop_gadgets += 1
            elif _k in (GadgetKind.CALL_REG, GadgetKind.JMP_REG, GadgetKind.INDIRECT_JMP):
                _rpt.jop_gadgets += 1
            elif _k in (GadgetKind.SYSCALL, GadgetKind.INT80):
                _rpt.syscall_gadgets += 1
            if _g.pac_protected:
                _rpt.pac_protected_count += 1

        # 计算 usefulness 评分
        for _g in _all:
            _g.usefulness_score = self._score_gadget_usefulness(_g)

        # 筛出高利用价值 gadget (usefulness > 0.5)
        _rpt.critical_gadgets = [_g for _g in _all if _g.usefulness_score > 0.5]
        _rpt.critical_gadgets.sort(key=lambda g: g.usefulness_score, reverse=True)

        # 筛出栈 pivot gadget
        _rpt.stack_pivot_gadgets = [
            _g for _g in _all
            if _g.side_effects == 'stack_pivot' or
            _g.kind in (GadgetKind.LEAVE_RET, GadgetKind.JMP_REG)
            if 'rsp' in _g.useful_regs or 'esp' in _g.useful_regs
        ]

        # 链式检测：找出可串联的 gadget 对
        _rpt.chainable_pairs = self._find_chainable_pairs(_all)

        # 估算最长链
        _rpt.longest_chain = self._estimate_longest_chain(_all)

        # 防御评分
        _rpt.defense_score = self._compute_defense_score(_rpt, len(_data))

        return _rpt

    # ── 二进制加载与段定位 ──────────────────────────────────────────

    def _load_binary(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as _fh:
                return _fh.read()
        except Exception:
            return None

    def _guess_code_sections(self, data: bytes) -> List[Tuple[int, int]]:
        """简易 ELF .text 定位 —— 不做完整 ELF 解析。
        未检测到 ELF header 则全量扫描。"""
        if data[:4] == b'\x7fELF':
            # 读 program headers，找 PT_LOAD | PF_X
            try:
                _phoff = struct.unpack_from('<Q', data, 0x20)[0]
                _phnum = struct.unpack_from('<H', data, 0x38)[0]
                _phent = struct.unpack_from('<H', data, 0x36)[0]
                _sections = []
                for _i in range(_phnum):
                    _poff = _phoff + _i * _phent
                    _p_type = struct.unpack_from('<I', data, _poff)[0]
                    _p_flags = struct.unpack_from('<I', data, _poff + 4)[0]
                    _p_offset = struct.unpack_from('<Q', data, _poff + 8)[0]
                    _p_filesz = struct.unpack_from('<Q', data, _poff + 32)[0]
                    if _p_type == 1 and (_p_flags & 0x1):  # PT_LOAD, PF_X
                        _sections.append((_p_offset, _p_offset + _p_filesz))
                if _sections:
                    return _sections
            except Exception:
                pass
        return [(0, len(data))]

    # ── gadget 逆向扫描 ─────────────────────────────────────────────

    def _scan_gadgets(self, data: bytes, base_offset: int) -> List[Gadget]:
        """逆向扫描：从终结束码向前回溯，收集所有可能 gadget。"""
        _gadgets = []
        _n = len(data)

        # 遍历所有终结束码位置
        for _terminator_bytes, (_kind, _regs, _is_pivot) in self._terminators.items():
            _tlen = len(_terminator_bytes)
            _pos = 0
            while _pos < _n - _tlen + 1:
                _pos = data.find(_terminator_bytes, _pos)
                if _pos == -1:
                    break

                # 向前回溯 2-32 字节
                for _glen in range(2, min(33, _pos + 1)):
                    _gstart = _pos - _glen + 1 + _tlen
                    _gbytes = data[_gstart:_pos + _tlen]

                    _g = Gadget(
                        offset=base_offset + _gstart,
                        size=len(_gbytes),
                        kind=_kind,
                        bytes=_gbytes,
                        disasm=self._quick_disas(_gbytes),
                        useful_regs=set(),
                        clobber_regs=set(),
                        pac_protected=(_kind == GadgetKind.PAC_RET),
                    )

                    # 解析 useful/clobber regs 与副作用
                    _g.useful_regs = self._extract_useful_regs(_gbytes)
                    _g.clobber_regs = self._extract_clobber_regs(_gbytes)
                    _g.side_effects = self._classify_side_effects(_g)

                    if _is_pivot:
                        _g.side_effects = 'stack_pivot'

                    _gadgets.append(_g)

                _pos += _tlen

        # 同 offset + kind 只保留最长
        return self._deduplicate_gadgets(_gadgets)

    def _deduplicate_gadgets(self, gadgets: List[Gadget]) -> List[Gadget]:
        _seen = {}
        for _g in gadgets:
            _key = (_g.offset, _g.kind)
            if _key not in _seen or _g.size > _seen[_key].size:
                _seen[_key] = _g
        return list(_seen.values())

    def _quick_disas(self, data: bytes) -> str:
        """快速反汇编标签 —— 不做完整解码，仅标记已知模式。"""
        _parts = []
        for _i in range(len(data)):
            _b = data[_i]
            if _b == 0x90:
                _parts.append('nop')
            elif _b == 0xc3:
                _parts.append('ret')
            elif _b in range(0x58, 0x60):
                _regs = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']
                _parts.append('pop {}'.format(_regs[_b - 0x58]))
            elif _b in range(0x50, 0x58):
                _regs = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi']
                _parts.append('push {}'.format(_regs[_b - 0x50]))
            elif _b == 0x0f and _i + 1 < len(data) and data[_i + 1] == 0x05:
                _parts.append('syscall')
            else:
                _parts.append('db {:02x}'.format(_b))
        return '; '.join(_parts)

    def _extract_useful_regs(self, data: bytes) -> Set[str]:
        """从 pop 序列提取攻击者可写寄存器。"""
        _regs = set()
        _reg_names = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi',
                      'r8','r9','r10','r11','r12','r13','r14','r15']
        for _b in data:
            if 0x58 <= _b <= 0x5f:
                _regs.add(_reg_names[_b - 0x58])
            elif _b == 0x41:  # REX.B prefix → r8-r15
                continue  # 简化，不做完整 REX 解码
        return _regs

    def _extract_clobber_regs(self, data: bytes) -> Set[str]:
        """检测被修改但不可控的寄存器（如 xor 清零）。"""
        _clobber = set()
        # xor reg, reg — 清零
        for _i in range(len(data) - 1):
            if data[_i] == 0x31 and 0xc0 <= data[_i + 1] <= 0xff:
                _clobber.add('eax')
            elif data[_i] == 0x33 and 0xc0 <= data[_i + 1] <= 0xff:
                _clobber.add('eax')
        return _clobber

    def _classify_side_effects(self, gadget: Gadget) -> str:
        """归类 gadget 副作用：栈读写、寄存器到内存、算术等。"""
        _data = gadget.bytes
        if b'\x89' in _data or b'\x8b' in _data:  # mov reg, [reg] or mov [reg], reg
            if b'\x04\x24' in _data or b'\x24' in _data:  # stack reference
                return 'read_from_stack'
            return 'reg_to_mem'
        if b'\xc9' in _data:  # leave
            return 'stack_pivot'
        if b'\x01' in _data or b'\x29' in _data:  # add/sub
            return 'arithmetic'
        return 'none'

    def _score_gadget_usefulness(self, gadget: Gadget) -> float:
        """评估 gadget 利用价值 (0..1)，参考 ARCANIST primitive 分类法。"""
        _s = 0.0
        _k = gadget.kind
        # pop 序列越长越有价值（可设更多寄存器）
        if _k == GadgetKind.POP_RET:
            _s = min(0.6, len(gadget.useful_regs) * 0.15)
        elif _k == GadgetKind.POP_POP_RET:
            _s = min(0.8, len(gadget.useful_regs) * 0.20)
        # syscall 极具价值
        elif _k == GadgetKind.SYSCALL:
            _s = 0.90
        elif _k == GadgetKind.INT80:
            _s = 0.85
        # 栈 pivot 最重要
        elif gadget.side_effects == 'stack_pivot':
            _s = 0.95
        # 间接跳转
        elif _k == GadgetKind.JMP_REG:
            _s = 0.65
        elif _k == GadgetKind.CALL_REG:
            _s = 0.55
        # PAC 保护打折扣
        if gadget.pac_protected:
            _s *= 0.30
        return round(min(_s, 1.0), 4)

    # ── 链式分析 ────────────────────────────────────────────────────

    def _find_chainable_pairs(self, gadgets: List[Gadget]) -> List[Tuple[int, int]]:
        """检测可串联 gadget 对：A 的 useful_regs 与 B 的 clobber_regs 不冲突。"""
        _pairs = []
        _by_offset = {_g.offset: _g for _g in gadgets}
        _offsets = sorted(_by_offset.keys())

        _idx = 0
        _n = len(_offsets)
        while _idx < _n:
            _jdx = _idx + 1
            while _jdx < _n and _jdx - _idx < 10:
                _ga = _by_offset[_offsets[_idx]]
                _gb = _by_offset[_offsets[_jdx]]
                # A.useful_regs 不能与 B.clobber_regs 冲突
                if not (_ga.useful_regs & _gb.clobber_regs):
                    _pairs.append((_ga.offset, _gb.offset))
                _jdx += 1
            _idx += 1

        return _pairs[:500]  # 截断，避免膨胀

    def _estimate_longest_chain(self, gadgets: List[Gadget]) -> int:
        """贪心 BFS 估算最长可串联 gadget 链。"""
        if len(gadgets) < 2:
            return min(len(gadgets), 1)

        # 邻接表
        _adj = defaultdict(set)
        _by_offset = {_g.offset: _g for _g in gadgets}
        for _o1, _o2 in self._find_chainable_pairs(gadgets):
            _adj[_o1].add(_o2)

        # BFS 求最长路径（DAG 假设，限制深度防环）
        _max_len = 0
        for _start in list(_adj.keys())[:100]:
            _visited = set()
            _q = deque([(_start, 1)])
            while _q:
                _cur, _depth = _q.popleft()
                _max_len = max(_max_len, _depth)
                if _depth < 20:  # 深度上限，防无限链
                    for _nxt in _adj.get(_cur, set()):
                        if _nxt not in _visited:
                            _visited.add(_nxt)
                            _q.append((_nxt, _depth + 1))
        return _max_len

    def _compute_defense_score(self, report: GadgetChainAnalysis,
                               binary_size: int) -> float:
        """防御评分（越高越安全）。

        综合 gauge 密度、syscall gadget 数量、PAC 覆盖率、最长链长度。
        """
        _s = 1.0
        if binary_size > 0:
            _density = report.total_gadgets / binary_size
            # 密度每 0.001 扣 0.05
            _s -= min(_density * 50, 0.40)

        # syscall gadget → 减分
        if report.syscall_gadgets > 0:
            _s -= min(report.syscall_gadgets * 0.05, 0.25)

        # PAC → 加分
        _s += min(report.pac_protected_count / max(report.total_gadgets, 1) * 0.30, 0.30)

        # 长链 → 减分
        if report.longest_chain >= 10:
            _s -= 0.20
        elif report.longest_chain >= 5:
            _s -= 0.10

        return round(min(max(_s, 0.0), 1.0), 4)


# ── 便捷入口 ────────────────────────────────────────────────────────

def analyze_gadget_chains(binary_path: str, arch: str = "x86_64") -> Dict:
    _analyzer = GadgetChainAnalyzer(arch=arch)
    _rpt = _analyzer.analyze(binary_path)
    return {'success': True, 'result': _rpt.to_dict()}
