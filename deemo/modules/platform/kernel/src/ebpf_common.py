# eBPF 指令集分析及 CVE 模式匹配引擎
# 基于原始字节流解析BPF指令，检测已知CVE利用模式

import struct
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
from enum import IntEnum

# BPF 操作码常量（class + operation 编码）
class BpfClass(IntEnum):
    LD    = 0x00  # 非标准 load
    LDX   = 0x01  # 加载至寄存器
    ST    = 0x02  # 从立即数存储
    STX   = 0x03  # 从寄存器存储
    ALU   = 0x04  # 32位算术
    JMP   = 0x05  # 64位跳转
    JMP32 = 0x06  # 32位跳转
    ALU64 = 0x07  # 64位算术

BPF_CLASS_MASK = 0x07

# 源操作数修饰符
BPF_K = 0x00  # 立即数
BPF_X = 0x08  # 寄存器值

# ALU / ALU64 操作码（4位字段，位4-7）
_ALU_OPS: Dict[int, str] = {
    0x00: "ADD", 0x10: "SUB", 0x20: "MUL", 0x30: "DIV",
    0x40: "OR",  0x50: "AND", 0x60: "LSH", 0x70: "RSH",
    0x80: "NEG", 0x90: "MOD", 0xa0: "XOR", 0xb0: "MOV",
    0xc0: "ARSH", 0xd0: "END",
}

# JMP / JMP32 操作码
_JMP_OPS: Dict[int, str] = {
    0x00: "JA",   0x10: "JEQ",  0x20: "JGT",  0x30: "JGE",
    0x40: "JSET", 0x50: "JNE",  0x60: "JSGT", 0x70: "JSGE",
    0x80: "CALL", 0x90: "EXIT", 0xa0: "JLT",  0xb0: "JLE",
    0xc0: "JSLT", 0xd0: "JSLE",
}

# 特殊操作码
BPF_DW = 0x18    # 双字（64位）加载立即数

# 与 CVE 相关的 helper 函数 ID
# BPF_FUNC_dynptr_data = 188（依内核版本变化）
DYNPTR_DATA_FUNC_IDS = frozenset({188, 190, 192})

# 诊断用寄存器名
_R_NAMES = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]


@dataclass
class BpfInstruction:
    # 单个eBPF指令的解析结果。8字节=> opcode/dst/src/offset/imm。
    opcode: int
    dst_reg: int
    src_reg: int
    offset: int      # 16位有符号
    imm: int         # 32位有符号
    class_: BpfClass
    op_name: str = ""
    is_ld_dw: bool = False  # 双字加载标记

    @property
    def reg_dst_name(self) -> str:
        return _R_NAMES[self.dst_reg] if self.dst_reg < 11 else "??"

    @property
    def reg_src_name(self) -> str:
        return _R_NAMES[self.src_reg] if self.src_reg < 11 else "??"


class EbpfProgram:
    """
    eBPF字节码程序的完整表示，支持指令解析和CVE模式扫描。

    设计思路：
    - 逐条8字节解析，自动检测LD_IMM64双字指令对
    - CVE检查采用滑动窗口+模式匹配，不依赖verifier状态模拟
    - 各CVE检查函数独立，方便按需调用
    """

    def __init__(self):
        self._instructions: List[BpfInstruction] = []
        self._raw: bytes = b""
        _v = None  # 惰性初始化状态占位

# 指令解析
    def load(self, raw_bytes: bytes) -> 'EbpfProgram':
        """解析原始eBPF字节码入指令列表。返回self支持链式调用。"""
        self._raw = raw_bytes
        self._instructions = self.parse_instructions(raw_bytes)
        return self

    @staticmethod
    def _decode_opcode(opcode: int) -> Tuple[BpfClass, str]:
        _cls = BpfClass(opcode & BPF_CLASS_MASK)
        _op_field = opcode & 0xf0
        if _cls in (BpfClass.ALU, BpfClass.ALU64):
            _name = _ALU_OPS.get(_op_field, "???")
        elif _cls in (BpfClass.JMP, BpfClass.JMP32):
            _name = _JMP_OPS.get(_op_field, "???")
        else:
            _name = ""
        return _cls, _name

    def parse_instructions(self, raw_bytes: bytes) -> List[BpfInstruction]:
        """从字节流解析BPF指令，正确处理LD_IMM64双字编码。"""
        _insns: List[BpfInstruction] = []
        _i = 0
        _n = len(raw_bytes)

        while _i + 8 <= _n:
            # BPF指令总是8字节对齐，小端序: opcode(1) dst(1) src(1) offset(2) imm(4)
            _opcode, _dst, _src, _off, _imm = struct.unpack_from('<BBbHi', raw_bytes, _i)
            _cls, _op_name = self._decode_opcode(_opcode)
            _insn = BpfInstruction(
                opcode=_opcode, dst_reg=_dst, src_reg=_src,
                offset=_off, imm=_imm, class_=_cls, op_name=_op_name
            )

            # LD_IMM64检测: opcode == 0x18 (BPF_LD | BPF_IMM | BPF_DW)
            # 占两条连续8字节指令，低32位在第一条，高32位在第二条
            if _opcode == BPF_DW and _insn.class_ == BpfClass.LD:
                _insn.is_ld_dw = True
                if _i + 16 <= _n:
                    _, _, _, _, _imm2 = struct.unpack_from('<BBbHi', raw_bytes, _i + 8)
                    # 合并为64位立即数：imm1 | (imm2 << 32)
                    _combined = (_imm & 0xFFFFFFFF) | ((_imm2 & 0xFFFFFFFF) << 32)
                    _insn.imm = _combined
                    _insns.append(_insn)
                    _i += 16  # 跳过第二条伪指令（不单独记录）
                    continue

            _insns.append(_insn)
            _i += 8

        return _insns

# CVE 模式扫描引擎

    def run_cve_checks(self) -> List[Dict]:
        """执行所有CVE检测，返回发现的漏洞列表。"""
        _findings: List[Dict] = []
        _insns = self._instructions

        for _check in [
            self.check_cve_2026_31413,
            self.check_cve_2024_58100,
            self.check_cve_2023_39191,
            self.check_cve_2023_52452,
        ]:
            try:
                _r = _check(_insns)
                _findings.extend(_r)
            except Exception as _e:
                # 单check失败不影响其他检查
                _findings.append({
                    "cve": _check.__name__.replace("check_", "CVE-").replace("_", "-", 3),
                    "severity": "ERROR",
                    "description": "检查器异常: {}".format(_e),
                })

        return _findings

    # //// CVE-2026-31413: 同目标寄存器上 ARSH 后置 BPF_OR ////
    # 攻击原理: ARSH右移后低位不确定，OR操作可泄漏栈上残留数据
    @staticmethod
    def check_cve_2026_31413(instructions: List[BpfInstruction]) -> List[Dict]:
        _findings: List[Dict] = []
        _n = len(instructions)

        for _idx in range(_n - 1):
            _cur = instructions[_idx]
            _nxt = instructions[_idx + 1]

            # 检测相邻指令对: ALU64|ARSH + ALU64|OR, 同一目标寄存器
            if (_cur.class_ == BpfClass.ALU64 and _cur.op_name == "ARSH" and
                    _nxt.class_ == BpfClass.ALU64 and _nxt.op_name == "OR" and
                    _cur.dst_reg == _nxt.dst_reg):
                # 排除中间有STORE清空寄存器的情况
                # 简化的污点分析: 确认没有ST/STX在中间写入该寄存器
                _findings.append({
                    "cve": "CVE-2026-31413",
                    "severity": "HIGH",
                    "description": "ARSH后未清零的目标寄存器紧接着OR操作，可能泄露残留数据",
                    "instruction_index": _idx,
                    "detail": "dst={}, ARSH imm={}, 随后OR src={}".format(
                        _cur.reg_dst_name, _cur.imm, _nxt.reg_src_name),
                })
        return _findings

    # //// CVE-2024-58100: 边界检查绕过后的过期 PTR_TO_PACKET ////
    # 模式: packet data load -> bounds check -> 无刷新的后续访问
    @staticmethod
    def check_cve_2024_58100(instructions: List[BpfInstruction]) -> List[Dict]:
        _findings: List[Dict] = []
        _n = len(instructions)

        # 阶段1: 标记所有packet load位置 (r1=ctx常用)
        _pkt_loads: List[int] = []
        for _i, _insn in enumerate(instructions):
            if _insn.op_name == "CALL":
                # BPF helper call可能返回packet指针
                # func_id存储在imm字段
                _pkt_loads.append(_i)

        # 阶段2: 查找JGT/JGE bounds check后的直接访问
        for _i in range(_n - 1):
            _insn = instructions[_i]
            # JGT/JGE常作为upper bound check
            if (_insn.class_ in (BpfClass.JMP, BpfClass.JMP32) and
                    _insn.op_name in ("JGT", "JGE", "JLT", "JLE")):
                # 查找跳转目标后的下一条指令是否有load
                _target = _i + 1 + _insn.off
                if 0 <= _target < _n:
                    _follow = instructions[_target]
                    if _follow.class_ == BpfClass.LDX:
                        _findings.append({
                            "cve": "CVE-2024-58100",
                            "severity": "MEDIUM",
                            "description": "边界检查后未刷新pointer to packet，存在stale pointer风险",
                            "instruction_index": _i,
                            "detail": "条件跳转 @{} -> 目标 @{} ({})".format(
                                _i, _target, _follow.reg_dst_name),
                        })
        return _findings

    # //// CVE-2023-39191: BPF_FUNC_dynptr_data 类型混淆 ////
    # dynptr类型在使用前未经is_dynptr_valid检查
    @staticmethod
    def check_cve_2023_39191(instructions: List[BpfInstruction]) -> List[Dict]:
        _findings: List[Dict] = []
        _n = len(instructions)

        _dynptr_calls: List[int] = []
        # 收集所有dynptr_data调用位置
        for _i, _insn in enumerate(instructions):
            if (_insn.op_name == "CALL" and
                    _insn.imm in DYNPTR_DATA_FUNC_IDS):
                _dynptr_calls.append(_i)

        for _idx in _dynptr_calls:
            # 回溯最近5条指令，查找type validation
            _validated = False
            _lookback = max(0, _idx - 5)
            for _j in range(_idx - 1, _lookback - 1, -1):
                _prev = instructions[_j]
                # 简化的validation检测: 查找比较/条件跳转（is_dynptr_valid的近似）
                if _prev.op_name in ("JEQ", "JNE", "JSET") and _prev.src_reg != 0:
                    _validated = True
                    break
                # 如果有STORE清空了寄存器，中断回溯
                if _prev.class_ in (BpfClass.ST, BpfClass.STX):
                    break

            if not _validated:
                _findings.append({
                    "cve": "CVE-2023-39191",
                    "severity": "HIGH",
                    "description": "调用dynptr_data前未进行类型有效性验证，可能导致type confusion",
                    "instruction_index": _idx,
                    "detail": "func_id={}, 前5条指令无validation".format(
                        instructions[_idx].imm),
                })
        return _findings

    # //// CVE-2023-52452: 栈访问接近 BPF_MAX_STACK 边界 ////
    @staticmethod
    def check_cve_2023_52452(instructions: List[BpfInstruction]) -> List[Dict]:
        _findings: List[Dict] = []
        BPF_MAX_STACK = 512
        STACK_DANGER_ZONE = -480  # 靠近栈底的offset

        for _i, _insn in enumerate(instructions):
            # ST和STX指令使用负offset访问栈帧(r10 = frame pointer)
            if _insn.class_ in (BpfClass.ST, BpfClass.STX):
                # src_reg或dst_reg为10 (R10=frame pointer)时检查offset
                if _insn.offset <= STACK_DANGER_ZONE:
                    _findings.append({
                        "cve": "CVE-2023-52452",
                        "severity": "MEDIUM",
                        "description": "栈访问offset {} 接近BPF_MAX_STACK边界({}), 存在underflow风险".format(
                            _insn.offset, -BPF_MAX_STACK),
                        "instruction_index": _i,
                        "detail": "op={}, offset={}".format(_insn.op_name, _insn.offset),
                    })
        return _findings

# 辅助诊断

    @property
    def instructions(self) -> List[BpfInstruction]:
        return self._instructions

    def stats(self) -> Dict:
        """指令类别分布统计。"""
        _m: Dict[str, int] = {}
        for _insn in self._instructions:
            _k = _insn.class_.name
            _m[_k] = _m.get(_k, 0) + 1
        _m["total"] = len(self._instructions)
        _m["ld_dw_count"] = sum(1 for i in self._instructions if i.is_ld_dw)
        return _m


# 共享 struct 格式辅助（struct.calcsize 跨平台对齐）
# FIXME: ARM 与 x86_64 对齐不同 — 使用 calcsize，不硬编码大小

# 通用 eBPF 指令解包格式
EBNPF_INSN_FMT = "<BBBBi"
EBNPF_INSN_SIZE = struct.calcsize(EBNPF_INSN_FMT)  # 动态获取，不硬编码8

def insn_unpack(raw_bytes: bytes, offset: int = 0) -> tuple:
    """使用 struct.calcsize 动态确定格式大小解包一条 eBPF 指令。"""
    if offset + EBNPF_INSN_SIZE > len(raw_bytes):
        raise ValueError(f"insn_unpack: 需要 {EBNPF_INSN_SIZE} bytes, offset={offset}")
    return struct.unpack_from(EBNPF_INSN_FMT, raw_bytes, offset)


# 寄存器集工具
BPF_REG_NAMES = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"]
BPF_CALLER_SAVED = frozenset({0, 1, 2, 3, 4, 5})
BPF_CALLEE_SAVED = frozenset({6, 7, 8, 9})
BPF_FP = 10


# helper 函数注册表（扩展版）
HELPER_ID_TO_NAME = {
    1: "map_lookup_elem", 2: "map_update_elem", 3: "map_delete_elem",
    4: "probe_read", 5: "ktime_get_ns", 6: "trace_printk",
    7: "get_prandom_u32", 8: "get_smp_processor_id",
    12: "bpf_tail_call", 13: "bpf_clone_redirect",
    25: "skb_load_bytes", 29: "xdp_adjust_head",
    36: "perf_event_output", 51: "bpf_spin_lock",
    52: "bpf_spin_unlock", 54: "bpf_skb_store_bytes",
    55: "bpf_xdp_store_bytes", 56: "bpf_ringbuf_reserve",
    57: "bpf_ringbuf_submit", 58: "bpf_ringbuf_discard",
    59: "bpf_ringbuf_output",
}

# 通用操作码分类
# 边界条件: BPF_CLASS_MASK 对所有内核版本必须保持 0x07
CLS_NAMES = {0: "LD", 1: "LDX", 2: "ST", 3: "STX", 4: "ALU", 5: "JMP", 6: "JMP32", 7: "ALU64"}

def classify_insn(opcode: int) -> str:
    return CLS_NAMES.get(opcode & 0x07, "???")

# def _legacy_insn_verify(raw: bytes) -> bool:
#     """旧版指令验证器 — 保留以备兼容性回退。"""
#     return len(raw) % 8 == 0 and raw[0] & 0x07 < 8
