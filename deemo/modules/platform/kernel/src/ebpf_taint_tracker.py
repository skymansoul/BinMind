"""
eBPF 字节码数据流污点分析。追踪用户可控输入 — 映射查询、数据包缓冲区 —
经 ALU 和内存操作流向不安全汇点：尾调用、带污点键的映射变更。
"""

import struct
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# eBPF 操作码及 helper 函数常量
BPF_LD = 0x00; BPF_LDX = 0x01; BPF_ST = 0x02; BPF_STX = 0x03
BPF_ALU = 0x04; BPF_JMP = 0x05; BPF_ALU64 = 0x07

BPF_ADD = 0x00; BPF_SUB = 0x10; BPF_MUL = 0x20; BPF_DIV = 0x30
BPF_OR = 0x40; BPF_AND = 0x50; BPF_LSH = 0x60; BPF_RSH = 0x70
BPF_NEG = 0x80; BPF_MOD = 0x90; BPF_XOR = 0xA0; BPF_MOV = 0xB0
BPF_ARSH = 0xC0

BPF_MAP_LOOKUP = 1
BPF_MAP_UPDATE = 2
BPF_MAP_DELETE = 3
BPF_PROBE_READ = 4
BPF_TAIL_CALL = 12
BPF_SKB_LOAD = 25
BPF_XDP_ADJUST = 29
BPF_RINGBUF_OUTPUT = 38
BPF_RINGBUF_RESERVE = 36
BPF_SKB_STORE = 54   # bpf_skb_store_bytes — 写入路径
BPF_XDP_STORE = 55    # bpf_xdp_store_bytes — 写入路径
BPF_PERF_EVENT_OUTPUT = 25

MAP_VALUE = 0xF0     # 合成源标签 — 映射查询结果
PACKET_DATA = 0xF1   # 合成源标签 — 数据包/xdp缓冲区
ARGUMENT = 0xF2      # 合成源标签 — 函数参数
STACK_SPILL = 0xF3   # 栈溢出路径引入的污点
RESERVED = 0xFF

R10 = 10  # 栈帧基址寄存器
CALL_REG = 1  # r1 持有上下文指针

# 辅助函数返回值污点继承规则
_HELPER_TAINT_RULES = {
    BPF_MAP_LOOKUP: (0, MAP_VALUE),
    BPF_SKB_LOAD:   (0, PACKET_DATA),
    BPF_PROBE_READ: (0, PACKET_DATA),
}

# 写入路径 helper — 若这些 helper 的源数据受污染，污点传播到目标对象
_WRITE_PATH_HELPERS = frozenset({
    BPF_SKB_STORE, BPF_XDP_STORE, BPF_MAP_UPDATE,
})


class TaintSource:
    __slots__ = ("name", "origins")
    def __init__(self, name=""):
        self.name = name
        self.origins: list[str] = []
    def add_origin(self, origin: str):
        self.origins.append(origin)
    def __repr__(self):
        return f"TaintSource({self.name!r}, origins={self.origins})"


class TaintSink:
    __slots__ = ("kind", "description")
    def __init__(self, kind="", description=""):
        self.kind = kind; self.description = description


class TaintPath:
    __slots__ = ("source_insn", "sink_insn", "hops", "registers")
    def __init__(self):
        self.source_insn: int = -1
        self.sink_insn: int = -1
        self.hops: list[str] = []
        self.registers: list[int] = []


class TrackerResult:
    __slots__ = ("inputs", "tainted_regs", "sinks", "sanitization_log",
                 "taint_paths", "toctou_alerts", "implicit_flows",
                 "stack_leak_alerts", "write_path_sinks")

    def __init__(self):
        self.inputs: list[tuple[int, str]] = []
        self.tainted_regs: dict[int, list[str]] = defaultdict(list)
        self.sinks: list[tuple[int, str, str]] = []
        self.sanitization_log: list[str] = []
        self.taint_paths: list[TaintPath] = []
        self.toctou_alerts: list[str] = []
        self.implicit_flows: list[tuple[int, str]] = []
        # 栈残留泄漏：记录可能导出未初始化栈数据的指令
        self.stack_leak_alerts: list[tuple[int, int]] = []
        # 写入路径汇点：记录污染数据被写入到内核对象的位置
        self.write_path_sinks: list[tuple[int, str]] = []


class EBPFTaintTracker:
    """
    逐指令污点传播引擎。将数据流从源（映射查询、数据包读取）经寄存器和栈
    状态路由至汇点。
    """

    SINK_MAP = {
        BPF_TAIL_CALL: TaintSink("tail_call", "bpf_tail_call with tainted target"),
        BPF_MAP_UPDATE: TaintSink("map_update", "map value update with tainted key"),
        BPF_MAP_DELETE: TaintSink("map_delete", "map deletion with tainted key"),
        BPF_RINGBUF_OUTPUT: TaintSink("data_leak", "ringbuf_output — 用户态数据泄漏"),
        BPF_RINGBUF_RESERVE: TaintSink("data_leak", "ringbuf_reserve — 保留污染数据的缓冲区"),
        BPF_PERF_EVENT_OUTPUT: TaintSink("data_leak", "perf_event_output — 事件数据泄漏"),
        BPF_SKB_STORE: TaintSink("data_inject", "skb_store_bytes — 污染数据写入数据包"),
        BPF_XDP_STORE: TaintSink("data_inject", "xdp_store_bytes — 污染数据写入 XDP 缓冲区"),
    }

    _CLEAR_ALU = frozenset({BPF_XOR, BPF_AND, BPF_SUB})

    def __init__(self):
        self._taint: dict[int, set[str]] = {}
        self._stack_taint: dict[int, set[str]] = {}
        self._stack_frame_taint: dict[tuple[int, int], set[str]] = {}
        self._history: list[TrackerResult] = []
        self._last_map_lookup: dict[int, int] = {}
        self._map_val_usage: set[int] = set()
        # 隐式流追踪：分支条件中使用的污染寄存器集合
        self._branch_taint: dict[int, set[str]] = {}
        # 栈初始化追踪：记录已显式写入（非残留）的栈偏移
        self._stack_initialized: set[int] = set()

    def track(self, prog: bytes) -> list[TrackerResult]:
        """对解析后的 eBPF 指令流执行污点传播。"""
        insns = self._parse(prog)
        result = TrackerResult()
        self._taint = {i: set() for i in range(11)}
        self._stack_taint = {}
        self._stack_frame_taint = {}
        self._last_map_lookup = {}
        self._map_val_usage = set()
        self._branch_taint = {}
        self._stack_initialized = set()
        if not insns:
            return [result]

        for idx, insn in enumerate(insns):
            self._step_insn(idx, insn, result)

        self._history.append(result)
        return [result]

    def _parse(self, prog: bytes) -> list[dict]:
        insns = []
        if len(prog) < 8: return insns
        chunk_size = 8
        for i in range(0, len(prog) - (chunk_size - 1), chunk_size):
            raw = prog[i:i + 8] if len(prog[i:]) >= 8 else prog[i:]
            if len(raw) < 8: break
            opcode, dst_src, offset, imm = struct.unpack("<BBhi", raw[:8])
            insns.append({
                "idx": i // chunk_size, "opcode": opcode,
                "dst": dst_src & 0xF, "src": (dst_src >> 4) & 0xF,
                "off": offset, "imm": imm,
                "cls": opcode & 0x07, "op_alu": opcode & 0xF0,
            })
        return insns

    def _step_insn(self, idx: int, insn: dict, result: TrackerResult):
        cls, op = insn["cls"], insn["op_alu"]
        dst, src, imm, off = insn["dst"], insn["src"], insn["imm"], insn["off"]

        # 条件分支隐式流追踪 — VeRefine (OOPSLA 2025) 概念：
        # 若分支条件依赖污染数据，则分支体内所有赋值都被隐式污染，
        # 因为控制流本身携带了信息。
        if cls == BPF_JMP and op != 0x80 and op != 0x90:
            # 条件跳转：检查 dst 或 src 是否被污染
            if self._taint.get(dst) or (insn["opcode"] & 0x08 and self._taint.get(src)):
                self._branch_taint[idx] = self._taint.get(dst, set()) | (
                    self._taint.get(src, set()) if insn["opcode"] & 0x08 else set())

        if cls == BPF_JMP and op == 0x80:
            self._handle_call(idx, insn, result)

        elif cls in (BPF_ALU, BPF_ALU64) and op == BPF_MOV:
            self._propagate_move(dst, src, result)

        elif cls in (BPF_ALU, BPF_ALU64):
            self._handle_alu(dst, src, imm, op, result)

        elif cls == BPF_STX:
            self._handle_stx(dst, src, off, result)
            # 标记栈初始化
            if dst == R10:
                self._stack_initialized.add(off)

        elif cls == BPF_ST:
            key = (dst, off)
            self._stack_frame_taint.pop(key, None)
            if off in self._stack_taint: del self._stack_taint[off]
            if dst == R10: self._stack_initialized.add(off)

        elif cls == BPF_LDX and src == R10:
            # 从栈加载 — 若该栈槽从未被初始化，标记为残留泄漏风险
            if off not in self._stack_initialized:
                result.stack_leak_alerts.append((idx, off))
            if off in self._stack_taint:
                self._taint[dst] |= self._stack_taint[off]
            frame_key = (R10, off)
            if frame_key in self._stack_frame_taint:
                self._taint[dst] |= self._stack_frame_taint[frame_key]

        elif cls == BPF_LDX:
            if src < len(self._taint) and self._taint[src]:
                frame_key = (src, off)
                if frame_key in self._stack_frame_taint:
                    self._taint[dst] |= self._stack_frame_taint[frame_key]

    def _handle_call(self, idx: int, insn: dict, result: TrackerResult):
        imm = insn["imm"]

        # 数据源标记
        if imm == BPF_MAP_LOOKUP:
            self._taint[0] = {f"map_val@{idx}"}
            result.inputs.append((idx, f"map_lookup(func={imm})"))
            self._last_map_lookup[insn.get("dst", 0)] = idx
        elif imm == BPF_SKB_LOAD:
            self._taint[0] = {f"pkt_data@{idx}"}
            result.inputs.append((idx, f"packet_load"))
        elif imm == BPF_PROBE_READ:
            self._taint[0] = {f"kern_read@{idx}"}
            result.inputs.append((idx, f"probe_read — 内核内存暴露"))

        if imm in _HELPER_TAINT_RULES:
            ret_reg, source_tag = _HELPER_TAINT_RULES[imm]
            self._taint[ret_reg] = {f"{source_tag:#x}@{idx}"}

        if imm == BPF_MAP_UPDATE:
            self._check_toctou(idx, insn, result)

        # 汇点 & 写入路径检测
        if imm in self.SINK_MAP:
            sink = self.SINK_MAP[imm]
            if imm == BPF_TAIL_CALL:
                tainted = self._taint.get(1) or self._taint.get(2) or self._taint.get(3)
                if tainted:
                    result.sinks.append((idx, sink.kind, f"{sink.description} at insn {idx}"))
            elif imm in _WRITE_PATH_HELPERS:
                # 写入路径：检查数据源（r3/skb_store 或 r4/xdp_store）
                data_reg = 3 if imm == BPF_MAP_UPDATE else 4
                src_reg = self._taint.get(data_reg)
                if src_reg:
                    result.write_path_sinks.append((idx, sink.kind))
                    result.sinks.append((idx, sink.kind, f"{sink.description} at insn {idx}"))
                    path = TaintPath(); path.sink_insn = idx
                    path.hops.append(f"write-path: {sink.kind}")
                    result.taint_paths.append(path)
                # 也检查 key/value 的污染
                if self._taint.get(1) or self._taint.get(2):
                    result.sinks.append((idx, sink.kind, f"{sink.description} at insn {idx}"))
            elif self._taint.get(1) or self._taint.get(2) or self._taint.get(3):
                result.sinks.append((idx, sink.kind, f"{sink.description} at insn {idx}"))
                path = TaintPath(); path.sink_insn = idx
                path.hops.append(f"call to {sink.kind}")
                result.taint_paths.append(key)

        elif imm == BPF_MAP_UPDATE:
            if self._taint.get(2):
                result.sinks.append((idx, "map_update", f"tainted key in map update at insn {idx}"))
            if self._taint.get(3):
                result.sinks.append((idx, "map_update", f"tainted value in map update at insn {idx}"))

    def _propagate_move(self, dst, src, result: TrackerResult):
        if src < len(self._taint):
            self._taint[dst] |= self._taint[src]
            for tag in self._taint[src]:
                result.tainted_regs[dst].append(tag)

    def _handle_alu(self, dst: int, src: int, imm: int, op: int,
                    result: TrackerResult):
        # 隐式流污染传播：若当前指令处于被污染的分支体内，
        # 即使源操作数不直接污染，目标操作数也获得隐式污染标记。
        # 这是 VeRefine (OOPSLA 2025) 中流敏感精化类型系统的核心思想。
        has_implicit = False
        for branch_idx, branch_tags in self._branch_taint.items():
            if branch_idx < _find_branch_dominator_end(
                branch_idx, self._instructions if hasattr(self, '_instructions') else []):
                has_implicit = True
                break

        if src < len(self._taint) and self._taint[src]:
            if op in self._CLEAR_ALU and dst == src:
                self._taint[dst].clear()
                result.sanitization_log.append(
                    f"taint cleared: r{dst} self-op at op=0x{op:02x}")
                return
            self._taint[dst] |= self._taint[src]
            for tag in self._taint[src]:
                result.tainted_regs[dst].append(tag)
        elif has_implicit and dst < len(self._taint):
            # 隐式流：目标获得 "implicit" 标签
            self._taint[dst].add("implicit_flow")
        elif src == 0 and imm == 0 and op == BPF_ADD:
            pass
        elif src == 0 and imm == 0 and op == BPF_MOV:
            self._taint[dst].clear()
        else:
            if imm != 0 and src == 0:
                if imm == 0 and op in (BPF_ADD, BPF_SUB): pass
                else: self._taint[dst] |= {f"const_{imm}"}

    def _handle_stx(self, dst: int, src: int, off: int,
                    result: TrackerResult):
        if dst == R10:
            if src < len(self._taint):
                self._stack_taint[off] = set(self._taint[src])
                self._stack_initialized.add(off)
        elif src < len(self._taint) and self._taint[src]:
            key = (dst, off)
            if key not in self._stack_frame_taint:
                self._stack_frame_taint[key] = set()
            self._stack_frame_taint[key] |= self._taint[src]

    def _check_toctou(self, idx: int, insn: dict, result: TrackerResult):
        map_reg = insn.get("dst", 0)
        if map_reg in self._last_map_lookup:
            lookup_idx = self._last_map_lookup[map_reg]
            if lookup_idx < idx:
                result.toctou_alerts.append(
                    f"TOCTOU risk: map_lookup at insn {lookup_idx} "
                    f"→ map_update at insn {idx} — "
                    f"intermediate use of r0 was not sanitized")

    def prune_unreachable(self, insn_idx: int, cfg: dict, sink_locations: set[int]):
        if not sink_locations: return
        dead_regs = set()
        for reg, tags in list(self._taint.items()):
            if not tags: continue
            if not self._path_exists(insn_idx, sink_locations, cfg, max_depth=32):
                dead_regs.add(reg)
        for dr in dead_regs:
            self._taint[dr].clear()

    def _path_exists(self, start: int, targets: set[int], cfg: dict,
                     max_depth: int) -> bool:
        if start in targets: return True
        visited = {start}; frontier = [start]; depth = 0
        while frontier and depth < max_depth:
            next_frontier = []
            for node in frontier:
                for succ, _ in cfg.get(node, []):
                    if succ in targets: return True
                    if succ not in visited:
                        visited.add(succ); next_frontier.append(succ)
            frontier = next_frontier; depth += 1
        return False

    def taint_summary(self) -> dict:
        if not self._history:
            return {"tainted_regs": {}, "stack_spills": {}, "sink_count": 0}
        last = self._history[-1]
        return {
            "tainted_regs": dict(last.tainted_regs),
            "stack_spills": {k: list(v) for k, v in self._stack_taint.items()},
            "sink_count": len(last.sinks),
            "total_inputs": len(last.inputs),
            "toctou_count": len(last.toctou_alerts),
            "path_count": len(last.taint_paths),
            "stack_leak_count": len(last.stack_leak_alerts),
            "implicit_flow_count": len(last.implicit_flows),
            "write_path_count": len(last.write_path_sinks),
        }


def _find_branch_dominator_end(branch_idx: int, insns: list) -> int:
    """粗略估计被污染分支的末尾位置（控制流汇合点之前的指令）。

    简化实现：从分支点开始扫描，找到第一个 JEQ/JNE 跳转目标超过
    分支点+16 的位置作为汇合点估计。精度有限，但足以捕获
    大多数短分支体内的隐式流。
    """
    if not insns: return branch_idx + 1
    n = len(insns)
    for j in range(branch_idx + 1, min(branch_idx + 32, n)):
        insn_j = insns[j] if isinstance(insns[j], dict) else None
        if insn_j is None: continue
        op = insn_j.get("opcode", 0) if isinstance(insn_j, dict) else 0
        if (op & 0x07) == BPF_JMP and (op & 0xF0) in (BPF_OP_JMP.JEQ, BPF_OP_JMP.JNE):
            return j + 1
    return min(branch_idx + 8, n)


def create_ebpf_tracker() -> EBPFTaintTracker:
    return EBPFTaintTracker()


# ─── 批量跟踪 & 导出 ───

def batch_track(programs: list[bytes]) -> list[dict]:
    """批量污点跟踪多个 eBPF 程序，返回每个程序的摘要。"""
    _results = []
    for _idx, _prog in enumerate(programs):
        try:
            _tracker = EBPFTaintTracker()
            _tracker.track(_prog)
            _sum = _tracker.taint_summary()
            _sum["index"] = _idx
            _results.append(_sum)
        except Exception:
            _results.append({"index": _idx, "error": "track failed"})
    return _results
