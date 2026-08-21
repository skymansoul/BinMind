#!/usr/bin/env python3
# 主接口：去混淆级别关联的流水线类
import json
import logging
import os
import re
import struct
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class DeobfuscationLevel(Enum):
    LIGHT = "light"; MEDIUM = "medium"; AGGRESSIVE = "aggressive"

class ControlFlowPattern(Enum):
    NORMAL = "normal"; FLATTENED = "flattened"; SPLIT = "split"
    JUNK = "junk"; OPAQUE = "opaque"; IRREDUCIBLE = "irreducible"


@dataclass
class BasicBlock:
    block_id: int; start_addr: int; end_addr: int
    instructions: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)
    successors: list = field(default_factory=list)
    is_junk: bool = False; original_pcode: str = ""
    is_loop_header: bool = False


@dataclass
class ControlFlowGraph:
    function_name: str; entry_block: int
    blocks: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    complexity: int = 0; idom: dict = field(default_factory=dict)


@dataclass
class DeobfuscationResult:
    success: bool
    original_cfg: Optional[ControlFlowGraph] = None
    deobfuscated_cfg: Optional[ControlFlowGraph] = None
    original_pseudocode: str = ""; deobfuscated_pseudocode: str = ""
    metrics: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)
    analysis_time: float = 0.0; modifications: list = field(default_factory=list)


@dataclass
class DeobfuscationMetrics:
    original_block_count: int = 0; deobfuscated_block_count: int = 0
    block_reduction_ratio: float = 0.0
    original_edge_count: int = 0; deobfuscated_edge_count: int = 0
    edge_reduction_ratio: float = 0.0
    original_complexity: int = 0; deobfuscated_complexity: int = 0
    complexity_reduction_ratio: float = 0.0
    dead_code_removed: int = 0; opaque_predicates_removed: int = 0
    control_flow_restructured: bool = False; loops_detected: int = 0
    jump_tables_recovered: int = 0


class ConstantValue:
    def __init__(self, value: Any, is_known: bool = True):
        self.value = value; self.is_known = is_known
    def __repr__(self): return f"Const({self.value})" if self.is_known else "Unknown"


class _LivenessInfo:
    __slots__ = ("defs", "uses", "live_in", "live_out")
    def __init__(self):
        self.defs: Set[str] = set(); self.uses: Set[str] = set()
        self.live_in: Set[str] = set(); self.live_out: Set[str] = set()


_OPERAND_RX = re.compile(r"\b(?:[er]?[abcd]x|[er]?si|[er]?di|[er]?[sb]p|r\d+[a-z]?|r[a-z]{1,2}|xmm\d+|ymm\d+|r\d+)\b", re.IGNORECASE)

def _extract_defs_uses(instr: str) -> Tuple[Set[str], Set[str]]:
    defs, uses = set(), set()
    operands = _OPERAND_RX.findall(instr)
    if not operands: return defs, uses
    lower = instr.lower().strip()
    if any(lower.startswith(p) for p in ("mov","lea","add","sub","xor","and","or","shl","shr","pop","imul","xchg","inc","dec")):
        defs.add(operands[0].lower())
        for op in operands[1:]: uses.add(op.lower())
    elif lower.startswith("cmp") or lower.startswith("test"):
        for op in operands: uses.add(op.lower())
    elif lower.startswith("push"): uses.add(operands[0].lower())
    elif lower.startswith("call") or lower.startswith("j"):
        for op in operands: uses.add(op.lower())
    return defs, uses


_PEEPHOLE_PATTERNS = [
    (re.compile(r"push\s+(\w+)\s*\n\s*pop\s+\1", re.I), ""),
    (re.compile(r"mov\s+(\w+),\s*\1", re.I), ""),
    (re.compile(r"xor\s+(\w+),\s*\1", re.I), r"mov \1, 0"),
    (re.compile(r"(?:add|sub)\s+(\w+),\s*0", re.I), ""),
    (re.compile(r"(?:shl|shr)\s+(\w+),\s*0", re.I), ""),
    (re.compile(r"or\s+(\w+),\s*0", re.I), ""),
]

def _apply_peephole(instrs):
    joined = "\n".join(instrs); removed = 0
    for pat, repl in _PEEPHOLE_PATTERNS:
        if pat.findall(joined) and repl == "": removed += len(pat.findall(joined))
        joined = pat.sub(repl, joined)
    return [l for l in joined.split("\n") if l.strip()], removed


# Switch-case 跳转表恢复
# 参考 Ghidra SwitchOverride.java 和 IDA switch_info_t 的算法:
# 1) 定位间接跳转 jmp [base + reg*scale]
# 2) 回溯范围检查 guard (cmp reg, max_val; ja default)
# 3) 从 base 地址读取连续的指针作为 case 目标

_INDIRECT_JMP_RX = re.compile(
    r"jmp\s+(?:qword\s+)?\[(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\]", re.IGNORECASE)
_CMP_GUARD_RX = re.compile(
    r"cmp\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)", re.IGNORECASE)


def _recover_jump_tables(cfg: ControlFlowGraph, raw_bytes: bytes) -> int:
    """扫描 CFG 中的所有基本块，识别 switch-case 跳转表模式
    返回恢复的跳转表数量
    """
    recovered = 0
    if not cfg or len(cfg.blocks) < 3:
        return 0

    for block_id, block in cfg.blocks.items():
        if len(block.successors) <= 1:
            continue
        text = " ".join(block.instructions)
        m = _INDIRECT_JMP_RX.search(text)
        if not m:
            continue

        base_reg = m.group(1).lower()
        index_reg = m.group(2).lower()
        scale = int(m.group(3))

        # 回溯搜索 guard: cmp index_reg, max_val; ja default
        max_val = 0
        default_target = -1
        for instr in reversed(block.instructions):
            cm = _CMP_GUARD_RX.search(instr)
            if cm and cm.group(1).lower() == index_reg:
                try: max_val = int(cm.group(2), 0)
                except ValueError: pass
                # 找紧随其后的 ja/jae/jnb 目标
                for later_instr in block.instructions[block.instructions.index(instr):]:
                    if "ja" in later_instr.lower() or "jnb" in later_instr.lower():
                        tgt_match = re.search(r"(0x[0-9a-fA-F]+)", later_instr)
                        if tgt_match:
                            try: default_target = int(tgt_match.group(1), 16)
                            except ValueError: pass
                        break
                break

        if max_val <= 0 or max_val > 256:
            continue

        # 从 base_reg 的使用位置推断跳转表基址
        # 启发式: 搜索 'lea base_reg, [addr]' 或 'mov base_reg, addr' 在间接跳转之前
        base_addr = 0
        for instr in block.instructions:
            lea_match = re.search(
                r"lea\s+" + base_reg + r",\s*\[(0x[0-9a-fA-F]+)\]", instr, re.IGNORECASE)
            if lea_match:
                try: base_addr = int(lea_match.group(1), 16)
                except ValueError: pass
                break

        if base_addr <= 0 or base_addr >= len(raw_bytes) - (max_val + 1) * scale:
            continue

        # 从 raw_bytes 中读取跳转表条目
        case_targets = []
        for i in range(max_val + 1):
            ptr_off = base_addr + i * scale
            if ptr_off + 4 > len(raw_bytes):
                break
            # 假设是 32-bit 相对偏移或绝对地址
            tgt = struct.unpack_from("<I", raw_bytes, ptr_off)[0]
            if 0x1000 <= tgt < len(raw_bytes):
                case_targets.append(tgt)

        if len(case_targets) >= 3:
            # 将每个 case 目标标记为独立的基本块
            for tgt in case_targets:
                existing_id = max(cfg.blocks.keys()) + 1 if cfg.blocks else 0
                cfg.blocks[existing_id] = BasicBlock(
                    block_id=existing_id, start_addr=tgt, end_addr=tgt + 4,
                    predecessors=[block_id],
                    successors=[default_target] if default_target > 0 else [])
                if block_id in cfg.blocks:
                    cfg.blocks[block_id].successors.extend([existing_id])
            recovered += 1

    return recovered


def _compute_dominators_raw(cfg):
    all_ids = set(cfg.blocks.keys()); entry = cfg.entry_block
    dom = {entry: {entry}}
    for bid in all_ids:
        if bid != entry: dom[bid] = set(all_ids)
    changed = True
    while changed:
        changed = False
        for bid in all_ids:
            if bid == entry: continue
            preds = cfg.blocks[bid].predecessors if bid in cfg.blocks else []
            new_dom = set(all_ids) if preds else set()
            for p in preds:
                if p in dom: new_dom &= dom[p]
            new_dom.add(bid)
            if new_dom != dom.get(bid, set()): dom[bid] = new_dom; changed = True
    return dom


class FunctionDeobfuscator:
    """
    函数级去混淆器

    能力:
    1. 死代码消除
    2. 控制流平坦化恢复
    3. 常量传播折叠
    4. 不透明谓词消除
    5. 去混淆效果评估
    """

    def __init__(self, binary_path=None, deobfuscation_level=DeobfuscationLevel.MEDIUM):
        self.binary_path = binary_path; self.deobfuscation_level = deobfuscation_level
        self.cfg = None; self.constants: Dict[str, ConstantValue] = {}
        self.dead_blocks: Set[int] = set(); self.opaque_predicates: Set[int] = set()
        self.state_variables: Set[str] = set(); self.loop_headers: Set[int] = set()
        self.raw_bytes: bytes = b""
        self.ollvm_patterns = {
            'dispatcher': [b'\x8b\x44\x24\x04', b'\x83\xc0\x01'],
            'state_var_init': [b'\xc7\x45\xfc\x00\x00\x00\x00']}

    def load_cfg(self, cfg_data):
        cfg = ControlFlowGraph(function_name=cfg_data.get('function_name', 'unknown'),
            entry_block=cfg_data.get('entry_block', 0))
        for block_id, block_data in cfg_data.get('blocks', {}).items():
            cfg.blocks[int(block_id)] = BasicBlock(
                block_id=int(block_id),
                start_addr=block_data.get('start_addr', 0),
                end_addr=block_data.get('end_addr', 0),
                instructions=block_data.get('instructions', []),
                predecessors=block_data.get('predecessors', []),
                successors=block_data.get('successors', []),
                is_junk=block_data.get('is_junk', False),
                original_pcode=block_data.get('pcode', ''))
        cfg.edges = cfg_data.get('edges', [])
        cfg.complexity = self._calc_complexity(cfg)
        if self.binary_path:
            try:
                with open(self.binary_path, "rb") as fh: self.raw_bytes = fh.read()
            except OSError: pass
        self.cfg = cfg; return cfg

    def _calc_complexity(self, cfg):
        if not cfg.blocks: return 0
        edges = sum(len(b.successors) for b in cfg.blocks.values())
        return edges - len(cfg.blocks) + 2 if len(cfg.blocks) > 1 else 1

    def recover_jump_tables(self) -> int:
        """Switch-case 跳转表恢复 - 在去混淆() 中死代码消除之前调用
        成功恢复后，CFG 中会新增 case 目标块，后续的死代码消除和
        常量传播可以处理这些新块
        """
        if not self.cfg or not self.raw_bytes: return 0
        return _recover_jump_tables(self.cfg, self.raw_bytes)

    def detect_control_flow_pattern(self):
        if not self.cfg: return ControlFlowPattern.NORMAL
        if self._detect_flattening_dispatcher(): return ControlFlowPattern.FLATTENED
        if self._detect_opaque_pattern(): return ControlFlowPattern.OPAQUE
        if self._detect_split_blocks(): return ControlFlowPattern.SPLIT
        if self._is_irreducible(): return ControlFlowPattern.IRREDUCIBLE
        if len(self.dead_blocks) > len(self.cfg.blocks) * 0.3: return ControlFlowPattern.JUNK
        return ControlFlowPattern.NORMAL

    def _detect_flattening_dispatcher(self):
        if not self.cfg: return False
        entry_blocks = [b for b in self.cfg.blocks.values() if len(b.predecessors) == 1]
        if len(entry_blocks) > len(self.cfg.blocks) * 0.8:
            cj = sum(1 for b in self.cfg.blocks.values() for _ in b.successors if len(b.successors) > 1)
            if cj < len(self.cfg.blocks) * 0.2: return True
        indeg = Counter()
        for b in self.cfg.blocks.values():
            for s in b.successors: indeg[s] += 1
        if len(self.cfg.blocks) > 5:
            avg = sum(indeg.values()) / max(len(indeg), 1)
            if any(v > avg * 3 and v > 5 for v in indeg.values()): return True
        return False

    def _detect_opaque_pattern(self):
        if not self.cfg or len(self.cfg.blocks) < 4: return False
        short = sum(1 for b in self.cfg.blocks.values() if len(b.instructions) <= 3 and len(b.successors) == 2)
        return short >= len(self.cfg.blocks) * 0.25

    def _detect_split_blocks(self):
        if not self.cfg: return False
        return sum(1 for b in self.cfg.blocks.values() if len(b.instructions) <= 2) > len(self.cfg.blocks) * 0.3

    def _is_irreducible(self):
        if not self.cfg or len(self.cfg.blocks) < 3: return False
        dom = _compute_dominators_raw(self.cfg)
        for bid, block in self.cfg.blocks.items():
            for succ in block.successors:
                if succ in dom and bid in dom[succ]: continue
                if succ in dom.get(bid, set()): continue
                return True
        return False

    def _compute_idom(self):
        if not self.cfg: return {}
        all_ids = set(self.cfg.blocks.keys()); entry = self.cfg.entry_block
        idom: Dict[int, int] = {entry: entry}
        for bid in all_ids:
            if bid != entry: idom[bid] = -1
        changed = True
        while changed:
            changed = False
            for bid in all_ids:
                if bid == entry: continue
                preds = self.cfg.blocks[bid].predecessors if bid in self.cfg.blocks else []
                new_idom = -1
                for p in preds:
                    if p in idom and idom[p] != -1: new_idom = p; break
                if new_idom != -1:
                    for p in preds:
                        if p != new_idom and p in idom and idom[p] != -1:
                            a, b = new_idom, p
                            while a != b and a != entry and b != entry:
                                while a < b: a = idom.get(a, entry)
                                while b < a: b = idom.get(b, entry)
                            new_idom = a if a == b else entry
                if new_idom != idom[bid]: idom[bid] = new_idom; changed = True
        return idom

    def _detect_loops(self):
        if not self.cfg or len(self.cfg.blocks) < 2: return 0
        dom = _compute_dominators_raw(self.cfg); idom = self._compute_idom()
        self.cfg.idom = idom; loop_count = 0
        for bid, block in self.cfg.blocks.items():
            for succ in block.successors:
                if succ in dom and bid in dom.get(succ, set()):
                    self.loop_headers.add(succ)
                    if succ in self.cfg.blocks: self.cfg.blocks[succ].is_loop_header = True
                    loop_count += 1
        return loop_count

    def eliminate_dead_code(self):
        if not self.cfg: return 0
        reachable = self._find_reachable_blocks(); dead_count = 0
        for bid in list(self.cfg.blocks.keys()):
            if bid not in reachable: self.dead_blocks.add(bid); dead_count += 1
        for bid in self.dead_blocks:
            if bid in self.cfg.blocks: del self.cfg.blocks[bid]
        self.cfg.edges = [(s, d) for s, d in self.cfg.edges if s in reachable and d in reachable]
        if self.deobfuscation_level == DeobfuscationLevel.AGGRESSIVE:
            dead_count += self._liveness_eliminate()
        return dead_count

    def _liveness_eliminate(self):
        if not self.cfg: return 0
        removed = 0; liveness: Dict[int, _LivenessInfo] = {}
        for bid, block in self.cfg.blocks.items():
            info = _LivenessInfo()
            for instr in block.instructions:
                d, u = _extract_defs_uses(instr); info.defs |= d; info.uses |= u
            liveness[bid] = info
        changed = True; max_r = len(self.cfg.blocks) + 1; rn = 0
        while changed and rn < max_r:
            changed = False; rn += 1
            for bid, info in liveness.items():
                if bid not in self.cfg.blocks: continue
                block = self.cfg.blocks[bid]; new_out: Set[str] = set()
                for succ in block.successors:
                    if succ in liveness: new_out |= liveness[succ].live_in
                if new_out != info.live_out: info.live_out = new_out; changed = True
                new_in = info.uses | (info.live_out - info.defs)
                if new_in != info.live_in: info.live_in = new_in; changed = True
        for bid, block in self.cfg.blocks.items():
            info = liveness.get(bid)
            if info is None: continue
            keep = []
            for instr in block.instructions:
                d, _ = _extract_defs_uses(instr)
                if d and not (d & info.live_out) and "call" not in instr.lower():
                    removed += 1; continue
                keep.append(instr)
            block.instructions = keep
        return removed

    def _find_reachable_blocks(self):
        if not self.cfg: return set()
        reachable = {self.cfg.entry_block}; stack = [self.cfg.entry_block]
        while stack:
            cur = stack.pop()
            if cur in self.cfg.blocks:
                for succ in self.cfg.blocks[cur].successors:
                    if succ not in reachable: reachable.add(succ); stack.append(succ)
        return reachable

    def peephole_simplify(self):
        if not self.cfg: return 0
        removed = 0
        for block in self.cfg.blocks.values():
            ni, r = _apply_peephole(block.instructions)
            block.instructions = ni; removed += r
        return removed

    def constant_propagation(self):
        if not self.cfg: return 0
        changes = 0
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if 'mov' in instr.lower() and '=' in instr:
                    parts = instr.replace('=', '=').split('=')
                    if len(parts) == 2:
                        lhs, rhs = parts[0].strip(), parts[1].strip()
                        cv = self._extract_constant(rhs)
                        if cv is not None: self.constants[lhs] = ConstantValue(cv); changes += 1
        return changes

    def _extract_constant(self, expr):
        expr = expr.strip()
        if expr.startswith('0x') or expr.startswith('0X'):
            try: return int(expr, 16)
            except ValueError: pass
        try: return int(expr)
        except ValueError: pass
        return None

    def constant_folding(self):
        if not self.cfg: return 0
        folded = 0
        for block in self.cfg.blocks.values():
            for i, instr in enumerate(block.instructions):
                if any(op in instr for op in ['+', '-', '*', '/']):
                    fi = self._fold_expression(instr)
                    if fi != instr: block.instructions[i] = fi; folded += 1
        return folded

    def _fold_expression(self, instr):
        for old, new in [('1 + 1', '2'), ('0 + ', ''), ('* 1', ''), ('/ 1', ''), ('& 0xff', '')]:
            instr = instr.replace(old, new)
        return instr

    def eliminate_opaque_predicates(self):
        if not self.cfg: return 0
        removed = 0
        for block in self.cfg.blocks.values():
            if len(block.successors) > 1 and self._is_opaque_predicate(block):
                if len(block.successors) >= 2: block.successors = [block.successors[0]]; removed += 1
        return removed

    def _is_opaque_predicate(self, block):
        if len(block.instructions) <= 3:
            for instr in block.instructions:
                if 'cmp' in instr.lower() or 'test' in instr.lower(): return True
        text = " ".join(block.instructions).lower()
        if re.search(r"xor\s+(\w+),\s*\1", text) and re.search(r"jz|je|jnz|jne", text): return True
        if re.search(r"cmp\s+(\w+),\s*\1", text): return True
        if re.search(r"test\s+(\w+),\s*\1", text) and len(block.instructions) <= 2: return True
        return False

    def deflatten_control_flow(self):
        if not self.cfg or self.deobfuscation_level == DeobfuscationLevel.LIGHT: return False
        if self.detect_control_flow_pattern() != ControlFlowPattern.FLATTENED: return False
        self._identify_state_variables(); self._rebuild_block_order(); self._restore_conditional_jumps()
        return True

    def _identify_state_variables(self):
        if not self.cfg: return
        vu = defaultdict(int)
        for b in self.cfg.blocks.values():
            for instr in b.instructions:
                for reg in ['eax','ebx','ecx','edx','ebp','esp','r12','r13','r14','r15']:
                    if reg in instr.lower(): vu[reg] += 1
        for var, cnt in vu.items():
            if cnt > len(self.cfg.blocks) * 0.5: self.state_variables.add(var)
        for b in self.cfg.blocks.values():
            for instr in b.instructions:
                m = re.search(r"cmp\s+(\w+),\s*(0x[0-9a-f]+|\d+)", instr, re.IGNORECASE)
                if m: self.state_variables.add(m.group(1).lower())

    def _rebuild_block_order(self):
        if not self.cfg: return
        sb = sorted(self.cfg.blocks.values(), key=lambda b: b.start_addr)
        nid = {b.block_id: i for i, b in enumerate(sb)}
        for b in self.cfg.blocks.values():
            b.predecessors = [nid.get(p, p) for p in b.predecessors]
            b.successors = [nid.get(s, s) for s in b.successors]

    def _restore_conditional_jumps(self):
        if not self.cfg: return
        for b in self.cfg.blocks.values():
            if b.instructions and 'jmp' in b.instructions[-1].lower():
                if len(b.successors) == 1: pass

    def deobfuscate(self, cfg_data=None):
        start_time = time.time(); result = DeobfuscationResult(success=False)
        try:
            if cfg_data: self.cfg = self.load_cfg(cfg_data)
            if not self.cfg: result.warnings.append("No CFG data"); return result
            result.original_cfg = self._copy_cfg(self.cfg)
            om = DeobfuscationMetrics(original_block_count=len(self.cfg.blocks),
                original_edge_count=len(self.cfg.edges), original_complexity=self.cfg.complexity)

            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                lc = self._detect_loops()
                if lc > 0: om.loops_detected = lc

            pattern = self.detect_control_flow_pattern()
            logger.info(f"Detected: {pattern.value}")
            modifications = []

# 跳转表恢复（aggressive 模式）
            if self.deobfuscation_level == DeobfuscationLevel.AGGRESSIVE:
                jtr = self.recover_jump_tables()
                if jtr > 0:
                    modifications.append(f"Jump tables recovered: {jtr}")
                    om.jump_tables_recovered = jtr

            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                pr = self.peephole_simplify()
                if pr > 0: modifications.append(f"Peephole: {pr} redundant instructions")

            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                dc = self.eliminate_dead_code()
                if dc > 0: modifications.append(f"Dead code: {dc} blocks"); om.dead_code_removed = dc

            cc = self.constant_propagation()
            if cc > 0: modifications.append(f"Const prop: {cc} sites")
            fc = self.constant_folding()
            if fc > 0: modifications.append(f"Const fold: {fc} sites")

            if self.deobfuscation_level == DeobfuscationLevel.AGGRESSIVE:
                oc = self.eliminate_opaque_predicates()
                if oc > 0: modifications.append(f"Opaque preds: {oc}"); om.opaque_predicates_removed = oc

            if self.deobfuscation_level != DeobfuscationLevel.LIGHT:
                if self.deflatten_control_flow():
                    modifications.append("CFG de-flattened"); om.control_flow_restructured = True

            result.deobfuscated_cfg = self._copy_cfg(self.cfg)
            result.deobfuscated_pseudocode = self._generate_pseudocode(self.cfg)
            if result.original_cfg: result.original_pseudocode = self._generate_pseudocode(result.original_cfg)

            dm = DeobfuscationMetrics(deobfuscated_block_count=len(self.cfg.blocks),
                deobfuscated_edge_count=len(self.cfg.edges),
                deobfuscated_complexity=self._calc_complexity(self.cfg),
                loops_detected=om.loops_detected, jump_tables_recovered=om.jump_tables_recovered)

            if om.original_block_count > 0:
                dm.block_reduction_ratio = (om.original_block_count - dm.deobfuscated_block_count) / om.original_block_count
            if om.original_edge_count > 0:
                dm.edge_reduction_ratio = (om.original_edge_count - dm.deobfuscated_edge_count) / om.original_edge_count
            if om.original_complexity > 0:
                dm.complexity_reduction_ratio = (om.original_complexity - dm.deobfuscated_complexity) / om.original_complexity

            result.metrics = {
                'original': {'block_count': om.original_block_count, 'edge_count': om.original_edge_count,
                             'complexity': om.original_complexity},
                'deobfuscated': {'block_count': dm.deobfuscated_block_count, 'edge_count': dm.deobfuscated_edge_count,
                                 'complexity': dm.deobfuscated_complexity},
                'reductions': {'block_reduction': f"{dm.block_reduction_ratio*100:.1f}%",
                               'edge_reduction': f"{dm.edge_reduction_ratio*100:.1f}%",
                               'complexity_reduction': f"{dm.complexity_reduction_ratio*100:.1f}%"},
                'control_flow_pattern': pattern.value, 'deobfuscation_level': self.deobfuscation_level.value,
                'loops_detected': om.loops_detected, 'jump_tables_recovered': om.jump_tables_recovered}
            result.modifications = modifications; result.success = True
            result.analysis_time = time.time() - start_time
        except Exception as e:
            logger.error(f"Deobfuscation failed: {e}"); result.warnings.append(f"Error: {e}")
        return result

    def _copy_cfg(self, cfg):
        nc = ControlFlowGraph(function_name=cfg.function_name, entry_block=cfg.entry_block,
            complexity=cfg.complexity, idom=dict(cfg.idom))
        for bid, block in cfg.blocks.items():
            nc.blocks[bid] = BasicBlock(block_id=block.block_id, start_addr=block.start_addr,
                end_addr=block.end_addr, instructions=block.instructions.copy(),
                predecessors=block.predecessors.copy(), successors=block.successors.copy(),
                is_junk=block.is_junk, original_pcode=block.original_pcode,
                is_loop_header=block.is_loop_header)
        nc.edges = cfg.edges.copy()
        return nc

    def _generate_pseudocode(self, cfg):
        lines = [f"// Function: {cfg.function_name}", f"// Complexity: {cfg.complexity}", ""]
        if not cfg.blocks: return "\n".join(lines)
        visited = set(); stack = [cfg.entry_block]
        while stack:
            bid = stack.pop()
            if bid in visited: continue
            visited.add(bid)
            if bid in cfg.blocks:
                b = cfg.blocks[bid]
                hm = " [loop_header]" if b.is_loop_header else ""
                lines.append(f"block_{bid}:{hm}")
                lines.append(f"    // {hex(b.start_addr)} - {hex(b.end_addr)}")
                for instr in b.instructions: lines.append(f"    {instr}")
                if b.successors:
                    tgt = ", ".join(f"block_{s}" for s in b.successors)
                    lines.append(f"    goto {tgt};" if len(b.successors) == 1 else f"    // Branch to {tgt}")
                lines.append("")
                for succ in b.successors:
                    if succ not in visited: stack.append(succ)
        return "\n".join(lines)

    def compare_pseudocode(self, orig, deob):
        ol = orig.strip().split('\n'); dl = deob.strip().split('\n')
        oc = [l for l in ol if l.strip() and not l.strip().startswith('//')]
        dc = [l for l in dl if l.strip() and not l.strip().startswith('//')]
        return {'original_lines': len(ol), 'deobfuscated_lines': len(dl),
            'original_code_lines': len(oc), 'deobfuscated_code_lines': len(dc),
            'line_reduction': len(oc) - len(dc),
            'line_reduction_ratio': (len(oc) - len(dc)) / max(len(oc), 1) * 100}


def deobfuscate_function(binary_path, function_name, deobfuscation_level="medium", cfg_data=None):
    lm = {'light': DeobfuscationLevel.LIGHT, 'medium': DeobfuscationLevel.MEDIUM,
          'aggressive': DeobfuscationLevel.AGGRESSIVE}
    return FunctionDeobfuscator(binary_path, lm.get(deobfuscation_level.lower(), DeobfuscationLevel.MEDIUM)).deobfuscate(cfg_data)


def format_deobfuscation_report(result):
    if not result.success: return f"Deobfuscation failed: {', '.join(result.warnings)}"
    parts = ["# 去混淆分析报告", "",
        f"Function: {result.deobfuscated_cfg.function_name if result.deobfuscated_cfg else 'unknown'}",
        f"Level: {result.metrics.get('deobfuscation_level', 'unknown')}",
        f"Pattern: {result.metrics.get('control_flow_pattern', 'unknown')}",
        f"Analysis time: {result.analysis_time:.2f}s", "", "## Effectiveness Metrics"]
    m = result.metrics
    if 'original' in m and 'deobfuscated' in m:
        parts.extend([
            f"- Blocks: {m['original']['block_count']} -> {m['deobfuscated']['block_count']} ({m['reductions']['block_reduction']})",
            f"- Edges: {m['original']['edge_count']} -> {m['deobfuscated']['edge_count']} ({m['reductions']['edge_reduction']})",
            f"- Complexity: {m['original']['complexity']} -> {m['deobfuscated']['complexity']} ({m['reductions']['complexity_reduction']})"])
        if m.get('loops_detected', 0) > 0: parts.append(f"- Loops: {m['loops_detected']}")
        if m.get('jump_tables_recovered', 0) > 0: parts.append(f"- Jump tables: {m['jump_tables_recovered']}")
    if result.modifications:
        parts.extend(["", "## Optimizations"]); parts.extend(f"- {mod}" for mod in result.modifications)
    return "\n".join(parts)


def export_deobfuscation_json(result, output_path):
    try:
        ed = {'success': result.success, 'analysis_time': result.analysis_time,
            'metrics': result.metrics, 'modifications': result.modifications,
            'warnings': result.warnings, 'original_pseudocode': result.original_pseudocode,
            'deobfuscated_pseudocode': result.deobfuscated_pseudocode,
            'function_name': result.deobfuscated_cfg.function_name if result.deobfuscated_cfg else None}
        with open(output_path, 'w', encoding='utf-8') as f: json.dump(ed, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e: logger.error(f"JSON export failed: {e}"); return False
