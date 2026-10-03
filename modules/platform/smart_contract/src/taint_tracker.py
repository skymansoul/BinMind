# Taint tracking: 栈级数据流追踪, intra-block 符号模拟 + inter-block BFS

# 策略：不追求完备（solver 太慢），只追踪直接数据流
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from collections import deque
from .parser import EVMOp
from .opcodes import TAINT_SOURCES, TAINT_SINKS, PUSH_OPCODES, DUP_OPCODES, SWAP_OPCODES, OPCODES

STACK_LIMIT = 1024

# //// Data structures ////


@dataclass
class TaintSource:
    """数据污染的来源点。"""
    opcode: int
    offset: int  # pc
    call_index: int = 0
    mnemonic: str = ""

    def __hash__(self):
        return hash((self.opcode, self.offset, self.call_index))

@dataclass
class TaintFinding:
    """从 source 到 sink 的完整污点路径。"""
    source: TaintSource
    sink_mnemonic: str
    sink_offset: int
    path: List[int]  # offsets along the flow
    description: str = ""

@dataclass
class TaintState:
    """每个基本块的污点状态快照。"""
    stack_taint: Dict[int, TaintSource] = field(default_factory=dict)  # slot -> source
    memory_taint: Dict[int, TaintSource] = field(default_factory=dict)  # addr -> source
    storage_taint: Dict[int, TaintSource] = field(default_factory=dict)  # slot -> source

    def copy(self) -> "TaintState":
        return TaintState(
            stack_taint=dict(self.stack_taint),
            memory_taint=dict(self.memory_taint),
            storage_taint=dict(self.storage_taint),
        )



class TaintTracker:
    """栈级污点追踪器。模拟 EVM 栈的 push/pop/dup/swap，
    标记 TAINT_SOURCES 引入的数据并追踪其流向 TAINT_SINKS 的路径。

    不执行实际计算, 只追踪标签传播。
    """

    def __init__(self):
        self._findings: List[TaintFinding] = []
        self._stack: List[Optional[TaintSource]] = []  # simulated stack of taint labels
        self._memory: Dict[int, TaintSource] = {}
        self._storage: Dict[int, TaintSource] = {}
        self._pc_to_op: Dict[int, EVMOp] = {}

    # Intra-block tracking

    def track_block(self, ops: List[EVMOp],
                    initial: Optional[TaintState] = None) -> TaintState:
        """单基本块内污点追踪。模拟栈操作传播 taint 标签。"""
        self._stack = []
        self._memory = {}
        self._storage = {}
        if initial:
            for _k, _v in initial.stack_taint.items():
                # Ensure stack sized enough; init from bottom
                while len(self._stack) <= _k:
                    self._stack.append(None)
                self._stack[_k] = _v
            self._memory = dict(initial.memory_taint)
            self._storage = dict(initial.storage_taint)

        _op_count = 0
        for _op in ops:
            _op_count += 1
            self._pc_to_op[_op.pc] = _op
            _fn = self._DISPATCH.get(_op.opcode, self._handle_generic)
            _fn(_op)

        return TaintState(
            stack_taint={i: s for i, s in enumerate(self._stack) if s is not None},
            memory_taint=dict(self._memory),
            storage_taint=dict(self._storage),
        )

# 指令分发表

    def _dispatch(self, op: EVMOp):
        return self._DISPATCH.get(op.opcode, self._handle_generic)(op)

# Push-style: 标记 taint source
    def _handle_taint_source(self, op: EVMOp):
        """将操作码输出标记为污点来源。"""
        _src = TaintSource(opcode=op.opcode, offset=op.pc, mnemonic=op.name)
        _pop_count, _push_count = self._get_stack_effect(op)
        self._pop_stack(_pop_count)
        for _ in range(_push_count):
            self._stack.append(_src)

# Arithmetic/bitwise: taint 从输入传播到输出
    def _handle_propagate(self, op: EVMOp):
        _pop_count, _push_count = self._get_stack_effect(op)
        # 收集输入的 taint
        _taints = []
        for _ in range(min(_pop_count, len(self._stack))):
            _t = self._stack.pop() if self._stack else None
            _taints.append(_t)
        _taints.reverse()
        # 合并：任意一个输入有 taint -> 输出有 taint (取第一个非 None)
        _result = None
        for _t in _taints:
            if _t is not None:
                _result = _t
                break
        for _ in range(_push_count):
            self._stack.append(_result)

# DUP: 复制 taint
    def _handle_dup(self, op: EVMOp):
        _n = op.opcode - 0x7f  # DUPn duplicates n-th item (1-indexed from top)
        if len(self._stack) >= _n:
            _t = self._stack[-_n]
            self._stack.append(_t)
        else:
            self._stack.append(None)

# SWAP: 交换 taint
    def _handle_swap(self, op: EVMOp):
        _n = op.opcode - 0x8f  # SWAPn swaps top with (n+1)-th
        if len(self._stack) >= _n + 1:
            self._stack[-1], self._stack[-(_n + 1)] = \
                self._stack[-(_n + 1)], self._stack[-1]

# Memory ops: taint memory
    def _handle_mstore(self, op: EVMOp):
        # MSTORE: offset, value -> (no output)
        if len(self._stack) >= 2:
            _val = self._stack.pop()
            _off_t = self._stack.pop()  # offset taint (usually not tracked)
            # We don't know concrete offset; use symbolic marker
            _idx = len(self._memory)
            if _val is not None:
                self._memory[_idx] = _val
                # Also mark the source flag was stored to memory
            # stack effect handled

    def _handle_mload(self, op: EVMOp):
        # MLOAD: offset -> value
        if self._stack:
            _off_t = self._stack.pop()
            # Conservative: if ANY memory is tainted, output is tainted
            _t = None
            for _v in self._memory.values():
                if _v is not None:
                    _t = _v
                    break
            self._stack.append(_t)

# Storage ops
    def _handle_sload(self, op: EVMOp):
        if self._stack:
            _slot_t = self._stack.pop()
            _t = None
            for _v in self._storage.values():
                if _v is not None:
                    _t = _v
                    break
            self._stack.append(_t)

    def _handle_sstore(self, op: EVMOp):
        # SSTORE: slot, value -> (check if value tainted -> finding)
        if len(self._stack) >= 2:
            _val = self._stack.pop()
            _slot_t = self._stack.pop()
            if _val is not None:
                _idx = len(self._storage)
                self._storage[_idx] = _val
                # Tainted data reaching SSTORE is a finding
                self._findings.append(TaintFinding(
                    source=_val,
                    sink_mnemonic="SSTORE",
                    sink_offset=op.pc,
                    path=[_val.offset, op.pc],
                    description="Tainted data written to storage slot (SSTORE sink)",
                ))

# CALL family: potential sinks
    def _handle_call_sink(self, op: EVMOp):
        """CALL/CALLCODE/DELEGATECALL/STATICCALL 的各项参数中
        若包含污点数据，标记为 finding。"""
        _pop_count, _push_count = self._get_stack_effect(op)
        # CALL args: gas, addr, value, args_offset, args_len, ret_offset, ret_len
        # Taint in addr or args is dangerous
        _args = []
        for _ in range(min(_pop_count, len(self._stack))):
            _args.insert(0, self._stack.pop())
        # addr is the second-to-last popped (depends on call type)
        _addr_idx = _pop_count - 3  # approximate: addr is near top
        if 0 <= _addr_idx < len(_args) and _args[_addr_idx] is not None:
            self._findings.append(TaintFinding(
                source=_args[_addr_idx],
                sink_mnemonic=op.name,
                sink_offset=op.pc,
                path=[_args[_addr_idx].offset, op.pc],
                description=f"Tainted target address flows into {op.name}",
            ))
        # Push return value with merged taint
        _ret_taint = None
        for _a in _args:
            if _a is not None:
                _ret_taint = _a
                break
        for _ in range(_push_count):
            self._stack.append(_ret_taint)

# CREATE family
    def _handle_create_sink(self, op: EVMOp):
        _pop_count, _push_count = self._get_stack_effect(op)
        _args = []
        for _ in range(min(_pop_count, len(self._stack))):
            _args.insert(0, self._stack.pop())
        # init code is tainted -> finding
        _code_taint = None
        for _a in _args:
            if _a is not None:
                _code_taint = _a
                break
        if _code_taint is not None:
            self._findings.append(TaintFinding(
                source=_code_taint,
                sink_mnemonic=op.name,
                sink_offset=op.pc,
                path=[_code_taint.offset, op.pc],
                description=f"Tainted init code flows into {op.name}",
            ))
        _ret_taint = _code_taint
        for _ in range(_push_count):
            self._stack.append(_ret_taint)

# SELFDESTRUCT sink
    def _handle_selfdestruct_sink(self, op: EVMOp):
        if self._stack:
            _addr = self._stack.pop()
            if _addr is not None:
                self._findings.append(TaintFinding(
                    source=_addr,
                    sink_mnemonic="SELFDESTRUCT",
                    sink_offset=op.pc,
                    path=[_addr.offset, op.pc],
                    description="Tainted beneficiary address in SELFDESTRUCT",
                ))

# JUMP/JUMPI
    def _handle_jump(self, op: EVMOp):
        if self._stack:
            _target = self._stack.pop()
            if _target is not None:
                self._findings.append(TaintFinding(
                    source=_target,
                    sink_mnemonic=op.name,
                    sink_offset=op.pc,
                    path=[_target.offset, op.pc],
                    description=f"Tainted jump destination in {op.name}",
                ))

    def _handle_jumpi(self, op: EVMOp):
        if len(self._stack) >= 2:
            _target = self._stack.pop()
            _cond = self._stack.pop()
            if _target is not None:
                self._findings.append(TaintFinding(
                    source=_target,
                    sink_mnemonic="JUMPI",
                    sink_offset=op.pc,
                    path=[_target.offset, op.pc],
                    description="Tainted conditional jump destination",
                ))

# RETURN/REVERT
    def _handle_return(self, op: EVMOp):
        if len(self._stack) >= 2:
            _len = self._stack.pop()
            _off = self._stack.pop()
            if _off is not None:
                self._findings.append(TaintFinding(
                    source=_off,
                    sink_mnemonic=op.name,
                    sink_offset=op.pc,
                    path=[_off.offset, op.pc],
                    description=f"Tainted data returned via {op.name}",
                ))

# Generic / no-taint-propagate
    def _handle_generic(self, op: EVMOp):
        _pop_count, _push_count = self._get_stack_effect(op)
        self._pop_stack(_pop_count)
        for _ in range(_push_count):
            self._stack.append(None)

# POP: no taint propagation
    def _handle_pop(self, op: EVMOp):
        self._pop_stack(1)

# Helpers

    def _get_stack_effect(self, op: EVMOp) -> Tuple[int, int]:
        """从 OPCODES 表获取栈输入/输出数。"""
        _entry = OPCODES.get(op.opcode)
        if _entry:
            return _entry[1], _entry[2]
        return 0, 1  # conservative default

    def _pop_stack(self, n: int):
        for _ in range(min(n, len(self._stack))):
            self._stack.pop()

    # Inter-block flow

    def flow_across_blocks(self, blocks: Dict[int, List[EVMOp]],
                           edges: Dict[int, List[int]],
                           entry_offset: int = 0) -> List[TaintFinding]:
        """BFS 跨基本块传播 taint state。每个块从一个或多个前驱继承 taint，
        在当前块内追踪，将结果传递给后继。
        """
        _all_findings = []
        _visited: Set[int] = set()
        _block_states: Dict[int, TaintState] = {}
        _q = deque([entry_offset])
        _initial = TaintState()
        _block_states[entry_offset] = _initial

        while _q:
            _b_offset = _q.popleft()
            if _b_offset in _visited:
                continue
            _visited.add(_b_offset)
            _ops = blocks.get(_b_offset, [])
            if not _ops:
                continue
            _input_state = _block_states.get(_b_offset, TaintState())
            # Run intra-block
            _findings_before = len(self._findings)
            _out_state = self.track_block(_ops, _input_state)
            _new = self._findings[_findings_before:]
            _all_findings.extend(_new)

            # Propagate to successors
            _succs = edges.get(_b_offset, [])
            for _s in _succs:
                if _s not in _visited:
                    _q.append(_s)
                # Merge taint from all predecessors
                _existing = _block_states.get(_s)
                if _existing is not None:
                    _merged = self._merge_states(_existing, _out_state)
                    _block_states[_s] = _merged
                else:
                    _block_states[_s] = _out_state.copy()
        return _all_findings

    def _merge_states(self, a: TaintState, b: TaintState) -> TaintState:
        """在交汇点合并两个前驱块的污点状态。
        取并集, 保守策略（任一前驱有 taint 则认为有 taint）。
        """
        _merged = a.copy()
        for _k, _v in b.stack_taint.items():
            if _k in _merged.stack_taint:
                # Keep existing; prefer more specific (earliest) source
                pass
            else:
                _merged.stack_taint[_k] = _v
        for _k, _v in b.memory_taint.items():
            if _k not in _merged.memory_taint:
                _merged.memory_taint[_k] = _v
        for _k, _v in b.storage_taint.items():
            if _k not in _merged.storage_taint:
                _merged.storage_taint[_k] = _v
        return _merged

    # Full analysis entry

    def detect_taint_flow(self, ops: List[EVMOp],
                          blocks: Dict[int, List[EVMOp]] = None,
                          edges: Dict[int, List[int]] = None) -> List[TaintFinding]:
        """完整的污点分析入口。若无 CFG 则退化为单个大 block 分析。"""
        self._findings = []
        if blocks and edges:
            return self.flow_across_blocks(blocks, edges, 0)
        else:
            self.track_block(ops)
            return list(self._findings)

# 指令分发表

    _DISPATCH = {}  # built below

# Build dispatch table
_t = TaintTracker.__new__(TaintTracker)

for _opcode, _info in OPCODES.items():
    _mnemonic = _info[0]
    if _opcode in TAINT_SOURCES:
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_taint_source
    elif _opcode in TAINT_SINKS:
        if _mnemonic in ("CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"):
            TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_call_sink
        elif _mnemonic in ("CREATE", "CREATE2"):
            TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_create_sink
        elif _mnemonic == "SELFDESTRUCT":
            TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_selfdestruct_sink
        elif _mnemonic == "SSTORE":
            TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_sstore
        else:
            TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_propagate
    elif _opcode in DUP_OPCODES:
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_dup
    elif _opcode in SWAP_OPCODES:
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_swap
    elif _mnemonic in ("MLOAD",):
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_mload
    elif _mnemonic in ("MSTORE", "MSTORE8"):
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_mstore
    elif _mnemonic == "SLOAD":
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_sload
    elif _mnemonic == "JUMP":
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_jump
    elif _mnemonic == "JUMPI":
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_jumpi
    elif _mnemonic in ("RETURN", "REVERT"):
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_return
    elif _mnemonic == "POP":
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_pop
    elif _mnemonic in ("ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", "ADDMOD",
                       "MULMOD", "EXP", "SIGNEXTEND", "LT", "GT", "SLT", "SGT",
                       "EQ", "ISZERO", "AND", "OR", "XOR", "NOT", "BYTE",
                       "SHL", "SHR", "SAR", "KECCAK256", "ADDRESS", "BALANCE",
                       "ORIGIN", "CALLER", "CALLVALUE", "CALLDATALOAD", "CALLDATASIZE",
                       "CODESIZE", "GASPRICE", "EXTCODESIZE", "RETURNDATASIZE",
                       "EXTCODEHASH", "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER",
                       "PREVRANDAO", "GASLIMIT", "CHAINID", "SELFBALANCE", "BASEFEE",
                       "BLOBHASH", "BLOBBASEFEE", "MSIZE", "GAS", "TLOAD", "TSTORE"):
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_propagate
    else:
        TaintTracker._DISPATCH[_opcode] = TaintTracker._handle_generic
