# 2026-07-19
# Vulnerability pattern matching engine — 序列匹配 + 上下文评分
# 设计取舍：不用 regex（字节码不是文本），不用 AST（无源码时不可用）。
# 采用滑动窗口 + 贪婪跳跃匹配，允许指令间隔——单一漏洞模式在字节码中
# 往往被编译器插入的栈操作（SWAP/DUP/POP）打断。
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Set
from .parser import EVMOp

# ----
@dataclass
class OpcodePattern:
    """漏洞指纹：一序列操作码 + 语义描述。sequence 是 mnemonic 列表。"""
    name: str
    sequence: List[str]          # opcode mnemonics in order
    description: str
    severity: str                # CRITICAL/HIGH/MEDIUM/LOW/INFO
    swc_id: str = ""
    tags: List[str] = field(default_factory=list)

# ----
@dataclass
class PatternMatch:
    pattern: OpcodePattern
    offset_range: Tuple[int, int]  # (start_pc, end_pc)
    confidence: float              # 0-1
    matched_instructions: List[EVMOp] = field(default_factory=list)

# ===========================================================================
# 20+ known vulnerability patterns
# ===========================================================================

KNOWN_PATTERNS: List[OpcodePattern] = []

def _register(name, seq, desc, sev, swc="", tags=None):
    KNOWN_PATTERNS.append(OpcodePattern(
        name=name, sequence=seq, description=desc,
        severity=sev, swc_id=swc, tags=tags or [],
    ))

# ////////////////////////////////
# 重入 & 调用安全问题
# ////////////////////////////////
_register("unprotected_selfdestruct",
    ["CALLER", "ADDRESS", "EQ", "ISZERO", "JUMPI", "SELFDESTRUCT"],
    "SELFDESTRUCT without owner verification via caller==address check",
    "CRITICAL", "SWC-106")
_register("delegatecall_to_user_input",
    ["CALLDATALOAD", "DELEGATECALL"],
    "User-controlled calldata flows into DELEGATECALL target",
    "CRITICAL", "SWC-112")
_register("tx_origin_auth",
    ["ORIGIN", "EQ", "JUMPI"],
    "tx.origin used for authentication — vulnerable to phishing",
    "HIGH", "SWC-115")
_register("unchecked_call_return",
    ["CALL", "POP"],
    "CALL return value popped without checking",
    "HIGH", "SWC-104")
_register("reentrancy_no_guard",
    ["CALL", "SSTORE"],
    "SSTORE after external CALL without reentrancy mutex",
    "CRITICAL", "SWC-107")

# ////////////////////////////////
# 算术 & 溢出
# ////////////////////////////////
_register("integer_overflow_add",
    ["ADD", "JUMPDEST"],
    "ADD without SafeMath/checked arithmetic guard",
    "HIGH", "SWC-101")
_register("integer_overflow_mul",
    ["MUL", "JUMPDEST"],
    "MUL without overflow check pattern",
    "HIGH", "SWC-101")
_register("division_by_zero_unchecked",
    ["DIV", "JUMPDEST"],
    "DIV without divisor non-zero check",
    "MEDIUM", "SWC-101")

# ////////////////////////////////
# 时间戳 & 随机性
# ////////////////////////////////
_register("timestamp_dependence",
    ["TIMESTAMP", "EQ", "JUMPI"],
    "block.timestamp used in critical conditional (MEV/DoS window)",
    "MEDIUM", "SWC-116")
_register("timestamp_dependence_gt",
    ["TIMESTAMP", "GT", "JUMPI"],
    "block.timestamp used in greater-than comparison",
    "MEDIUM", "SWC-116")
_register("weak_randomness_blockhash",
    ["NUMBER", "BLOCKHASH"],
    "blockhash keyed on block.number — predictable within 256 blocks",
    "MEDIUM", "SWC-120")
_register("weak_randomness_prevrandao",
    ["CALLDATALOAD", "PREVRANDAO"],
    "Using PREVRANDAO (prev difficulty/randao) directly as randomness",
    "MEDIUM", "SWC-120")

# ////////////////////////////////
# 存储 & 代理
# ////////////////////////////////
_register("uninitialized_storage",
    ["SLOAD", "ISZERO", "SSTORE"],
    "Storage slot read before initialization check absent",
    "LOW", "SWC-109")
_register("storage_collision_proxy",
    ["DELEGATECALL", "SSTORE"],
    "DELEGATECALL followed by SSTORE — potential proxy storage collision",
    "MEDIUM", "SWC-124")
_register("locked_ether_no_withdraw",
    ["CALLVALUE", "STOP"],
    "Contract receives ETH but has no withdrawal path",
    "HIGH", "SWC-105")
_register("front_running_gas",
    ["GASPRICE", "EQ", "JUMPI"],
    "Logic dependent on gas price — frontrunning vector",
    "LOW", "SWC-114")

# ////////////////////////////////
# 签名 & 权限
# ////////////////////////////////
_register("signature_replay_no_chainid",
    ["ECRECOVER", "EQ", "JUMPI"],
    "ECRECOVER used without CHAINID check — replay across chains",
    "HIGH", "SWC-121")
_register("hidden_owner",
    ["CALLER", "SSTORE"],
    "CALLER stored but no subsequent owner check enforcement",
    "LOW", "SWC-100")

# ////////////////////////////////
# DoS & Gas
# ////////////////////////////////
_register("dos_unbounded_loop",
    ["JUMPDEST", "CALL", "JUMP"],
    "External CALL inside unbounded loop pattern — gas DoS",
    "MEDIUM", "SWC-126")
_register("dos_external_send",
    ["JUMPDEST", "CALL", "POP"],
    "Low-level CALL in loop without gas limit — failed external contract blocks loop",
    "MEDIUM", "SWC-113")

# ////////////////////////////////
# 其他
# ////////////////////////////////
_register("short_address_attack",
    ["CALLDATALOAD", "CALL"],
    "Raw CALL with calldata-derived target — short address vulnerability",
    "HIGH", "SWC-136")
_register("arbitrary_call",
    ["CALLDATALOAD", "DELEGATECALL"],
    "DELEGATECALL with user-supplied calldata — arbitrary code execution",
    "CRITICAL", "SWC-112")
_register("forced_ether_selfdestruct",
    ["SELFDESTRUCT", "STOP"],
    "SELFDESTRUCT with no withdrawal mechanism for locked ETH",
    "MEDIUM", "SWC-106")

# ===========================================================================
# PatternMatcher — 核心匹配引擎
# ===========================================================================

class PatternMatcher:
    """操作码序列匹配器 —— 滑动窗口 + 贪婪跳跃 + 上下文评分。
    不在所有可能的 gap 组合上做 DP（指数爆炸），而是按顺序
    找下一个匹配位置，允许合理间隔（默认 <= 8 条跳过的指令）。
    """

    def __init__(self, max_gap: int = 8):
        self.max_gap = max_gap
        self._compiled: dict = {}  # cache pattern -> compiled internal

    def match(self, ops: List[EVMOp], pattern: OpcodePattern,
              min_confidence: float = 0.5) -> List[PatternMatch]:
        """在指令流中查找 pattern 的所有匹配位置。
        策略：每个 offset 尝试作为起点，按序搜索 sequence 中各 mnemonic，
        允许最多 max_gap 条跳过。找到完整匹配后记录，继续下一位置。
        """
        _m = []
        if not ops or not pattern.sequence:
            return _m
        _seq = pattern.sequence
        _n_ops = len(ops)
        _n_seq = len(_seq)

        i = 0
        while i < _n_ops:
            _matched = self._greedy_match_from(ops, i, _seq)
            if _matched is not None:
                _start = _matched[0].pc
                _end = _matched[-1].pc
                _conf = self._score_match(pattern, ops, i, _matched)
                if _conf >= min_confidence:
                    _m.append(PatternMatch(
                        pattern=pattern,
                        offset_range=(_start, _end),
                        confidence=_conf,
                        matched_instructions=_matched,
                    ))
                # 从匹配起点的下一位置继续（非贪婪——允许重叠匹配）
                i = _matched[0].pc + 1
                # remap i back to index
                for _j in range(len(ops)):
                    if ops[_j].pc >= i:
                        i = _j
                        break
                else:
                    break
            else:
                i += 1
        return _m

    def _greedy_match_from(self, ops: List[EVMOp], start_idx: int,
                           seq: List[str]) -> Optional[List[EVMOp]]:
        """从 start_idx 开始，贪婪寻找 seq 中的每个 mnemonic。
        允许跳过非匹配指令，但跳过的数量不能超过 max_gap 每步。
        返回匹配到的 ops 列表，或 None。
        """
        _matched = []
        _seq_pos = 0
        _op_idx = start_idx
        _ops_len = len(ops)

        while _seq_pos < len(seq) and _op_idx < _ops_len:
            _target = seq[_seq_pos]
            # 在 max_gap 范围内找下一个匹配
            _limit = min(_op_idx + self.max_gap + 1, _ops_len)
            _found = -1
            for _k in range(_op_idx, _limit):
                if ops[_k].name == _target:
                    _found = _k
                    break
            if _found < 0:
                return None
            _matched.append(ops[_found])
            _seq_pos += 1
            _op_idx = _found + 1
        if _seq_pos == len(seq):
            return _matched
        return None

    def match_all(self, ops: List[EVMOp]) -> List[PatternMatch]:
        """对所有已知 pattern 运行匹配。"""
        _all = []
        for _p in KNOWN_PATTERNS:
            _matches = self.match(ops, _p)
            _all.extend(_matches)
        return sorted(_all, key=lambda m: -m.confidence)

    def _score_match(self, pattern: OpcodePattern, ops: List[EVMOp],
                     start_idx: int, matched: List[EVMOp]) -> float:
        """基于 pattern 特异性 + 上下文评估置信度。
        因素：pattern 长度（越长越特异）、gap 大小（越小越好）、
        相邻危险操作（如附近有 CALLER 检查则降低风险评分）、
        JUMPDEST 隔离（pattern 跨越 JUMPDEST 时可能属于不同逻辑块）。
        """
        _conf = 0.60  # 基线分
        _seq_len = len(pattern.sequence)
        _gap_count = len(matched) - _seq_len
        # 长度权重：3-4 tokens +0.05, 5-6 +0.10, 7+ +0.15
        if _seq_len >= 7:
            _conf += 0.15
        elif _seq_len >= 5:
            _conf += 0.10
        elif _seq_len >= 3:
            _conf += 0.05
        # gap 惩罚：每个 gap token -0.03
        _conf -= _gap_count * 0.03
        # swc_id 不为空 +0.05
        if pattern.swc_id:
            _conf += 0.05
        # 跨越 JUMPDEST 惩罚：-0.08
        for _k in range(1, len(matched)):
            _prev_pc = matched[_k - 1].pc
            _curr_pc = matched[_k].pc
            # 检查中间的 ops 是否有 JUMPDEST
            for _mid_op in ops:
                if _prev_pc < _mid_op.pc < _curr_pc:
                    if _mid_op.name == "JUMPDEST":
                        _conf -= 0.08
                        break
        # 附近有 CALLER + EQ 检查 -> recover 一点 (说明有一些鉴权)
        _nearby_access = False
        _scan_start = max(0, start_idx - 10)
        _scan_end = min(len(ops), start_idx + len(matched) + 10)
        for _j in range(_scan_start, _scan_end - 1):
            if ops[_j].name == "CALLER" and _j + 1 < _scan_end:
                if ops[_j + 1].name in ("EQ", "SUB"):
                    _nearby_access = True
        if _nearby_access:
            _conf += 0.03
        return min(1.0, max(0.0, _conf))

    def search_by_tag(self, tag: str) -> List[OpcodePattern]:
        """按 tag 检索已知模式。"""
        return [_p for _p in KNOWN_PATTERNS if tag in _p.tags]

    def get_pattern_names(self) -> List[str]:
        return [_p.name for _p in KNOWN_PATTERNS]

# ----
def patterns_by_severity(severity: str) -> List[OpcodePattern]:
    """过滤指定 severity 级别的所有 pattern。"""
    return [_p for _p in KNOWN_PATTERNS if _p.severity == severity]

# ----
def swc_index() -> dict:
    """构建 SWC ID -> pattern 的索引。"""
    _idx = {}
    for _p in KNOWN_PATTERNS:
        if _p.swc_id:
            _idx.setdefault(_p.swc_id, []).append(_p)
    return _idx
