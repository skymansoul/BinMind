"""ACFPC 主压缩器 — 判决合成与误报压缩.

三证据链按优先级求值: 双常量几何 > 守卫支配 > strncpy 特例 >
参数耦合 > 派生写确认. 任一链给出 SUPPRESS 即压制; CONFIRM 提升
置信度并补齐检测器盲区 (确认增强). 地址映射缺失时不做压制,
保证召回不受损. 显式偏移写预扫描独立于调用级证据链.
"""
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .def_chain import DefChainTracker, DefKind, DefNode
from .alloc_contract import AllocContractExtractor, AllocContract
from .write_coupling import WriteCouplingAnalyzer, Coupling
from .guard_dominance import GuardDominanceChecker
from .allocator_geometry import usable_size, write_fits
from .verdict import VerdictSynthesizer, ACFPCVerdict, ACFPCVerdictKind
from .explicit_write import ExplicitWriteChecker

class ACFPCVerdictKind(Enum):
    SUPPRESS = auto()
    CONFIRM = auto()
    UNCHANGED = auto()


@dataclass
class ACFPCVerdict:
    kind: ACFPCVerdictKind
    reason: str = ''
    evidence: List[str] = field(default_factory=list)
    confidence_delta: float = 0.0


class VerdictSynthesizer:
    """综合证据, 输出每个写点的判决."""

    def __init__(self, mode: str = 'strict'):
        self._mode = mode

    def synthesize_imm_write(self, contract: AllocContract,
                             write_imm: int) -> ACFPCVerdict:
        """双常量数值判定: 写 size 与分配大小直接比较."""
        req = contract.size_imm
        if write_imm <= 0 or req <= 0:
            return ACFPCVerdict(ACFPCVerdictKind.UNCHANGED,
                                '常量缺失, 无法数值判定')
        usable = usable_size(req, self._mode)
        if write_fits(req, 0, write_imm, self._mode):
            return ACFPCVerdict(
                ACFPCVerdictKind.SUPPRESS,
                f'{contract.func}({req}) 可用 {usable}B ≥ 写 {write_imm}B',
                [f'usable_size({req})={usable}',
                 f'write={write_imm} fits'])
        ob = overflow_bytes(req, 0, write_imm, self._mode)
        return ACFPCVerdict(
            ACFPCVerdictKind.CONFIRM,
            f'{contract.func}({req}) 可用 {usable}B < 写 {write_imm}B'
            f' (溢出 {ob}B)',
            [f'write_end={write_imm}', f'usable={usable}',
             f'overflow={ob}'],
            confidence_delta=0.15)

    def synthesize_guarded_write(self, usable: int, guarded: bool,
                                 guard_reason: str) -> ACFPCVerdict:
        if guarded:
            return ACFPCVerdict(
                ACFPCVerdictKind.SUPPRESS,
                f'守卫支配: {guard_reason}',
                ['guard_dominance'])
        return ACFPCVerdict(ACFPCVerdictKind.UNCHANGED,
                            f'守卫不成立: {guard_reason}')

    def synthesize_coupled_write(self, cv: CouplingVerdict) -> ACFPCVerdict:
        if cv.verdict == Coupling.COUPLED:
            return ACFPCVerdict(
                ACFPCVerdictKind.SUPPRESS,
                f'参数耦合: {cv.reason}',
                ['write_alloc_coupling'])
        return ACFPCVerdict(ACFPCVerdictKind.UNCHANGED, cv.reason)

    def synthesize_strncpy_same_size(self, contract: AllocContract) -> ACFPCVerdict:
        """strncpy 语义特例: 写入量为 n+1 (含终止符).

        strict 模式下 usable(n) = n, n+1 > n 恒成立 → 语言语义越界
        1 字节. 仅当分配 size 与写入 n 相同 (同源或等值) 时触发,
        该条件表明缓冲区恰无终止符空间."""
        return ACFPCVerdict(
            ACFPCVerdictKind.CONFIRM,
            f'strncpy(dst, src, {contract.size_imm}) 写入含终止符 '
            f'{contract.size_imm + 1}B > 分配 {contract.size_imm}B',
            ['strncpy_nul_overflow'],
            confidence_delta=0.15)

_WIDTH = {'qword': 8, 'dword': 4, 'word': 2, 'byte': 1}
_PAT = re.compile(
    r'mov\s+(?:(qword|dword|word|byte)\s+ptr\s+)?'
    r'\[([a-z0-9]+)([+-])(0x[0-9a-fA-F]+|\d+)\]\s*,',
    re.IGNORECASE)
_PAT0 = re.compile(
    r'mov\s+(?:(qword|dword|word|byte)\s+ptr\s+)?'
    r'\[([a-z0-9]+)\]\s*,',
    re.IGNORECASE)


@dataclass
class ExplicitWrite:
    insn_idx: int
    offset: int
    width: int
    base_reg: str
    reason: str = ''


class ExplicitWriteChecker:
    """显式 store 的几何安全检查 (在线状态判定)."""

    def __init__(self, tracker: DefChainTracker, mode: str = 'strict'):
        self._tracker = tracker
        self._mode = mode

    def scan(self, instructions: List[str],
             contracts: List[AllocContract]) -> Dict[int, ExplicitWrite]:
        """返回 {insn_idx: ExplicitWrite}, 仅含可证明安全的写.

        逐条 step 更新定义状态后再判定, 保证 def 查询位置敏感."""
        safe: Dict[int, ExplicitWrite] = {}
        for i, line in enumerate(instructions):
            self._tracker.step(line, i)
            m = _PAT.search(line)
            if m:
                width = _WIDTH[m.group(1).lower()] if m.group(1) else 4
                reg, sign, num = m.group(2), m.group(3), m.group(4)
            else:
                m0 = _PAT0.search(line)
                if not m0:
                    continue
                width = _WIDTH[m0.group(1).lower()] if m0.group(1) else 4
                reg, sign, num = m0.group(2), '+', '0'
            try:
                off = int(num, 0)
            except ValueError:
                continue
            if sign == '-':
                off = -off
            if off < 0:
                continue
            node = self._tracker.def_of_reg(reg)
            reg_id = self._tracker.identity(node)
            if not reg_id:
                continue
            for c in contracts:
                if c.size_kind != 'IMM':
                    continue
                if c.result_identity != reg_id:
                    continue
                if write_fits(c.size_imm, off, width, self._mode):
                    usable = usable_size(c.size_imm, self._mode)
                    safe[i] = ExplicitWrite(
                        insn_idx=i, offset=off, width=width,
                        base_reg=reg,
                        reason=(f'显式写 [{reg}+{off}] 宽 {width}B ≤ '
                                f'可用 {usable}B ({c.func}({c.size_imm}))'))
                    break
        return safe
DST_REGS = {'win64': 'rcx', 'sysv': 'rdi'}
_SIZE_REGS = {'win64': 'r8', 'sysv': 'rdx'}


@dataclass
class SuppressedSite:
    """一个被压制的写点."""
    insn_idx: int
    addr: int
    kind: str
    reason: str
    evidence: List[str] = field(default_factory=list)
    contract_idx: int = -1


@dataclass
class CompressStats:
    total_writes: int = 0
    suppressed: int = 0
    confirmed: int = 0
    unchanged: int = 0
    n_contracts: int = 0
    reasons: Dict[str, int] = field(default_factory=dict)


@dataclass
class CompressResult:
    kept: List  = field(default_factory=list)
    suppressed_sites: List[SuppressedSite] = field(default_factory=list)
    stats: CompressStats = field(default_factory=CompressStats)


class FpCompressor:
    """误报压缩主流程."""

    def __init__(self, abi: str = 'win64', mode: str = 'strict'):
        self._abi = abi
        self._mode = mode
        self._synth = VerdictSynthesizer(mode=mode)

    def _dst_offset(self, tracker: DefChainTracker, snap) -> int:
        """写目标指针的固定偏移 (lea [reg+off] 直通)."""
        reg = DST_REGS[self._abi]
        node = snap.args.get(reg)
        if node is None:
            return 0
        root = tracker.resolve(node)
        if root.kind != DefKind.DERIVED:
            return 0
        op = root.derived_op
        try:
            tail = op[op.index('+') + 1:].strip().rstrip(']')
            return int(tail, 0)
        except (ValueError, IndexError):
            return 0

    def _dst_identity(self, tracker: DefChainTracker, snap) -> str:
        """写目标指针的身份键, 与契约 result_identity 配对."""
        reg = DST_REGS[self._abi]
        node = snap.args.get(reg)
        if node is None:
            return ''
        return tracker.identity(node)

    def compress(self, instructions: List[str], findings: List,
                 addrs: Optional[List[int]] = None,
                 import_map: Optional[Dict[int, str]] = None,
                 ) -> CompressResult:
        tracker = DefChainTracker()
        if import_map:
            tracker.set_import_map(import_map)
        tracker.scan(instructions, addrs)
        extractor = AllocContractExtractor(tracker, self._abi)
        contracts = extractor.extract(instructions)
        coupling = WriteCouplingAnalyzer(tracker, self._abi)
        guards = GuardDominanceChecker(tracker)
        synth = self._synth

        result = CompressResult()
        result.stats.n_contracts = len(contracts)
        addr_at: Dict[int, int] = {}
        if addrs and len(addrs) >= len(instructions):
            for i, a in enumerate(addrs):
                addr_at[i] = a

        suppressed_idx: Dict[int, Tuple[str, str, List[str], int]] = {}
        confirmed_idx: Dict[int, Tuple[str, str]] = {}

        # 显式偏移写预扫描: 非 call 型 store 的几何安全判定
        # (独立 tracker, 避免重复 step 污染调用快照)
        exp_tracker = DefChainTracker()
        if import_map:
            exp_tracker.set_import_map(import_map)
        explicit_safe = ExplicitWriteChecker(exp_tracker, self._mode).scan(
            instructions, contracts)
        for idx, ew in explicit_safe.items():
            suppressed_idx[idx] = (
                ew.reason, ['explicit_store_geometry'], -1, 0.0)
            result.stats.suppressed += 1
            result.stats.reasons['suppress'] = \
                result.stats.reasons.get('suppress', 0) + 1

        for contract in contracts:
            usable = usable_size(contract.size_imm, self._mode) if \
                contract.size_kind == DefKind.IMM else 0
            for snap in tracker.calls():
                if snap.callee.lower() not in (
                        'memcpy', 'memset', 'strncpy', 'sprintf'):
                    continue
                if snap.insn_idx <= contract.insn_idx:
                    continue
                result.stats.total_writes += 1
                wnode = coupling.write_size_node(snap)
                if wnode is None:
                    continue

                # 配对验证: 写目标身份须与分配返回落点一致
                dst_id = self._dst_identity(tracker, snap)
                matched = bool(contract.result_identity) and \
                    contract.result_identity == dst_id

                verdict: Optional[ACFPCVerdict] = None

                # 证据1: 双常量几何 — 数值独立成立, 不要求配对,
                # 但 SUPPRESS 仅限配对成立 (防错配漏报)
                wimm = tracker.resolve(wnode)
                if wimm.kind == DefKind.IMM and contract.size_kind == DefKind.IMM:
                    off = self._dst_offset(tracker, snap)
                    usable2 = usable_size(contract.size_imm, self._mode)
                    if not write_fits(contract.size_imm, off, wimm.imm,
                                      self._mode):
                        verdict = ACFPCVerdict(
                            ACFPCVerdictKind.CONFIRM,
                            f'偏移写 {off}+{wimm.imm} 越出 {usable2}B'
                            f' ({contract.func}({contract.size_imm}))',
                            ['numeric_overflow'],
                            confidence_delta=0.15)
                    elif matched:
                        verdict = synth.synthesize_imm_write(contract,
                                                             wimm.imm)
                # 证据2: 守卫支配 — 需要配对
                if verdict is None and matched and \
                        contract.size_kind == DefKind.IMM:
                    gs = guards.collect(instructions, snap.insn_idx)
                    bounded, reason = guards.prove_write_within(
                        gs, wnode, usable)
                    if bounded:
                        verdict = synth.synthesize_guarded_write(
                            usable, True, reason)
                # 证据3b: strncpy 同源/等值特例 — 语言语义必越界 1 字节
                # (strncpy 强制写 n+1, 对象大小为 n 时无终止符空间)
                # 必须在通用耦合之前: 同源对 strncpy 意味着必越界而非安全
                if verdict is None and matched and \
                        snap.callee.lower() == 'strncpy':
                    if wimm.kind == DefKind.IMM and \
                            contract.size_kind == DefKind.IMM and \
                            wimm.imm == contract.size_imm:
                        verdict = synth.synthesize_strncpy_same_size(contract)
                    elif wimm.kind != DefKind.IMM:
                        cv = coupling.judge(contract, snap)
                        if cv.verdict == Coupling.COUPLED:
                            verdict = \
                                synth.synthesize_strncpy_same_size(contract)

                # 证据3: 参数耦合 — 需要配对且非常量
                if verdict is None and matched and \
                        wimm.kind != DefKind.IMM:
                    off = self._dst_offset(tracker, snap)
                    cv = coupling.judge(contract, snap)
                    if cv.verdict == Coupling.COUPLED and off == 0:
                        verdict = synth.synthesize_coupled_write(cv)

                # 证据5: 派生写确认 — 写 size = alloc + delta (delta>0)
                # 严格模式下 alloc+delta 恒越界, 补齐动态 off-by-one 盲区.
                # 基身份回退: lea [reg+1] 的 reg 无定义链时, 从调用点
                # 参数寄存器中找与分配同身份者 (寄存器传递模式).
                if verdict is None and matched and \
                        wimm.kind == DefKind.DERIVED and \
                        wimm.derived_delta > 0:
                    base_ok = (wimm.derived_base ==
                               contract.size_identity)
                    if not base_ok:
                        for _reg, _node in snap.args.items():
                            if tracker.identity(_node) == \
                                    contract.size_identity:
                                base_ok = True
                                break
                    if base_ok:
                        verdict = ACFPCVerdict(
                            ACFPCVerdictKind.CONFIRM,
                            f'派生写 {contract.size_identity} + '
                            f'{wimm.derived_delta} > 分配大小, 越界 '
                            f'{wimm.derived_delta}B',
                            ['derived_write_overflow'],
                            confidence_delta=0.15)

                if verdict is None:
                    result.stats.unchanged += 1
                    continue
                if verdict.kind == ACFPCVerdictKind.SUPPRESS:
                    result.stats.suppressed += 1
                    result.stats.reasons['suppress'] = \
                        result.stats.reasons.get('suppress', 0) + 1
                    suppressed_idx[snap.insn_idx] = (
                        verdict.reason, verdict.evidence,
                        contract.insn_idx, verdict.confidence_delta)
                elif verdict.kind == ACFPCVerdictKind.CONFIRM:
                    result.stats.confirmed += 1
                    result.stats.reasons['confirm'] = \
                        result.stats.reasons.get('confirm', 0) + 1
                    confirmed_idx[snap.insn_idx] = (
                        verdict.reason, verdict.evidence)
                else:
                    result.stats.unchanged += 1

        # 映射到 findings
        covered: set = set()
        for f in findings:
            addr = getattr(f, 'insn_addr', None)
            if addr is None and isinstance(f, dict):
                addr = f.get('insn_addr')
            if addr is None:
                result.kept.append(f)
                continue
            site = self._find_idx_by_addr(addr_at, addr)
            if site is not None and site in suppressed_idx:
                reason, ev, cidx, delta = suppressed_idx[site]
                result.suppressed_sites.append(SuppressedSite(
                    insn_idx=site, addr=addr, kind='SUPPRESS',
                    reason=reason, evidence=ev, contract_idx=cidx))
                covered.add(site)
                continue
            if site is not None and site in confirmed_idx:
                reason, ev = confirmed_idx[site]
                if isinstance(f, dict):
                    f['confidence'] = max(f.get('confidence', 0.5),
                                          f.get('semantic_score', 0.5))
                    f['acfpc_verdict'] = 'CONFIRM'
                elif hasattr(f, 'confidence'):
                    f.confidence = max(f.confidence,
                                       getattr(f, 'semantic_score', 0.5))
                    setattr(f, 'acfpc_verdict', 'CONFIRM')
                covered.add(site)
                result.kept.append(f)
                continue
            result.kept.append(f)

        # 确认增强: CONFIRM 写点无 base finding 对应时生成新 finding,
        # 补齐检测器盲区 (动态 size 越界), 保证召回不降
        for site, (reason, ev) in confirmed_idx.items():
            if site in covered:
                continue
            addr = addr_at.get(site, 0)
            result.kept.append({
                'insn_addr': addr,
                'semantic_score': 0.85,
                'confidence': 0.85,
                'acfpc_verdict': 'CONFIRM',
                'description': reason,
                'evidence': ev,
            })
            result.stats.reasons['added'] = \
                result.stats.reasons.get('added', 0) + 1
        return result

    def _find_idx_by_addr(self, addr_at: Dict[int, int],
                          addr: int) -> Optional[int]:
        for idx, a in addr_at.items():
            if a == addr:
                return idx
        return None
