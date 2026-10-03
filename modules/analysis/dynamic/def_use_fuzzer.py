import logging
import os
import re
import json
import hashlib
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from enum import Enum, auto

logger = logging.getLogger(__name__)


class DefUseRelation(Enum):
    REG_DEF = auto()
    REG_USE = auto()
    MEM_DEF = auto()
    MEM_USE = auto()
    FLAG_DEF = auto()
    FLAG_USE = auto()


@dataclass
class DUPoint:
    address: int
    instruction: str
    variable: str
    relation: DefUseRelation
    block_addr: int = 0

    def is_def(self) -> bool:
        return self.relation in (DefUseRelation.REG_DEF,
                                  DefUseRelation.MEM_DEF,
                                  DefUseRelation.FLAG_DEF)


@dataclass
class DUChain:
    def_point: DUPoint
    use_points: List[DUPoint] = field(default_factory=list)
    chain_id: str = ""
    distance: int = 0
    crossing_branches: int = 0

    def __post_init__(self):
        if not self.chain_id:
            self.chain_id = f"{self.def_point.address:x}_{self.def_point.variable}"

    def is_exploitable(self) -> bool:
        sensitive_vars = {'buf', 'size', 'len', 'ptr', 'idx', 'offset',
                         'nbytes', 'count', 'src', 'dst', 'dest'}
        var_lower = self.def_point.variable.lower()
        return any(sv in var_lower for sv in sensitive_vars)


@dataclass
class DUCoverageMap:
    bitmap: bytearray = field(default_factory=lambda: bytearray(65536))
    hit_count: int = 0
    unique_chains: int = 0

    def record(self, chain: DUChain) -> bool:
        key = (chain.def_point.address, chain.use_points[0].address
               if chain.use_points else 0)
        idx = (hash(key) & 0xFFFF)

        old_val = self.bitmap[idx]
        if old_val < 255:
            self.bitmap[idx] = old_val + 1

        is_new = (old_val == 0)
        if is_new:
            self.unique_chains += 1
        self.hit_count += 1
        return is_new

    def hit_ratio(self) -> float:
        filled = sum(1 for b in self.bitmap if b > 0)
        return round(filled / len(self.bitmap), 4) if self.bitmap else 0.0

    def reset(self) -> None:
        self.bitmap = bytearray(65536)
        self.hit_count = 0
        self.unique_chains = 0


class DUExtractor:
    # x86-64 指令的隐式 def/use 模式
    _IMPLICIT_PATTERNS = {
        'push': {'def': ['rsp'], 'use': ['rsp']},
        'pop': {'def': ['rsp'], 'use': ['rsp']},
        'call': {'def': ['rsp', 'rax'], 'use': ['rsp']},
        'ret': {'def': ['rsp', 'rip'], 'use': ['rsp']},
        'mul': {'def': ['rax', 'rdx'], 'use': ['rax']},
        'imul': {'def': ['rax', 'rdx'], 'use': ['rax']},
        'div': {'def': ['rax', 'rdx'], 'use': ['rax', 'rdx']},
        'idiv': {'def': ['rax', 'rdx'], 'use': ['rax', 'rdx']},
        'loop': {'def': ['rcx'], 'use': ['rcx']},
        'rep': {'use': ['rcx']},
        'syscall': {'def': ['rax', 'rcx', 'r11'], 'use': ['rax']},
    }

    # 寄存器使用模式 (def)
    _REG_DEF_PATTERN = re.compile(
        r'^(?:mov|lea|pop|xor|sub|and|or|add|adc|sbb|shl|shr|sar|rol|ror|'
        r'mul|imul|div|idiv|not|neg|inc|dec|xchg|xadd)\b',
        re.IGNORECASE
    )

    def extract_from_asm(
        self, assembly: str, base_addr: int = 0
    ) -> List[DUChain]:
        lines = assembly.strip().split('\n')
        defs: Dict[str, DUPoint] = {}
        chains: Dict[str, DUChain] = {}

        addr_pattern = re.compile(r'^\s*(0x[0-9a-fA-F]+)\s*[:]?\s*')

        for line in lines:
            addr_match = addr_pattern.match(line)
            addr = int(addr_match.group(1), 16) if addr_match else 0
            instr = addr_pattern.sub('', line).strip()

            if not instr:
                continue

            # 解析 defs
            defs_in_instr = self._extract_defs(instr, addr)
            for d in defs_in_instr:
                defs[d.variable] = d

                if d.variable not in chains:                    chains[d.variable] = DUChain(
                        def_point=d,
                        chain_id=f"{addr:x}_{d.variable}"
                    )

            # 解析 uses
            uses_in_instr = self._extract_uses(instr, addr)
            for u in uses_in_instr:
                if u.variable in defs and u.variable in chains:
                    chains[u.variable].use_points.append(u)

        return list(chains.values())

    def _extract_defs(self, instr: str, addr: int) -> List[DUPoint]:
        defs = []

        mnemonic = instr.split()[0] if instr.split() else ''

        # 显式 def
        if self._REG_DEF_PATTERN.match(mnemonic):
            parts = instr[len(mnemonic):].strip().split(',')
            if parts:
                dst = parts[0].strip()
                regs = re.findall(
                    r'\b(?:r[abcd]x|r[sd]i|r[bp]|r[sd]p|r\d+\w?|'
                    r'e[abcd]x|e[sd]i|e[bp]|e[sd]p|'
                    r'[abcd]x|[sd]i|[sb]p|sp|rip)\b',
                    dst, re.IGNORECASE
                )
                for r in regs:
                    defs.append(DUPoint(addr, instr, r.lower(),
                                        DefUseRelation.REG_DEF))

        # 隐式 def
        for base_mnem, patterns in self._IMPLICIT_PATTERNS.items():
            if mnemonic.lower().startswith(base_mnem):
                for r in patterns.get('def', []):
                    defs.append(DUPoint(addr, instr, r,
                                        DefUseRelation.REG_DEF))

        return defs

    def _extract_uses(self, instr: str, addr: int) -> List[DUPoint]:
        uses = []

        regs = re.findall(
            r'\b(?:r[abcd]x|r[sd]i|r[bp]|r[sd]p|r\d+\w?|'
            r'e[abcd]x|e[sd]i|e[bp]|e[sd]p|'
            r'[abcd]x|[sd]i|[sb]p|sp|rip|cr\d|dr\d)\b',
            instr, re.IGNORECASE
        )

        mnemonic = instr.split()[0] if instr.split() else ''
        parts = instr[len(mnemonic):].strip().split(',')

        for r in regs:
            r_lower = r.lower()
            in_dst = len(parts) > 0 and r_lower in parts[0].lower()
            in_src = len(parts) > 1 and r_lower in parts[1].lower()

            if in_src or (not in_dst):
                uses.append(DUPoint(addr, instr, r_lower,
                                    DefUseRelation.REG_USE))

        # 隐式 use
        for base_mnem, patterns in self._IMPLICIT_PATTERNS.items():
            if mnemonic.lower().startswith(base_mnem):
                for r in patterns.get('use', []):
                    uses.append(DUPoint(addr, instr, r,
                                        DefUseRelation.REG_USE))

        return uses


class DefUseGuidedFuzzer:
    def __init__(
        self,
        target_binary: str,
        extractor: Optional[DUExtractor] = None,
        max_seeds: int = 1000
    ):
        self.target = target_binary
        self.extractor = extractor or DUExtractor()
        self.max_seeds = max_seeds

        self.coverage = DUCoverageMap()
        self.seed_queue: List[bytes] = []
        self.seed_scores: Dict[bytes, float] = {}
        self.du_chains: List[DUChain] = []
        self._crash_inputs: List[bytes] = []

        # 统计
        self.executions = 0
    def initialize_chains(self, assembly: str) -> int:
        """初始化 def-use 链（静态分析阶段），返回链数量"""
        self.du_chains = self.extractor.extract_from_asm(assembly)
        logger.info(
            f"[Dufuzz] 发现 {len(self.du_chains)} 条 def-use 链, "
            f"其中 {sum(1 for c in self.du_chains if c.is_exploitable())} 条可被利用"
        )
        return len(self.du_chains)

    def add_seed(self, seed: bytes) -> None:
        """添加种子到队列"""
        if len(seed) == 0:
            return

        seed_hash = hashlib.md5(seed).digest()
        # 基于 du-chain 覆盖计算权重
        score = self._compute_seed_score(seed)
        self.seed_scores[seed_hash] = score

        # 按分数排序插入
        self.seed_queue.append(seed)
        self.seed_queue.sort(key=lambda s: self.seed_scores.get(
            hashlib.md5(s).digest(), 0
        ), reverse=True)

        # 限制队列大小
        if len(self.seed_queue) > self.max_seeds:
            self.seed_queue = self.seed_queue[:self.max_seeds]

    def _compute_seed_score(self, seed: bytes) -> float:
        score = 1.0
        seed_len = len(seed)

        # 小种子基础加分（更易变异）
        if seed_len < 100:
            score += 0.5
        elif seed_len > 10000:
            score -= 0.3

        # 包含特定模式的加分
        interesting_patterns = [b'\x00', b'\xff', b'AAAA', b'%s', b'%n',
                                b'%x', b'/bin/sh', b'||']
        for pat in interesting_patterns:
            if pat in seed:
                score += 0.1

        return max(score, 0.1)

    def mutate(self, seed: bytes) -> bytes:
        data = bytearray(seed)

        if len(data) == 0:
            return bytes([0x41] * 4)

        # 1. 位翻转（确定性）
        pos = self.executions % max(len(data), 1)
        for bit in range(8):
            data[pos] ^= (1 << bit)

        # 2. 字节替换
        if len(data) > 4 and self.executions % 7 == 0:
            idx = (self.executions * 3) % (len(data) - 4)
            interesting = [0x00, 0xFF, 0x41, 0x0A, 0x25, 0x2F]
            data[idx] = interesting[self.executions % len(interesting)]

        # 3. 算术运算
        if self.executions % 11 == 0 and len(data) > 0:
            idx = self.executions % len(data)
            data[idx] = (data[idx] + (self.executions % 35) - 17) & 0xFF

        # 4. 块插入/删除
        if self.executions % 13 == 0 and len(data) > 8:
            pos = self.executions % (len(data) - 4)
            data[pos:pos + 2] = b'\x41\x41'

        return bytes(data)

    def run_cycle(
        self,
        execute_callback,
        max_cycles: int = 1000
    ) -> Dict[str, Any]:
        if not self.seed_queue:
            return {'error': '无种子', 'executions': 0}

        for cycle in range(max_cycles):
            if not self.seed_queue:
                break

            # 选种（优先高分种子）
            seed = self.seed_queue[0]
            mutated = self.mutate(seed)

            # 执行
            try:
                retcode, stdout, stderr = execute_callback(mutated)
            except Exception as e:
                logger.debug(f"[Dufuzz] 执行异常: {e}")
                continue

            self.executions += 1

            # 检测 crash
            if retcode != 0 and retcode != 1:
                crash_sig = hashlib.md5(mutated).hexdigest()[:12]
                if crash_sig not in [hashlib.md5(c).hexdigest()[:12]
                                       for c in self._crash_inputs]:
                    self._crash_inputs.append(bytes(mutated))
                    self.unique_crashes += 1
                    logger.warning(
                        f"[Dufuzz] 发现 crash #{self.unique_crashes} "
                        f"(exit={retcode}, size={len(mutated)})"
                    )

            # 检查新的 du-chain 覆盖
            new_chains = self._check_du_coverage(
                stdout + stderr if stdout and stderr else b''
            )
            if new_chains:
                self.add_seed(bytes(mutated))

            # 周期性报告
            if cycle > 0 and cycle % 200 == 0:
                logger.info(
                    f"[Dufuzz] cycle={cycle}/{max_cycles}, "
                    f"execs={self.executions}, "
                    f"crashes={self.unique_crashes}, "
                    f"du_chains={self.coverage.unique_chains}, "
                    f"seeds={len(self.seed_queue)}"
                )

        return {
            'executions': self.executions,
            'cycles': min(cycle + 1, max_cycles),
            'unique_crashes': self.unique_crashes,
            'crash_inputs': [c.hex()[:64] for c in self._crash_inputs[:10]],
            'du_coverage': {
                'unique_chains': self.coverage.unique_chains,
                'hit_ratio': self.coverage.hit_ratio(),
            },
            'seed_count': len(self.seed_queue),
        }

    def _check_du_coverage(self, output: bytes) -> bool:
        """检查执行输出中是否出现新的 du-chain 覆盖"""
        had_new = False
        output_str = output.decode('utf-8', errors='replace')

        for chain in self.du_chains:
            # 检查 def 地址和 use 地址是否在输出中被引用
            def_str = f"{chain.def_point.address:x}"
            if def_str in output_str:
                for use in chain.use_points:
                    use_str = f"{use.address:x}"
                    if use_str in output_str:
                        is_new = self.coverage.record(chain)
                        if is_new:
                            had_new = True

        return had_new


def run_def_use_fuzzing(
    binary_path: str,
    seed_inputs: List[bytes],
    assembly_code: str,
    executor,  # callable: bytes → (int, bytes, bytes)
    max_cycles: int = 500
) -> Dict[str, Any]:
    fuzzer = DefUseGuidedFuzzer(binary_path)

    chain_count = fuzzer.initialize_chains(assembly_code)
    if chain_count == 0:
        return {'error': '未找到 def-use 链', 'executions': 0}

    for seed in seed_inputs:
        fuzzer.add_seed(seed)

    if not seed_inputs:
        fuzzer.add_seed(b'\x00' * 64)  # 默认种子

    return fuzzer.run_cycle(executor, max_cycles=max_cycles)
