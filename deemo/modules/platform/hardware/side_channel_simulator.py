import logging
import time
import math
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from enum import Enum

logger = logging.getLogger(__name__)



# 修复: SideChannelType 原为普通 class，line 21 POWER = SideChannelType("power")
# 调用 object.__init__("power") → TypeError: object() takes no arguments。
# 改为 str Enum，消除导入时崩溃。
class SideChannelType(str, Enum):
    TIMING = "timing"
    CACHE_ACCESS = "cache_access"
    CACHE_TIMING = "cache_timing"
    POWER = "power"
    BRANCH_PREDICTION = "branch_prediction"
    SPECULATIVE_EXECUTION = "speculative_execution"
    MEMORY_ACCESS_PATTERN = "memory_access_pattern"

class AttackMethod(Enum):
    FLUSH_RELOAD = "flush_reload"
    PRIME_PROBE = "prime_probe"
    EVICT_TIME = "evict_time"
    EVICT_RELOAD = "evict_reload"
    SPA = "simple_power_analysis"
    DPA = "differential_power_analysis"
    SPECTRE_V1 = "spectre_v1"
    SPECTRE_V2 = "spectre_v2"
    TIMING_CORRELATION = "timing_correlation"

# 修复: LeakageSeverity 同样的问题, line 39 LOW = LeakageSeverity("low") 导致导入时 TypeError。
class LeakageSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class InstructionTiming:
    mnemonic: str = ""
    base_cycles: int = 1
    memory_cycles: int = 0
    branch_cycles: int = 0
    division_variable: bool = False

@dataclass
class CacheLine:
    tag: int = 0
    set_index: int = 0
    valid: bool = True
    access_count: int = 0

@dataclass
class CacheSet:
    index: int = 0
    ways: int = 8
    lines: List[CacheLine] = field(default_factory=list)

    def access(self, tag: int) -> bool:
        for line in self.lines:
            if line.tag == tag and line.valid:
                line.access_count += 1
                return True
        if len(self.lines) < self.ways:
            self.lines.append(CacheLine(tag=tag, set_index=self.index))
        else:
            self.lines.sort(key=lambda l: l.access_count)
            self.lines[0] = CacheLine(tag=tag, set_index=self.index)
        return False


class CacheSimulator:
    L1D_SETS = 64
    L1D_WAYS = 8
    L1D_LINE_SIZE = 64
    # L2 参数（含延迟模拟）
    L2_SETS = 512
    L2_WAYS = 16
    L2_LATENCY_PENALTY = 12  # 相对于 L1 的周期代价

    def __init__(self, l2_inclusive: bool = True):
        self.l1d: List[CacheSet] = [
            CacheSet(index=i, ways=self.L1D_WAYS) for i in range(self.L1D_SETS)]
        # 可选的 L2 缓存层（含延迟模型）
        self._l2: Optional[List[CacheSet]] = None
        self._l2_enabled = l2_inclusive
        if self._l2_enabled:
            self._l2 = [CacheSet(index=i, ways=self.L2_WAYS) for i in range(self.L2_SETS)]
        self._access_log: List[Tuple[str, float, int, bool]] = []

    def access_data(self, addr: int, with_l2: bool = True) -> Tuple[bool, int]:
        """返回 (命中, 延迟周期数)。含 L2 回退逻辑。"""
        set_idx = (addr // self.L1D_LINE_SIZE) % self.L1D_SETS
        tag = addr // (self.L1D_SETS * self.L1D_LINE_SIZE)
        l1_hit = self.l1d[set_idx].access(tag)
        self._access_log.append(('data', time.time(), set_idx, l1_hit))
        if l1_hit:
            return True, 1
        # L1 miss → 尝试 L2
        if self._l2 is not None and with_l2:
            l2_set = (addr // self.L1D_LINE_SIZE) % self.L2_SETS
            l2_tag = addr // (self.L2_SETS * self.L1D_LINE_SIZE)
            l2_hit = self._l2[l2_set].access(l2_tag)
            if l2_hit:
                return True, 1 + self.L2_LATENCY_PENALTY
        return False, 1 + self.L2_LATENCY_PENALTY + 80  # DRAM 估算

    def flush_address(self, addr: int):
        set_idx = (addr // self.L1D_LINE_SIZE) % self.L1D_SETS
        tag = addr // (self.L1D_SETS * self.L1D_LINE_SIZE)
        for line in self.l1d[set_idx].lines:
            if line.tag == tag:
                line.valid = False

    def probe_set(self, set_idx: int) -> int:
        return sum(1 for line in self.l1d[set_idx].lines if line.valid)

    def l2_evict_set(self, set_idx: int) -> int:
        """驱逐 L2 中指定组的全部行（用于构造 Evict+Reload 的 eviction set）。"""
        if self._l2 is None:
            return 0
        evicted = 0
        for line in self._l2[set_idx % self.L2_SETS].lines:
            line.valid = False
            evicted += 1
        return evicted


class PowerTrace:
    __slots__ = ('time_points', 'power_values', 'hamming_weight',)

    def __init__(self, time_points=None, power_values=None, hamming_weight=0):
        self.time_points = time_points if time_points is not None else []
        self.power_values = power_values if power_values is not None else []
        self.hamming_weight = hamming_weight

    def add_point(self, hw: int, weight: float = 1.0):
        self.time_points.append(len(self.time_points))
        self.power_values.append(hw * weight)


class TimingLeakDetector:
    TIMING_TABLE: Dict[str, InstructionTiming] = {
        'div': InstructionTiming(mnemonic='div', base_cycles=20, division_variable=True),
        'idiv': InstructionTiming(mnemonic='idiv', base_cycles=20, division_variable=True),
        'imul': InstructionTiming(mnemonic='imul', base_cycles=3),
        'mul': InstructionTiming(mnemonic='mul', base_cycles=3),
        'mov': InstructionTiming(mnemonic='mov', base_cycles=1, memory_cycles=3),
        'add': InstructionTiming(mnemonic='add', base_cycles=1),
        'sub': InstructionTiming(mnemonic='sub', base_cycles=1),
        'cmp': InstructionTiming(mnemonic='cmp', base_cycles=1),
        'je': InstructionTiming(mnemonic='je', base_cycles=1, branch_cycles=2),
        'jne': InstructionTiming(mnemonic='jne', base_cycles=1, branch_cycles=2),
        'call': InstructionTiming(mnemonic='call', base_cycles=3, branch_cycles=2),
        'ret': InstructionTiming(mnemonic='ret', base_cycles=3, branch_cycles=2),
    }

    def estimate_cycles(self, instructions: List[str]) -> Tuple[int, int]:
        min_cycles, max_cycles = 0, 0
        for instr in instructions:
            mnemonic = instr.split()[0].lower() if instr else ''
            timing = self.TIMING_TABLE.get(mnemonic)
            if timing:
                min_cycles += timing.base_cycles
                max_cycles += timing.base_cycles + (
                    timing.memory_cycles if timing.division_variable else 0)
                if timing.division_variable:
                    max_cycles = timing.base_cycles * 3
            else:
                min_cycles += 1
                max_cycles += 2
        return (min_cycles, max_cycles)

    def detect_timing_discrepancy(self, instructions: List[str],
                                  secret_dependent_instrs: Set[int]
                                  ) -> Optional[Dict[str, Any]]:
        if not secret_dependent_instrs:
            return None
        variable_points = []
        for i in secret_dependent_instrs:
            if i < len(instructions):
                mnemonic = instructions[i].split()[0].lower()
                timing = self.TIMING_TABLE.get(mnemonic)
                if timing and (timing.division_variable or timing.memory_cycles > 0
                              or timing.branch_cycles > 0):
                    variable_points.append({
                        'index': i, 'mnemonic': mnemonic,
                        'reason': 'division' if timing.division_variable else
                                  'memory' if timing.memory_cycles > 0 else 'branch'})
        if variable_points:
            return {'detected': True, 'severity': LeakageSeverity.HIGH.value,
                    'variable_points': variable_points,
                    'leakage_type': SideChannelType.TIMING.value}
        return None


class CacheSideChannelSimulator:
    def __init__(self):
        self.cache = CacheSimulator()

    def simulate_flush_reload(self, victim_func_addr: int,
                              victim_data_addrs: List[int],
                              iterations: int = 100) -> Dict[str, Any]:
        results = []
        for _ in range(iterations):
            for addr in victim_data_addrs:
                self.cache.flush_address(addr)
            for addr in victim_data_addrs[:1]:
                self.cache.access_data(addr)
            hit_map = {}
            for addr in victim_data_addrs:
                hit, _ = self.cache.access_data(addr)
                hit_map[hex(addr)] = hit
            results.append(hit_map)
        hit_counts = defaultdict(int)
        for r in results:
            for addr, hit in r.items():
                if hit:
                    hit_counts[addr] += 1
        success = any(c > iterations * 0.8 for c in hit_counts.values())
        return {'attack_method': AttackMethod.FLUSH_RELOAD.value,
                'iterations': iterations, 'success': success,
                'leaked_data': [{'address': addr, 'hit_rate': round(c / iterations, 2)}
                               for addr, c in hit_counts.items() if c > iterations * 0.5]}

    def simulate_prime_probe(self, probe_set_indices: List[int],
                             iterations: int = 100) -> Dict[str, Any]:
        results = []
        for _ in range(iterations):
            for set_idx in probe_set_indices:
                for way in range(self.cache.L1D_WAYS):
                    self.cache.l1d[set_idx].access(0xDEAD0000 | way)
            probe_result = {}
            for set_idx in probe_set_indices:
                valid_count = self.cache.probe_set(set_idx)
                probe_result[f"set_{set_idx}"] = self.cache.L1D_WAYS - valid_count
            results.append(probe_result)
        avg_evictions = {}
        for set_idx in probe_set_indices:
            key = f"set_{set_idx}"
            avg_evictions[key] = sum(r.get(key, 0) for r in results) / max(1, len(results))
        has_signal = any(v > 0.5 for v in avg_evictions.values())
        return {'attack_method': AttackMethod.PRIME_PROBE.value,
                'iterations': iterations, 'signal_detected': has_signal,
                'avg_evictions': avg_evictions}

    def simulate_evict_reload(self, victim_addrs: List[int],
                              eviction_addrs: List[int],
                              iterations: int = 100) -> Dict[str, Any]:
        """Evict+Reload 模拟：使用冲突地址驱逐而非 clflush。

        参考 NDSS 2025 评估：Evict+Reload 在无特权场景下比 Flush+Reload
        更可行（不需要 clflush），但需要构造 eviction set。
        """
        results = []
        for _ in range(iterations):
            # Evict：通过访问冲突组地址踢出 victim 行
            for ea in eviction_addrs:
                self.cache.access_data(ea)
            hit_map = {}
            for addr in victim_addrs:
                hit, latency = self.cache.access_data(addr)
                hit_map[hex(addr)] = hit
            results.append(hit_map)
        hit_counts = defaultdict(int)
        for r in results:
            for addr_str, hit in r.items():
                if hit:
                    hit_counts[addr_str] += 1
        success = any(c < iterations * 0.3 for c in hit_counts.values())
        return {'attack_method': AttackMethod.EVICT_RELOAD.value,
                'iterations': iterations, 'success': success,
                'hit_rates': {addr: round(c / iterations, 2)
                             for addr, c in hit_counts.items()}}


class PowerAnalysisSimulator:
    HAMMING_WEIGHT_MAP: Dict[str, int] = defaultdict(lambda: 1, {
        'mov': 2, 'add': 3, 'sub': 3, 'mul': 5, 'div': 10,
        'xor': 2, 'and': 2, 'or': 2, 'shl': 2, 'shr': 2,
        'call': 6, 'ret': 6, 'push': 3, 'pop': 3,
        'cmp': 2, 'test': 2, 'lea': 2,
    })

    def __init__(self, noise_level: float = 0.1):
        self.noise_level = noise_level

    def generate_power_trace(self, instructions: List[str],
                             secret_values: Optional[List[int]] = None) -> PowerTrace:
        trace = PowerTrace()
        for i, instr in enumerate(instructions):
            mnemonic = instr.split()[0].lower()
            base_hw = self.HAMMING_WEIGHT_MAP.get(mnemonic, 1)
            if secret_values and i < len(secret_values):
                hw = bin(secret_values[i]).count('1')
                trace.hamming_weight += hw
                trace.add_point(base_hw + hw, 1.0 + self.noise_level)
            else:
                trace.add_point(base_hw, 1.0)
        return trace

    def generate_template_trace(self, instructions: List[str],
                                hamming_weight_profile: List[int]) -> PowerTrace:
        """模板攻击轨迹生成：按给定的汉明权重轮廓构造功耗曲线。

        比随机噪声更接近实际功耗测量, 模板攻击（Template Attack）的核心步骤。
        """
        trace = PowerTrace()
        hw_sum = 0
        for i, (instr, hw) in enumerate(zip(instructions, hamming_weight_profile)):
            mnemonic = instr.split()[0].lower()
            base = self.HAMMING_WEIGHT_MAP.get(mnemonic, 1)
            hw_sum += hw
            trace.add_point(base + hw, 1.0 + self.noise_level * 0.5)
        trace.hamming_weight = hw_sum
        return trace

    def differential_analysis(self, traces_group0: List[PowerTrace],
                              traces_group1: List[PowerTrace]) -> Dict[str, Any]:
        if not traces_group0 or not traces_group1:
            return {'success': False, 'error': '轨迹不足'}
        max_len = min(min(len(t.time_points) for t in traces_group0),
                     min(len(t.time_points) for t in traces_group1))
        diff_trace = []
        for i in range(max_len):
            mean0 = sum(t.power_values[i] for t in traces_group0
                       if i < len(t.power_values)) / len(traces_group0)
            mean1 = sum(t.power_values[i] for t in traces_group1
                       if i < len(t.power_values)) / len(traces_group1)
            diff_trace.append(abs(mean1 - mean0))
        peaks = [{'time': i, 'diff': round(d, 3)}
                for i, d in enumerate(diff_trace) if d > 0.5]
        return {'success': True, 'attack_method': AttackMethod.DPA.value,
                'max_differential': round(max(diff_trace) if diff_trace else 0, 3),
                'leakage_points': peaks, 'key_recoverable': len(peaks) > 0}


class SpectreDetector:
    def detect_spectre_v1(self, instructions: List[str],
                          array_bounds_check_indices: Set[int]) -> List[Dict[str, Any]]:
        findings = []
        for i, instr in enumerate(instructions):
            mnemonic = instr.split()[0].lower() if instr else ''
            if mnemonic.startswith('j') and i in array_bounds_check_indices:
                post_branch = instructions[i+1:i+10]
                for j, post_instr in enumerate(post_branch):
                    post_mnem = post_instr.split()[0].lower() if post_instr else ''
                    if post_mnem in ('mov', 'lea') and ('[' in post_instr or 'ptr' in post_instr):
                        multiplier = '4096' in post_instr or '0x1000' in post_instr
                        findings.append({
                            'type': 'spectre_v1', 'branch_index': i,
                            'array_access_index': i + 1 + j,
                            'instruction': post_instr.strip(),
                            'multiplier_4096': multiplier,
                            'confidence': 0.7 if multiplier else 0.4,
                            'remediation': '在array访问前insert lfence 结束投机execute'
                        })
        return findings


class SideChannelSimulator:
    def __init__(self):
        self.timing_detector = TimingLeakDetector()
        self.cache_simulator = CacheSideChannelSimulator()
        self.power_simulator = PowerAnalysisSimulator()
        self.spectre_detector = SpectreDetector()
        self._findings: List[Dict[str, Any]] = []

    def analyze(self, func_name: str = "",
                instructions: Optional[List[str]] = None,
                secret_dependent_instrs: Optional[Set[int]] = None,
                enable_cache: bool = True, enable_power: bool = True,
                enable_spectre: bool = True, **kwargs) -> Dict[str, Any]:
        if instructions is None:
            instructions = []
        if secret_dependent_instrs is None:
            secret_dependent_instrs = set()
        results = {'success': True, 'func_name': func_name,
                   'total_instructions': len(instructions),
                   'secret_dependent_count': len(secret_dependent_instrs),
                   'findings': []}

        timing_result = self.timing_detector.detect_timing_discrepancy(
            instructions, secret_dependent_instrs)
        if timing_result:
            self._findings.append(timing_result)
            results['findings'].append({
                'type': SideChannelType.TIMING.value,
                'severity': timing_result['severity']})

        if enable_cache and instructions:
            cache_result = self.cache_simulator.simulate_flush_reload(
                0x400000, [0x400010, 0x400020])
            if cache_result['success']:
                self._findings.append({'type': SideChannelType.CACHE_ACCESS.value,
                                       'attack_method': AttackMethod.FLUSH_RELOAD.value})
                results['findings'].append({
                    'type': SideChannelType.CACHE_ACCESS.value,
                    'severity': LeakageSeverity.HIGH.value})

        if enable_power and secret_dependent_instrs:
            trace = self.power_simulator.generate_power_trace(
                instructions,
                secret_values=[1 if i in secret_dependent_instrs else 0
                             for i in range(len(instructions))])
            if trace.hamming_weight > 10:
                self._findings.append({'type': SideChannelType.POWER.value})
                results['findings'].append({
                    'type': SideChannelType.POWER.value,
                    'severity': LeakageSeverity.MEDIUM.value})

        if enable_spectre and instructions:
            spec_findings = self.spectre_detector.detect_spectre_v1(
                instructions, secret_dependent_instrs)
            for f in spec_findings:
                self._findings.append(f)
                results['findings'].append({
                    'type': SideChannelType.SPECULATIVE_EXECUTION.value,
                    'severity': LeakageSeverity.CRITICAL.value if f['confidence'] > 0.5
                    else LeakageSeverity.HIGH.value})

        return results

    def generate_report(self) -> Dict[str, Any]:
        if not self._findings:
            return {'success': True, 'summary': '未detected侧信道泄露',
                    'risk_level': 'none', 'findings': []}
        by_type = Counter(f.get('type', 'unknown') for f in self._findings)
        critical = sum(1 for f in self._findings
                      if f.get('severity') == LeakageSeverity.CRITICAL.value)
        high = sum(1 for f in self._findings
                  if f.get('severity') == LeakageSeverity.HIGH.value)
        risk = 'critical' if critical > 0 else 'high' if high > 0 else 'medium'
        # 按攻击面生成缓解列表
        mitigations = []
        if any('FLUSH_RELOAD' in str(f) for f in self._findings):
            mitigations.append('刷新指令检测/禁用：限制用户态 clflush 使用（内核页表隔离）')
        if any('PRIME_PROBE' in str(f) for f in self._findings):
            mitigations.append('缓存分区（CAT/Intel RDT）：将敏感数据隔离到专用缓存路')
        return {
            'success': True,
            'summary': f'发现 {len(self._findings)} 个侧信道风险: '
                      f'{critical} critical, {high} high',
            'risk_level': risk, 'types_detected': dict(by_type),
            'total_findings': len(self._findings), 'findings': self._findings[:100],
            'recommendations': [
                '使用常数时间算法处理秘密data',
                '避免based on秘密value的分支, 使用condition移动 (cmov) 替代',
                '对于 Spectre v1: 在array访问前insert lfence',
                '使用硬件encrypt加速器进行secret key操作'
            ] + mitigations
        }


def simulate_side_channels(func_name: str, instructions: List[str],
                           secret_indices: Optional[List[int]] = None,
                           **kwargs) -> Dict[str, Any]:
    simulator = SideChannelSimulator()
    result = simulator.analyze(
        func_name=func_name, instructions=instructions,
        secret_dependent_instrs=set(secret_indices or []),
        enable_cache=kwargs.get('cache', True),
        enable_power=kwargs.get('power', True),
        enable_spectre=kwargs.get('spectre', True))
    report = simulator.generate_report()
    result['report'] = report
    return result


__all__ = ["SideChannelSimulator", "TimingLeakDetector", "CacheSideChannelSimulator",
           "PowerAnalysisSimulator", "SpectreDetector", "CacheSimulator",
           "SideChannelType", "AttackMethod", "LeakageSeverity",
           "simulate_side_channels"]
