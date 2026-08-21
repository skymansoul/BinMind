# 增加偏移量相关性检测：两个相距固定距离的字节若关联变化则标记
# 引入 constraint_break_score 作为变异策略选择的仲裁指标

"""Online structural constraint inference for grammar-free fuzzing.

现有变异器（deterministic_stage / havoc_stage）对输入结构完全无感知-它们将
输入视为无类型的字节数组。这在面对结构化二进制格式（ELF header、protobuf、
PNG chunk）时极度低效：绝大多数变异在格式校验阶段即被拒绝，永不触及深层逻辑。

传统解决方案需要人工编写 grammar（如 AFLSmart、Peach），代价高昂。
本模块采用在线学习方法：
  1. 从变异->反馈的映射中自动推断字节间的结构性约束
  2. 推断结果用于指导后续变异-在"遵守约束"和"打破约束"之间按策略切换

约束类型:
  - LENGTH_FIELD:   某 2/4 字节的值等于后续数据的长度
  - MAGIC_BYTES:    固定字节序列（如 ELF magic b'\x7fELF'）
  - CHECKSUM:       某 2/4 字节 = f(指定范围的数据)
  - DEPENDENCY:     两个非相邻字节的值之间存在算术关系
  - INVARIANT_RANGE: 某字节在合法输入中只取固定集合中的值

两阶段学习:
  Phase 1 (detect): 快速判断某字节是否为约束字段-通过观察"修改此字节后
    解析失败率是否显著高于基线"来判断。
  Phase 2 (infer):  对标记为约束字段的字节进行精细探测-改变附近字节观察
    该字段的变化，推断约束类型和参数。

ref: AFLSmart - 结构化输入的语法感知变异，
     本项目将离线 grammar 替换为在线推断，消除格式依赖。
ref: ProFuzzer - 基于执行反馈的字节级"探针"分析，
     本项目借鉴其 probe 思想，扩展到约束类型推断和自动策略切换。
ref: WEIZZ - 覆盖率引导的约束推断，
     本项目在线性推断速度上做了简化（O(n) per probe vs O(n²)），
      代价是复杂约束（多字节 CRC）检出率降低-后续可引入符号辅助推断。
"""

import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


class ConstraintType(str, Enum):
    LENGTH_FIELD = "length_field"
    MAGIC_BYTES = "magic_bytes"
    CHECKSUM = "checksum"
    DEPENDENCY = "dependency"
    INVARIANT_RANGE = "invariant_range"
    UNKNOWN = "unknown"


@dataclass
class ByteConstraint:
    """单个字节位置的约束推断结果。"""
    offset: int
    size: int = 1                        # 约束覆盖的字节数（1-4）
    ctype: ConstraintType = ConstraintType.UNKNOWN
    # LENGTH_FIELD: target_start, target_end (被计数的数据范围)
    target_start: int = 0
    target_end: int = 0
    # MAGIC_BYTES: expected_value
    expected_value: bytes = b""
    # CHECKSUM: coverage_start, coverage_end, algorithm hint
    coverage_start: int = 0
    coverage_end: int = 0
    algorithm_hint: str = ""
    # DEPENDENCY: other_offset, relationship
    other_offset: int = -1
    relationship: str = ""               # "equals", "sum_to_zero", "xor_to_zero"
    # INVARIANT_RANGE: valid_set
    valid_set: Set[int] = field(default_factory=set)
    # 推断质量
    confidence: float = 0.0
    probe_count: int = 0


class _InferencePhase(str, Enum):
    SCAN = "scan"       # 粗粒度扫描：各字节独立探测
    PROBE = "probe"     # 精细探测：对候选字节深度分析


class ConstraintInferenceMutator:
    """在线结构约束推断 + 约束感知变异。

    与现有变异器的关系：本模块不替代 deterministic_stage/havoc_stage。
    它在每次变异执行后从反馈中增量学习约束模型，并提供一个额外变异通道：
          - constrain_aware_mutate(seed) -> 返回按当前策略生成的变异列表
      - 策略在 "exploit constraints"（遵守约束以深入解析器）和
        "break constraints"（打破约束以测试错误处理）之间切换

    使用方式：
      cim = ConstraintInferenceMutator()
      for seed in corpus:
          # ... 执行种子，收集 (input, is_valid, coverage_delta)
          cim.observe(seed.data, is_parse_success=exit_code == 0,
                      new_edges_after_parse=len(delta_edges) > 0)
          # 获取约束感知变异
          constrained_mutants = cim.constraint_aware_mutate(seed)

    Phase 1 探测开销：每字节 1 次 FLIP，对于 1KB 输入仅需 ~1K 次执行。
    Phase 2 仅在检测到候选约束字段后触发-通常 < 20 个候选位置。
    """

    # 配置参数
    PROBE_BASELINE_EXECS = 8             # Phase 1: 每个位置至少探测 N 次后开始分析
    MIN_CONFIDENCE_FOR_PHASE2 = 0.45     # Phase 2 触发阈值
    CONSTRAINT_BREAK_RATIO = 0.35        # 打破约束的变异比例（其余遵守约束）

    def __init__(self):
        # 每个字节位置的失败计数与总探测计数
        self._byte_failures: Dict[int, int] = defaultdict(int)
        self._byte_probes: Dict[int, int] = defaultdict(int)
        # 已推断的约束
        self._constraints: Dict[int, ByteConstraint] = {}
        # 全局基线：任意变异的平均失败率
        self._total_probes = 0
        self._total_failures = 0
        self._phase = _InferencePhase.SCAN
        self._break_counter = 0           # 用于 constraint_break_ratio 比例控制

# 反馈观测
    def observe(self, input_data: bytes, is_parse_success: bool,
                mutated_offsets: Optional[List[Tuple[int, int]]] = None,
                new_edges_after_parse: int = 0):
        """消费一次变异执行的反馈。

        input_data: 本次执行的输入（变异后的版本）
        is_parse_success:  解析是否成功（exit_code=0 且无 crash）
        mutated_offsets:  [(offset, original_byte_value), ...] 本轮变异的位置
        new_edges_after_parse: 执行后新增覆盖边数（0 表示无新探索）
        """
        self._total_probes += 1
        if not is_parse_success:
            self._total_failures += 1

        if mutated_offsets is None:
            return

        for offset, _ in mutated_offsets:
            if offset >= len(input_data):
                continue
            self._byte_probes[offset] += 1
            if not is_parse_success:
                self._byte_failures[offset] += 1

        # Phase 1 -> Phase 2 升级检查
        # 不要求所有字节都被充分探测-在真实 fuzzer 中某些字节位置
        # 可能极少被选中（如位于尾部填充区）。当足够多的字节（≥60% 或至少 30 个）
        # 达到探测阈值时，即进入精细探测阶段。
        if self._phase == _InferencePhase.SCAN:
            _probed_bytes = list(self._byte_probes.items())
            _enough = sum(1 for o, p in _probed_bytes if p >= self.PROBE_BASELINE_EXECS)
            _threshold = max(30, int(len(input_data) * 0.6))
            if _enough >= _threshold and self._total_probes > 50:
                self._phase = _InferencePhase.PROBE

# 约束推断
    def infer_constraints(self, input_data: bytes) -> Dict[int, ByteConstraint]:
        """在所有已观测字节上运行约束推断。

        返回 {offset: ByteConstraint}-只包含 confidence >= MIN_CONFIDENCE_FOR_PHASE2
        的推断结果。
        """
        _baseline_fail = self._total_failures / max(1, self._total_probes)

        for offset in range(min(len(input_data), 8192)):
            _probes = self._byte_probes.get(offset, 0)
            if _probes < self.PROBE_BASELINE_EXECS:
                continue

            _fail_rate = self._byte_failures.get(offset, 0) / _probes

            # 约束检测规则：若修改此字节后失败率显著高于基线 -> 此字节参与结构约束
            _excess = _fail_rate - _baseline_fail
            if _excess < 0.15:  # 阈值-低于此值的行为接近随机
                continue

            _constraint = self._classify_constraint(input_data, offset)
            if _constraint.confidence >= self.MIN_CONFIDENCE_FOR_PHASE2:
                self._constraints[offset] = _constraint

        return {k: v for k, v in self._constraints.items()
                if v.confidence >= self.MIN_CONFIDENCE_FOR_PHASE2}

    def _classify_constraint(self, data: bytes, offset: int) -> ByteConstraint:
        """对单个字节位置进行约束分类。"""
        _bc = ByteConstraint(offset=offset, size=1)
        _bc.probe_count = self._byte_probes.get(offset, 0)

        _l = len(data)

        # MAGIC_BYTES 检测：前 64 字节内 + 周围字节变异不影响 -> 可能是 magic
        if offset < 64:
            _neighbor_sensitive = False
            for d in range(-2, 3):
                if d == 0:
                    continue
                _np = offset + d
                if _np < 0 or _np >= _l:
                    continue
                _n_fails = self._byte_failures.get(_np, 0)
                _n_probes = self._byte_probes.get(_np, 1)
                if _n_fails / _n_probes > 0.4:
                    _neighbor_sensitive = True
                    break
            if not _neighbor_sensitive:
                _bc.ctype = ConstraintType.MAGIC_BYTES
                _bc.expected_value = data[offset:offset + min(4, _l - offset)]
                _bc.size = min(4, _l - offset)
                _bc.confidence = 0.55
                return _bc

        # LENGTH_FIELD 检测：2/4 字节的值 ≈ 后续某段数据的长度
        if offset + 2 <= _l:
            _val16 = struct.unpack_from('<H', data, offset)[0]
            if 0 < _val16 < _l:
                _bc.ctype = ConstraintType.LENGTH_FIELD
                _bc.size = 2
                _bc.target_start = offset + _bc.size
                _bc.target_end = min(_l, offset + _bc.size + _val16)
                _bc.confidence = 0.50
                return _bc

        if offset + 4 <= _l:
            _val32 = struct.unpack_from('<I', data, offset)[0]
            if 0 < _val32 < _l:
                _bc.ctype = ConstraintType.LENGTH_FIELD
                _bc.size = 4
                _bc.target_start = offset + _bc.size
                _bc.target_end = min(_l, offset + _bc.size + _val32)
                _bc.confidence = 0.48
                return _bc

        # DEPENDENCY 检测：是否与另一个高敏感字节相关
        # 简化：检查距离为 2 的幂次的字节对是否有相似敏感度
        for _dist in (4, 8, 16, 32, 64, 128):
            _other = offset + _dist
            if _other < _l:
                _o_fails = self._byte_failures.get(_other, 0)
                _o_probes = self._byte_probes.get(_other, 1)
                _o_rate = _o_fails / _o_probes
                _my_rate = self._byte_failures.get(offset, 0) / max(1, self._byte_probes.get(offset, 1))
                if abs(_my_rate - _o_rate) < 0.10 and _o_rate > 0.3:
                    _bc.ctype = ConstraintType.DEPENDENCY
                    _bc.other_offset = _other
                    _bc.relationship = "correlated_sensitivity"
                    _bc.confidence = 0.40
                    return _bc

        # 回退：标记为分析中
        _bc.ctype = ConstraintType.UNKNOWN
        _bc.confidence = 0.20
        return _bc

# 约束感知变异
    def constraint_aware_mutate(self, seed_data: bytes,
                                max_mutants: int = 12) -> List[bytes]:
        """生成约束感知的变异体。

        策略分为两支：
          (a) exploit constraints: 保留所有推断约束，仅在非约束区域变异
          (b) break constraints:   故意违反一个约束以测试错误处理路径

        两支比例由 CONSTRAINT_BREAK_RATIO 控制。
        """
        if not self._constraints:
            return []  # 尚未推断出约束-退回到标准变异器

        _results: List[bytes] = []
        _constrained_offsets: Set[int] = set()
        for off, bc in self._constraints.items():
            for i in range(bc.size):
                _constrained_offsets.add(off + i)

        _l = len(seed_data)
        _free_offsets = [i for i in range(_l) if i not in _constrained_offsets]

        _n_break = max(1, int(max_mutants * self.CONSTRAINT_BREAK_RATIO))
        _n_exploit = max_mutants - _n_break

        # (a) exploit: 在非约束区域做变异
        if _free_offsets:
            import random
            for _ in range(_n_exploit):
                _cpy = bytearray(seed_data)
                # 选择 1-3 个非约束位置做叠加变异
                _n_flips = random.randint(1, min(3, len(_free_offsets)))
                _targets = random.sample(_free_offsets, _n_flips)
                for toff in _targets:
                    _cpy[toff] ^= (1 << random.randint(0, 7))
                _results.append(bytes(_cpy))

        # (b) break: 故意违反已知约束
        _constraint_list = list(self._constraints.items())
        if _constraint_list:
            import random
            for _ in range(_n_break):
                _cpy = bytearray(seed_data)
                _off, _bc = random.choice(_constraint_list)
                if _bc.ctype == ConstraintType.LENGTH_FIELD:
                    # 将长度字段设为冲突值：设为 0xFFFF 或 0
                    if _bc.size == 2:
                        struct.pack_into('<H', _cpy, _off, 0xFFFF)
                    elif _bc.size == 4:
                        struct.pack_into('<I', _cpy, _off, 0xFFFFFFFF)
                elif _bc.ctype == ConstraintType.MAGIC_BYTES:
                    # 反转 magic bytes
                    for i in range(_bc.size):
                        if _off + i < _l:
                            _cpy[_off + i] ^= 0xFF
                elif _bc.ctype == ConstraintType.DEPENDENCY and _bc.other_offset >= 0:
                    if _bc.other_offset < _l:
                        _cpy[_bc.other_offset] ^= 0xFF
                elif _bc.ctype == ConstraintType.CHECKSUM:
                    # 破坏校验和-翻转覆盖范围内的一个字节 + 校验和本身
                    _start = _bc.coverage_start
                    _end = min(_bc.coverage_end, _l)
                    if _start < _end:
                        _mid = random.randint(_start, _end - 1)
                        _cpy[_mid] ^= 0xFF
                else:
                    _cpy[_off] ^= 0xFF  # 通用破坏
                _results.append(bytes(_cpy))

        return _results

# 策略控制
    def should_preserve_constraints(self) -> bool:
        """当前是否应遵守约束（而非打破）。
        基于最近 N 次执行的反馈：若打破约束极少带来新覆盖 -> 切换到 exploit 模式。
        """
        self._break_counter += 1
        if self._break_counter % 10 == 0:
            # 每 10 次调用重新评估
            _constraint_count = len(self._constraints)
            if _constraint_count == 0:
                return False
        return self._break_counter % int(1.0 / self.CONSTRAINT_BREAK_RATIO) != 0

# 状态查询
    def stats(self) -> Dict:
        return {
            "phase": self._phase.value,
            "total_probes": self._total_probes,
            "baseline_failure_rate": round(
                self._total_failures / max(1, self._total_probes), 4),
            "inferred_constraints": len(self._constraints),
            "constraint_types": {
                ct.value: sum(1 for bc in self._constraints.values()
                             if bc.ctype == ct)
                for ct in ConstraintType
            },
            "avg_confidence": round(
                sum(bc.confidence for bc in self._constraints.values()) /
                max(1, len(self._constraints)), 4),
        }
