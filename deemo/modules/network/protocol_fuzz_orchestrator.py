"""协议模糊测试编排器 —— 统一协议感知模糊测试调度框架。

整合模块内多个fuzz引擎（CAN注入、ICS模板、IoT协议），提供：
- 基于覆盖反馈的种子调度（LibAFL-style）
- 协议状态感知的变异策略选择
- 跨协议模糊测试结果关联分析

参考文献：
- LibAFL: 构建模块化可复用Fuzzer的框架
- 协议模糊化调查 —— 协议模糊测试分类法
- 基于模糊测试与符号执行的IoT协议需求测试: CoAP应用 (Asadian et al., 2024)
"""
import time, math, uuid, logging
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Dict, Optional, Any, Tuple, Callable

_log = logging.getLogger(__name__)

class FuzzStrategy(IntEnum):
    """协议模糊测试策略 —— 协议模糊化调查分类法"""
    GENERATION_BASED = 0    # 基于语法生成（需协议模型）
    MUTATION_BASED = 1      # 基于种子变异（不依赖模型）
    STATE_GUIDED = 2        # 状态引导（需状态机模型）
    COVERAGE_GUIDED = 3     # 覆盖率引导（需插桩）
    GREYBOX_HYBRID = 4      # 灰盒混合（本实现默认策略）


@dataclass
class FuzzSeed:
    """模糊测试种子 —— 含协议上下文和反馈元数据

    设计决策：每种子绑定协议+状态上下文，使调度器可按
    协议×状态维度分配fuzz预算。维度划分参考协议模糊化
    调查 §4.2 的状态感知调度策略。
    """
    seed_id: str = ""
    protocol: str = ""
    data: bytes = b""
    state_context: str = ""      # 协议状态标识（如 CONNECTED, IDLE）
    creation_time: float = 0.0
    parent_id: str = ""          # 产生此种子的变异源
    energy: float = 1.0          # LibAFL 能量调度 —— 高能种子获得更多变异次数
    fuzz_count: int = 0          # 已执行的模糊迭代次数
    crash_count: int = 0         # 产生的崩溃数
    edge_coverage: int = 0       # 覆盖的新边数（需插桩）
    # 熵反馈 —— Asadian et al. 2024: 高熵输出暗示深路径
    entropy_score: float = 0.0


@dataclass
class FuzzReport:
    protocol: str = ""
    total_iterations: int = 0
    unique_crashes: int = 0
    seeds_evaluated: int = 0
    strategy_distribution: Dict[str, int] = field(default_factory=dict)
    top_seeds: List[str] = field(default_factory=list)
    entropy_trajectory: List[float] = field(default_factory=list)


class PowerScheduler:
    """LibAFL 风格的能量调度器 —— 基于历史反馈分配变异预算

    核心思想（LibAFL §3.2）：种子能量 = f(执行时间, 覆盖率增益, 崩溃次数)
    新发现的路径→高能；频繁执行但无新覆盖→能量衰减。

    本实现简化为基于熵反馈+崩溃计数的加权方案（无实际覆盖率插桩）。
    """

    def __init__(self, alpha: float = 0.3):
        self._alpha = alpha
        self._seed_scores: Dict[str, float] = {}

    def assign_energy(self, seed: FuzzSeed, base: int = 100) -> int:
        """计算种子应获得的变异次数

        公式（简化自 LibAFL compute_energy）：
        energy = base × (1 + log(1 + crashes) × 0.5 + entropy × 0.3)
        """
        crash_bonus = math.log2(1 + seed.crash_count) * 0.5
        ent_bonus = seed.entropy_score * 0.3

        key = seed.seed_id
        prev = self._seed_scores.get(key, 1.0)
        raw_score = 1.0 + crash_bonus + ent_bonus
        # EWMA 平滑以避免能量剧烈波动
        new_score = prev + self._alpha * (raw_score - prev)
        self._seed_scores[key] = new_score

        energy = max(1, int(base * new_score))
        return min(energy, base * 10)  # 上限：防止单一种子垄断预算

    def decay(self, seed: FuzzSeed) -> None:
        """衰减无产出种子能量 —— 执行多次但无新发现则降权"""
        key = seed.seed_id
        self._seed_scores[key] = self._seed_scores.get(key, 1.0) * 0.8


class ProtocolFuzzOrchestrator:
    """协议模糊测试编排器 —— 管理多协议fuzz会话调度与结果聚合。

    架构：
    1. 种子队列：按协议+状态分组的优先级队列
    2. 能量调度：LibAFL style power scheduling with entropy feedback
    3. 策略选择：基于协议类型自动选择 generation/mutation/hybrid
    4. 结果关联：跨协议崩溃模式匹配（同一解析器缺陷可被多协议触发）

    不直接执行fuzz —— 委托给各协议专用 injector/generator。
    本类负责调度逻辑和结果聚合。
    """

    def __init__(self, differential_voter=None):
        # differential_voter: 可选ConsensusVoter实例，用于跨实现差分测试
        self._seeds: Dict[str, List[FuzzSeed]] = defaultdict(list)  # protocol → seeds
        self._scheduler = PowerScheduler()
        self._reports: List[FuzzReport] = []
        self._crash_signatures: Dict[str, List[str]] = defaultdict(list)
        self._session_id = uuid.uuid4().hex[:8]
        self._differential_voter = differential_voter
        self._diff_verdicts: List[Any] = []  # OracleVerdict列表

    def register_seed(self, protocol: str, data: bytes,
                      state: str = "default",
                      parent_id: str = "") -> FuzzSeed:
        """注册新种子到调度队列"""
        seed = FuzzSeed(
            seed_id=f"{protocol}_{uuid.uuid4().hex[:6]}",
            protocol=protocol,
            data=data,
            state_context=state,
            creation_time=time.time(),
            parent_id=parent_id,
        )
        self._seeds[protocol].append(seed)
        return seed

    def select_seed(self, protocol: str,
                    strategy: FuzzStrategy = FuzzStrategy.GREYBOX_HYBRID) -> Optional[FuzzSeed]:
        """选取下一待模糊测试种子 —— 加权随机选择

        权重 = 能量调度分 × 种子年龄（优先年老未充分fuzz的种子）
        """
        candidates = self._seeds.get(protocol, [])
        if not candidates:
            return None

        now = time.time()
        # 计算权重
        weights = []
        for s in candidates:
            energy = self._scheduler._seed_scores.get(s.seed_id, 1.0)
            age_hours = max(0.0, (now - s.creation_time) / 3600.0)
            w = energy * (1.0 + math.log2(1 + age_hours))
            weights.append(w)

        total = sum(weights)
        if total <= 0:
            import random
            return random.choice(candidates)

        # 加权随机
        import random
        r = random.uniform(0, total)
        acc = 0.0
        for s, w in zip(candidates, weights):
            acc += w
            if r <= acc:
                s.fuzz_count += 1
                return s
        return candidates[-1]

    def feedback(self, seed: FuzzSeed, crashes: int = 0,
                 entropy: float = 0.0, unique_paths: int = 0) -> None:
        """反馈循环 —— 更新种子评分和能量

        参考 Asadian et al. 2024 的 CoAP 模糊测试反馈策略：
        将输出熵作为覆盖率代理信号，高熵变异→深解析路径。
        """
        seed.crash_count += crashes
        seed.entropy_score = max(seed.entropy_score, entropy)
        seed.edge_coverage += unique_paths

        if crashes > 0 or unique_paths > 0:
            self._scheduler.assign_energy(seed)
        else:
            self._scheduler.decay(seed)

    def record_crash(self, protocol: str, crash_sig: str,
                     seed_id: str = "") -> None:
        """记录崩溃签名 —— 用于跨协议去重和模式关联"""
        key = f"{protocol}:{crash_sig[:64]}"
        self._crash_signatures[key].append(seed_id)

    def select_strategy(self, protocol: str,
                        has_state_model: bool = False,
                        has_instrumentation: bool = False) -> FuzzStrategy:
        if has_state_model and has_instrumentation:
            return FuzzStrategy.STATE_GUIDED
        if has_state_model:
            return FuzzStrategy.GENERATION_BASED
        return FuzzStrategy.GREYBOX_HYBRID  # 默认：无模型+无instrument → 灰盒

    def generate_report(self, protocol: str) -> FuzzReport:
        """生成单协议模糊测试报告"""
        seeds = self._seeds.get(protocol, [])
        crashes = sum(
            1 for key in self._crash_signatures
            if key.startswith(f"{protocol}:")
        )

        strategies_used = Counter()
        for s in seeds:
            strategies_used["greybox_hybrid"] += 1  # 默认策略

        top_seeds = sorted(seeds, key=lambda s: -s.crash_count)[:5]

        report = FuzzReport(
            protocol=protocol,
            total_iterations=sum(s.fuzz_count for s in seeds),
            unique_crashes=crashes,
            seeds_evaluated=len(seeds),
            strategy_distribution=dict(strategies_used),
            top_seeds=[s.seed_id for s in top_seeds],
            entropy_trajectory=[s.entropy_score for s in seeds if s.entropy_score > 0],
        )
        self._reports.append(report)
        return report

    def correlate_crashes(self) -> Dict[str, List[str]]:
        """跨协议崩溃关联 —— 检测同一解析器缺陷引起的多协议崩溃。

        相关性评分：若两协议出现相同崩溃签名前缀（如相同的
        缓冲区溢出模式），可能为同一底层库缺陷。
        """
        correlations: Dict[str, List[str]] = defaultdict(list)
        sig_by_proto: Dict[str, set] = defaultdict(set)

        for key, seed_ids in self._crash_signatures.items():
            proto, sig = key.split(":", 1)
            sig_by_proto[proto].add(sig[:32])  # 取签名前缀

        protocols = list(sig_by_proto.keys())
        for i in range(len(protocols)):
            for j in range(i + 1, len(protocols)):
                p1, p2 = protocols[i], protocols[j]
                overlap = sig_by_proto[p1] & sig_by_proto[p2]
                if overlap:
                    correlations[f"{p1}<->{p2}"] = list(overlap)[:5]

        return dict(correlations)

    def summary(self) -> Dict[str, Any]:
        base = {
            "session_id": self._session_id,
            "total_seeds": sum(len(s) for s in self._seeds.values()),
            "protocols_fuzzed": list(self._seeds.keys()),
            "total_iterations": sum(
                s.fuzz_count for seeds in self._seeds.values() for s in seeds
            ),
            "unique_crashes": len(self._crash_signatures),
            "cross_protocol_correlations": self.correlate_crashes(),
            "top_protocol_by_crashes": sorted(
                [(p, sum(1 for k in self._crash_signatures if k.startswith(f"{p}:")))
                 for p in self._seeds],
                key=lambda x: -x[1],
            )[:5],
        }
        if self._diff_verdicts:
            diverged = [v for v in self._diff_verdicts
                       if hasattr(v, 'verdict') and
                       getattr(v.verdict, 'name', '') == 'CONSENSUS_MINORITY_BUG']
            base["differential"] = {
                "total_verdicts": len(self._diff_verdicts),
                "bugs_found": len(diverged),
                "minority_impls": list(set(
                    impl for v in diverged
                    for impl in getattr(v, 'minority_impls', [])
                )),
            }
        return base

    # ── 差分跨实现测试 ─────────────────────────────────────
    def run_differential_check(self,
                                protocol: str,
                                impl_responses: List[Any]
                                ) -> Optional[Any]:
        """对多实现响应执行差分预言机判定。

        impl_responses: ImplResponse列表(N≥3)，来自同一输入发送至
        不同协议实现的响应。若提供了differential_voter，
        执行共识投票并将判定缓存至_diff_verdicts。

        返回OracleVerdict或None(未配置voter时)。
        """
        if self._differential_voter is None:
            return None
        if len(impl_responses) < 3:
            return None
        verdict = self._differential_voter.vote(impl_responses)
        self._diff_verdicts.append(verdict)
        return verdict


def orchestrate_fuzzing(protocol_seeds: Dict[str, List[bytes]]) -> Dict[str, Any]:
    """便捷入口 —— 传入 {protocol: [seed_bytes, ...]} 启动编排会话"""
    orch = ProtocolFuzzOrchestrator()
    for proto, seed_list in protocol_seeds.items():
        for data in seed_list:
            orch.register_seed(proto, data)
        orch.generate_report(proto)
    return orch.summary()


__all__ = ["ProtocolFuzzOrchestrator", "PowerScheduler", "FuzzSeed",
           "FuzzReport", "FuzzStrategy", "orchestrate_fuzzing"]
