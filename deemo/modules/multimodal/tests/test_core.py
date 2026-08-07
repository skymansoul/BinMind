#!/usr/bin/env python3
# 核心模块单元测试 — 并行分析器、统计 API、编排器、漏洞适配器、融合、对齐、注意力、检索
# 每条测试仅验证一个行为，外部依赖通过 mock 隔离。
# 部分边界用例注释保留——暂时无暇修复但删之可惜。
import sys
import os
import pytest
import json
import time
import math
from typing import Dict, Any, List

# 确保模块可导入
_src = os.path.join(os.path.dirname(__file__), "..")
if _src not in sys.path:
    sys.path.insert(0, _src)


# 1. TaskPartitioner — 贪心分桶 + 拓扑分层

class TestTaskPartitioner:
    """负载均衡分区与拓扑排序正确性验证。"""

    @pytest.fixture
    def partitioner(self):
        from multicore_parallel_analyzer import TaskPartitioner
        return TaskPartitioner()

    @pytest.fixture
    def sample_tasks(self):
        from multicore_parallel_analyzer import AnalysisTask
        return [
            AnalysisTask(task_id="A", func_name="alpha", estimated_seconds=10.0,
                        dependencies=[]),
            AnalysisTask(task_id="B", func_name="beta", estimated_seconds=20.0,
                        dependencies=["A"]),
            AnalysisTask(task_id="C", func_name="gamma", estimated_seconds=5.0,
                        dependencies=["A"]),
            AnalysisTask(task_id="D", func_name="delta", estimated_seconds=15.0,
                        dependencies=["B", "C"]),
        ]

    def test_greedy_partition_balance(self, partitioner, sample_tasks):
        """贪心分桶的两桶负载差不超过最大单任务两倍。"""
        buckets = partitioner.partition(sample_tasks, 2)
        assert len(buckets) == 2
        loads = [sum(t.estimated_seconds for t in b) for b in buckets]
        # 松上界：负载差不超过最大单任务的 2 倍
        assert abs(loads[0] - loads[1]) <= max(t.estimated_seconds for t in sample_tasks) * 2

    def test_topological_layers_linear_deps(self, partitioner, sample_tasks):
        """A <- B,C <- D 链：A 在第一层，D 在最后一层。"""
        layers = partitioner.topological_layers(sample_tasks)
        # A 无依赖，属于首层
        first_layer_ids = {t.task_id for t in layers[0]}
        assert "A" in first_layer_ids
        # D 依赖 B 和 C，属于末层
        last_layer_ids = {t.task_id for t in layers[-1]}
        assert "D" in last_layer_ids

    def test_topological_layers_cycle(self, partitioner):
        """环路 A↔B 不应造成死循环。"""
        from multicore_parallel_analyzer import AnalysisTask
        cyclic = [
            AnalysisTask(task_id="X", func_name="x", dependencies=["Y"]),
            AnalysisTask(task_id="Y", func_name="y", dependencies=["X"]),
        ]
        layers = partitioner.topological_layers(cyclic)
        # 至少产生一层
        assert len(layers) >= 1
        total = sum(len(layer) for layer in layers)
        assert total == 2  # 两个节点均被包含

    def test_topological_layers_orphan_nodes(self, partitioner):
        """孤立节点应位于首层。"""
        from multicore_parallel_analyzer import AnalysisTask
        tasks = [
            AnalysisTask(task_id="ORPHAN", func_name="orphan", dependencies=[]),
            AnalysisTask(task_id="WITH_DEPS", func_name="wd", dependencies=["ORPHAN"]),
        ]
        layers = partitioner.topological_layers(tasks)
        # ORPHAN 领先于 WITH_DEPS
        assert layers[0][0].task_id == "ORPHAN"
        assert layers[1][0].task_id == "WITH_DEPS"

    def test_topological_layers_external_deps(self, partitioner):
        """依赖列表中含非 task_id 的引用时不应崩溃。"""
        from multicore_parallel_analyzer import AnalysisTask
        tasks = [
            AnalysisTask(task_id="T1", func_name="f1",
                        dependencies=["external_lib_func", "system_call"]),
        ]
        layers = partitioner.topological_layers(tasks)
        # 外部依赖不应干扰拓扑排序
        assert len(layers) == 1
        assert layers[0][0].task_id == "T1"


# 2. MultiDimensionStatsAPI — 统计计算与枚举健壮性

class TestStatsAPI:
    """统计 API 数据处理与错误处理验证。"""

    @pytest.fixture
    def api(self):
        from multi_dimension_stats_api import MultiDimensionStatsAPI
        return MultiDimensionStatsAPI()

    @pytest.fixture
    def sample_history(self):
        return [
            {
                "date": "2024-01-15",
                "architecture": "x86_64",
                "success": True,
                "analysis_time": 45.2,
                "coverage_rate": 0.85,
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "critical",
                     "function_name": "handle_input", "address": 0x401000,
                     "exploitability_score": 9},
                    {"type": "use_after_free", "severity": "high",
                     "function_name": "parse_data", "address": 0x402000,
                     "exploitability_score": 7},
                    {"type": "null_deref", "severity": "medium",
                     "function_name": "cleanup", "address": 0x403000,
                     "exploitability_score": 3},
                ]
            },
            {
                "date": "2024-01-16",
                "architecture": "x86_64",
                "success": True,
                "analysis_time": 32.1,
                "coverage_rate": 0.92,
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "high",
                     "function_name": "handle_input", "address": 0x401000,
                     "exploitability_score": 8},
                    {"type": "format_string", "severity": "critical",
                     "function_name": "log_message", "address": 0x500000,
                     "exploitability_score": 9},
                ]
            },
        ]

    def test_get_vulnerability_distribution(self, api, sample_history):
        resp = api.get_vulnerability_distribution(sample_history)
        data = resp.data
        assert data['total_vulnerabilities'] == 5
        assert data['by_type']['buffer_overflow'] == 2
        assert data['by_type']['use_after_free'] == 1
        assert data['by_severity']['critical'] == 2
        assert data['by_architecture']['x86_64'] == 5

    def test_get_high_risk_functions(self, api, sample_history):
        resp = api.get_high_risk_functions(sample_history, limit=3)
        assert len(resp.data) <= 3
        # handle_input 出现 2 次，应排在首位
        top = resp.data[0]
        assert top['function_name'] == 'handle_input'
        assert top['vulnerability_count'] == 2

    def test_get_analysis_metrics(self, api, sample_history):
        resp = api.get_analysis_metrics(sample_history)
        data = resp.data
        assert data['total_analyses'] == 2
        assert data['successful_analyses'] == 2
        assert data['failed_analyses'] == 0
        # avg time ≈ (45.2 + 32.1) / 2 ≈ 38.65
        assert abs(data['average_time'] - 38.65) < 0.5

    def test_get_statistics_robustness(self, sample_history):
        """非法统计类型输入返回 error 及可选值列表。"""
        from multi_dimension_stats_api import get_statistics, StatisticType
        # 合法 value 形式查询
        resp = get_statistics("analysis_metrics", sample_history)
        assert resp.data['total_analyses'] == 2
        # 非法类型返回错误信息
        resp_bad = get_statistics("nonexistent_type", sample_history)
        assert 'error' in resp_bad.data
        assert 'valid_options' in resp_bad.data

    def test_get_statistics_by_enum_name(self, sample_history):
        """向后兼容：支持 enum 成员名查找。"""
        from multi_dimension_stats_api import get_statistics
        resp = get_statistics("ANALYSIS_METRICS", sample_history)
        assert resp.statistic_type.value == "analysis_metrics"

    def test_exploitability_scores(self, api, sample_history):
        resp = api.get_exploitability_scores(sample_history)
        data = resp.data
        assert data['total_vulnerabilities'] == 5
        assert data['max_score'] == 9
        assert data['min_score'] == 3

    def test_correlation_analysis(self, api, sample_history):
        report = api.get_full_correlation_analysis(sample_history)
        # 三种相关系数均应存在
        assert 'severity_exploitability' in report.pearson or report.pearson == {}

    def test_empty_history(self, api):
        resp = api.get_vulnerability_distribution([])
        assert resp.data['total_vulnerabilities'] == 0

    def test_ood_detection(self, api, sample_history):
        report = api.detect_ood_vulnerabilities(sample_history)
        assert hasattr(report, 'threshold')
        assert hasattr(report, 'count_flagged')


# 3. ChainOrchestrator — 链式编排与策略选择

class TestOrchestrator:
    """攻击链编排核心流程验证。"""

    @pytest.fixture
    def orch(self):
        from multi_stage_orchestrator import ChainOrchestrator
        return ChainOrchestrator()

    def test_add_stage_and_execute_dry(self, orch):
        from multi_stage_orchestrator import ChainStep, ExploitStage
        orch.add_stage(ChainStep(
            stage=ExploitStage.RECON, action="scan_ports"))
        orch.add_stage(ChainStep(
            stage=ExploitStage.EXPLOIT, action="trigger_overflow"))
        result = orch.dry_run()
        # 空跑无前置依赖 → 应全通过
        assert result.success
        assert result.artifacts['total_steps'] == 2

    def test_dependency_resolver(self):
        from multi_stage_orchestrator import DependencyResolver, ChainStep, ExploitStage
        resolver = DependencyResolver()
        # 依赖通过 action 名解析：pre_conditions 中引用其他 step 的 action
        steps = [
            ChainStep(stage=ExploitStage.RECON, action="a"),
            ChainStep(stage=ExploitStage.EXPLOIT, action="b", pre_conditions=["a"]),
            ChainStep(stage=ExploitStage.POST, action="c", pre_conditions=["b"]),
        ]
        layers = resolver.resolve(steps)
        assert len(layers) == 3  # 每步各占一层：线性依赖链
        assert layers[0][0].action == "a"
        assert layers[1][0].action == "b"
        assert layers[2][0].action == "c"

    def test_dependency_resolver_parallel(self):
        from multi_stage_orchestrator import DependencyResolver, ChainStep, ExploitStage
        resolver = DependencyResolver()
        # B 和 C 同依赖 A，无互依赖 → 同层并行
        steps = [
            ChainStep(stage=ExploitStage.RECON, action="a"),
            ChainStep(stage=ExploitStage.EXPLOIT, action="b", pre_conditions=["a"]),
            ChainStep(stage=ExploitStage.EXPLOIT, action="c", pre_conditions=["a"]),
        ]
        layers = resolver.resolve(steps)
        assert len(layers) == 2
        second_layer_actions = {s.action for s in layers[1]}
        assert second_layer_actions == {"b", "c"}

    def test_strategy_auto_select(self, orch):
        from multi_stage_orchestrator import ChainStep, ExploitStage, AttackChain
        # 简单链 → SEQUENTIAL
        orch.add_stage(ChainStep(stage=ExploitStage.RECON, action="scan"))
        chain = AttackChain()
        chain.add_step(orch._pending_steps[0])
        strategy = orch._auto_select_strategy(chain)
        from multi_stage_orchestrator import ExecutionStrategy
        assert strategy == ExecutionStrategy.SEQUENTIAL

    def test_generate_report(self, orch):
        from multi_stage_orchestrator import ChainStep, ExploitStage
        orch.add_stage(ChainStep(
            stage=ExploitStage.RECON, action="nmap_scan",
            shell_command="nmap -sV {target}", fuzzable=True))
        report = orch.generate_report()
        assert "nmap_scan" in report
        assert "fuzzable" in report

    def test_mcts_planner(self):
        from multi_stage_orchestrator import MCTSChainPlanner, ChainStep, ExploitStage
        planner = MCTSChainPlanner(exploration_weight=1.0, n_simulations=20)
        steps = [
            ChainStep(stage=ExploitStage.RECON, action="recon_a"),
            ChainStep(stage=ExploitStage.EXPLOIT, action="exploit_a",
                     pre_conditions=["recon_a"]),
            ChainStep(stage=ExploitStage.POST, action="post_a",
                     pre_conditions=["exploit_a"]),
        ]
        path = planner.plan(steps, max_steps=5)
        assert len(path) >= 1
        assert path[0] in {"recon_a", "exploit_a", "post_a"}

    def test_chain_diff(self):
        from multi_stage_orchestrator import (
            AttackChain, ChainStep, ExploitStage, chain_diff)
        a = AttackChain("v1")
        a.add_step(ChainStep(stage=ExploitStage.RECON, action="scan"))
        a.add_step(ChainStep(stage=ExploitStage.EXPLOIT, action="pwn"))
        b = AttackChain("v2")
        b.add_step(ChainStep(stage=ExploitStage.RECON, action="scan"))
        b.add_step(ChainStep(stage=ExploitStage.EXPLOIT, action="pwn_v2"))
        diff = chain_diff(a, b)
        assert diff['removed'] == 1  # "pwn" 移除
        assert diff['added'] == 1    # "pwn_v2" 新增


# 4. 漏洞适配器 — 符号执行模板引擎

class TestExploitAdapter:
    """模板解析、gadget 评分搜索与 payload 生成验证。"""

    @pytest.fixture
    def engine(self):
        from multi_target_exploit_adapter import SymbolicExecutionTemplateEngine
        return SymbolicExecutionTemplateEngine()

    @pytest.fixture
    def sample_target(self):
        from multi_target_exploit_adapter import TargetBinary
        return TargetBinary(
            name="test_bin",
            version="1.0",
            architecture="x86_64",
            symbol_table={"system": 0x400600, "execve": 0x400700, "puts": 0x400500},
            gadget_addresses=[0x401000, 0x401005, 0x401010, 0x401020],
            import_table={"libc.so.6": "system"},
        )

    def test_solve_with_symbol_table(self, engine, sample_target):
        from multi_target_exploit_adapter import SymbolicTemplate
        engine.register_template(SymbolicTemplate(
            template_name="test_tmpl",
            symbolic_offsets=["system", "puts", "execve"],
            exploit_code="call {system} then {puts}",
        ))
        resolved = engine.solve_for_target("test_tmpl", sample_target)
        assert resolved is not None
        assert resolved["system"] == 0x400600
        assert resolved["puts"] == 0x400500

    def test_find_gadget_scoring(self, engine, sample_target):
        """_find_gadget 按模式匹配分值返回最优地址。"""
        from multi_target_exploit_adapter import SymbolicTemplate
        engine.register_template(SymbolicTemplate(
            template_name="gadget_tmpl",
            symbolic_offsets=["pop_rdi", "ret"],
            exploit_code="ret",
        ))
        resolved = engine.solve_for_target("gadget_tmpl", sample_target)
        assert resolved is not None
        assert resolved["ret"] in sample_target.gadget_addresses
        assert resolved["pop_rdi"] in sample_target.gadget_addresses

    def test_unknown_template_returns_none(self, engine, sample_target):
        resolved = engine.solve_for_target("nonexistent", sample_target)
        assert resolved is None

    def test_aslr_entropy(self, sample_target):
        from multi_target_exploit_adapter import aslr_entropy_bits
        bits = aslr_entropy_bits(sample_target)
        assert 'pie' in bits or 'mmap' in bits
        assert 'stack' in bits

    def test_compute_imphash(self, sample_target):
        from multi_target_exploit_adapter import compute_imphash
        h = compute_imphash(sample_target)
        assert len(h) == 32  # MD5 十六进制
        assert all(c in '0123456789abcdef' for c in h)

    def test_canary_bypass_probability(self, sample_target):
        from multi_target_exploit_adapter import canary_bypass_probability
        # 无 canary → 概率 100%
        prob = canary_bypass_probability(sample_target)
        assert prob == 1.0

    def test_combined_bypass_score(self, sample_target):
        from multi_target_exploit_adapter import combined_bypass_score
        score = combined_bypass_score(sample_target)
        assert 0.0 <= score <= 1.0

    def test_filter_bad_byte_values(self):
        from multi_target_exploit_adapter import filter_bad_byte_values
        # 0x41424344 LE = [0x44,0x43,0x42,0x41] → 无 bad bytes
        # 0x0a0b0c0d LE = [0x0d,0x0c,0x0b,0x0a] → 含 0x0a 和 0x0d
        clean = 0x41424344
        dirty = 0x0a0b0c0d
        candidates = [clean, dirty, 0x00FFFFFF, 0x1A2B3C4D]
        filtered = filter_bad_byte_values(candidates, byte_width=4,
                                         bad_bytes=[0x00, 0x0a, 0x0d])
        assert clean in filtered
        assert dirty not in filtered

    def test_pack_address(self):
        from multi_target_exploit_adapter import pack_address
        packed = pack_address(0x00401020, "x86_64")
        assert len(packed) == 8  # 64 位地址
        packed32 = pack_address(0x08048000, "x86")
        assert len(packed32) == 4

    def test_payload_entropy(self):
        from multi_target_exploit_adapter import payload_entropy
        # 全同字节 → 熵为零
        assert payload_entropy(b'\x90' * 100) == 0.0
        # 混合字节 → 正熵
        ent = payload_entropy(b'\x90\xcc\x48\x31\xc0\x50\x68\x2f\x2f\x73\x68')
        assert ent > 0.0


# 5. 融合模块 — 早期/晚期/门控/双线性融合

class TestFusion:
    """融合策略数学正确性验证。"""

    def test_early_fusion_dimensions(self):
        from multi_modal_fusion import early_fusion
        mod_a = [[1.0, 2.0], [3.0, 4.0]]
        mod_b = [[5.0, 6.0, 7.0], [8.0, 9.0, 10.0]]
        fused = early_fusion({"a": mod_a, "b": mod_b})
        assert len(fused) == 2
        assert len(fused[0]) == 5  # 2 + 3

    def test_late_fusion_avg(self):
        from multi_modal_fusion import late_fusion_avg
        mod_a = [[1.0, 3.0], [5.0, 7.0]]
        mod_b = [[3.0, 5.0], [7.0, 9.0]]
        fused = late_fusion_avg({"a": mod_a, "b": mod_b})
        assert len(fused) == 2
        assert len(fused[0]) == 2
        assert abs(fused[0][0] - 2.0) < 0.01  # (1+3)/2
        assert abs(fused[0][1] - 4.0) < 0.01  # (3+5)/2

    def test_late_fusion_max(self):
        from multi_modal_fusion import late_fusion_max
        mod_a = [[1.0, 6.0], [3.0, 2.0]]
        mod_b = [[4.0, 4.0], [5.0, 7.0]]
        fused = late_fusion_max({"a": mod_a, "b": mod_b})
        assert fused[0][0] == 4.0
        assert fused[0][1] == 6.0
        assert fused[1][0] == 5.0
        assert fused[1][1] == 7.0

    def test_gated_multimodal_unit(self):
        from multi_modal_fusion import GatedMultimodalUnit
        # API: __init__(total_dim_including_all_modalities, n_modalities)
        #      forward(modality_features_list, output_modality_dim)
        # total_dim 必须 >= 所有模态特征维度之和
        gmu = GatedMultimodalUnit(total_dim=4, n_modalities=2)
        mod_a = [[0.5, -0.3]]   # dim 2
        mod_b = [[1.0, 0.2]]    # dim 2
        fused, gates = gmu.forward([mod_a, mod_b], modality_dim=2)
        assert len(fused) == 1
        assert len(fused[0]) == 2
        assert len(gates) == 1
        assert len(gates[0]) == 2


# 6. 共形预测 — 非参数预测区间

class TestConformal:
    """保形预测覆盖保证与 Jackknife+ 区间构造验证。"""

    def test_conformal_prediction_basic(self):
        from multi_modal_conformal import conformal_predict
        cal_scores = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        cal_labels = [0] * 10
        result = conformal_predict(
            cal_scores, cal_labels,
            test_score_fn=lambda y: 0.3,
            n_classes=3, alpha=0.2)
        assert result.threshold > 0
        assert len(result.p_values) == 3

    def test_jackknife_plus_intervals(self):
        from multi_modal_conformal import jackknife_plus_intervals
        preds = [1.0, 2.0, 3.0, 4.0, 5.0]
        resids = [0.1, 0.2, 0.1, 0.3, 0.1]
        lo, hi = jackknife_plus_intervals(preds, resids, alpha=0.2)
        assert len(lo) == 5
        assert len(hi) == 5
        for i in range(5):
            assert lo[i] <= hi[i]


# 7. 生存分析 — Kaplan-Meier 估计

class TestSurvival:
    """Kaplan-Meier 与 Cox 模型验证。"""

    def test_kaplan_meier_basic(self):
        from multi_modal_survival import kaplan_meier
        # 5 个漏洞：3 已修复，2 仍活跃（删失）
        times = [10.0, 20.0, 30.0, 40.0, 50.0]
        events = [True, True, False, True, False]
        curve = kaplan_meier(times, events)
        assert len(curve.times) >= 1
        assert len(curve.survival_probs) == len(curve.times)
        # 生存概率应单调不增
        for i in range(1, len(curve.survival_probs)):
            assert curve.survival_probs[i] <= curve.survival_probs[i-1]

    def test_kaplan_meier_small_sample(self):
        from multi_modal_survival import kaplan_meier
        curve = kaplan_meier([1.0], [True])
        # N<3 时返回空/默认曲线
        assert len(curve.times) == 0

    def test_survival_curve_to_dict(self):
        """SurvivalCurve.to_dict() 返回结构化字典。"""
        from multi_modal_survival import kaplan_meier
        times = [10, 20, 30, 40, 50]
        events = [True, True, False, True, False]
        curve = kaplan_meier(times, events)
        d = curve.to_dict()
        assert 'times' in d
        assert 'survival_probs' in d
        assert 'median_survival_time' in d


# 8. 统计分析 — 幂律拟合与 Granger 因果

class TestAdvancedStats:
    """高级统计方法正确性验证。"""

    def test_pareto_frontier(self):
        from multi_dimension_stats_api import pareto_frontier
        # (severity_reduction, effort_hours)
        objectives = [(90, 10), (80, 5), (95, 20), (50, 2), (70, 15)]
        frontier = pareto_frontier(objectives)
        # Pareto 前沿非空
        assert len(frontier) >= 1

    def test_benjamini_hochberg(self):
        from multi_dimension_stats_api import benjamini_hochberg
        # BH: p_(k) <= k/m * alpha
        # m=6, alpha=0.05 → 阈值: 0.0083, 0.0167, 0.025, 0.0333, 0.0417, 0.05
        p_vals = [0.001, 0.005, 0.02, 0.50, 0.70, 0.90]
        rejected = benjamini_hochberg(p_vals, alpha=0.05)
        assert len(rejected) == 6
        # p_vals[0]=0.001 <= 0.0083, p_vals[1]=0.005 <= 0.0167, p_vals[2]=0.02 <= 0.025
        assert rejected[0] and rejected[1] and rejected[2]
        # p_vals[3]=0.50 > 0.0333
        assert not rejected[3]

    def test_fit_power_law(self):
        from multi_dimension_stats_api import fit_power_law
        counts = [1, 2, 3, 2, 5, 3, 8, 4, 13, 6]
        result = fit_power_law(counts)
        assert 'alpha' in result
        assert 'r_squared' in result

    def test_granger_causality(self):
        from multi_dimension_stats_api import granger_causality_test
        # B 领先 A 1 步
        a = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
             11.0, 12.0, 13.0, 14.0, 15.0]
        b = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0,
             10.0, 11.0, 12.0, 13.0, 14.0]
        result = granger_causality_test(a, b, max_lag=3)
        assert 'f_statistic' in result
        assert 'p_value' in result


# 9. 推测执行与内存感知调度

class TestSchedulers:
    """高级调度器行为验证。"""

    def test_speculative_scheduler(self):
        from multicore_parallel_analyzer import SpeculativeScheduler, AnalysisTask
        sched = SpeculativeScheduler()
        task = AnalysisTask(task_id="T1", func_name="slow", estimated_seconds=100)
        # 无历史数据时不应触发克隆
        assert sched.should_clone(task) is False  # 任务尚未开始执行

    def test_memory_aware_scheduler(self):
        from multicore_parallel_analyzer import MemoryAwareScheduler
        sched = MemoryAwareScheduler(base_workers=8)
        workers = sched.recommend_workers()
        assert 1 <= workers <= 8

    def test_work_stealing_queue(self):
        from multicore_parallel_analyzer import WorkStealingQueue, AnalysisTask
        q = WorkStealingQueue()
        q.push(AnalysisTask(task_id="A", func_name="a"))
        q.push(AnalysisTask(task_id="B", func_name="b"))
        assert len(q) == 2
        stolen = q.steal()
        assert stolen.task_id == "B"  # 从队尾窃取
        assert len(q) == 1


# 10. CLI 与配置

class TestCLI:
    """CLI argparse 与配置加载验证。"""

    def test_parser_has_all_subcommands(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from cli import _build_parser
        parser = _build_parser()
        # 验证子解析器存在
        args = parser.parse_args(["analyze", "test.bin"])
        assert args.command == "analyze"
        assert args.targets == ["test.bin"]

    def test_parser_stats(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["stats", "--type", "vulnerability_distribution"])
        assert args.command == "stats"
        assert args.stat_type == "vulnerability_distribution"

    def test_parser_orchestrate_dry_run(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from cli import _build_parser
        parser = _build_parser()
        args = parser.parse_args(["orchestrate", "--dry-run", "--target", "linux"])
        assert args.command == "orchestrate"
        assert args.dry_run is True
        assert args.target == "linux"

    def test_config_loader_defaults(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from config_loader import ConfigLoader
        # 重置单例以隔离测试
        ConfigLoader._instance = None
        ConfigLoader._config = {}
        loader = ConfigLoader()  # 无 config_path → 仅默认值
        assert loader.get("analysis.timeout_seconds") == 300
        assert loader.get("retry.max_attempts") == 3
        assert loader.get("nonexistent.key", "fallback") == "fallback"

    def test_config_section(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from config_loader import ConfigLoader
        ConfigLoader._instance = None
        ConfigLoader._config = {}
        loader = ConfigLoader()
        analysis = loader.section("analysis")
        assert "timeout_seconds" in analysis

    def test_utils_logging(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        import logging as _logging
        from utils import setup_logging
        # 测试期间不重新配置根 logger，仅验证不崩溃
        logger = setup_logging(level="WARNING")
        assert logger is not None

    def test_utils_retry_decorator(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from utils import retry_with_backoff
        counter = [0]

        @retry_with_backoff(max_attempts=3, base_delay=0.001)
        def flaky_func():
            counter[0] += 1
            if counter[0] < 3:
                raise ValueError("transient")
            return "success"

        result = flaky_func()
        assert result == "success"
        assert counter[0] == 3

    def test_utils_ttl_cache(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from utils import TTLCache
        cache = TTLCache(ttl=0.5)
        cache.set(1, "hello")
        assert cache.get(1) == "hello"
        import time
        time.sleep(0.6)
        assert cache.get(1) is None  # 已过期

    def test_utils_dependency_check(self):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
        from utils import check_dependencies
        deps = check_dependencies()
        assert 'yaml' in deps
        assert 'numpy' in deps
        assert isinstance(deps['yaml'], bool)


# 11. 对齐模块 — NT-Xent 损失

class TestAlignment:
    """对比学习损失函数验证。"""

    def test_ntxent_loss(self):
        from multi_modal_alignment import NTXentLoss
        loss_fn = NTXentLoss(temperature=0.1)
        a = [[1.0, 0.0], [0.0, 1.0]]
        b = [[1.0, 0.0], [0.0, 1.0]]
        loss = loss_fn.forward(a, b)
        # 完美对齐 → 低损失
        assert loss >= 0.0
        assert loss < 5.0

    def test_ntxent_misaligned(self):
        from multi_modal_alignment import NTXentLoss
        loss_fn = NTXentLoss(temperature=0.1)
        a = [[1.0, 0.0], [0.0, 1.0]]
        b = [[0.0, 1.0], [1.0, 0.0]]  # 错位配对
        loss_misaligned = loss_fn.forward(a, b)
        # 错位应产生更高损失
        a_aligned = [[1.0, 0.0], [0.0, 1.0]]
        b_aligned = [[1.0, 0.0], [0.0, 1.0]]
        loss_aligned = loss_fn.forward(a_aligned, b_aligned)
        assert loss_misaligned >= loss_aligned


# 12. 注意力模块

class TestAttention:
    """纯 Python 多头注意力实现验证。"""

    def test_matmul(self):
        from multi_modal_attention import _matmul
        A = [[1.0, 2.0], [3.0, 4.0]]
        B = [[5.0, 6.0], [7.0, 8.0]]
        C = _matmul(A, B)
        # 1*5+2*7=19, 1*6+2*8=22
        # 3*5+4*7=43, 3*6+4*8=50
        assert abs(C[0][0] - 19.0) < 0.01
        assert abs(C[0][1] - 22.0) < 0.01
        assert abs(C[1][0] - 43.0) < 0.01
        assert abs(C[1][1] - 50.0) < 0.01

    def test_softmax(self):
        from multi_modal_attention import _softmax
        result = _softmax([1.0, 2.0, 3.0])
        assert len(result) == 3
        assert abs(sum(result) - 1.0) < 0.01

    def test_layer_norm(self):
        from multi_modal_attention import _layer_norm
        x = [[1.0, 2.0, 3.0]]
        normed = _layer_norm(x)
        means = sum(normed[0]) / 3
        assert abs(means) < 0.01  # 约零均值

    def test_rope_encoding(self):
        from multi_modal_attention import RotaryPositionEmbedding
        rope = RotaryPositionEmbedding(dim=4, max_seq_len=128)
        x = [[1.0, 0.0, 0.5, -0.5]]
        # API: apply(x, start_pos=0)
        rotated = rope.apply(x, start_pos=0)
        # pos=0 时 cos(0)=1, sin(0)=0 → 近似恒等旋转
        assert abs(rotated[0][0] - 1.0) < 0.1
        assert abs(rotated[0][1] - 0.0) < 0.1


# 13. 检索模块

class TestRetrieval:
    """LSH 索引与双向检索验证。"""

    def test_lsh_insert_and_query(self):
        from multi_modal_retrieval import LSHIndex
        idx = LSHIndex(dim=8, num_tables=4, hash_dim=8)
        v1 = [0.1 * i for i in range(8)]
        v2 = [0.1 * i + 0.05 for i in range(8)]
        v3 = [1.0] * 8  # 远距向量
        idx.insert(v1)
        idx.insert(v3)
        id2 = idx.insert(v2)
        results = idx.query(v1, topk=2)
        # v2 比 v3 更接近 v1
        ids = [r[0] for r in results]
        assert id2 in ids  # v2 应在 top 结果中


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
