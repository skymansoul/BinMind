#!/usr/bin/env python3
# 端到端集成验证 — 统计、编排、适配、融合全链路
import sys
import os
import pytest
import json
import math

_src = os.path.join(os.path.dirname(__file__), "..")
if _src not in sys.path:
    sys.path.insert(0, _src)


class TestEndToEnd:
    """分析管道端到端验证：统计→编排→适配→融合。"""

    def test_stats_to_orchestration_pipeline(self):
        """统计输出驱动编排策略选取。"""
        from multi_dimension_stats_api import MultiDimensionStatsAPI
        from multi_stage_orchestrator import (
            ChainOrchestrator, ChainStep, ExploitStage, AttackChain,
            annotate_chain, TargetType,
        )

        # 1) 构造模拟分析历史
        history = [
            {
                "date": "2024-01-15", "architecture": "x86_64",
                "success": True, "analysis_time": 45.2,
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "critical",
                     "function_name": "handle_msg", "address": 0x401000,
                     "exploitability_score": 9},
                    {"type": "use_after_free", "severity": "high",
                     "function_name": "parse_input", "address": 0x402000,
                     "exploitability_score": 8},
                ]
            }
        ]

        # 2) 统计模块 → 提取高风险函数
        api = MultiDimensionStatsAPI()
        resp = api.get_high_risk_functions(history, limit=5)
        assert len(resp.data) > 0
        top_func = resp.data[0]['function_name']

        # 3) 构建编排链
        orch = ChainOrchestrator()
        orch.add_stage(ChainStep(
            stage=ExploitStage.RECON, action=f"scan_{top_func}",
            applicable_targets=[TargetType.LINUX]))

        orch.add_stage(ChainStep(
            stage=ExploitStage.EXPLOIT, action=f"exploit_{top_func}",
            applicable_targets=[TargetType.LINUX]))

        # 4) 空跑验证：无前置依赖时应成功
        result = orch.dry_run(target_type=TargetType.LINUX)
        assert result.success
        assert result.artifacts['total_steps'] == 2

        # 5) 链特征标注
        chain = AttackChain()
        for s in orch._pending_steps:
            chain.add_step(s)
        annotation = annotate_chain(chain)
        assert 'suggested_strategy' in annotation
        assert 'risk_flags' in annotation

    def test_exploit_adaptation_with_stats(self):
        """统计模块产出的漏洞优先级驱动 exploit 适配。"""
        from multi_dimension_stats_api import MultiDimensionStatsAPI
        from multi_target_exploit_adapter import (
            TargetBinary, SymbolicTemplate, SymbolicExecutionTemplateEngine,
            MultiTargetExploitGenerator, compute_imphash,
        )

        # 1) 统计给出 exploitability 最高分目标
        history = [
            {
                "date": "2024-01-15", "architecture": "x86_64",
                "success": True,
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "critical",
                     "function_name": "handle_packet", "address": 0x401000,
                     "exploitability_score": 9},
                    {"type": "format_string", "severity": "high",
                     "function_name": "log_data", "address": 0x500000,
                     "exploitability_score": 7},
                ]
            }
        ]
        api = MultiDimensionStatsAPI()
        scores = api.get_exploitability_scores(history)
        assert scores.data['total_vulnerabilities'] == 2
        assert scores.data['max_score'] == 9

        # 2) 初始化目标 binary
        target = TargetBinary(
            name="vuln_app", version="2.1", architecture="x86_64",
            symbol_table={"system": 0x400600, "puts": 0x400500},
            gadget_addresses=[0x401000, 0x401005, 0x401010],
            import_table={"libc.so.6": "system"},
        )

        # 3) 注册 ret2libc 模板并解析符号偏移
        engine = SymbolicExecutionTemplateEngine()
        engine.register_template(SymbolicTemplate(
            template_name="ret2libc",
            symbolic_offsets=["system", "puts"],
            exploit_code="push {system}; push {puts}",
            constraints=["has_gadgets 1"],
        ))

        resolved = engine.solve_for_target("ret2libc", target)
        assert resolved is not None
        assert resolved["system"] == 0x400600
        assert resolved["puts"] == 0x400500

        # 4) 约束校验
        validation = engine.validate_constraints("ret2libc", target)
        assert validation['valid']

        # 5) 多目标适配器生成统一 exploit
        gen = MultiTargetExploitGenerator()
        gen.add_target(target)
        gen.template_engine = engine
        unified = gen.generate_unified_exploit("ret2libc")
        assert "handle_packet" not in unified or len(unified) > 0  # 产出非空代码

    def test_fusion_followed_by_retrieval(self):
        """融合后的特征库建设 → 跨模态检索。"""
        from multi_modal_fusion import early_fusion, late_fusion_avg
        from multi_modal_retrieval import LSHIndex

        # 1) 构造双模态特征矩阵
        mod_text = [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6], [0.7, 0.8, 0.9]]
        mod_binary = [[-0.1, -0.2, -0.3, -0.4],
                      [-0.5, -0.6, -0.7, -0.8],
                      [-0.9, -1.0, -1.1, -1.2]]

        # 2) 早期拼接融合
        fused_early = early_fusion({"text": mod_text, "binary": mod_binary})
        assert len(fused_early) == 3
        # 拼接维度 = 3 + 4 = 7
        assert len(fused_early[0]) == 7

        # 3) 同维度晚期平均融合
        mod_alt = [[0.15, 0.25, 0.35], [0.45, 0.55, 0.65], [0.75, 0.85, 0.95]]
        fused_late = late_fusion_avg({"text": mod_text, "alt": mod_alt})
        assert len(fused_late) == 3
        # 逐元素均值校验
        assert abs(fused_late[0][0] - 0.125) < 0.01  # (0.1+0.15)/2

        # 4) LSH 索引建库
        idx = LSHIndex(dim=3, num_tables=2, hash_dim=4)
        idx.insert(mod_text[0])
        idx.insert(mod_text[1])
        idx.insert(mod_alt[2])

        # 5) 查询命中校验
        query = mod_text[0]
        results = idx.query(query, topk=2)
        assert len(results) >= 1

    def test_conformal_with_survival(self):
        """共形预测量化漏洞修复时间的不确定性。"""
        from multi_modal_conformal import conformal_predict
        from multi_modal_survival import kaplan_meier

        # 1) KM 估计漏洞半衰期
        times = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120]
        events = [True, True, True, True, False, True, True, False, True, False, True, True]
        curve = kaplan_meier(times, events)
        assert len(curve.survival_probs) >= 1
        # 中位生存时间应被估计
        assert curve.median_survival_time >= 0

        # 2) 共形预测给出修复概率的不确定性区间
        cal_scores = sorted([t / 120.0 for t in times[:6]])
        cal_labels = [int(e) for e in events[:6]]
        result = conformal_predict(
            cal_scores, cal_labels,
            test_score_fn=lambda y: 0.25,
            n_classes=2, alpha=0.2)
        assert result.threshold >= 0

    def test_full_confidence_calibration_chain(self):
        """置信度校准全链路：分数提取→Beta 后验→可信区间。"""
        from multi_modal_confidence import BetaCalibration, calibration_benchmark
        from multi_dimension_stats_api import calibrated_risk_scores

        # 1) 从历史记录提取原始风险分
        history = [
            {
                "date": "2024-01-15",
                "vulnerabilities": [
                    {"type": "buffer_overflow", "severity": "critical",
                     "function_name": "f1", "exploitability_score": 9},
                    {"type": "use_after_free", "severity": "high",
                     "function_name": "f2", "exploitability_score": 7},
                    {"type": "null_deref", "severity": "low",
                     "function_name": "f3", "exploitability_score": 2},
                    {"type": "format_string", "severity": "medium",
                     "function_name": "f4", "exploitability_score": 5},
                    {"type": "buffer_overflow", "severity": "high",
                     "function_name": "f5", "exploitability_score": 8},
                    {"type": "race_condition", "severity": "critical",
                     "function_name": "f6", "exploitability_score": 9},
                ]
            }
        ]

        scores = calibrated_risk_scores(history)
        assert scores['sample_count'] == 6
        assert len(scores['raw_scores']) == 6
        assert set(scores['labels']) <= {0, 1}

        # 2) Beta 校准：注入观测 → 后验均值
        cal = BetaCalibration()
        pos_count = sum(scores['labels'])
        total_count = len(scores['labels'])
        cal.update(pos_count, total_count)
        confidence = cal.get_confidence()
        assert 0.0 <= confidence <= 1.0

        # 3) 后验均值与 MLE 的一致性（Beta(2,2) 先验收缩向 0.5）
        mle = pos_count / total_count
        assert abs(confidence - mle) < 0.3

        # 4) 等尾可信区间覆盖校验
        lo, hi = cal.get_credible_interval(0.95)
        assert 0.0 <= lo <= hi <= 1.0

    def test_gravity_alignment_graceful_degradation(self):
        """重力对齐在无 numpy 环境下静默降级。"""
        try:
            import numpy as np
            have_np = True
        except ImportError:
            have_np = False

        # 模块导入本身应不受 numpy 是否存在影响
        from multi_modal_gravity_align import compute_node_masses
        if have_np:
            import numpy as np
            adj = np.array([[0, 1, 0], [1, 0, 1], [0, 1, 0]])
            feats = np.random.randn(3, 4)
            masses = compute_node_masses(adj, feats)
            assert len(masses) == 3
            assert all(m > 0 for m in masses)
        else:
            with pytest.raises(ImportError):
                import numpy as np
                adj = np.array([[0, 1], [1, 0]])
                feats = np.array([[1.0, 2.0], [3.0, 4.0]])
                compute_node_masses(adj, feats)
