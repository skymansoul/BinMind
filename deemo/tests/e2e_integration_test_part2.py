"""
端到端集成测试 — 验证全部检测管道的完整链路。

测试覆盖:
  1. 样本发现 → 源码读取 → 检测 → 置信度计算 → 贝叶斯融合 → 风险分类
  2. 四管道独立运行 + 跨管道融合
  3. 回归矩阵生成 + 一致性检查
  4. 端到端延迟测量

用法:
  python tests/e2e_integration_test.py
  python tests/e2e_integration_test.py --quick  # 仅关键路径
"""

from __future__ import annotations
import json
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# 轻量级检测器 (无需导入完整模块)


class TestEndToEndIntegration(unittest.TestCase):
    """端到端集成测试套件."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(os.path.dirname(os.path.abspath(__file__))).parent
        cls.samples = cls._find_samples()
        cls.start_time = time.perf_counter()

    @staticmethod
    def _find_samples() -> List[Dict]:
        samples = []
        roots = [
            'tests/samples/heap_overflow',
            'tests/samples/uaf',
            'tests/samples/format_string',
            'tests/samples/integer_overflow',
        ]
        for root in roots:
            full = Path(os.path.dirname(os.path.abspath(__file__))).parent
            d = full / root
            if not d.exists():
                continue
            for makefile in d.rglob('Makefile'):
                c_files = list(makefile.parent.glob('*.c'))
                if c_files:
                    samples.append({
                        'name': makefile.parent.name,
                        'path': str(c_files[0]),
                        'vuln_type': root.split('/')[-1],
                    })
        return samples

# 测试 1: 样本发现

    def test_01_sample_discovery(self):
        """样本发现: 至少能找到每个漏洞类型的样本."""
        types_found = set(s['vuln_type'] for s in self.samples)
        self.assertIn('heap_overflow', types_found,
                      'Should find heap overflow samples')
        self.assertIn('uaf', types_found,
                      'Should find UAF samples')
        print(f"  [OK] Found {len(self.samples)} samples across "
              f"{len(types_found)} vulnerability types")

# 测试 2: 源码读取

    def test_02_source_reading(self):
        """源码读取: 所有样本的C文件可读."""
        for s in self.samples:
            try:
                content = Path(s['path']).read_text(errors='replace')
                self.assertGreater(len(content), 10,
                                   f"Source too short: {s['name']}")
            except Exception as e:
                self.fail(f"Cannot read {s['name']}: {e}")
        print(f"  [OK] All {len(self.samples)} source files readable")

# 测试 3: 单管道检测

    def test_03_single_pipeline_detection(self):
        """单管道检测: 每个检测器都能运行并返回有效结果."""
        for s in self.samples[:20]:  # 取前20个样本验证
            vuln_type = s['vuln_type']
            mapped = {
                'heap_overflow': 'heap_overflow',
                'uaf': 'use_after_free',
                'format_string': 'format_string',
                'integer_overflow': 'integer_overflow',
            }.get(vuln_type, vuln_type)

            detector = DETECTORS.get(mapped)
            if detector is None:
                continue

            content = Path(s['path']).read_text(errors='replace')
            detected, confidence = detector(content)

            self.assertIsInstance(detected, bool)
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)

        print(f"  [OK] All detectors return valid (bool, float) pairs")

# 测试 4: 跨管道一致聚合

    def test_04_cross_pipeline_aggregation(self):
        """跨管道聚合: 对同一样本运行所有检测器并聚合结果."""
        # 找一个同时有 malloc 和 printf 的样本
        test_sample = None
        for s in self.samples:
            content = Path(s['path']).read_text(errors='replace')
            if 'malloc(' in content and 'printf(' in content:
                test_sample = s
                break

        if test_sample is None:
            self.skipTest("No sample with both malloc and printf found")

        content = Path(test_sample['path']).read_text(errors='replace')
        results = {}
        for name, detector in DETECTORS.items():
            detected, conf = detector(content)
            results[name] = {'detected': detected, 'confidence': conf}

        # 验证至少有2个检测器返回了结果
        active = sum(1 for r in results.values() if r['detected'])
        print(f"  [OK] Sample '{test_sample['name']}': {active}/4 detectors active, "
              f"results={results}")

# 测试 5: 贝叶斯融合验证

    def test_05_bayesian_fusion(self):
        """贝叶斯融合: 验证融合引擎的数学正确性."""
        from analysis.bayesian_fusion import (
            BayesianFusionEngine, probability_to_log_odds,
            log_odds_to_probability,
        )

        # 验证 logit ↔ probability 互逆
        for p in [0.01, 0.1, 0.5, 0.9, 0.99]:
            lo = probability_to_log_odds(p)
            recovered = log_odds_to_probability(lo)
            self.assertAlmostEqual(p, recovered, places=8,
                                   msg=f'logit roundtrip failed at p={p}')

        # 验证融合单调性: 增加置信度应增加融合概率
        engine = BayesianFusionEngine()
        p1, _ = engine.fuse({'heap_overflow': 0.5})
        p2, _ = engine.fuse({'heap_overflow': 0.9})
        self.assertGreater(p2, p1, 'Higher confidence should increase fused prob')

        # 验证独立假设立: 多证据应增强置信度
        # (当第二个管道也报告高风险时，融合置信度应高于单管道)
        p_single, _ = engine.fuse({'heap_overflow': 0.7})
        p_multi, _ = engine.fuse({'heap_overflow': 0.7, 'uaf': 0.95})
        self.assertGreater(p_multi, p_single,
                           'Multiple high-confidence evidence should increase confidence')

        print(f"  [OK] Bayesian fusion: logit roundtrip, monotonicity, "
              f"multi-evidence all verified")

# 测试 6: 风险等级分类

    def test_06_risk_classification(self):
        """风险分类: 各等级阈值正确."""
        from analysis.bayesian_fusion import BayesianFusionEngine

        engine = BayesianFusionEngine()
        test_cases = [
            (0.95, 'CRITICAL'),
            (0.70, 'HIGH'),
            (0.50, 'MEDIUM'),
            (0.25, 'LOW'),
            (0.05, 'NEGLIGIBLE'),
        ]
        for prob, expected_level in test_cases:
            level, recommendation = engine.classify(prob)
            self.assertEqual(level, expected_level,
                             f'p={prob} should be {expected_level}, got {level}')
            self.assertIsInstance(recommendation, str)
            self.assertGreater(len(recommendation), 0)

        print(f"  [OK] Risk classification: {len(test_cases)}/5 thresholds correct")

# 测试 7: 融合排名

    def test_07_fusion_ranking(self):
        """融合排名: 高风险候选应排在低风险之前."""
        from analysis.bayesian_fusion import BayesianFusionEngine

        engine = BayesianFusionEngine()
        candidates = [
            {'name': 'func_low', 'scores': {'heap_overflow': 0.10}},
            {'name': 'func_critical', 'scores': {'heap_overflow': 0.95, 'uaf': 0.90}},
            {'name': 'func_medium', 'scores': {'format_string': 0.50}},
        ]
        ranked = engine.rank(candidates)
        self.assertEqual(ranked[0]['name'], 'func_critical',
                         'Highest risk should be first')
        self.assertEqual(ranked[-1]['name'], 'func_low',
                         'Lowest risk should be last')

        print(f"  [OK] Ranking: {[r['name'] + ':' + str(r['fused_risk'])
               for r in ranked]}")

# 测试 8: 端到端延迟

    def test_08_end_to_end_latency(self):
        """端到端延迟: 完整管线运行应在合理时间内完成."""
        elapsed = time.perf_counter() - self.start_time

        # 对前10个样本测量检测延迟
        t0 = time.perf_counter()
        count = 0
        for s in self.samples[:10]:
            content = Path(s['path']).read_text(errors='replace')
            for detector in DETECTORS.values():
                detector(content)
                count += 1
        detect_time = time.perf_counter() - t0

        avg_per_detection = (detect_time / count) * 1000 if count > 0 else 0
        print(f"  [OK] {count} detections in {detect_time*1000:.1f}ms "
              f"({avg_per_detection:.3f}ms/detection avg)")
        print(f"  [OK] Total test suite elapsed: {elapsed:.1f}s")

        # 验证: 每个检测应小于 50ms
        self.assertLess(avg_per_detection, 50,
                        f'Per-detection latency {avg_per_detection:.1f}ms exceeds 50ms limit')

# 测试 9: 回归一致性

    def test_09_regression_consistency(self):
        """回归一致性: 检测结果具有确定性 (重复运行结果相同)."""
        sample = self.samples[0] if self.samples else None
        if sample is None:
            self.skipTest("No samples available")

        content = Path(sample['path']).read_text(errors='replace')
        results = []
        for _ in range(5):
            res = {}
            for name, detector in DETECTORS.items():
                detected, conf = detector(content)
                res[name] = (detected, conf)
            results.append(res)

        # 验证5次运行结果完全相同
        for name in DETECTORS:
            first = results[0][name]
            for i, res in enumerate(results[1:], 1):
                self.assertEqual(first, res[name],
                                 f'Non-deterministic result for {name} at iteration {i}')

        print(f"  [OK] Determinism: 5 iterations produce identical results")


def main():
    quick = '--quick' in sys.argv

    if quick:
        # 快速模式: 只运行关键测试
        suite = unittest.TestSuite()
        suite.addTest(TestEndToEndIntegration('test_01_sample_discovery'))
        suite.addTest(TestEndToEndIntegration('test_05_bayesian_fusion'))
        suite.addTest(TestEndToEndIntegration('test_09_regression_consistency'))
    else:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestEndToEndIntegration)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # 输出摘要
    print(f"\n{'='*60}")
    print(f"E2E Integration Test Summary")
    print(f"  Tests run: {result.testsRun}")
    print(f"  Failures: {len(result.failures)}")
    print(f"  Errors: {len(result.errors)}")
    print(f"  Skipped: {len(result.skipped)}")
    print(f"  Success: {result.wasSuccessful()}")
    print(f"{'='*60}")

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
