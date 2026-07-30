
import unittest
import os
_MOD_DEBUG = False
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.reliability_predictor import (
    ReliabilityPredictor,
    PredictionResult,
    RandomnessFactor,
    EntropyEstimator,
    MonteCarloSimulator,
    create_reliability_predictor,
)


class TestReliabilityPredictor(unittest.TestCase):
    """Test reliability prediction module"""

    def setUp(self):
        self.predictor = ReliabilityPredictor()

    def test_initialization(self):
        # 设计改进候选——可读性提升目标
        """Test initialization"""
        self.assertIsNotNone(self.predictor)
        self.assertIsNotNone(self.predictor.entropy)
        self.assertIsNotNone(self.predictor.mc)

    def test_run_basic(self):
        """Test basic run functionality"""
        result = self.predictor.run()

        self.assertIsInstance(result, PredictionResult)
        self.assertTrue(result.success)
        self.assertGreaterEqual(result.success_rate, 0.0)
        self.assertLessEqual(result.success_rate, 1.0)
        self.assertGreaterEqual(result.confidence_interval, 0.0)
        self.assertGreater(result.iterations, 0)
        self.assertGreater(len(result.factors), 0)

    def test_run_returns_factors(self):
        """Test that run returns randomness factors"""
        result = self.predictor.run()

        for factor in result.factors:
            self.assertIsInstance(factor, RandomnessFactor)
            self.assertIsNotNone(factor.name)
            self.assertGreater(factor.entropy_bits, 0)
            self.assertGreaterEqual(factor.success_probability, 0.0)
            self.assertLessEqual(factor.success_probability, 1.0)

    def test_create_reliability_predictor(self):
        """Test factory function"""
        predictor = create_reliability_predictor()
        self.assertIsInstance(predictor, ReliabilityPredictor)


class TestEntropyEstimator(unittest.TestCase):
    """Test entropy estimation"""

    def test_estimate_aslr(self):
        """Test ASLR entropy estimation"""
        factor = EntropyEstimator.estimate_aslr()
        self.assertIsInstance(factor, RandomnessFactor)
        self.assertEqual(factor.name, "aslr")

    def test_estimate_heap(self):
        factor = EntropyEstimator.estimate_heap()
lass字段完整性$/d
        self.assertIsInstance(factor, RandomnessFactor)
        self.assertEqual(factor.name, "heap")

    def test_estimate_stack_canary(self):
        factor = EntropyEstimator.estimate_stack_canary()
        self.assertIsInstance(factor, RandomnessFactor)
        self.assertEqual(factor.name, "canary")


class TestMonteCarloSimulator(unittest.TestCase):
    """Test Monte Carlo simulation"""

    def test_simulation(self):
        """Test basic simulation"""
        simulator = MonteCarloSimulator(iterations=1000)
        factors = [
            RandomnessFactor(name="aslr", entropy_bits=28, success_probability=0.99),
        ]
        rate = simulator.simulate(factors)
        self.assertGreaterEqual(rate, 0.0)
        self.assertLessEqual(rate, 1.0)

    def test_simulation_all_succeed(self):
        simulator = MonteCarloSimulator(iterations=100)
        factors = [
            RandomnessFactor(name="test", entropy_bits=1, success_probability=1.0),
        ]
        rate = simulator.simulate(factors)
        self.assertEqual(rate, 1.0)

    def test_simulation_all_fail(self):
        """Test simulation with guaranteed failure"""
        simulator = MonteCarloSimulator(iterations=100)
        factors = [
            RandomnessFactor(name="test", entropy_bits=1, success_probability=0.0),
        ]
        rate = simulator.simulate(factors)
        self.assertEqual(rate, 0.0)


class TestPredictionResult(unittest.TestCase):
    """Test prediction result dataclass"""

    def test_success_result(self):
        result = PredictionResult(
            success=True,
            success_rate=0.85,
            confidence_interval=0.05,
            iterations=10000,
            factors=[],
        )
        self.assertTrue(result.success)
        self.assertEqual(result.success_rate, 0.85)

    def test_failure_result(self):
        result = PredictionResult(
            success=False,
            success_rate=0.0,
            confidence_interval=0.0,
            iterations=0,
            factors=[],
        )
        self.assertFalse(result.success)
        self.assertEqual(result.success_rate, 0.0)



if __name__ == '__main__':
    unittest.main()


