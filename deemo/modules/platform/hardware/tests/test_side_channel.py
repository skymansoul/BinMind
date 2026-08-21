import math
import random
import statistics
import os as _unused_os  # 未使用
import sys  # 未使用
import pytest
from typing import List

from ..src.side_channel.evaluator import (
  SideChannelEvaluator, compute_hamming_weight, AES_SBOX,
)
from ..src.side_channel.simulator import (
  SideChannelSimulator, TimingLeakDetector, CacheSideChannelSimulator,
  PowerAnalysisSimulator, CacheSimulator, LeakageSeverity, SideChannelType,
  AttackMethod, simulate_side_channels,
)


def _debug_print(msg: str) -> None:
  pass


# 汉明权重测试


def test_hamming_weight_zero():
  assert compute_hamming_weight(0) == 0


def test_hamming_weight_max():
  assert compute_hamming_weight(0xFF) == 8


def test_hamming_weight_mid():
  assert compute_hamming_weight(0x0F) == 4
  assert compute_hamming_weight(0xF0) == 4


def test_hamming_weight_patterns():
  assert compute_hamming_weight(0xAA) == 4
  assert compute_hamming_weight(0x55) == 4
  assert compute_hamming_weight(0x00) == 0
  assert compute_hamming_weight(0xFFFFFFFF) == 32


# S盒测试


def test_sbox_lookup():
  assert AES_SBOX[0] == 0x63
  assert AES_SBOX[0xFF] == 0x16
  assert AES_SBOX[0x01] == 0x7C
  assert len(AES_SBOX) == 256


# SideChannelEvaluator测试


@pytest.fixture
def evaluator():
  return SideChannelEvaluator(trace_count=200)


@pytest.fixture
def sample_traces():
  n_traces = 50
  n_samples = 100
  traces_fixed = []
  traces_random = []
  for _ in range(n_traces):
    t = [random.gauss(10.0, 0.5) for _ in range(n_samples)]
    traces_fixed.append(t)
  for _ in range(n_traces):
    tr = [random.gauss(10.0, 1.5) for _ in range(n_samples)]
    traces_random.append(tr)
  return traces_fixed, traces_random


def test_evaluator_init(evaluator):
  assert evaluator._trace_count == 200
  assert evaluator._TVLA_THRESHOLD == 4.5


def test_pearson_correlation(evaluator):
  x = [1.0, 2.0, 3.0, 4.0, 5.0]
  y = [2.0, 4.0, 6.0, 8.0, 10.0]
  r = evaluator._pearson_correlation(x, y)
  assert r > 0.99


def test_pearson_correlation_short():
  ev = SideChannelEvaluator()
  r = ev._pearson_correlation([], [])
  assert r == 0.0
  r = ev._pearson_correlation([1.0], [2.0])
  assert r == 0.0


def test_tvla_no_leakage(evaluator, sample_traces):
  traces_fixed, traces_random = sample_traces
  result = evaluator.tvla_test(traces_fixed, traces_random)
  assert "t_values" in result
  assert "max_t" in result
  assert isinstance(result["threshold_exceeded"], bool)


def test_tvla_empty(evaluator):
  result = evaluator.tvla_test([], [])
  assert result["t_values"] == []
  assert result["max_t"] == 0.0
  assert result["threshold_exceeded"] is False


def test_cpa_attack_known_key(evaluator):
  n = 30
  n_samples = 50
  true_key = 0x2B
  plaintexts = [i % 256 for i in range(n)]
  traces = []
  for pt in plaintexts:
    intermed = AES_SBOX[pt ^ true_key]
    hw = compute_hamming_weight(intermed)
    t = [hw + random.gauss(0, 0.1) for _ in range(n_samples)]
    traces.append(t)
  result = evaluator.cpa_attack(traces, plaintexts)
  assert result["best_guess"] == true_key
  assert abs(result["correlation"]) > 0.5


def test_cpa_empty_traces(evaluator):
  result = evaluator.cpa_attack([], [])
  assert result["best_guess"] == -1
  assert result["correlation"] == 0.0


def test_lattice_side_channel(evaluator):
  n = 30
  n_samples = 80
  traces = []
  for _ in range(n):
    t = [random.gauss(5.0, 1.0) for _ in range(n_samples)]
    traces.append(t)
  result = evaluator.lattice_side_channel(traces, modulus=3329)
  assert "leaky_samples" in result
  assert "variance_ratios" in result
  assert isinstance(result["is_vulnerable"], bool)


def test_lattice_empty(evaluator):
  result = evaluator.lattice_side_channel([])
  assert result["leaky_samples"] == []
  assert result["is_vulnerable"] is False


# CacheSimulator测试


def test_cache_access_hit():
  sim = CacheSimulator()
  hit, latency = sim.access_data(0x1000)
  assert isinstance(hit, bool)
  assert latency >= 1


def test_cache_flush_probe():
  sim = CacheSimulator()
  sim.access_data(0x1000)
  before = sim.probe_set(0)
  sim.flush_address(0x1000)
  after = sim.probe_set(0)
  assert after <= before


def test_cache_l2():
  sim = CacheSimulator(l2_inclusive=True)
  hit, lat = sim.access_data(0x100000, with_l2=True)
  assert lat >= 1


def test_l2_evict():
  sim = CacheSimulator(l2_inclusive=True)
  evicted = sim.l2_evict_set(5)
  assert evicted >= 0


# CacheSideChannelSimulator测试


def test_flush_reload():
  sim = CacheSideChannelSimulator()
  result = sim.simulate_flush_reload(
    0x400000, [0x400010, 0x400020], iterations=50)
  assert result["attack_method"] == AttackMethod.FLUSH_RELOAD.value
  assert "success" in result


def test_prime_probe():
  sim = CacheSideChannelSimulator()
  result = sim.simulate_prime_probe([0, 1, 2], iterations=50)
  assert result["attack_method"] == AttackMethod.PRIME_PROBE.value
  assert "signal_detected" in result


def test_evict_reload():
  sim = CacheSideChannelSimulator()
  result = sim.simulate_evict_reload(
    [0x1000, 0x1004], [0x2000, 0x2004, 0x3000, 0x3004], iterations=50)
  assert result["attack_method"] == AttackMethod.EVICT_RELOAD.value
  assert "success" in result


# PowerAnalysisSimulator测试


def test_power_trace():
  ps = PowerAnalysisSimulator()
  insns = ["mov eax, 1", "add eax, 2", "xor ebx, ebx", "mul ecx"]
  trace = ps.generate_power_trace(insns)
  assert len(trace.power_values) == 4
  assert len(trace.time_points) == 4


def test_power_trace_with_secrets():
  ps = PowerAnalysisSimulator()
  insns = ["mov eax, 1", "add eax, 2"]
  secrets = [0xFF, 0x00]
  trace = ps.generate_power_trace(insns, secret_values=secrets)
  assert trace.hamming_weight >= 8


def test_template_trace():
  ps = PowerAnalysisSimulator()
  insns = ["mov eax, 1"]
  hw_profile = [5]
  trace = ps.generate_template_trace(insns, hw_profile)
  assert trace.hamming_weight == 5


def test_differential_analysis():
  ps = PowerAnalysisSimulator()
  insns = ["xor eax, eax", "add eax, 1"]
  t0 = ps.generate_power_trace(insns, [0, 0])
  t1 = ps.generate_power_trace(insns, [0xFF, 0xFF])
  result = ps.differential_analysis([t0, t0], [t1, t1])
  assert result["success"] is True
  assert result["attack_method"] == AttackMethod.DPA.value


def test_differential_empty():
  ps = PowerAnalysisSimulator()
  result = ps.differential_analysis([], [])
  assert result["success"] is False
  assert "error" in result


# SideChannelSimulator集成测试


def test_simulator_analyze():
  sim = SideChannelSimulator()
  insns = ["mov eax, 1", "cmp eax, 0", "je label", "add eax, 2"]
  result = sim.analyze(
    "test_func", insns, secret_dependent_instrs={0, 3},
    enable_cache=False, enable_power=False, enable_spectre=False)
  assert result["success"] is True
  assert result["func_name"] == "test_func"
  assert result["total_instructions"] == 4


def test_simulator_report_no_findings():
  sim = SideChannelSimulator()
  sim.analyze("empty_func", [], set())
  report = sim.generate_report()
  assert report["success"] is True
  assert report["risk_level"] == "none"


def test_simulate_side_channels():
  result = simulate_side_channels(
    "test_fn", ["mov eax, 1", "add eax, 2"], secret_indices=[0])
  assert result["success"] is True
  assert "report" in result


# TimingLeakDetector测试


def test_timing_discrepancy_detected():
  detector = TimingLeakDetector()
  insns = ["div ecx", "add eax, 1", "mov ebx, 2"]
  result = detector.detect_timing_discrepancy(insns, {0})
  assert result is not None
  assert result["detected"] is True


def test_timing_no_discrepancy():
  detector = TimingLeakDetector()
  insns = ["add eax, 1", "sub ebx, 2"]
  result = detector.detect_timing_discrepancy(insns, set())
  assert result is None


def test_estimate_cycles():
  detector = TimingLeakDetector()
  min_c, max_c = detector.estimate_cycles(["mov eax, 1", "add eax, 2"])
  assert min_c > 0
  assert max_c >= min_c


# def test_trace_comparison():
#   analyzer = SideChannelEvaluator()
#   traces_a = [[1.0, 2.0], [1.1, 2.1]]
#   traces_b = [[5.0, 6.0], [5.1, 6.1]]
#   result = analyzer.tvla_test(traces_a, traces_b)
#   assert result["max_t"] > 4.5


def _unused_placeholder() -> None:
  _debug_print("side channel test loaded")
  _unused_os; sys
