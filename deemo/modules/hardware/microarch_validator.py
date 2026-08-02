# 2026-07-26

import array
import math
import os
import random
import statistics
import time

# ===== 独立微架构工具函数 =====


def rdtsc() -> int:
    """高精度时间戳 — 通过perf_counter_ns近似RDTSC"""
    return time.perf_counter_ns()


def memory_barrier():
    """序列化指令模拟 — 全屏障刷新流水线"""
    # Python无直接序列化指令，使用原子性操作模拟
    _ = os.urandom(0)  # syscall作为隐式屏障
    time.sleep(0)  # 触发上下文切换 → 隐式序列化


def clflush_emulate(address: int):
    """容量驱逐模拟 — 通过访问大量冲突缓存行来逐出目标行"""
    # 分配一个大数组，覆盖L3缓存以驱逐特定地址
    _eviction_buf = array.array("Q", [0]) * (256 * 1024)  # 2MB
    for _i in range(0, len(_eviction_buf), 8):
        _ = _eviction_buf[_i]


# ===== MicroarchValidator =====
# 微架构侧信道检测: Flush+Reload, Prime+Probe, 跨核泄漏


class MicroarchValidator:
    def __init__(self, cpu_affinity: int = 0):
        self._affinity = cpu_affinity
        self._probe_array: array.array | None = None
        self._cache_line_size = 64  # 假设64字节缓存行
        self._cache_sets = 64  # 默认L1 dcache set数
        self._cache_ways = 8  # 默认关联度

    # //// 内部计时 ////
    def _measure_access_time(self, address: int) -> int:
        """Flush后reload时间测量 — 区分缓存命中/缺失"""
        memory_barrier()
        clflush_emulate(address)
        memory_barrier()
        _t0 = time.perf_counter_ns()
        # 访问目标: 使用volatile风格
        _dummy = address ^ 0xDEAD
        memory_barrier()
        _t1 = time.perf_counter_ns()
        return _t1 - _t0

    # ---- 阈值校准 ----
    def _calibrate_threshold(self, iterations: int = 5000) -> int:
        """中位数 * 2作为命中/缺失阈值"""
        _times: list[int] = []
        _probe = array.array("Q", [0]) * 256
        for _ in range(iterations):
            _idx = random.randint(0, 255)
            # 先访问以确保在缓存中
            _ = _probe[_idx]
            _t0 = time.perf_counter_ns()
            _ = _probe[_idx]
            _t1 = time.perf_counter_ns()
            _times.append(_t1 - _t0)
        _median = statistics.median(_times)
        return max(int(_median * 2), 5)  # 最小5ns避免假阳性

    # ---- 缓存集驱逐 ----
    def _evict_cache_set(self, set_index: int):
        """访问一个set的所有way以强制驱逐"""
        if self._probe_array is None:
            return
        _stride = self._cache_line_size * self._cache_sets
        for _way in range(self._cache_ways):
            _offset = set_index * self._cache_line_size + _way * _stride * 16
            if _offset < len(self._probe_array) * 8:
                _ = self._probe_array[_offset // 8]

    # ---- 哈希集索引 ----
    def _compute_set_index(self, address: int) -> int:
        """基于地址计算缓存集索引 — 简单bit-slice"""
        _addr = address >> 6  # 跳过行内偏移
        _set = _addr & (self._cache_sets - 1)
        return _set

    # ===== 驱逐集构建 ==========================================================
    # Prime+Probe 攻击的关键预备步骤：找到映射到同一缓存组的地址集合。
    # 原理：分配大数组，对每组逐一测试——访问候选地址后测量探针延迟，
    # 延迟升高说明候选地址与探针属于同一组。
    def build_eviction_set(self, target_set: int, max_candidates: int = 512) -> list[int]:
        """为指定缓存组构建驱逐集。

        返回能与 target_set 产生冲突的地址列表。
        复杂度 O(candidates × ways)，适合 L1 (64组 × 8路) 的规模。
        """
        n_elements = max_candidates * 16  # 每候选16个探针
        probe = array.array("Q", [0]) * n_elements
        threshold = self._calibrate_threshold(2000)
        eviction_addrs: list[int] = []

        # 填充探针：访问 target_set 的所有 way
        set_base = target_set * self._cache_line_size * self._cache_sets
        for way in range(self._cache_ways):
            offset = set_base + way * self._cache_line_size * self._cache_sets * 2
            if offset // 8 < len(probe):
                _ = probe[offset // 8]

        for cand in range(max_candidates):
            cand_addr = (target_set * self._cache_line_size +
                        (cand + 1) * self._cache_line_size * self._cache_sets * 4)
            if cand_addr // 8 >= len(probe):
                break
            # 访问候选地址
            _ = probe[cand_addr // 8]
            # 测量探针延迟
            t0 = time.perf_counter_ns()
            _ = probe[set_base // 8]
            t1 = time.perf_counter_ns()
            if (t1 - t0) > threshold:
                eviction_addrs.append(cand_addr)

        return eviction_addrs

    # ===== Flush+Reload近似 =====
    # 基于容量驱逐而非clflush指令
    def flush_reload_approx(
        self, target_address: int, probe_array_size: int = 256 * 4096
    ) -> dict:
        # 分配探针数组 — 覆盖多个缓存集
        _elem_count = probe_array_size // 8
        self._probe_array = array.array("Q", [0]) * _elem_count
        _threshold = self._calibrate_threshold()

        # 步骤1: 访问目标 → 装入缓存
        _target_idx = (target_address // self._cache_line_size) % _elem_count
        _ = self._probe_array[_target_idx]

        # 步骤2: 容量驱逐 → 模拟flush
        memory_barrier()
        clflush_emulate(target_address)
        memory_barrier()

        # 步骤3: 重新加载并计时
        _times: list[int] = []
        for _ in range(100):
            _t0 = time.perf_counter_ns()
            _ = self._probe_array[_target_idx]
            _t1 = time.perf_counter_ns()
            _times.append(_t1 - _t0)

        _median_reload = statistics.median(_times) if _times else 0
        _hit = _median_reload < _threshold
        return {
            "hit": _hit,
            "reload_time": _median_reload,
            "threshold": _threshold,
            "confidence": 0.85 if _hit else 0.3,
        }

    # ===== Prime+Probe =====
    # 填充→等待→探测模式
    def prime_probe_detect(
        self, cache_sets: int = 64, ways: int = 8
    ) -> dict:
        self._cache_sets = cache_sets
        self._cache_ways = ways
        _total_lines = cache_sets * ways
        _probe_size = _total_lines * self._cache_line_size
        self._probe_array = array.array("Q", [0]) * (_probe_size // 8)

        # Prime: 填充所有set的所有way
        for _set in range(cache_sets):
            for _way in range(ways):
                _idx = (_set * ways + _way) * (self._cache_line_size // 8)
                _ = self._probe_array[_idx]

        # 等待 — 模拟受害者执行
        memory_barrier()
        # 在这个窗口内，受害者可能驱逐某些set

        # Probe: 测量每个set的访问时间
        _slow_sets: list[int] = []
        _eviction_count = 0
        _all_latencies: list[float] = []
        _threshold = self._calibrate_threshold()

        for _set in range(cache_sets):
            _set_latencies: list[int] = []
            for _way in range(ways):
                _idx = (_set * ways + _way) * (self._cache_line_size // 8)
                _t0 = time.perf_counter_ns()
                _ = self._probe_array[_idx]
                _t1 = time.perf_counter_ns()
                _set_latencies.append(_t1 - _t0)
            _avg_set_latency = statistics.median(_set_latencies)
            _all_latencies.append(_avg_set_latency)
            if _avg_set_latency > _threshold:
                _slow_sets.append(_set)
                _eviction_count += 1

        _avg_latency = statistics.median(_all_latencies) if _all_latencies else 0.0
        _is_suspicious = _eviction_count > len(_all_latencies) * 0.1

        return {
            "evicted_sets": _slow_sets,
            "eviction_count": _eviction_count,
            "avg_latency": _avg_latency,
            "is_suspicious": _is_suspicious,
        }

    # ===== 缓存行计时 =====
    def cache_line_timing(self, iterations: int = 10000) -> dict:
        _hit_times: list[int] = []
        _miss_times: list[int] = []

        _probe = array.array("Q", [0]) * 1024
        for _ in range(iterations):
            _idx = random.randint(0, 1023)
            # 缓存命中: 重复访问同一位置
            _ = _probe[_idx]
            _t0 = time.perf_counter_ns()
            _ = _probe[_idx]
            _t1 = time.perf_counter_ns()
            _hit_times.append(_t1 - _t0)

        for _ in range(iterations):
            _idx = random.randint(0, 1023)
            # 缓存缺失: clflush后再访问
            clflush_emulate(_idx)
            memory_barrier()
            _t0 = time.perf_counter_ns()
            _ = _probe[_idx]
            _t1 = time.perf_counter_ns()
            _miss_times.append(_t1 - _t0)

        _hit_ns = statistics.median(_hit_times) if _hit_times else 0
        _miss_ns = statistics.median(_miss_times) if _miss_times else 0
        _threshold_ns = max(int(_hit_ns * 2.5), _hit_ns + 10)
        _resolution = _miss_ns - _hit_ns

        return {
            "hit_time_ns": _hit_ns,
            "miss_time_ns": _miss_ns,
            "threshold_ns": _threshold_ns,
            "resolution": _resolution,
        }

    # ===== 跨核泄漏测试 =====
    # 检测共享L3缓存中的状态变化
    def cross_core_leakage_test(self, iterations: int = 5000) -> dict:
        _probe_size = 16 * 1024 * 1024  # 16MB — 覆盖L3
        _probe = array.array("Q", [0]) * (_probe_size // 8)
        _stride = 64 // 8  # 一个缓存行 = 8个QWORD
        _detections = 0
        _snr_values: list[float] = []

        _threshold = self._calibrate_threshold(1000)

        for _round in range(min(iterations, 500)):
            # 发送者: 访问一组缓存行
            _sender_line = random.randint(0, len(_probe) - _stride)
            for _ in range(8):
                _ = _probe[_sender_line + _]

            # 模拟核心切换 — 延迟
            memory_barrier()

            # 接收者: 探测共享缓存状态
            _noise_times: list[int] = []
            _signal_times: list[int] = []

            # 信号: 测量发送者访问过的行
            for _ in range(10):
                _t0 = time.perf_counter_ns()
                _ = _probe[_sender_line]
                _t1 = time.perf_counter_ns()
                _signal_times.append(_t1 - _t0)

            # 噪声: 测量随机其他行
            _noise_line = random.randint(0, len(_probe) - _stride)
            while abs(_noise_line - _sender_line) < _stride * 64:
                _noise_line = random.randint(0, len(_probe) - _stride)
            for _ in range(10):
                _t0 = time.perf_counter_ns()
                _ = _probe[_noise_line]
                _t1 = time.perf_counter_ns()
                _noise_times.append(_t1 - _t0)

            _sig_mean = statistics.mean(_signal_times) if _signal_times else 0
            _noise_mean = statistics.mean(_noise_times) if _noise_times else 0
            _noise_std = statistics.stdev(_noise_times) if len(_noise_times) > 1 else 0.01
            _snr = (_noise_mean - _sig_mean) / _noise_std if _noise_std > 0 else 0
            _snr_values.append(_snr)

            if _sig_mean < _noise_mean - _noise_std:  # 信号比噪声快 → 缓存命中
                _detections += 1

        _detected = _detections > iterations * 0.3
        _avg_snr = statistics.mean(_snr_values) if _snr_values else 0.0
        _bps = _detections / max(iterations, 1) * 1000

        # Welch t-test 验证统计显著性
        # 用前100轮的信号/噪声数据做双样本检验
        _signal_all: list[float] = []
        _noise_all: list[float] = []
        for _round in range(min(100, len(_snr_values))):
            _signal_all.append(_snr_values[_round])
        _t_pvalue = 1.0
        if len(_signal_all) > 5:
            # 简化 Welch t: 信号 SNR vs 零假设 (mu=0)
            _m = statistics.mean(_signal_all)
            _s = statistics.stdev(_signal_all) if len(_signal_all) > 1 else 1.0
            _n = len(_signal_all)
            _t_stat = _m / (_s / math.sqrt(_n)) if _s > 0 else 0
            _t_pvalue = min(1.0, max(0.0, 2.0 * (1.0 - _approx_normal_cdf(abs(_t_stat)))))

        return {
            "detected": _detected,
            "channel_capacity_bps": _bps,
            "snr": round(_avg_snr, 3),
            "p_value": round(_t_pvalue, 4),
            "cores_tested": 1,
        }


def _approx_normal_cdf(x: float) -> float:
    """标准正态CDF的快速近似。"""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))
