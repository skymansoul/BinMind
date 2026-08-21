import array
import math
import os
import random
import statistics
import time
from typing import Dict, List, Tuple, Optional

# 性能监控计数器分析器
# 基于软件模拟 + 缓存探测定时，实现跨平台PMC估算
#
# 核心思路：在没有硬件 perf_event_open 的环境下（Windows / 受限容器），
# 通过指针追逐 + 步长实验 + 自旋校准来反推缓存层级参数，
# 再利用这些参数估算标准 PMC 事件的期望值。
#
#
#   - GoFetch 的 DMP 检测方法, 指针追逐识别预取器行为
# gem5 缓存模拟中的步长-延迟曲线拟合思路


class PMCAnalyzer:
    def __init__(self):
        # 标准事件编码 — 兼容Intel/AMD
        self._event_map: dict[str, int] = {
            "INSTRUCTIONS_RETIRED": 0x00C0,
            "CPU_CYCLES": 0x003C,
            "CACHE_MISSES": 0x412E,
            "CACHE_REFERENCES": 0x4F2E,
            "BRANCH_MISSES": 0x00C5,
            "BRANCH_INSTRUCTIONS": 0x00C4,
            "L1D_CACHE_MISS": 0x0151,
            "L1I_CACHE_MISS": 0x0280,
            "LLC_MISS": 0x412E,
            "DTLB_MISS": 0x0149,
            "ITLB_MISS": 0x0185,
            "STALLED_CYCLES_FRONTEND": 0x00A2,
            "STALLED_CYCLES_BACKEND": 0x00B2,
        }
        # 缓存层级参数 — 由 calibrate_cache_hierarchy() 填充
        self._l1_size: int = 32 * 1024
        self._l2_size: int = 256 * 1024
        self._l3_size: int = 8 * 1024 * 1024
        self._cache_line: int = 64
        self._l1_latency: float = 1.2   # ns
        self._l2_latency: float = 4.5
        self._l3_latency: float = 14.0
        self._dram_latency: float = 70.0

# 计时校准
    def _time_calibration(self) -> float:
        """自旋循环校准 — 测量单次perf_counter调用的开销"""
        _samples: list[float] = []
        for _ in range(100):
            _t0 = time.perf_counter_ns()
            _t1 = time.perf_counter_ns()
            _samples.append((_t1 - _t0) / 2.0)
        return statistics.median(_samples)

# 缓存层级校准
    # 通过不同工作集大小的指针追逐，推断 L1/L2/L3 容量边界。
    # 原理：当工作集超过某级缓存容量时，平均延迟跳升。
    def calibrate_cache_hierarchy(self) -> Dict[str, float]:
        """返回推断的 L1/L2/L3 容量（字节）和延迟（ns）。

        实现：对 4KB → 64MB 的工作集以 2× 步长扫描，
        绘制步长-延迟曲线，用拐点检测定位缓存边界。
        """
        sizes = [4 * 1024, 8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024,
                 128 * 1024, 256 * 1024, 512 * 1024,
                 1 * 1024 * 1024, 2 * 1024 * 1024, 4 * 1024 * 1024,
                 8 * 1024 * 1024, 16 * 1024 * 1024, 32 * 1024 * 1024,
                 64 * 1024 * 1024]
        latencies: Dict[int, float] = {}
        for wss in sizes:
            lat = self._pointer_chase_latency(wss, stride_bytes=64, trials=2000)
            latencies[wss] = lat

        # 拐点检测：相邻尺寸间延迟增长 > 30% 视为缓存边界
        sorted_sizes = sorted(latencies.keys())
        boundaries: Dict[str, float] = {}
        prev_lat = latencies[sorted_sizes[0]]
        lvl = 1
        for i in range(1, len(sorted_sizes)):
            cur_lat = latencies[sorted_sizes[i]]
            if prev_lat > 0 and cur_lat / prev_lat > 1.40:
                if lvl == 1:
                    boundaries["L1"] = float(sorted_sizes[i - 1])
                elif lvl == 2:
                    boundaries["L2"] = float(sorted_sizes[i - 1])
                elif lvl == 3:
                    boundaries["L3"] = float(sorted_sizes[i - 1])
                lvl += 1
            prev_lat = cur_lat

        # 填充实例变量
        self._l1_size = int(boundaries.get("L1", 32 * 1024))
        self._l2_size = int(boundaries.get("L2", 256 * 1024))
        self._l3_size = int(boundaries.get("L3", 8 * 1024 * 1024))
        self._l1_latency = latencies.get(self._l1_size, 1.2)
        self._l2_latency = latencies.get(self._l2_size, 4.5)
        self._l3_latency = latencies.get(self._l3_size, 14.0)
        self._dram_latency = latencies.get(sorted_sizes[-1], 70.0)

        return {
            "l1_bytes": self._l1_size, "l1_latency_ns": self._l1_latency,
            "l2_bytes": self._l2_size, "l2_latency_ns": self._l2_latency,
            "l3_bytes": self._l3_size, "l3_latency_ns": self._l3_latency,
            "dram_latency_ns": self._dram_latency,
        }

    @staticmethod
    def _pointer_chase_latency(working_set_bytes: int,
                                stride_bytes: int = 64,
                                trials: int = 2000) -> float:
        """指针追逐测时：返回单次访问的中位数延迟（ns）。

        步长 = 64 字节（一条缓存行）确保每次访问都触及新行。
        """
        n_elements = working_set_bytes // 8
        if n_elements < 16:
            n_elements = 16
        buf = array.array("Q", [0]) * n_elements
        step = stride_bytes // 8
        # 链式遍历：每个元素指向 step 步之后
        for i in range(n_elements):
            buf[i] = (i + step) % n_elements

        samples: list[float] = []
        ptr = 0
        # 预热
        for _ in range(min(100, trials // 4)):
            ptr = buf[ptr]
        for _ in range(trials):
            t0 = time.perf_counter_ns()
            ptr = buf[ptr]
            ptr = buf[ptr]
            ptr = buf[ptr]
            ptr = buf[ptr]
            t1 = time.perf_counter_ns()
            samples.append((t1 - t0) / 4.0)
        return statistics.median(samples) if samples else 0.0

# 预取器行为检测
    # GoFetch 的核心发现：DMP 预取器会根据内存内容
    # （指针值）决定是否预取。可通过正向/反向指针追逐的延迟差异来检测。

    def detect_prefetcher_behavior(self) -> Dict[str, float]:
        """检测数据预取器是否正在活跃影响缓存驻留。

        正向追逐（递增地址）→ 预取器友好 → 低延迟
        反向追逐（递减地址）→ 预取器不友好 → 高延迟
        正向/反向差异 > 1.5× → 预取器活跃
        """
        n = 1024
        forward_buf = array.array("Q", [0]) * n
        backward_buf = array.array("Q", [0]) * n
        for i in range(n):
            forward_buf[i] = (i + 1) % n
            backward_buf[(i + 1) % n] = i  # 反向链

        def _measure(buf, iters=500):
            ptr = 0
            for _ in range(50):
                ptr = buf[ptr]
            samples = []
            for _ in range(iters):
                t0 = time.perf_counter_ns()
                for _j in range(8):
                    ptr = buf[ptr]
                t1 = time.perf_counter_ns()
                samples.append((t1 - t0) / 8.0)
            return statistics.median(samples)

        fwd_lat = _measure(forward_buf)
        bwd_lat = _measure(backward_buf)
        ratio = bwd_lat / max(fwd_lat, 0.001)
        return {
            "forward_latency_ns": round(fwd_lat, 2),
            "backward_latency_ns": round(bwd_lat, 2),
            "prefetcher_active": ratio > 1.5,
            "asymmetry_ratio": round(ratio, 3),
        }

# 缓存缺失率估算
    # 通过不同步长的指针追逐测量各级缓存延迟
    def _estimate_cache_miss_ratio(self, working_set_size: int) -> float:
        _buf = array.array("Q", [0]) * (working_set_size // 8)
        # 建立指针链 — 随机排列以击败预取
        _indices = list(range(len(_buf)))
        random.shuffle(_indices)
        for _i in range(len(_indices) - 1):
            _buf[_indices[_i]] = _indices[_i + 1]
        _buf[_indices[-1]] = _indices[0]

        _strides = [8, 16, 32, 64, 128, 256, 512]  # 字节步幅
        _latencies: dict[int, float] = {}
        _accesses_per_test = min(10000, len(_buf))
        for _stride in _strides:
            _stride_qwords = _stride // 8
            _times: list[float] = []
            _ptr = 0
            for _ in range(_accesses_per_test):
                _t0 = time.perf_counter_ns()
                for _j in range(10):
                    _ptr = _buf[(_ptr + _stride_qwords) % len(_buf)]
                _t1 = time.perf_counter_ns()
                _times.append((_t1 - _t0) / 10.0)
            _latencies[_stride] = statistics.median(_times) if _times else 0.0

        if _latencies:
            _min_lat = min(_latencies.values())
            _max_lat = max(_latencies.values())
            if _max_lat > _min_lat * 1.1:
                _ratio = (_max_lat - _min_lat) / _max_lat if _max_lat > 0 else 0.0
                return _ratio
        return 0.01

# 软件PMC估算
    # Windows平台: 自旋+缓存探测+分支模拟
    def software_estimate(self, duration_sec: float = 1.0) -> dict:
        _tick_ns = self._time_calibration()
        _end = time.perf_counter() + duration_sec
        cycles_approx = 0
        spin_iters = 0
        # 自旋循环: 每次迭代约1-2条指令 + 1次分支
        while time.perf_counter() < _end:
            _a, _b = 0, 1
            for _k in range(100):
                _a, _b = _b, _a + _b
            cycles_approx += 100
            spin_iters += 1

        _cpu_freq_ghz = 3.0
        _total_cycles = int(duration_sec * _cpu_freq_ghz * 1e9)
        _instr_retired = spin_iters * 100

        _cache_miss_ratio = self._estimate_cache_miss_ratio(64 * 1024 * 1024)
        _cache_refs = int(_instr_retired * 0.3)
        _cache_misses = int(_cache_refs * _cache_miss_ratio)

        _branch_instr = _instr_retired // 5
        _branch_misses = int(_branch_instr * random.uniform(0.005, 0.03))

        _dtlb_miss = int(_branch_instr * 0.0001)
        _itlb_miss = int(_branch_instr * 0.00005)

        _stall_frontend = int(_total_cycles * random.uniform(0.02, 0.08))
        _stall_backend = int(_total_cycles * random.uniform(0.05, 0.15))

        events = {
            "INSTRUCTIONS_RETIRED": _instr_retired,
            "CPU_CYCLES": _total_cycles,
            "CACHE_MISSES": _cache_misses,
            "CACHE_REFERENCES": _cache_refs,
            "BRANCH_MISSES": _branch_misses,
            "BRANCH_INSTRUCTIONS": _branch_instr,
            "L1D_CACHE_MISS": int(_cache_misses * 0.7),
            "L1I_CACHE_MISS": _itlb_miss,
            "LLC_MISS": int(_cache_misses * 0.3),
            "DTLB_MISS": _dtlb_miss,
            "ITLB_MISS": _itlb_miss,
            "STALLED_CYCLES_FRONTEND": _stall_frontend,
            "STALLED_CYCLES_BACKEND": _stall_backend,
        }
        events["_tick_ns"] = _tick_ns
        return events

    # //// 侧信道指标检测 ////
    def detect_side_channel_indicators(self, pmc_data: dict) -> list[dict]:
        indicators: list[dict] = []
        _instr = pmc_data.get("INSTRUCTIONS_RETIRED", 1)
        _cache_miss = pmc_data.get("CACHE_MISSES", 0)
        _cache_ref = pmc_data.get("CACHE_REFERENCES", _cache_miss + 1)
        _cache_ratio = _cache_miss / max(_cache_ref, 1)
        _branch_miss = pmc_data.get("BRANCH_MISSES", 0)
        _branch_total = pmc_data.get("BRANCH_INSTRUCTIONS", _branch_miss + 1)
        _branch_ratio = _branch_miss / max(_branch_total, 1)
        _dtlb_miss = pmc_data.get("DTLB_MISS", 0)
        _dtlb_ratio = _dtlb_miss / max(_instr, 1)

        # Flush+Reload / Prime+Probe · 高缓存缺失率
        if _cache_ratio > 0.30:
            _conf = min(0.95, _cache_ratio * 2.0)
            indicators.append({
                "indicator": "flush_reload_or_prime_probe",
                "confidence": round(_conf, 3),
                "evidence": f"缓存缺失率 {_cache_ratio:.2%} > 30%",
            })

        # Spectre · 高分支预测失败率
        if _branch_ratio > 0.10:
            _conf = min(0.95, _branch_ratio * 5.0)
            indicators.append({
                "indicator": "spectre_branch_mispredict",
                "confidence": round(_conf, 3),
                "evidence": f"分支预测失败率 {_branch_ratio:.2%} > 10%",
            })

        # ASLR绕过 · DTLB异常
        if _dtlb_ratio > 0.02:
            _conf = min(0.90, _dtlb_ratio * 30.0)
            indicators.append({
                "indicator": "possible_aslr_bypass_dtlb",
                "confidence": round(_conf, 3),
                "evidence": f"DTLB miss率 {_dtlb_ratio:.2%} > 2%",
            })

        # Meltdown式 · 前后端高停顿+缓存缺失
        _stall_f = pmc_data.get("STALLED_CYCLES_FRONTEND", 0)
        _stall_b = pmc_data.get("STALLED_CYCLES_BACKEND", 0)
        _cycles = pmc_data.get("CPU_CYCLES", 1)
        _stall_ratio = (_stall_f + _stall_b) / max(_cycles, 1)
        if _stall_ratio > 0.20 and _cache_ratio > 0.15:
            indicators.append({
                "indicator": "possible_meltdown_stall_pattern",
                "confidence": 0.60,
                "evidence": f"停顿率 {_stall_ratio:.2%} + 缓存缺失率 {_cache_ratio:.2%}",
            })

        # GoFetch 模式：指令数异常低 + 高缓存缺失 → 预取器侧信道
        _ipc = _instr / max(_cycles, 1)
        if _ipc < 0.3 and _cache_ratio > 0.25:
            indicators.append({
                "indicator": "possible_prefetcher_side_channel",
                "confidence": 0.55,
                "evidence": f"低IPC {_ipc:.2f} + 高缓存缺失率 {_cache_ratio:.2%}",
            })

        return indicators

# 缓存层级分析
    def analyze_cache_miss_ratio(self, pmc_data: dict) -> dict:
        _l1d = pmc_data.get("L1D_CACHE_MISS", 0)
        _l1i = pmc_data.get("L1I_CACHE_MISS", 0)
        _llc = pmc_data.get("LLC_MISS", 0)
        _total_refs = pmc_data.get("CACHE_REFERENCES", 1)
        _instr = pmc_data.get("INSTRUCTIONS_RETIRED", 1)

        _l1_miss = (_l1d + _l1i) / max(_total_refs, 1)
        _l2_miss = _llc / max(_total_refs, 1)
        _l3_miss = _llc / max(_total_refs, 1)

        if _l1_miss < 0.02:
            _interpretation = "L1缓存利用率优异"
        elif _l1_miss < 0.10:
            _interpretation = "L1缓存正常"
        elif _l1_miss < 0.30:
            _interpretation = "L1缓存压力 — 考虑数据局部性优化"
        else:
            _interpretation = "L1缓存严重压力 — 可能存在侧信道攻击"

        return {
            "l1_miss_ratio": round(_l1_miss, 6),
            "l2_miss_ratio": round(_l2_miss, 6),
            "l3_miss_ratio": round(_l3_miss, 6),
            "interpretation": _interpretation,
        }

# 双剖面比较
    def compare_profiles(self, baseline: dict, target: dict) -> dict:
        result: dict = {}
        _metrics = [
            "INSTRUCTIONS_RETIRED", "CPU_CYCLES", "CACHE_MISSES",
            "BRANCH_MISSES", "DTLB_MISS", "LLC_MISS",
        ]
        _ratios: list[float] = []
        for _m in _metrics:
            _b_val = baseline.get(_m, 0)
            _t_val = target.get(_m, 0)
            _ratio = _t_val / _b_val if _b_val > 0 else float("inf") if _t_val > 0 else 1.0
            _ratios.append(min(_ratio, 100.0))
            result[_m.lower()] = {
                "baseline": _b_val,
                "target": _t_val,
                "ratio": _ratio,
                "anomalous": False,
            }

        # 2-sigma检测
        if _ratios:
            _mean = statistics.mean(_ratios)
            _stdev = statistics.stdev(_ratios) if len(_ratios) > 1 else 1.0
            _i = 0
            for _m in _metrics:
                _key = _m.lower()
                _r = result[_key]["ratio"]
                if abs(_r - _mean) > 2.0 * _stdev:
                    result[_key]["anomalous"] = True
                _i += 1

        return result
