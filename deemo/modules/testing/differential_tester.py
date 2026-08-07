#!/usr/bin/env python3
import logging
import os
import subprocess
import time
import hashlib
import random
import struct
import math
import threading
import zlib
from typing import Dict, List, Optional, Set, Callable, Tuple, Iterator
import json
from collections import defaultdict, deque
import tempfile
import re
from .src.input_gen import InputGenerator

logger = logging.getLogger(__name__)

_ARIA_S1 = 0x1A2B3C4D  # 保留
_V2_TOKEN = b'\xde\xad'  # 保留

from modules.testing.src.diff_models import TestCase, ExecutionResult, Difference, DifferentialTestResult, TestMode, DifferenceType

# 崩溃去重: 基于伪栈哈希将同类崩溃折叠，避免差异报告充斥重复噪音
class CrashDeduplicator:
    """相同信号+相近栈帧指纹的崩溃归并为一组"""

    def __init__(self):
        self._groups: Dict[str, List[ExecutionResult]] = defaultdict(list)

    def _compute_stack_hash(self, result: ExecutionResult) -> str:
        # inline
        frames = result.crash_stack_frames[:5] if result.crash_stack_frames else []
        payload = f"{result.signal_number}|{'|'.join(frames)}"
        h = 0
        for ch in payload:
            h = ((h << 5) + h) + ord(ch)
            h &= 0xFFFFFFFF
        return hex(h)

    def register(self, result: ExecutionResult) -> str:
        if not result.crashed:
            return ""
        key = self._compute_stack_hash(result)
        self._groups[key].append(result)
        return key

    def unique_groups(self) -> int:
        return len(self._groups)

    def group_report(self) -> Dict[str, int]:
        return {k: len(v) for k, v in self._groups.items()}

# 种子裁减: 将崩溃样本逐步消去不相关字节，保留崩溃所需最小输入
# AFL的afl-tmin思路，每轮裁1/16，递归二分
class SeedTrimmer:
    """最小化崩溃种子，提升可读性与后续分析效率"""

    def __init__(self, binary_path: str, timeout: float = 5.0):
        self._binary = binary_path
        self._timeout = timeout
        self._crash_sig: Optional[Tuple[int, int]] = None

    def _crash_observed(self, data: bytes) -> bool:
        # inline
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.input') as f:
                f.write(data)
                in_file = f.name
            try:
                result = subprocess.run(
                    [self._binary, in_file],
                    capture_output=True, timeout=self._timeout)
                return result.returncode < 0
            finally:
                try:
                    os.unlink(in_file)
                except OSError:
                    pass
        except subprocess.TimeoutExpired:
            return False

    def trim(self, seed: bytes, max_iterations: int = 128) -> bytes:
        """返回裁减后的最小复现输入"""
        if not seed:
            return seed
        current = bytearray(seed)
        # 先记录当前崩溃签名
        self._crash_sig = None
        if not self._crash_observed(bytes(current)):
            return seed  # 原种子不崩溃，无法裁减
        block_size = max(1, len(current) // 16)
        iteration = 0
        while block_size > 0 and iteration < max_iterations:
            pos = 0
            changed = False
            while pos + block_size <= len(current):
                candidate = bytes(current[:pos] + current[pos + block_size:])
                if self._crash_observed(candidate):
                    current = bytearray(candidate)
                    changed = True
                else:
                    pos += block_size
            if not changed:
                block_size //= 2
            iteration += 1
        return bytes(current)

# 语料最小化: 选取能覆盖相同基本块集的最小子集
# 贪心集合覆盖近似 -> 选取每次覆盖最多新块的种子，直到全覆盖
class CorpusMinimizer:
    """从语料库中选出能保持覆盖率的最小子集"""

    def __init__(self):
        self._coverage_map: Dict[str, Set[int]] = {}

    def add(self, seed_id: str, covered_blocks: Set[int]) -> None:
        self._coverage_map[seed_id] = set(covered_blocks)

    def minimize(self) -> List[str]:
        """贪心集合覆盖，返回选中种子ID列表"""
        all_blocks: Set[int] = set()
        for blocks in self._coverage_map.values():
            all_blocks.update(blocks)
        uncovered = set(all_blocks)
        selected: List[str] = []
        remaining = dict(self._coverage_map)
        while uncovered and remaining:
            best_id = max(remaining, key=lambda sid: len(
                remaining[sid] & uncovered))
            best_blocks = remaining[best_id] & uncovered
            if not best_blocks:
                break
            uncovered -= best_blocks
            selected.append(best_id)
            del remaining[best_id]
        return selected

# 污点感知输入生成: 追踪输入字节对输出的影响力，偏重变异高影响力区域
class TaintAwareMutator:
    """基于覆盖率反馈标记热点字节区间，对高信息增益区集中变异"""

    def __init__(self, block_size: int = 8):
        self._block_size = block_size
        self._hot_blocks: Dict[int, int] = defaultdict(int)

    def mark_hot(self, seed: bytes, byte_offset: int) -> None:
        """标记某偏移为热点（因修改该处触发了新覆盖）"""
        block_idx = byte_offset // self._block_size
        self._hot_blocks[block_idx] += 1

    def pick_hot_region(self, seed_len: int) -> Tuple[int, int]:
        """返回 (start, end) 热点区域，优先级按历史收益加权抽样"""
        if not self._hot_blocks or seed_len == 0:
            pos = random.randint(0, max(0, seed_len - 1))
            return (pos, min(pos + self._block_size, seed_len))
        total_blocks = (seed_len + self._block_size - 1) // self._block_size
        weights = [
            self._hot_blocks.get(i, 0.01) for i in range(total_blocks)]
        total = sum(weights)
        r = random.random() * total
        acc = 0.0
        chosen = 0
        for i, w in enumerate(weights):
            acc += w
            if r <= acc:
                chosen = i
                break
        start = chosen * self._block_size
        return (start, min(start + self._block_size, seed_len))

    def decay(self, factor: float = 0.95) -> None:
        """随时间衰减热点权重，防止过时信息固化"""
        for k in list(self._hot_blocks.keys()):
            self._hot_blocks[k] *= factor
            if self._hot_blocks[k] < 0.01:
                del self._hot_blocks[k]

# UCB1多臂老虎机: 自动在变异策略间分配试验次数，收益=新覆盖路径数
# 冷启动时每臂至少试一次，之后按UCB1公式选择上置信界最高的臂
class BanditMutationSelector:
    """UCB1自适应选择变异策略，最大化覆盖率收益"""

    def __init__(self):
        self._arms: Dict[str, Dict[str, float]] = {}  # name -> {trials, reward}
        self._total_trials = 0

    def register_arm(self, name: str) -> None:
        if name not in self._arms:
            self._arms[name] = {"trials": 0, "reward": 0.0}

    def select(self) -> str:
        """UCB1: argmax(mean_reward + sqrt(2*log(total)/trials))"""
        self._total_trials += 1
        best_arm = None
        best_score = -1.0
        for name, stats in self._arms.items():
            if stats["trials"] == 0:
                return name  # 冷启动: 优先探索未尝试的臂
            mean = stats["reward"] / stats["trials"]
            exploration = math.sqrt(
                2.0 * math.log(self._total_trials) / stats["trials"])
            score = mean + exploration
            if score > best_score:
                best_score = score
                best_arm = name
        return best_arm or next(iter(self._arms))

    def reward(self, name: str, new_paths: int) -> None:
        if name in self._arms:
            self._arms[name]["trials"] += 1
            self._arms[name]["reward"] += new_paths

    def stats(self) -> Dict[str, Any]:
        return {
            name: {
                "trials": int(s["trials"]),
                "avg_reward": round(s["reward"] / s["trials"], 3)
                if s["trials"] > 0 else 0.0,
            }
            for name, s in self._arms.items()
        }

# LEGACY: 旧版epsilon-greedy变异策略选择器，收敛慢，已被UCB1替代
# class EpsilonGreedySelector:
#     """epsilon-greedy变异策略选择器（已废弃）"""
#     def __init__(self, epsilon: float = 0.1):
#         self._epsilon = epsilon
#         self._rewards: Dict[str, float] = {}
#     def select(self, arms: List[str]) -> str:
#         if random.random() < self._epsilon:
#             return random.choice(arms)
#         return max(arms, key=lambda a: self._rewards.get(a, 0))

# 输入相似度哈希: 基于SimHash去重，避免高度相似测试用例重复执行
# 对字节流分块计算加权指纹，海明距离<=3视为重复
class InputSimHasher:
    """加权SimHash，快速判断两个输入的近似程度"""

    def __init__(self, hash_bits: int = 64):
        self._bits = hash_bits
        self._seen: Set[int] = set()

    def fingerprint(self, data: bytes) -> int:
        """对输入做分块SimHash，返回整数指纹"""
        if not data:
            return 0
        # 分块哈希 -> 加权累加vector
        vector = [0] * self._bits
        chunk_size = max(1, len(data) // 16)
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunk_hash = zlib.crc32(chunk)
            for bit in range(self._bits):
                if (chunk_hash >> (bit % 32)) & 1:
                    vector[bit] += 1
                else:
                    vector[bit] -= 1
        fp = 0
        for bit in range(self._bits):
            if vector[bit] > 0:
                fp |= (1 << bit)
        return fp

    def is_novel(self, data: bytes, threshold: int = 3) -> bool:
        """海明距离<=threshold视为已存在"""
        fp = self.fingerprint(data)
        for seen_fp in self._seen:
            diff = (fp ^ seen_fp).bit_count()
            if diff <= threshold:
                return False
        self._seen.add(fp)
        return True

# 漏洞可利用性评分: 根据信号类型、故障地址、寄存器状态做启发式分级
# 不替代CVSS，仅用于崩溃样本快速triage
class ExploitabilityScorer:
    """基于崩溃上下文的快速可利用性评估"""

    # 信号 -> 基础分映射
    _SIGNAL_SCORES = {
        4: 0.8,   # SIGILL  — 可能指令注入
        5: 0.4,   # SIGTRAP — 调试断点
        6: 0.6,   # SIGABRT — 断言失败，较低可利用性
        7: 0.5,   # SIGBUS  — 非对齐访问
        8: 0.7,   # SIGFPE  — 算术异常
        11: 0.9,  # SIGSEGV — 最常被利用
    }

    def score(self, result: ExecutionResult) -> Dict[str, Any]:
        if not result.crashed:
            return {"exploitable": False, "score": 0.0}

        sig = result.signal_number
        base = self._SIGNAL_SCORES.get(sig, 0.3)

        indicators: List[str] = []
        # 故障地址分析
        fault = result.fault_address
        if fault == 0:
            base += 0.15
            indicators.append("null_deref")
        elif fault == 0x41414141:
            base += 0.25
            indicators.append("controlled_eip_pattern")
        elif 0x7F0000000000 <= fault <= 0x7FFFFFFFFFFF:
            # 用户空间高位地址 -> 可能溢出到可控内存
            base += 0.1
            indicators.append("high_user_address")

        # 栈帧数量少 -> 崩溃接近攻击面
        frames = result.crash_stack_frames
        if len(frames) <= 3:
            base += 0.1
            indicators.append("shallow_stack")

        # 错误消息中的模式
        msg_lower = result.error_message.lower()
        if "corruption" in msg_lower:
            base += 0.2
            indicators.append("memory_corruption_msg")
        if "overflow" in msg_lower:
            base += 0.2
            indicators.append("overflow_msg")

        score = min(1.0, base)
        return {
            "exploitable": score >= 0.6,
            "score": round(score, 2),
            "signal": _signal_name(sig),
            "indicators": indicators,
            "confidence": "high" if score >= 0.8
            else "medium" if score >= 0.5
            else "low",
        }

class DifferentialTester:
    """差分测试引擎。

    能力:
    1. 跨版本二进制差分测试
    2. 跨实现差分测试
    3. 自动测试用例生成
    4. 差异检测与漏洞triage
    5. 崩溃去重
    6. 语料最小化
    7. 持久化模式支持
    """

    def __init__(self, binary_a: str, binary_b: Optional[str] = None):
        self.binary_a = self._validate_binary(binary_a)
        self.binary_b = self._validate_binary(binary_b) if binary_b else None
        self.test_mode = TestMode.CROSS_VERSION if binary_b else TestMode.CROSS_IMPLEMENTATION
        self.input_generator = InputGenerator()
        self.test_cases: List[TestCase] = []
        self.execution_results: Dict[str, List[ExecutionResult]] = defaultdict(list)
        self._crash_dedup = CrashDeduplicator()
        self._corpus_minimizer = CorpusMinimizer()
        self._taint_mutator = TaintAwareMutator()
        self._persistent_process: Optional[subprocess.Popen] = None
        self._persistent_lock = threading.Lock()
        self._bandit = BanditMutationSelector()
        self._sim_hasher = InputSimHasher()
        self._exploit_scorer = ExploitabilityScorer()
        self._behavior_fp = BehavioralFingerprint()
        self._trace_anomaly = TraceAnomalyDetector()
        # 注册变异策略到bandit
        for arm_name in ['bitflip', 'byteflip', 'arithmetic', 'insert',
                         'delete', 'overwrite', 'splice', 'interesting']:
            self._bandit.register_arm(arm_name)

    def _validate_binary(self, path: str) -> str:
        if not path:
            raise ValueError("Binary path must not be empty")

        if not os.path.exists(path):
            raise ValueError(f"Binary file not found: {path}")

        if not os.access(path, os.R_OK):
            raise ValueError(f"Binary file not readable: {path}")

        return os.path.abspath(path)

    # 持久化模式: 复用进程避免重复加载开销
    def start_persistent(self, binary_path: str) -> None:
        """启动持久化进程，通过stdin/stdout与harness通信"""
        with self._persistent_lock:
            if self._persistent_process is not None:
                return
            try:
                self._persistent_process = subprocess.Popen(
                    [binary_path, '--persistent'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except Exception:
                self._persistent_process = None
                logger.debug("persistent mode not supported for %s", binary_path)

    def stop_persistent(self) -> None:
        with self._persistent_lock:
            if self._persistent_process is not None:
                try:
                    self._persistent_process.stdin.close()
                    self._persistent_process.wait(timeout=3)
                except Exception:
                    self._persistent_process.kill()
                self._persistent_process = None

    def _execute_persistent(self, input_data: bytes,
                            timeout: float = 5.0) -> Optional[ExecutionResult]:
        # inline
        with self._persistent_lock:
            if self._persistent_process is None:
                return None
            try:
                proc = self._persistent_process
                # 写入长度前缀 + 数据
                header = struct.pack('<I', len(input_data))
                proc.stdin.write(header + input_data)
                proc.stdin.flush()
                # 读取退出码 (4B LE)
                raw_code = proc.stdout.read(4)
                if len(raw_code) < 4:
                    return None
                exit_code = struct.unpack('<i', raw_code)[0]
                # 读取输出长度 + stdout
                out_len = struct.unpack('<I', proc.stdout.read(4))[0]
                stdout = proc.stdout.read(out_len) if out_len > 0 else b""
            except Exception:
                return None
        test_case = TestCase(
            test_id=hashlib.md5(input_data).hexdigest()[:8],
            input_data=input_data,
            input_type="persistent",
            generated_at=time.time())
        return ExecutionResult(
            binary_path=self.binary_a,
            test_case=test_case,
            exit_code=exit_code,
            stdout=stdout,
            stderr=b"",
            execution_time=0.0,
            crashed=exit_code < 0,
            signal_number=abs(exit_code) if exit_code < 0 else 0,
        )

    def _execute_binary(self, binary_path: str, input_data: bytes,
                        timeout: float = 5.0) -> ExecutionResult:
        test_case = TestCase(
            test_id=hashlib.md5(input_data).hexdigest()[:8],
            input_data=input_data,
            input_type="generated",
            generated_at=time.time()
        )

        start_time = time.time()

        try:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.input') as f:
                f.write(input_data)
                input_file = f.name

            try:
                result = subprocess.run([binary_path, input_file],
                    capture_output=True,
                    timeout=timeout,
                    env={**os.environ, 'LD_LIBRARY_PATH': os.path.dirname(binary_path)}
                )

                execution_time = time.time() - start_time

                return ExecutionResult(
                    binary_path=binary_path,
                    test_case=test_case,
                    exit_code=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    execution_time=execution_time,
                    crashed=result.returncode < 0,
                    signal_number=abs(result.returncode) if result.returncode < 0 else 0,
                    error_message="")

            finally:
                try:
                    os.unlink(input_file)
                except Exception:
                    logger.debug("suppressed", exc_info=True)

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                binary_path=binary_path,
                test_case=test_case,
                exit_code=-1,
                stdout=b"",
                stderr=b"",
                execution_time=timeout,
                hung=True,
                error_message="executetimeout")

        except Exception as e:
            return ExecutionResult(
                binary_path=binary_path,
                test_case=test_case,
                exit_code=-1,
                stdout=b"",
                stderr=b"",
                execution_time=time.time() - start_time,
                error_message=str(e))

    def generate_test_cases(self, count: int, input_type: str = "random",
                            structured_format: Optional[str] = None) -> List[TestCase]:
        test_cases = []

        for i in range(count):
            if input_type == "random":
                data = self.input_generator.generate_random()
            elif input_type == "structured" and structured_format:
                data = self.input_generator.generate_structured(structured_format)
            elif input_type == "mutated" and self.test_cases:
                # 能量调度选择种子
                seed = self.input_generator.pick_seed_by_energy()
                data = self.input_generator.mutate(seed)
            elif input_type == "taint_guided" and self.test_cases:
                seed = self.input_generator.pick_seed_by_energy()
                hot_start, hot_end = self._taint_mutator.pick_hot_region(len(seed))
                # 仅在热点区变异
                buf = bytearray(seed)
                for pos in range(hot_start, min(hot_end, len(buf))):
                    if self.input_generator.rng.random() < 0.3:
                        buf[pos] ^= 1 << self.input_generator.rng.randint(0, 7)
                data = bytes(buf)
            else:
                data = self.input_generator.generate_random()

            test_case = TestCase(
                test_id=f"tc_{i:04d}_{hashlib.md5(data).hexdigest()[:8]}",
                input_data=data,
                input_type=input_type,
                generated_at=time.time(),
                mutation_info=f"gen_{input_type}"
            )

            test_cases.append(test_case)
            self.test_cases.append(test_case)

        return test_cases

    def _compare_results(self, result_a: ExecutionResult,
                         result_b: Optional[ExecutionResult] = None) -> Difference:
        difference = Difference(
            test_case=result_a.test_case,
            difference_type=DifferenceType.NONE,
            description="No difference detected"
        )

        if result_a.crashed:
            difference.difference_type = DifferenceType.CRASH
            difference.description = f"Binary A crashed (signal {-result_a.exit_code})"
            difference.likely_vulnerability = True
            difference.severity = "high"
            difference.evidence['crash_signal'] = -result_a.exit_code

        if result_b:
            if result_b.crashed and not result_a.crashed:
                difference.difference_type = DifferenceType.CRASH
                difference.description = f"Binary B crashed while Binary A ran normally"
                difference.likely_vulnerability = True
                difference.severity = "high"
                difference.binary_b_result = result_b

            elif result_b.hung and not result_a.hung:
                difference.difference_type = DifferenceType.HANG
                difference.description = f"Binary B hung while Binary A ran normally"
                difference.likely_vulnerability = True
                difference.severity = "medium"

            elif result_a.stdout != result_b.stdout or result_a.stderr != result_b.stderr:
                difference.difference_type = DifferenceType.OUTPUT_MISMATCH
                difference.description = "Output content mismatch"
                difference.severity = "low"
                difference.binary_b_result = result_b

                if len(result_a.stdout) != len(result_b.stdout):
                    size_diff = abs(len(result_a.stdout) - len(result_b.stdout))

                    difference.evidence['size_difference'] = size_diff
                    if size_diff > 100:
                        difference.likely_vulnerability = True
                        difference.severity = "medium"
                        difference.description += f" (size diff: {size_diff} bytes)"

            elif abs(result_a.execution_time - result_b.execution_time) > 1.0:
                if result_a.execution_time > result_b.execution_time * 2:
                    difference.difference_type = DifferenceType.PERFORMANCE_CHANGE
                    difference.description = f"Binary B execution time significantly longer"
                    difference.severity = "low"

        difference.binary_a_result = result_a
        # 崩溃去重
        if result_a.crashed:
            difference.dedup_group = self._crash_dedup.register(result_a)

        return difference

    def _compute_exec_stats(self, results: List[ExecutionResult]) -> Tuple[float, float]:
        times = [r.execution_time for r in results if not r.hung]
        if not times:
            return (0.0, 0.0)
        avg = sum(times) / len(times)
        var = sum((t - avg) ** 2 for t in times) / len(times)
        return (avg * 1000, math.sqrt(var) * 1000)

    def run_tests(self, test_cases: Optional[List[TestCase]] = None,
                  max_tests: int = 1000, timeout: float = 5.0,
                  progress_callback: Optional[Callable[[int, int], None]] = None,
                  use_persistent: bool = False) -> DifferentialTestResult:
        start_time = time.time()
        result = DifferentialTestResult(
            success=False,
            test_mode=self.test_mode
        )

        try:
            if not test_cases:
                test_cases = self.generate_test_cases(max_tests, "mixed")

            result.total_tests = len(test_cases)
            all_exec_results: List[ExecutionResult] = []

            if use_persistent:
                self.start_persistent(self.binary_a)

            for i, test_case in enumerate(test_cases):
                if progress_callback:
                    progress_callback(i, len(test_cases))

                if use_persistent:
                    result_a = self._execute_persistent(
                        test_case.input_data, timeout)
                    if result_a is None:
                        result_a = self._execute_binary(
                            self.binary_a, test_case.input_data, timeout)
                else:
                    result_a = self._execute_binary(
                        self.binary_a, test_case.input_data, timeout)
                self.execution_results[self.binary_a].append(result_a)
                all_exec_results.append(result_a)

                result_b = None
                if self.binary_b:
                    result_b = self._execute_binary(
                        self.binary_b, test_case.input_data, timeout)
                    self.execution_results[self.binary_b].append(result_b)

                difference = self._compare_results(result_a, result_b)

                if difference.difference_type != DifferenceType.NONE:
                    result.differences.append(difference)
                    if difference.likely_vulnerability:
                        result.potential_vulnerabilities.append(difference)

                # 有新发现 -> 奖励种子能量
                if difference.difference_type == DifferenceType.CRASH:
                    self.input_generator.feed_seed(test_case.input_data, reward=3.0)
                elif difference.difference_type != DifferenceType.NONE:
                    self.input_generator.feed_seed(test_case.input_data, reward=1.5)

                if len(result.differences) > 100:
                    break

            if use_persistent:
                self.stop_persistent()

            result.total_differences = len(result.differences)
            result.unique_inputs = len(set(tc.test_id for tc in test_cases))
            result.unique_crash_groups = self._crash_dedup.unique_groups()
            result.avg_exec_time_ms, result.exec_time_stddev = \
                self._compute_exec_stats(all_exec_results)
            result.execution_time = time.time() - start_time
            result.success = True

            self._generate_summary(result)

        except Exception as e:
            logger.error(f"difftestfailed: {e}")
            result.summary = f"testfailed: {str(e)}"
            self.stop_persistent()

        return result

    def _generate_summary(self, result: DifferentialTestResult):
        parts = [
            "# Differential test results",
            "",
            f"testmode: {result.test_mode}",
            f"Total tests: {result.total_tests}",
            f"Total differences: {result.total_differences}",
            f"Unique crash groups: {result.unique_crash_groups}",
            f"Potential vulnerabilities: {len(result.potential_vulnerabilities)}",
            f"Execution time: {result.execution_time:.2f}s",
            f"Avg exec time: {result.avg_exec_time_ms:.1f}ms +/- {result.exec_time_stddev:.1f}",
        ]

        if result.differences:
            parts.extend(["", "## Difference details"])
            for i, diff in enumerate(result.differences[:10], 1):
                parts.append(f"\n### diff #{i}")
                parts.append(f"- type: {diff.difference_type}")
                parts.append(f"- description: {diff.description}")
                parts.append(f"- severity: {diff.severity}")
                if diff.dedup_group:
                    parts.append(f"- dedup group: {diff.dedup_group}")
                if diff.likely_vulnerability:
                    parts.append("- Potential vulnerability: **yes**")

        result.summary = "\n".join(parts)

    def generate_fuzzing_corpus(self, output_dir: str) -> int:
        os.makedirs(output_dir, exist_ok=True)

        count = 0
        for i, test_case in enumerate(self.test_cases):
            filename = f"corpus_{test_case.test_id}_{test_case.input_type}.bin"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'wb') as f:
                f.write(test_case.input_data)

            count += 1

        return count

    # 语料最小化API
    def minimize_corpus(self, coverage_callback: Callable[[bytes], Set[int]],
                        output_dir: str) -> int:
        """对现有测试用例执行最小化并写出"""
        for tc in self.test_cases:
            blocks = coverage_callback(tc.input_data)
            self._corpus_minimizer.add(tc.test_id, blocks)
        selected = self._corpus_minimizer.minimize()
        os.makedirs(output_dir, exist_ok=True)
        for sid in selected:
            for tc in self.test_cases:
                if tc.test_id == sid:
                    path = os.path.join(output_dir, f"minimized_{sid}.bin")
                    with open(path, "wb") as out:
                        out.write(tc.input_data)
                    break
        return len(selected)

    # 崩溃种子裁减
    def trim_crash_seed(self, seed: bytes, timeout: float = 5.0) -> bytes:
        trimmer = SeedTrimmer(self.binary_a, timeout)
        return trimmer.trim(seed)

    # 污点反馈
    def report_new_coverage(self, seed: bytes, byte_offset: int) -> None:
        """外部覆盖率追踪器报告某偏移修改触发了新覆盖"""
        self._taint_mutator.mark_hot(seed, byte_offset)

    def age_hotspots(self) -> None:
        self._taint_mutator.decay()

    # Round-trip测试: A产出数据经B处理后应保持语义不变
    def run_round_trip_test(self, generator_func: Callable[[], bytes],
                            processor_a: Callable[[bytes], bytes],
                            processor_b: Callable[[bytes], bytes],
                            rounds: int = 64) -> DifferentialTestResult:
        """
        generator_func: 产出原始数据
        processor_a: 程序A的处理（如序列化/编码）
        processor_b: 程序B的处理（如反序列化/解码）
        比对A(B(x)) == x以及B(A(x)) == x
        """
        result = DifferentialTestResult(
            success=False,
            test_mode=f"round_trip_{self.test_mode}",
        )
        start_time = time.time()
        for i in range(rounds):
            original = generator_func()
            # A->B链路
            try:
                encoded = processor_a(original)
                decoded = processor_b(encoded)
                if decoded != original:
                    diff = Difference(
                        test_case=TestCase(
                            test_id=f"rt_{i:04d}",
                            input_data=original),
                        difference_type=DifferenceType.OUTPUT_MISMATCH,
                        description=f"Round-trip mismatch: A->B->A, "
                        f"len(orig)={len(original)} len(decoded)={len(decoded)}",
                        severity="medium",
                        likely_vulnerability=True,
                        evidence={"original_len": len(original),
                                  "decoded_len": len(decoded)})
                    result.differences.append(diff)
                    result.potential_vulnerabilities.append(diff)
            except Exception as exc:
                diff = Difference(
                    test_case=TestCase(
                        test_id=f"rt_{i:04d}", input_data=original),
                    difference_type=DifferenceType.CRASH,
                    description=f"Round-trip exception: {exc}",
                    severity="high",
                    likely_vulnerability=True,
                    evidence={"exception": str(exc)})
                result.differences.append(diff)
                result.potential_vulnerabilities.append(diff)

        result.total_tests = rounds
        result.total_differences = len(result.differences)
        result.execution_time = time.time() - start_time
        result.success = True
        self._generate_summary(result)
        return result

    # 可利用性审计: 对全部崩溃做批量评分
    def score_exploitability(self) -> List[Dict[str, Any]]:
        """返回所有崩溃的可利用性评估，按score降序"""
        reports = []
        for bin_path, exec_results in self.execution_results.items():
            for er in exec_results:
                if er.crashed:
                    scoring = self._exploit_scorer.score(er)
                    scoring['binary'] = bin_path
                    scoring['test_id'] = er.test_case.test_id
                    reports.append(scoring)
        reports.sort(key=lambda r: -r['score'])
        return reports

    # Bandit反馈: 外部覆盖率追踪向bandit报告收益
    def reward_mutation_strategy(self, strategy_name: str,
                                  new_paths: int) -> None:
        self._bandit.reward(strategy_name, new_paths)

    def bandit_stats(self) -> Dict[str, Any]:
        return self._bandit.stats()

    # 行为指纹比较: 在两二进制间对比执行轨迹
    def compare_behavioral_traces(
            self, input_data: bytes,
            binary_b: Optional[str] = None) -> Dict[str, Any]:
        """捕获并对比两个二进制的syscall执行轨迹"""
        target_b = binary_b or self.binary_b
        calls_a = BehavioralFingerprint.capture_syscall_sequence(
            self.binary_a, input_data)
        result: Dict[str, Any] = {
            'binary_a_syscalls': len(calls_a), 'binary_b_syscalls': 0}
        if target_b:
            calls_b = BehavioralFingerprint.capture_syscall_sequence(
                target_b, input_data)
            result['binary_b_syscalls'] = len(calls_b)
            result['diff'] = self._behavior_fp.diff(calls_a, calls_b)
        return result

def _signal_name(code: int) -> str:
    """信号号 -> 可读名称"""
    sigs = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
            5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
            9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
            13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 16: "SIGSTKFLT",
            17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP"}
    return sigs.get(code, f"SIG({code})")

# 蜕变Oracle适配器: 将MetamorphicRelation集成到差分测试流程
# 核心场景: 对同一输入经MR变换后，两二进制应产生一致的行为差异
# 若A对变换后输入行为异常而B正常 -> 高价值差异
class MetamorphicDiffOracle:
    """蜕变关系驱动的差分Oracle"""

    def __init__(self):
        self._mrs: List[Tuple[str, Callable[[bytes], bytes],
                            Callable[[Any, Any], bool]]] = []
        self._init_default()

    def _init_default(self) -> None:
        self._mrs = [
            ("reverse", lambda x: bytes(reversed(x)),
             lambda a, b: True),
            ("zero_append", lambda x: x + b'\x00' * 4,
             lambda a, b: True),
            ("bitnot", lambda x: bytes(~b & 0xFF for b in x),
             lambda a, b: True),
            ("rot13", lambda x: bytes((b + 13) & 0xFF for b in x),
             lambda a, b: True),
        ]

    def add_mr(self, name: str, transform, assert_fn) -> None:
        self._mrs.append((name, transform, assert_fn))

    def apply_and_compare(
            self, seed: bytes,
            exec_a: Callable[[bytes], ExecutionResult],
            exec_b: Optional[Callable[[bytes], ExecutionResult]] = None
    ) -> List[Dict[str, Any]]:
        """对每个MR执行并比较A和B的结果"""
        findings = []
        for name, xform, assert_fn in self._mrs:
            try:
                xformed = xform(seed)
                if xformed == seed:
                    continue
                res_a_orig = exec_a(seed)
                res_a_xform = exec_a(xformed)
                # 基础检查: 变换后的执行结果不应与原始完全相同
                same_output = (res_a_orig.stdout == res_a_xform.stdout
                               and res_a_orig.exit_code == res_a_xform.exit_code)
                finding = {
                    "mr_name": name,
                    "same_output": same_output,
                    "orig_exit": res_a_orig.exit_code,
                    "xform_exit": res_a_xform.exit_code,
                }
                if exec_b:
                    res_b_orig = exec_b(seed)
                    res_b_xform = exec_b(xformed)
                    # A和B对变换的响应是否一致
                    a_diverged = (res_a_orig.exit_code != res_a_xform.exit_code)
                    b_diverged = (res_b_orig.exit_code != res_b_xform.exit_code)
                    finding["a_diverged"] = a_diverged
                    finding["b_diverged"] = b_diverged
                    # 仅A发散 -> 潜在漏洞
                    if a_diverged and not b_diverged:
                        finding["suspicious"] = True
                        finding["severity"] = "high"
                    elif a_diverged == b_diverged:
                        finding["suspicious"] = False
                findings.append(finding)
            except Exception as exc:
                findings.append({"mr_name": name, "error": str(exc)})
        return findings

# 后门触发器检测: 基于ROSA的蜕变Oracle思想
# 检测隐蔽运行时后门: 对输入中嵌入魔术字节/特殊命令序列，
# 比较行为是否一致。若仅一个二进制对特殊输入产生异常反应 -> 可疑
class BackdoorTriggerProber:
    """嵌入后门触发序列并观察行为偏差"""

    TRIGGERS = [
        (b"backdoor", "literal_string"),
        (b"DEBUG_MODE=1", "env_debug_enable"),
        (b"\xDE\xAD\xBE\xEF", "magic_deadbeef"),
        (b"admin:true", "auth_bypass"),
        (b"eval(", "code_injection_probe"),
    ]

    def probe(self, seed: bytes,
              exec_func: Callable[[bytes], ExecutionResult]
              ) -> List[Dict[str, Any]]:
        results = []
        baseline = exec_func(seed)
        for trigger, tag in self.TRIGGERS:
            injected = seed + trigger if len(seed) < 128 else (
                seed[:len(seed) // 2] + trigger + seed[len(seed) // 2:])
            try:
                triggered = exec_func(injected)
                # 行为偏差指标
                exit_diverged = baseline.exit_code != triggered.exit_code
                output_diverged = baseline.stdout != triggered.stdout
                time_diverged = (triggered.execution_time >
                                 baseline.execution_time * 3.0)
                suspicious = (exit_diverged
                              or (output_diverged and time_diverged))
                results.append({
                    "trigger": tag, "suspicious": suspicious,
                    "exit_diverged": exit_diverged,
                    "output_diverged": output_diverged,
                    "time_diverged": time_diverged,
                })
            except Exception as exc:
                results.append({
                    "trigger": tag, "error": str(exc),
                    "suspicious": True})
        return results

# 自动崩溃分类流水线: minimize -> symbolize -> dedup -> root cause
# 参照ClusterFuzz的四阶段管道，将原始崩溃转化为可操作安全报告
class CrashTriagePipeline:
    """自动化崩溃triage: 裁减->符号化->去重->根因提取"""

    def __init__(self, binary_path: str, symbol_resolver=None):
        self._binary = binary_path
        self._symbols = symbol_resolver
        self._dedup_groups: Dict[str, List[ExecutionResult]] = defaultdict(list)

    def triage(self, result: ExecutionResult,
               timeout: float = 5.0) -> Dict[str, Any]:
        report = {
            'test_id': result.test_case.test_id,
            'phase1_minimized': None,
            'phase2_symbolized': [],
            'phase3_dedup_key': '',
            'phase4_root_cause_hint': '',
        }

        # 阶段1: 裁减
        if result.crashed and result.test_case.input_data:
            trimmer = SeedTrimmer(self._binary, timeout)
            minimized = trimmer.trim(result.test_case.input_data)
            report['phase1_minimized_size'] = len(minimized)
            report['phase1_reduction_ratio'] = round(
                1.0 - len(minimized) / max(1, len(
                    result.test_case.input_data)), 3)

        # 阶段2: 符号化
        if result.crash_stack_frames:
            symbolized = []
            for frame in result.crash_stack_frames:
                if self._symbols:
                    resolved = self._symbols(frame)
                    symbolized.append(resolved or frame)
                else:
                    symbolized.append(frame)
            report['phase2_symbolized'] = symbolized[:8]

        # 阶段3: 去重
        dedup_key = f"s{result.signal_number}|"
        dedup_key += '|'.join(
            (report['phase2_symbolized'] or result.crash_stack_frames)[:3])
        dedup_key = hashlib.md5(dedup_key.encode()).hexdigest()[:12]
        report['phase3_dedup_key'] = dedup_key
        self._dedup_groups[dedup_key].append(result)
        report['phase3_group_size'] = len(self._dedup_groups[dedup_key])

        # 阶段4: 根因提示
        sig = result.signal_number
        if sig == 11:
            fault = result.fault_address
            if fault == 0:
                report['phase4_root_cause_hint'] = 'NULL指针解引用'
            elif fault == 0x41414141:
                report['phase4_root_cause_hint'] = '栈缓冲区溢出（EIP被覆盖为0x41414141）'
            elif fault > 0x7F0000000000:
                report['phase4_root_cause_hint'] = '堆越界写（高位用户空间地址）'
            else:
                report['phase4_root_cause_hint'] = f'段错误 @ {hex(fault)}'
        elif sig == 6:
            report['phase4_root_cause_hint'] = '堆损坏或断言失败（SIGABRT）'
        elif sig == 8:
            report['phase4_root_cause_hint'] = '整数溢出或除零（SIGFPE）'

        return report

    def dedup_stats(self) -> Dict[str, Any]:
        groups = {k: len(v) for k, v in self._dedup_groups.items()}
        return {
            'unique_crashes': len(groups),
            'total_crashes': sum(groups.values()),
            'most_frequent': max(groups, key=groups.get) if groups else None,
            'most_frequent_count': max(groups.values()) if groups else 0,
        }

# 加壳二进制差分器: 比较加壳前/后或不同解包层的执行行为
# 检测项: 解包后入口OEP偏差/IAT解析差异/动态代码生成差异/反分析触发点
# 思路来自Gunpack的PTE非同步与GoaTracer的wave追踪
class PackedBinaryDiffer:
    """加壳/解包二进制行为差异比较"""

    def __init__(self):
        self._oep_candidates: Dict[str, int] = {}
        self._iat_entries: Dict[str, Set[int]] = defaultdict(set)

    def record_oep(self, binary_label: str, entry_point: int) -> None:
        self._oep_candidates[binary_label] = entry_point

    def record_iat(self, binary_label: str,
                    resolved_addresses: List[int]) -> None:
        self._iat_entries[binary_label].update(resolved_addresses)

    def compare_unpacking(self, packed_label: str,
                           unpacked_label: str) -> Dict[str, Any]:
        """比较加壳版与解包版的差异"""
        oep_packed = self._oep_candidates.get(packed_label)
        oep_unpacked = self._oep_candidates.get(unpacked_label)

        iat_packed = self._iat_entries.get(packed_label, set())
        iat_unpacked = self._iat_entries.get(unpacked_label, set())

        new_entries = iat_unpacked - iat_packed if iat_unpacked else set()

        return {
            'oep_shift': (oep_unpacked - oep_packed
                          if oep_packed and oep_unpacked else None),
            'new_iat_entries': len(new_entries),
            'iat_growth_ratio': round(
                len(iat_unpacked) / max(1, len(iat_packed)), 2),
            'likely_packed': len(new_entries) >= 5,
            'unpacking_success': (
                len(iat_unpacked) > len(iat_packed)
                if oep_packed and oep_unpacked else None),
        }

    def detect_layer_transition(self,
                                 wave_tracker) -> Dict[str, Any]:
        """检测解包层转换: 从wave tracker获取层信息"""
        return {
            'layer_count': wave_tracker.layer_count,
            'is_packed': wave_tracker.is_packed(),
            'packing_confidence': wave_tracker.packing_confidence(),
        }

# 思路: 攻击面入口参数 -> 污点传播 -> 敏感syscall参数
# 若存在从入口到syscall的可控路径 -> 标记为CFI可绕过的高危路径
# Syscall Reachability under CFI分析框架
class SyscallReachabilityAnalyzer:
    """静态污点可达性: 攻击面->敏感syscall"""

    SENSITIVE_SYSCALLS = {
        'execve': {'risk': 'code_execution', 'args': 3},
        'mmap': {'risk': 'memory_manipulation', 'args': 6},
        'mprotect': {'risk': 'memory_permission', 'args': 3},
        'open': {'risk': 'file_access', 'args': 3},
        'write': {'risk': 'data_exfiltration', 'args': 3},
        'ptrace': {'risk': 'process_hijack', 'args': 4},
    }

    def __init__(self):
        self._def_use: Dict[int, List[int]] = defaultdict(list)
        self._syscall_sites: Dict[str, List[int]] = defaultdict(list)

    def add_def_use(self, producer: int, consumer: int) -> None:
        self._def_use[producer].append(consumer)

    def mark_syscall_site(self, syscall_name: str, arg_offset: int) -> None:
        self._syscall_sites[syscall_name].append(arg_offset)

    def find_reachable_syscalls(self, entry_params: List[int]
                                 ) -> Dict[str, Any]:
        """从入口参数出发做BFS污点传播，返回可达的敏感syscall列表"""
        tainted: Set[int] = set(entry_params)
        queue = deque(entry_params)
        while queue:
            node = queue.popleft()
            for succ in self._def_use.get(node, []):
                if succ not in tainted:
                    tainted.add(succ)
                    queue.append(succ)
        reachable = {}
        for syscall, risk_info in self.SENSITIVE_SYSCALLS.items():
            sites = self._syscall_sites.get(syscall, [])
            tainted_sites = [s for s in sites if s in tainted]
            if tainted_sites:
                reachable[syscall] = {
                    'risk': risk_info['risk'],
                    'tainted_arg_sites': len(tainted_sites),
                    'total_arg_sites': len(sites),
                }
        return {
            'reachable_syscalls': len(reachable),
            'details': reachable,
            'cfi_bypass_risk': (
                'critical' if any(
                    r['risk'] == 'code_execution'
                    for r in reachable.values())
                else 'high' if len(reachable) >= 2
                else 'medium' if reachable
                else 'low'),
        }

# 对每个(producer_block, consumer_block)边对追踪覆盖状态，
# 新def-use覆盖 -> 种子能量x2，驱动fuzzer探索数据流多样性
# FuzzRDUCC (arXiv 2509.04967)的def-use链反馈机制
class DefUseFeedbackIntegrator:
    """def-use对粒度的覆盖率反馈"""

    def __init__(self):
        self._du_pairs: Dict[Tuple[int, int], int] = defaultdict(int)
        self._total_execs = 0
        self._last_new_pair_at = 0

    def record_def_use(self, producer_block: int,
                        consumer_block: int) -> bool:
        """返回True表示首次发现此def-use对"""
        key = (producer_block, consumer_block)
        is_new = key not in self._du_pairs
        self._du_pairs[key] += 1
        self._total_execs += 1
        if is_new:
            self._last_new_pair_at = self._total_execs
        return is_new

    def seed_energy_boost(self, new_du_pairs: int) -> float:
        """发现新def-use对 -> 能量倍率 (1.0 ~ 3.0)"""
        if new_du_pairs <= 0:
            return 1.0
        return min(3.0, 1.0 + new_du_pairs * 0.5)

    def stagnation_score(self) -> float:
        """自上次发现新def-use对以来的执行次数 / 总执行次数"""
        if self._total_execs == 0:
            return 0.0
        since = self._total_execs - self._last_new_pair_at
        return since / self._total_execs

    @property
    def unique_pairs(self) -> int:
        return len(self._du_pairs)

# 检测项: malloc/free参数可控、fastbin损坏、tcache poisoning迹象、
# unsorted bin信息泄露、堆元数据覆写
# BloodFang和PwnPasi的自动化利用检测思路
class HeapExploitPrimitiveDetector:
    """检测崩溃是否展示可利用的堆操纵能力"""

    def detect(self, result: ExecutionResult) -> Dict[str, Any]:
        primitives = []
        if not result.crashed:
            return {'exploitable_primitive': False, 'primitives': []}

        sig = result.signal_number
        msg = result.error_message.lower()
        frames = result.crash_stack_frames
        fault = result.fault_address

        # 原语1: fastbin损坏 -> free时SIGABRT
        if sig == 6 and ('free' in msg or any(
                'free' in f.lower() for f in frames[:2])):
            if 'invalid' in msg or 'corrupted' in msg:
                primitives.append({
                    'type': 'fastbin_corruption',
                    'confidence': 0.70,
                    'detail': 'free时fastbin链表损坏，可能存在堆溢出或UAF',
                })

        # 原语2: 可控EIP (0x41414141模式)
        if fault == 0x41414141:
            primitives.append({
                'type': 'controlled_eip',
                'confidence': 0.95,
                'detail': '指令寄存器被覆盖为0x41414141，代码执行控制',
            })

        # 原语3: 空指针+free路径 -> 可能UAF
        if fault == 0 and sig == 11 and any(
                'free' in f.lower() for f in frames[:3]):
            primitives.append({
                'type': 'uaf_null_crash',
                'confidence': 0.55,
                'detail': 'free路径上的空指针崩溃，可能UAF被触发',
            })

        # 原语4: SIGSEGV+写入模式 (fault addr在堆区域)
        if sig == 11 and 0x100000 <= fault <= 0x7F0000000000:
            primitives.append({
                'type': 'heap_write_primitive',
                'confidence': 0.45,
                'detail': f'堆区域 ({hex(fault)}) 的SIGSEGV，可能任意地址写入',
            })

        # 原语5: tcache poisoning -> malloc返回任意地址
        if sig == 11 and any(
                'malloc' in f.lower() for f in frames[:3]):
            primitives.append({
                'type': 'tcache_poisoning',
                'confidence': 0.50,
                'detail': 'malloc路径上的SIGSEGV，tcache可能被污染',
            })

        primitives.sort(key=lambda p: -p['confidence'])
        return {
            'exploitable_primitive': len(primitives) > 0
            and primitives[0]['confidence'] >= 0.45,
            'primitives': primitives,
            'highest_confidence': primitives[0]['confidence'] if primitives else 0.0,
        }

# 行为指纹: 基于strace/ftrace的轻量执行轮廓捕获
# 对同一输入在不同二进制上的行为做向量化比较，捕获输出之外的语义差异
# Hybrid Fuzzing 的语义反馈思想
class BehavioralFingerprint:
    """捕获执行时的syscall序列作为行为指纹"""

    def __init__(self):
        self._baselines: Dict[str, List[Tuple[int, int]]] = {}

    @staticmethod
    def capture_syscall_sequence(binary: str, input_data: bytes,
                                 timeout: float = 5.0,
                                 max_syscalls: int = 256) -> List[str]:
        """通过strace捕获系统调用序列，返回syscall名列表"""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.strace') as sf:
            strace_path = sf.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='.input') as inf:
            inf.write(input_data)
            input_path = inf.name
        try:
            proc = subprocess.run(
                ['strace', '-f', '-e', 'trace=%file,%process,%network',
                 '-o', strace_path, binary, input_path],
                capture_output=True, timeout=timeout)
            with open(strace_path, 'r', errors='ignore') as fh:
                lines = fh.readlines()[:max_syscalls]
            calls: List[str] = []
            for line in lines:
                # 提取syscall名（strace输出第一组括号前的内容）
                match = re.match(r'\d+\s+(\w+)\(', line)
                if match:
                    calls.append(match.group(1))
            return calls
        except Exception:
            return []
        finally:
            for p in (strace_path, input_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def diff(self, calls_a: List[str], calls_b: List[str]) -> Dict[str, Any]:
        """比较两个syscall序列的差异度"""
        if not calls_a and not calls_b:
            return {'divergence': 0.0, 'reason': 'both_empty'}
        common = set(calls_a) & set(calls_b)
        all_calls = set(calls_a) | set(calls_b)
        jaccard = len(common) / len(all_calls) if all_calls else 1.0
        # 序列编辑距离（简化LCS比率）
        lcs_len = _lcs_length(calls_a, calls_b)
        seq_sim = (2 * lcs_len) / max(1, len(calls_a) + len(calls_b))
        return {
            'divergence': round(1.0 - jaccard, 3),
            'sequence_similarity': round(seq_sim, 3),
            'extra_in_a': sorted(set(calls_a) - set(calls_b)),
            'extra_in_b': sorted(set(calls_b) - set(calls_a)),
            'count_a': len(calls_a), 'count_b': len(calls_b),
        }

def _lcs_length(a: List[str], b: List[str]) -> int:
    """LCS长度，O(n*m)空间优化到O(min(n,m))"""
    if len(a) < len(b):
        a, b = b, a
    prev = [0] * (len(b) + 1)
    for i, ca in enumerate(a):
        curr = [0] * (len(b) + 1)
        for j, cb in enumerate(b):
            if ca == cb:
                curr[j + 1] = prev[j] + 1
            else:
                curr[j + 1] = max(curr[j], prev[j + 1])
        prev = curr
    return prev[-1]

# 执行轨迹异常检测: 对同一输入在A和B上的行为差异做分层分析
# 第一层: syscall集合差异; 第二层: 执行时间异常; 第三层: 输出差异
# 综合三层评分标记为行为异常
class TraceAnomalyDetector:
    """执行轨迹分层差异检测器"""

    def detect(self, result_a: ExecutionResult,
               result_b: Optional[ExecutionResult] = None) -> Dict[str, Any]:
        layers: Dict[str, Any] = {
            'layer1_exit_code': (result_a.exit_code != (result_b.exit_code if result_b else 0)),
            'layer2_timing': False,
            'layer3_output': False,
            'anomaly_score': 0.0,
        }
        score = 0.0

        # Layer 1: 退出码差异
        if layers['layer1_exit_code']:
            score += 0.4

        # Layer 2: 执行时间差异 > 5x
        if result_b and result_a.execution_time > 0:
            ratio = max(result_a.execution_time, result_b.execution_time) / max(
                0.001, min(result_a.execution_time, result_b.execution_time))
            if ratio > 5.0:
                layers['layer2_timing'] = True
                layers['timing_ratio'] = round(ratio, 1)
                score += 0.25

        # Layer 3: stdout/stderr内容差异
        if result_b and (result_a.stdout != result_b.stdout
                         or result_a.stderr != result_b.stderr):
            layers['layer3_output'] = True
            score += 0.35

        layers['anomaly_score'] = round(score, 2)
        layers['flagged'] = score >= 0.4
        return layers

def run_differential_test(binary_a: str, binary_b: Optional[str] = None,
                          max_tests: int = 1000, input_type: str = "random",
                          output_dir: Optional[str] = None) -> DifferentialTestResult:
    tester = DifferentialTester(binary_a, binary_b)

    test_cases = tester.generate_test_cases(max_tests, input_type)

    result = tester.run_tests(test_cases)

    if output_dir:
        corpus_count = tester.generate_fuzzing_corpus(output_dir)
        logger.info(f"Generated {corpus_count} test corpus files to {output_dir}")

    return result

def format_differential_report(result: DifferentialTestResult) -> str:
    return result.summary

def export_differential_json(result: DifferentialTestResult,
                             output_path: str) -> bool:
    try:
        export_data = {
            'success': result.success,
            'test_mode': result.test_mode,
            'total_tests': result.total_tests,
            'total_differences': result.total_differences,
            'unique_crash_groups': result.unique_crash_groups,
            'unique_inputs': result.unique_inputs,
            'execution_time': result.execution_time,
            'avg_exec_time_ms': result.avg_exec_time_ms,
            'potential_vulnerabilities': [
                {
                    'test_id': diff.test_case.test_id,
                    'difference_type': diff.difference_type,
                    'description': diff.description,
                    'severity': diff.severity,
                    'evidence': diff.evidence,
                    'dedup_group': diff.dedup_group,
                }
                for diff in result.potential_vulnerabilities
            ],
            'all_differences': [
                {
                    'test_id': diff.test_case.test_id,
                    'difference_type': diff.difference_type,
                    'description': diff.description,
                    'severity': diff.severity
                }
                for diff in result.differences
            ],
            'summary': result.summary
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        return True
    except Exception as e:
        logger.error(f"exportJSONfailed: {e}")
        return False
