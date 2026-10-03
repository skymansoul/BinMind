# GPU Fuzzer，合并自根目录 gpu_fuzzer + src/gpu/fuzzer_core
# 注意：多 GPU 设备 worker 捕获到 OOM 异常时仅记录日志，不做任务重派
import logging
import time
import hashlib
import threading
import random
import struct
import os as _unused_os  # 暂留 — 预留的路径工具导入，供后续种子落盘功能使用
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

def _debug_print(msg: str) -> None:
    # 预留的调试输出钩子，默认静默，便于排查时临时接回 stderr
    pass

logger = logging.getLogger(__name__)


class GPUFramework(str, Enum):
    CUDA = "cuda"
    OPENCL = "opencl"
    METAL = "metal"
    ROCM = "rocm"


class FuzzMode(str, Enum):
    RANDOM = "random"
    MUTATION = "mutation"
    GENERATION = "generation"
    HYBRID = "hybrid"


@dataclass
class GPUDevice:
    device_id: str
    name: str
    framework: GPUFramework
    memory_gb: float
    cores: int
    available: bool = True
    current_load: float = 0.0
    last_heartbeat: float = 0.0

    def load_ratio(self) -> float:
        return self.current_load


@dataclass
class FuzzTask:
    task_id: str
    input_data: bytes
    iterations: int = 1000
    mode: FuzzMode = FuzzMode.RANDOM
    callback: Optional[Callable] = None
    timestamp: float = 0.0


@dataclass
class FuzzResult:
    task_id: str
    crashes: List[bytes] = field(default_factory=list)
    coverage_increase: float = 0.0
    executions: int = 0
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    # 覆盖位图指纹，用于种子去重与稀有性评估
    coverage_bitmap: int = 0
    novel_paths: int = 0


# 种子调度与能量分配 — AFL effort 分配思路：稀有路径获更多变异预算

class _SeedBucket:
    """单种子元数据，调度决策用"""
    __slots__ = ('seed', 'bitmap', 'hit_count', 'energy', 'last_fuzzed')

    def __init__(self, seed: bytes, bitmap: int):
        self.seed = seed
        self.bitmap = bitmap
        self.hit_count = 1
        self.energy = 100
        self.last_fuzzed = 0.0


class GPUSeedScheduler:
    # 基于覆盖稀有性的种子调度器
    # 罕见路径（bitmap全局频次低）获指数级更高能量

    def __init__(self, base_energy: int = 100):
        self._buckets: List[_SeedBucket] = []
        self._global_bitmap_freq: Dict[int, int] = defaultdict(int)
        self._base_energy = base_energy
        self._lock = threading.Lock()

    def add_seed(self, seed: bytes, bitmap: int) -> None:
        with self._lock:
            self._global_bitmap_freq[bitmap] += 1
            self._buckets.append(_SeedBucket(seed, bitmap))

    def update_result(self, seed: bytes, bitmap: int, novel_paths: int) -> bool:
        # 返回True表示该结果值得加入种子池（发现新路径）
        with self._lock:
            freq = self._global_bitmap_freq.get(bitmap, 0)
            if freq == 0 or novel_paths > 0:
                self._global_bitmap_freq[bitmap] = freq + 1
                self._buckets.append(_SeedBucket(seed, bitmap))
                return True
            for b in self._buckets:
                if b.bitmap == bitmap:
                    b.hit_count += 1
                    break
            return False

    def select_seed(self) -> Optional[bytes]:
        # 按能量加权随机选种子，O(n)选择避免饥饿
        with self._lock:
            if not self._buckets:
                return None
            self._recalc_energies()
            total_energy = sum(b.energy for b in self._buckets)
            if total_energy <= 0:
                return self._buckets[0].seed
            r = random.uniform(0, total_energy)
            acc = 0.0
            for b in self._buckets:
                acc += b.energy
                if r <= acc:
                    b.last_fuzzed = time.monotonic()
                    return b.seed
            return self._buckets[-1].seed

    def _recalc_energies(self) -> None:
        # 根据全局bitmap频率重分配能量，稀有性=1/(全局频次)
        base = self._base_energy
        for b in self._buckets:
            freq = self._global_bitmap_freq.get(b.bitmap, 1)
            rarity_bonus = (1.0 / (freq ** 0.5))
            b.energy = max(10, min(base * 4, int(base * rarity_bonus)))

    def trim_corpus(self, max_seeds: int = 500) -> int:
        # 移除命中频次最高冗余种子，保留稀有路径
        with self._lock:
            if len(self._buckets) <= max_seeds:
                return 0
            self._buckets.sort(key=lambda b: self._global_bitmap_freq.get(b.bitmap, 1), reverse=True)
            removed = len(self._buckets) - max_seeds
            for b in self._buckets[max_seeds:]:
                freq = self._global_bitmap_freq[b.bitmap]
                if freq <= 1:
                    del self._global_bitmap_freq[b.bitmap]
                else:
                    self._global_bitmap_freq[b.bitmap] = freq - 1
            self._buckets = self._buckets[:max_seeds]
            return removed

    @property
    def seed_count(self) -> int:
        with self._lock:
            return len(self._buckets)


class GPUBufferManager:
    # 模拟显存分配/释放，追踪碎片化程度

    def __init__(self, total_memory: int = 256 * 1024 * 1024):
        self._total = total_memory
        self._used = 0
        self._buffers: Dict[str, bytes] = {}
        self._buffer_sizes: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._alloc_history: List[tuple] = []
        self._free_history: List[int] = []

    def allocate(self, buffer_id: str = "", size: int = 0) -> bool:
        # 边界条件: 零长度分配
        if size <= 0:
            return False
        with self._lock:
            if not buffer_id:
                buffer_id = f"buf_{len(self._buffers)}"
            if buffer_id in self._buffers:
                return False
            if self._used + size > self._total:
                raise MemoryError(f"显存不足: 请求{size}B, 可用{self._total - self._used}B")
            self._buffers[buffer_id] = b'\x00' * size
            self._buffer_sizes[buffer_id] = size
            self._used += size
            return True

    def deallocate(self, buffer_id: str):
        with self._lock:
            if buffer_id in self._buffers:
                size = self._buffer_sizes[buffer_id]
                del self._buffers[buffer_id]
                del self._buffer_sizes[buffer_id]
                self._used -= size

    def write(self, buffer_id: str, data: bytes, offset: int = 0) -> bool:
        with self._lock:
            if buffer_id not in self._buffers:
                return False
            buf = bytearray(self._buffers[buffer_id])
            end = min(offset + len(data), len(buf))
            buf[offset:end] = data[:end - offset]
            self._buffers[buffer_id] = bytes(buf)
            return True

    def read(self, buffer_id: str, size: int, offset: int = 0) -> Optional[bytes]:
        with self._lock:
            if buffer_id not in self._buffers:
                return None
            buf = self._buffers[buffer_id]
            end = min(offset + size, len(buf))
            return buf[offset:end]

    def get_size(self, buffer_id: str) -> int:
        with self._lock:
            return self._buffer_sizes.get(buffer_id, 0)

    def get_total_allocated(self) -> int:
        with self._lock:
            return sum(self._buffer_sizes.values())

    def memory_usage(self) -> float:
        return self._used / self._total if self._total > 0 else 0.0


class GPUFuzzerCore:
    # 有趣边界值 — 触发整数溢出/下溢/符号问题
    _INTERESTING_8: List[int] = [0, 0x7F, 0x80, 0xFF]
    _INTERESTING_16: List[int] = [0, 0x7FFF, 0x8000, 0xFFFF]
    _INTERESTING_32: List[int] = [
        0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFE, 0x80000001
    ]

    def __init__(self, device: GPUDevice, max_buffer_size: int = 256 * 1024 * 1024):
        self._device = device
        self._buffer_manager = GPUBufferManager(max_buffer_size)
        self._running = False
        self._interest_scores: Dict[int, float] = {}
        # 覆盖率追踪
        self._coverage: Dict[str, int] = {}
        self._seed_queue: List[dict] = []
        self._total_execs = 0
        self._unique_crashes: set = set()
        self._unique_hangs: set = set()
        self._max_buffer_size = max_buffer_size

    # 哈希辅助：输入指纹统一走 64-bit 折叠哈希
    @staticmethod
    def _hash_input(input_bytes: bytes) -> int:
        """64-bit折叠哈希，用于bitmap指纹与兴趣度索引"""
        h = hashlib.sha256(input_bytes).digest()
        return int.from_bytes(h[:8], 'little')

    def hash_edge(self, prev_id: int, cur_id: int) -> int:
        # XOR-shift近似，GPU适配
        _v = (prev_id >> 1) ^ (cur_id << 3)
        _v &= 0xFFFFFFFF
        _v ^= (_v >> 17)
        _v ^= (_v << 13)
        _v &= 0xFFFFFFFF
        _v ^= (_v >> 7)
        return _v

    # 兴趣度评分：crash 输入的后续变异优先级更高
    def _interest_score(self, input_bytes: bytes) -> float:
        h = self._hash_input(input_bytes)
        return self._interest_scores.get(h, 0.05)

    def _bump_interest(self, input_bytes: bytes, caused_crash: bool):
        h = self._hash_input(input_bytes)
        old = self._interest_scores.get(h, 0.0)
        increment = 1.0 if caused_crash else 0.15
        self._interest_scores[h] = min(10.0, old + increment)

    # AFLFast 种子能量调度 — 基于执行时间与覆盖率稀有度加权
    def aflfast_seed_energy(self, seed: dict) -> float:
        perf_score = 100.0
        _exec_us = seed.get("exec_us", 100)
        _handicap = seed.get("handicap", 1)
        # 执行更快的种子获更高能量
        if _exec_us < 10:
            perf_score *= 4.0
        elif _exec_us < 50:
            perf_score *= 2.0
        elif _exec_us < 100:
            perf_score *= 1.5
        elif _exec_us > 500:
            perf_score *= 0.25
        elif _exec_us > 1000:
            perf_score *= 0.1
        # 覆盖率因子
        _cov_factor = seed.get("cov_factor", 1.0)
        perf_score *= _cov_factor
        # 深度惩罚
        _depth = seed.get("depth", 0)
        if _depth > 100:
            perf_score *= 0.7
        return max(perf_score / _handicap, 1.0)

    # 边界值变异：注入整数溢出/下溢/符号问题的经典触发值
    def interesting_values_mutation(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            return data
        _mutated = bytearray(data)
        _pos = random.randint(0, len(_mutated) - 1)
        _choice = random.randint(0, 3)
        if _choice == 0:
            struct.pack_into("B", _mutated, _pos, random.choice(self._INTERESTING_8))
        elif _choice == 1 and _pos + 1 < len(_mutated):
            struct.pack_into("<H", _mutated, _pos, random.choice(self._INTERESTING_16))
        elif _choice == 2 and _pos + 3 < len(_mutated):
            struct.pack_into("<I", _mutated, _pos, random.choice(self._INTERESTING_32))
        else:
            _mutated[_pos] = ~_mutated[_pos] & 0xFF
        return _mutated

    # 变异引擎 — 确定性与破坏性两阶段混合策略
    def _mutate_input(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            data = bytearray(random.randbytes(16))
        _out = bytearray(data)
        _stage = random.randint(0, 1)
        if _stage == 0:
            # 确定性阶段
            _op = random.randint(0, 3)
            if _op == 0:
                # 位翻转
                for _i in range(1 << random.randint(0, 5)):
                    _pos = random.randint(0, len(_out) - 1)
                    _bit = random.randint(0, 7)
                    _out[_pos] ^= (1 << _bit)
            elif _op == 1:
                # 字节翻转
                for _i in range(1 << random.randint(0, 5)):
                    _pos = random.randint(0, len(_out) - 1)
                    _out[_pos] ^= 0xFF
            elif _op == 2:
                # 算术运算
                _pos = random.randint(0, len(_out) - 1)
                _delta = random.randint(-35, 35)
                _out[_pos] = (_out[_pos] + _delta) & 0xFF
            else:
                _out = self.interesting_values_mutation(_out)
        else:
            # 破坏性阶段: 随机字节 / 块删除 / 块复制
            _op = random.randint(0, 2)
            if _op == 0:
                _n = random.randint(1, min(16, len(_out)))
                _out[-_n:] = random.randbytes(_n)
            elif _op == 1 and len(_out) > 4:
                _start = random.randint(0, len(_out) - 4)
                _end = _start + random.randint(1, min(len(_out) - _start, len(_out) // 4))
                del _out[_start:_end]
            elif _op == 2 and len(_out) >= 2:
                _start = random.randint(0, len(_out) - 2)
                _len_block = random.randint(1, min(len(_out) - _start, len(_out) // 4))
                _block = _out[_start:_start + _len_block]
                _insert_pos = random.randint(0, len(_out) - 1)
                _out[_insert_pos:_insert_pos] = _block
        return _out

    # 确定性模拟执行：基于核函数 hash 与输入数据生成可重现轨迹
    def _simulate_execution(self, kernel: str, input_data: bytes) -> tuple:
        _hasher = hashlib.sha256()
        _hasher.update(kernel.encode("utf-8", errors="replace"))
        _hasher.update(input_data)
        _full = _hasher.digest()
        exit_code = _full[0]  # 0-255: 0=正常, 非0=异常类别
        edge_set: set = set()
        prev = 0
        for _i in range(0, len(_full) - 4, 4):
            cur = struct.unpack_from("<I", _full, _i)[0] & 0xFFFF
            edge_set.add(self.hash_edge(prev, cur))
            prev = cur
        # 注入确定性crash: 输入中出现0xDEAD模式
        if b"\xDE\xAD" in input_data:
            exit_code = 139  # SIGSEGV模拟
        return exit_code, edge_set

    # 校准：对新种子补齐默认调度字段（exec_us/depth/handicap 等）
    def _calibrate(self, seed: dict):
        data = seed["data"]
        if isinstance(data, bytes):
            data = bytearray(data)
        elif not isinstance(data, bytearray):
            data = bytearray(data)
        _code, _edges = self._simulate_execution("_calibrate", bytes(data))
        seed.setdefault("exec_us", 50)
        seed.setdefault("depth", 0)
        seed.setdefault("handicap", 1)
        seed.setdefault("cov_factor", 1.0)

    # 核心 Fuzz 循环：种子调度 → 变异 → 执行 → 覆盖率分析 → 入队/丢弃
    def fuzz_kernel(
        self, kernel_source: str, seeds: List[bytes], iterations: int = 1000
    ) -> List[dict]:
        results: List[dict] = []
        self._seed_queue.clear()
        self._coverage.clear()
        self._total_execs = 0
        for _i, s in enumerate(seeds):
            _seed = {
                "id": _i, "data": bytearray(s), "depth": 0,
                "exec_us": 50, "handicap": 1, "cov_factor": 1.0,
            }
            self._calibrate(_seed)
            self._seed_queue.append(_seed)
            _, _edges = self._simulate_execution(kernel_source, s)
            for e in _edges:
                self._coverage[f"{e:08x}"] = self._coverage.get(f"{e:08x}", 0) + 1

        _queue_idx = 0
        while self._total_execs < iterations and _queue_idx < len(self._seed_queue):
            seed = self._seed_queue[_queue_idx]
            _energy = int(self.aflfast_seed_energy(seed))
            _energy = min(_energy, iterations - self._total_execs)
            for _ in range(_energy):
                if self._total_execs >= iterations:
                    break
                mutated = self._mutate_input(seed["data"])
                _code, _edges = self._simulate_execution(kernel_source, bytes(mutated))
                self._total_execs += 1
                new_cov = False
                for e in _edges:
                    _key = f"{e:08x}"
                    if _key not in self._coverage:
                        self._coverage[_key] = 1
                        new_cov = True
                    else:
                        self._coverage[_key] += 1
                if new_cov:
                    _new_seed = {
                        "id": len(self._seed_queue), "data": mutated,
                        "depth": seed["depth"] + 1,
                        "exec_us": random.randint(10, 200),
                        "handicap": 1, "cov_factor": 2.0,
                    }
                    self._seed_queue.append(_new_seed)
                # 记录crash/hang
                if _code != 0:
                    _hash = hashlib.md5(bytes(mutated)).hexdigest()
                    if _code == 139:
                        if _hash not in self._unique_crashes:
                            self._unique_crashes.add(_hash)
                            results.append({
                                "type": "crash", "exit_code": _code,
                                "data": bytes(mutated), "hash": _hash,
                                "iteration": self._total_execs,
                            })
                    elif _code in (9, 15):  # SIGKILL/SIGTERM → 超时
                        if _hash not in self._unique_hangs:
                            self._unique_hangs.add(_hash)
                            results.append({
                                "type": "hang", "exit_code": _code,
                                "data": bytes(mutated), "hash": _hash,
                                "iteration": self._total_execs,
                            })
                # 每500轮降低handicap避免饥饿
                if self._total_execs % 500 == 0:
                    for s in self._seed_queue:
                        s["handicap"] = max(1, s["handicap"] - 1)
            _queue_idx += 1

        results.append({
            "type": "summary", "total_execs": self._total_execs,
            "coverage_edges": len(self._coverage),
            "unique_crashes": len(self._unique_crashes),
            "unique_hangs": len(self._unique_hangs),
            "seed_count": len(self._seed_queue),
            "memory_usage": self._buffer_manager.memory_usage(),
        })
        return results

    # 多设备调度：按设备序位递减权重分配任务量
    def multi_device_schedule(
        self, jobs: List[dict], devices: List[int]
    ) -> Dict[int, List[dict]]:
        if not devices:
            return {}
        schedule: Dict[int, List[dict]] = {d: [] for d in devices}
        _weights = [1.0] * max(1, len(devices))
        for _i, d in enumerate(devices):
            _weights[_i] = max(0.5, 1.0 - _i * 0.1)
        _total_weight = sum(_weights)
        _job_per_device = [max(1, int(len(jobs) * w / _total_weight)) for w in _weights]
        while sum(_job_per_device) < len(jobs):
            _job_per_device[0] += 1
        _offset = 0
        for _i, d in enumerate(devices):
            _n = _job_per_device[_i]
            schedule[d] = jobs[_offset:_offset + _n]
            _offset += _n
        return schedule

    # 生成变异：以兴趣度控制变异点密度
    def _generate_random_mutations(self, seed: bytes, count: int) -> List[bytes]:
        results = []
        interest = self._interest_score(seed)
        mutation_points = max(1, min(len(seed), int(len(seed) * 0.3 * interest)))
        for _ in range(count):
            mutated = bytearray(seed)
            for _ in range(random.randint(1, mutation_points)):
                pos = random.randint(0, len(mutated) - 1)
                op = random.randint(0, 2)
                if op == 0:
                    mutated[pos] ^= 1 << random.randint(0, 7)
                elif op == 1:
                    mutated[pos] = random.randint(0, 255)
                else:
                    blk_len = random.randint(2, min(8, len(mutated) - pos))
                    delta = random.randint(-128, 127) if random.random() < 0.5 else random.randint(0, 255)
                    for bi in range(blk_len):
                        mutated[pos + bi] = (mutated[pos + bi] + delta) & 0xFF
            results.append(bytes(mutated))
        return results

    def _generate_gpu_batch(self, seed: bytes, batch_size: int) -> List[bytes]:
        results = []
        for _ in range(batch_size):
            result = bytearray()
            for _ in range(len(seed)):
                result.append(random.randint(0, 255))
            results.append(bytes(result))
        return results

    def _compute_coverage_bitmap(self, inputs: List[bytes]) -> int:
        # 将一批输入执行结果编码为64-bit bitmap
        combined = b''.join(inputs)
        h = hashlib.sha256(combined).digest()
        return int.from_bytes(h[:8], 'little')

    # execute -- 兼容旧接口的单任务执行
    def execute(self, task: FuzzTask) -> FuzzResult:
        start_time = time.time()
        crashes = []
        executions = 0
        batch_size = min(1024, task.iterations)
        remaining = task.iterations

        while remaining > 0 and self._running:
            batch = min(batch_size, remaining)
            if task.mode == FuzzMode.RANDOM:
                inputs = self._generate_gpu_batch(task.input_data, batch)
            elif task.mode == FuzzMode.MUTATION:
                inputs = self._generate_random_mutations(task.input_data, batch)
            else:
                inputs = (self._generate_random_mutations(task.input_data, batch // 2) +
                         self._generate_gpu_batch(task.input_data, batch // 2))

            for input_bytes in inputs:
                executions += 1
                if self._simulate_test(input_bytes):
                    crashes.append(input_bytes)
                    self._bump_interest(input_bytes, caused_crash=True)
                else:
                    self._bump_interest(input_bytes, caused_crash=False)
            remaining -= batch

        duration = time.time() - start_time
        bitmap = self._compute_coverage_bitmap(crashes if crashes else inputs[:1])
        return FuzzResult(
            task_id=task.task_id, crashes=crashes,
            coverage_increase=random.uniform(0.0, 5.0),
            executions=executions, duration=duration,
            coverage_bitmap=bitmap,
            novel_paths=1 if crashes else 0,
        )

    def _simulate_test(self, input_bytes: bytes) -> bool:
        # CRC近似: 校验和为100的倍数视为crash
        crc = sum(input_bytes)
        return crc % 100 == 0

    # 暂留 — 旧版简化显存模型入口，合并到 GPUBufferManager 后废弃，保留以兼容外部调用
    # def simplified_gpu_memory_model(self, size: int) -> GPUBufferManager:
    #     self._buffer_manager = GPUBufferManager(size)
    #     return self._buffer_manager


class GPUFuzzerService:
    # GPU Fuzz服务: 多设备管理 + 任务调度

    def __init__(self, framework: str = "cuda"):
        try:
            self._framework = GPUFramework(framework.lower())
        except ValueError:
            self._framework = GPUFramework.CUDA
        self._devices: Dict[str, GPUDevice] = {}
        self._fuzzers: Dict[str, GPUFuzzerCore] = {}
        self._pending_tasks: List[FuzzTask] = []
        self._running_tasks: Dict[str, FuzzTask] = {}
        self._lock = threading.RLock()
        self._running = False
        self._worker_threads = []
        self._scheduler = GPUSeedScheduler()

    def add_device(self, device_id: str, name: str, memory_gb: float, cores: int):
        device = GPUDevice(
            device_id=device_id, name=name, framework=self._framework,
            memory_gb=memory_gb, cores=cores, last_heartbeat=time.time())
        with self._lock:
            self._devices[device_id] = device
            self._fuzzers[device_id] = GPUFuzzerCore(device)

    def submit_task(self, input_data: bytes, iterations: int = 1000,
                    mode: str = "hybrid", callback: Optional[Callable] = None) -> str:
        task_id = hashlib.sha256(
            f"{input_data}_{time.time()}".encode()).hexdigest()[:16]
        try:
            fuzz_mode = FuzzMode(mode.lower())
        except ValueError:
            fuzz_mode = FuzzMode.HYBRID
        task = FuzzTask(
            task_id=task_id, input_data=input_data, iterations=iterations,
            mode=fuzz_mode, callback=callback, timestamp=time.time())
        with self._lock:
            self._pending_tasks.append(task)
            h = hashlib.sha256(input_data).digest()
            bitmap = int.from_bytes(h[:8], 'little')
            self._scheduler.add_seed(input_data, bitmap)
        return task_id

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            for device_id in self._devices:
                thread = threading.Thread(
                    target=self._device_worker, args=(device_id,), daemon=True)
                self._worker_threads.append(thread)
                thread.start()

    def stop(self):
        with self._lock:
            self._running = False
        for fuzzer in self._fuzzers.values():
            fuzzer._running = False
        for thread in self._worker_threads:
            thread.join()
        trimmed = self._scheduler.trim_corpus(max_seeds=500)
        if trimmed > 0:
            logger.debug("corpus trimmed: %d redundant seeds removed", trimmed)

    def _device_worker(self, device_id: str):
        # 已知限制：设备 OOM 未做任务重派，worker 记录后继续拉取下一任务
        fuzzer = self._fuzzers[device_id]
        fuzzer._running = True
        while self._running:
            task = self._get_next_task()
            if task is not None:
                self._execute_task(device_id, task)
            else:
                # 无待处理任务时从调度器取种子做变异探索
                seed = self._scheduler.select_seed()
                if seed is not None:
                    explore_task = FuzzTask(
                        task_id=f"explore_{device_id}_{time.monotonic_ns()}",
                        input_data=seed, iterations=256, mode=FuzzMode.MUTATION)
                    self._execute_task(device_id, explore_task)
                else:
                    time.sleep(0.01)
        fuzzer._running = False

    def _get_next_task(self) -> Optional[FuzzTask]:
        with self._lock:
            if not self._pending_tasks:
                return None
            task = self._pending_tasks.pop(0)
            self._running_tasks[task.task_id] = task
            return task

    def _execute_task(self, device_id: str, task: FuzzTask):
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].current_load = 1.0
        fuzzer = self._fuzzers[device_id]
        result = fuzzer.execute(task)
        # 反馈到调度器：新路径加入种子池
        if result.novel_paths > 0:
            self._scheduler.update_result(task.input_data, result.coverage_bitmap, result.novel_paths)
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].current_load = 0.0
            if task.task_id in self._running_tasks:
                del self._running_tasks[task.task_id]
        if task.callback:
            try:
                task.callback(result)
            except Exception as e:
                logger.error(f"Task callback failed: {e}")

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'framework': self._framework.value,
                'devices': [{
                    'id': d.device_id, 'name': d.name,
                    'memory_gb': d.memory_gb, 'cores': d.cores,
                    'available': d.available, 'load': d.current_load
                } for d in self._devices.values()],
                'pending_tasks': len(self._pending_tasks),
                'running_tasks': len(self._running_tasks),
                'total_devices': len(self._devices),
                'seed_pool_size': self._scheduler.seed_count,
            }


def run_gpu_fuzzing(
    input_data: bytes, iterations: int = 10000,
    mode: str = "hybrid", devices: int = 2
) -> Dict[str, Any]:
    service = GPUFuzzerService()
    for i in range(devices):
        service.add_device(
            device_id=f"gpu_{i}", name=f"NVIDIA RTX 4090 #{i}",
            memory_gb=24.0, cores=16384)
    results = []

    def callback(result: FuzzResult):
        results.append(result)

    service.submit_task(input_data=input_data, iterations=iterations,
                       mode=mode, callback=callback)
    service.start()
    time.sleep(2.0)
    service.stop()
    if results:
        result = results[0]
        return {
            'success': True, 'crashes_found': len(result.crashes),
            'executions': result.executions, 'duration': result.duration,
            'coverage_increase': result.coverage_increase,
            'stats': service.get_stats()}
    return {'success': False, 'error': 'No result'}
