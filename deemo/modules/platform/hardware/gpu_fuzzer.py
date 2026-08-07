import logging
import time
import hashlib
import threading
import random
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

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


# 种子调度与能量分配
# AFL 的 effort 分配思路：稀有路径获得更多变异预算。
# 与 CuFuzz 的知识图谱驱动不同，这里用轻量级 bitmap 指纹做快速稀有性近似，
# 适合 GPU kernel fuzz 的高吞吐场景（单次 kernel 执行通常 <1ms）。

class _SeedBucket:
    """单一种子元数据，用于调度决策。"""
    __slots__ = ('seed', 'bitmap', 'hit_count', 'energy', 'last_fuzzed')

    def __init__(self, seed: bytes, bitmap: int):
        self.seed = seed
        self.bitmap = bitmap
        self.hit_count = 1
        self.energy = 100
        self.last_fuzzed = 0.0


class GPUSeedScheduler:
    """基于覆盖稀有性的种子调度器。

    每个种子的能量（energy）决定下一轮变异时该种子被选中的概率。
    罕见路径（bitmap 在全局出现频次低）获得指数级更高能量。
    """

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
        """返回 True 表示该结果值得加入种子池（发现新路径）。"""
        with self._lock:
            freq = self._global_bitmap_freq.get(bitmap, 0)
            if freq == 0 or novel_paths > 0:
                self._global_bitmap_freq[bitmap] = freq + 1
                self._buckets.append(_SeedBucket(seed, bitmap))
                return True
            # 更新已有种子的命中计数
            for b in self._buckets:
                if b.bitmap == bitmap:
                    b.hit_count += 1
                    break
            return False

    def select_seed(self) -> Optional[bytes]:
        """按能量加权随机选择一个种子。

        采用 weighted reservoir 而非全量排序，O(n) 选择且避免 starvation。
        """
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
        """根据全局 bitmap 频率重新分配能量。

        稀有性 = 1 / (全局频次)，乘以基准能量。
        频次为 1 的种子获 4x 基准能量，频次 >10 的种子降至 0.5x 基准。
        """
        base = self._base_energy
        for b in self._buckets:
            freq = self._global_bitmap_freq.get(b.bitmap, 1)
            # 反比例 + 平方根平滑，防止极端值
            rarity_bonus = (1.0 / (freq ** 0.5))
            b.energy = max(10, min(base * 4, int(base * rarity_bonus)))

    def trim_corpus(self, max_seeds: int = 500) -> int:
        """移除命中频次最高的冗余种子，保留稀有路径。

        策略：按 bitmap 频次降序排列，删除前 N 个过频繁的种子。
        此为 AFL 式 corpus minimization 的简化版——不做最小集覆盖，
        因 GPU fuzz 中 bitmap 碰撞率低，删除高频种子基本等价于去重。
        """
        with self._lock:
            if len(self._buckets) <= max_seeds:
                return 0
            # 按频次降序，保留低频种子
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
    def __init__(self):
        self._buffers: Dict[str, bytes] = {}
        self._buffer_sizes: Dict[str, int] = {}
        self._lock = threading.RLock()

    def allocate(self, buffer_id: str, size: int) -> bool:
        with self._lock:
            if buffer_id in self._buffers:
                return False
            self._buffers[buffer_id] = b'\x00' * size
            self._buffer_sizes[buffer_id] = size
            return True

    def deallocate(self, buffer_id: str):
        with self._lock:
            if buffer_id in self._buffers:
                del self._buffers[buffer_id]
                del self._buffer_sizes[buffer_id]

    def write(self, buffer_id: str, data: bytes, offset: int = 0) -> bool:
        with self._lock:
            if buffer_id not in self._buffers:
                return False
            buffer = bytearray(self._buffers[buffer_id])
            end = min(offset + len(data), len(buffer))
            buffer[offset:end] = data[:end - offset]
            self._buffers[buffer_id] = bytes(buffer)
            return True

    def read(self, buffer_id: str, size: int, offset: int = 0) -> Optional[bytes]:
        with self._lock:
            if buffer_id not in self._buffers:
                return None
            buffer = self._buffers[buffer_id]
            end = min(offset + size, len(buffer))
            return buffer[offset:end]

    def get_size(self, buffer_id: str) -> int:
        with self._lock:
            return self._buffer_sizes.get(buffer_id, 0)

    def get_total_allocated(self) -> int:
        with self._lock:
            return sum(self._buffer_sizes.values())


class GPUFuzzerCore:
    def __init__(self, device: GPUDevice):
        self._device = device
        self._buffer_manager = GPUBufferManager()
        self._running = False
        # 输入兴趣度评分：对产生 crash 或新覆盖的输入加分
        self._interest_scores: Dict[int, float] = {}

    @staticmethod
    def _hash_input(input_bytes: bytes) -> int:
        """64-bit 折叠哈希，用于 bitmap 指纹和兴趣度索引。"""
        h = hashlib.sha256(input_bytes).digest()
        return int.from_bytes(h[:8], 'little')

    def _interest_score(self, input_bytes: bytes) -> float:
        """输入兴趣度：产生过 crash 的输入类型获得更高变异优先级。"""
        h = self._hash_input(input_bytes)
        return self._interest_scores.get(h, 0.05)

    def _bump_interest(self, input_bytes: bytes, caused_crash: bool):
        h = self._hash_input(input_bytes)
        old = self._interest_scores.get(h, 0.0)
        increment = 1.0 if caused_crash else 0.15
        self._interest_scores[h] = min(10.0, old + increment)

    def _generate_random_mutations(self, seed: bytes, count: int) -> List[bytes]:
        results = []
        # 高兴趣度种子获得更多变异点
        interest = self._interest_score(seed)
        mutation_points = max(1, min(len(seed), int(len(seed) * 0.3 * interest)))

        for _ in range(count):
            mutated = bytearray(seed)
            for _ in range(random.randint(1, mutation_points)):
                pos = random.randint(0, len(mutated) - 1)
                # 混合变异策略：位翻转 / 字节替换 / 块插入
                op = random.randint(0, 2)
                if op == 0:
                    mutated[pos] ^= 1 << random.randint(0, 7)
                elif op == 1:
                    mutated[pos] = random.randint(0, 255)
                else:
                    # 块操作：2-8 字节的算术加减
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
        """将一批输入的执行结果编码为 64-bit bitmap。

        实际场景中来自 GPU 覆盖率回传（如 nvbit 插桩），此处用哈希模拟。
        """
        combined = b''.join(inputs)
        h = hashlib.sha256(combined).digest()
        return int.from_bytes(h[:8], 'little')

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
            task_id=task.task_id,
            crashes=crashes,
            coverage_increase=random.uniform(0.0, 5.0),
            executions=executions,
            duration=duration,
            coverage_bitmap=bitmap,
            novel_paths=1 if crashes else 0,
        )

    def _simulate_test(self, input_bytes: bytes) -> bool:
        crc = sum(input_bytes)
        return crc % 100 == 0


class GPUFuzzerService:
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
        # 种子调度器跨设备共享
        self._scheduler = GPUSeedScheduler()

    def add_device(self, device_id: str, name: str, memory_gb: float, cores: int):
        device = GPUDevice(
            device_id=device_id,
            name=name,
            framework=self._framework,
            memory_gb=memory_gb,
            cores=cores,
            last_heartbeat=time.time()
        )
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
            task_id=task_id,
            input_data=input_data,
            iterations=iterations,
            mode=fuzz_mode,
            callback=callback,
            timestamp=time.time()
        )

        with self._lock:
            self._pending_tasks.append(task)
            # 将输入种子注册到调度器
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
                    target=self._device_worker,
                    args=(device_id,),
                    daemon=True
                )
                self._worker_threads.append(thread)
                thread.start()

    def stop(self):
        with self._lock:
            self._running = False
        for fuzzer in self._fuzzers.values():
            fuzzer._running = False
        for thread in self._worker_threads:
            thread.join()
        # 停止时执行一次语料库裁剪
        trimmed = self._scheduler.trim_corpus(max_seeds=500)
        if trimmed > 0:
            logger.debug("corpus trimmed: %d redundant seeds removed", trimmed)

    def _device_worker(self, device_id: str):
        fuzzer = self._fuzzers[device_id]
        fuzzer._running = True

        while self._running:
            task = self._get_next_task()
            if task is not None:
                self._execute_task(device_id, task)
            else:
                # 无待处理任务时，从调度器取种子做变异探索
                seed = self._scheduler.select_seed()
                if seed is not None:
                    explore_task = FuzzTask(
                        task_id=f"explore_{device_id}_{time.monotonic_ns()}",
                        input_data=seed,
                        iterations=256,
                        mode=FuzzMode.MUTATION,
                    )
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

        # 反馈至调度器：新路径加入种子池
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
                    'id': d.device_id,
                    'name': d.name,
                    'memory_gb': d.memory_gb,
                    'cores': d.cores,
                    'available': d.available,
                    'load': d.current_load
                } for d in self._devices.values()],
                'pending_tasks': len(self._pending_tasks),
                'running_tasks': len(self._running_tasks),
                'total_devices': len(self._devices),
                'seed_pool_size': self._scheduler.seed_count,
            }


def run_gpu_fuzzing(
    input_data: bytes,
    iterations: int = 10000,
    mode: str = "hybrid",
    devices: int = 2
) -> Dict[str, Any]:
    service = GPUFuzzerService()

    for i in range(devices):
        service.add_device(
            device_id=f"gpu_{i}",
            name=f"NVIDIA RTX 4090 #{i}",
            memory_gb=24.0,
            cores=16384
        )

    results = []

    def callback(result: FuzzResult):
        results.append(result)

    service.submit_task(
        input_data=input_data,
        iterations=iterations,
        mode=mode,
        callback=callback
    )

    service.start()
    time.sleep(2.0)
    service.stop()

    if results:
        result = results[0]
        return {
            'success': True,
            'crashes_found': len(result.crashes),
            'executions': result.executions,
            'duration': result.duration,
            'coverage_increase': result.coverage_increase,
            'stats': service.get_stats()
        }
    return {'success': False, 'error': 'No result'}
