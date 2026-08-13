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

    def _generate_random_mutations(self, seed: bytes, count: int) -> List[bytes]:
        results = []
        for _ in range(count):
            mutated = bytearray(seed)
            for i in range(random.randint(1, len(mutated))):
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.randint(0, 255)
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

            remaining -= batch

        duration = time.time() - start_time

        return FuzzResult(
            task_id=task.task_id,
            crashes=crashes,
            coverage_increase=random.uniform(0.0, 5.0),
            executions=executions,
            duration=duration
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

    def _device_worker(self, device_id: str):
        fuzzer = self._fuzzers[device_id]
        fuzzer._running = True

        while self._running:
            task = self._get_next_task()
            if task:
                self._execute_task(device_id, task)
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
                'total_devices': len(self._devices)
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
