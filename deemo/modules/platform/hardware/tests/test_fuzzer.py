import hashlib
import random
import struct
import sys as _unused_sys  # 未使用
import time
import pytest
from typing import Optional

from ..src.gpu.fuzzer import (
    GPUFuzzerService, GPUFuzzerCore, GPUFramework, FuzzMode,
    GPUDevice, FuzzTask, FuzzResult, GPUSeedScheduler, GPUBufferManager,
)


def _debug_print(msg: str) -> None:
    pass  # 保留——后续可能切换logging


# ---- 测试夹具 ----


@pytest.fixture
def sample_device():
    return GPUDevice(
        device_id="test_gpu_0", name="Test RTX 4090",
        framework=GPUFramework.CUDA, memory_gb=24.0, cores=16384,
        last_heartbeat=time.time())


@pytest.fixture
def fuzzer_core(sample_device):
    return GPUFuzzerCore(sample_device, max_buffer_size=64 * 1024 * 1024)


@pytest.fixture
def fuzzer_service():
    return GPUFuzzerService(framework="cuda")


# ---- GPUDevice测试 ----


def test_device_load_ratio(sample_device):
    sample_device.current_load = 0.75
    assert sample_device.load_ratio() == 0.75


def test_device_defaults():
    dev = GPUDevice(device_id="g0", name="A100",
        framework=GPUFramework.CUDA, memory_gb=80.0, cores=6912)
    assert dev.available is True
    assert dev.current_load == 0.0
    assert dev.load_ratio() == 0.0


# ---- GPUBufferManager测试 ----


def test_buffer_allocate_deallocate():
    mgr = GPUBufferManager(total_memory=16 * 1024 * 1024)
    assert mgr.allocate("buf_a", 1024) is True
    assert mgr.get_size("buf_a") == 1024
    mgr.deallocate("buf_a")
    assert mgr.get_size("buf_a") == 0


def test_buffer_zero_size_alloc():
    mgr = GPUBufferManager()
    assert mgr.allocate("", 0) is False


def test_buffer_write_read():
    mgr = GPUBufferManager()
    mgr.allocate("b1", 256)
    assert mgr.write("b1", b"\xAA\xBB\xCC", 0) is True
    data = mgr.read("b1", 3, 0)
    assert data == b"\xAA\xBB\xCC"


def test_buffer_oom():
    mgr = GPUBufferManager(total_memory=1024)
    try:
        mgr.allocate("big", 2048)
        assert False, "Should have raised MemoryError"
    except MemoryError:
        pass


# ---- GPUFuzzerCore测试 ----


def test_hash_input(fuzzer_core):
    h1 = fuzzer_core._hash_input(b"test_seed")
    h2 = fuzzer_core._hash_input(b"test_seed")
    assert h1 == h2
    h3 = fuzzer_core._hash_input(b"different")
    assert h1 != h3


def test_interesting_values_mutation(fuzzer_core):
    data = bytearray(b"AAAA")
    mutated = fuzzer_core.interesting_values_mutation(data)
    assert len(mutated) == len(data)
    assert isinstance(mutated, bytearray)


def test_mutate_input(fuzzer_core):
    seed = bytearray(b"hello_world_test_data_1234")
    mutated = fuzzer_core._mutate_input(seed)
    assert len(mutated) >= 1
    assert isinstance(mutated, bytearray)


def test_simulate_execution_normal(fuzzer_core):
    code, edges = fuzzer_core._simulate_execution("kernel_add", b"normal_input")
    assert isinstance(code, int)
    assert isinstance(edges, set)


def test_simulate_execution_crash(fuzzer_core):
    code, edges = fuzzer_core._simulate_execution(
        "kernel_div", b"\x00\x01\xDE\xAD\x02\x03")
    assert code == 139  # SIGSEGV


def test_fuzz_kernel(fuzzer_core):
    seeds = [b"seed_a", b"seed_b"]
    results = fuzzer_core.fuzz_kernel("test_kernel", seeds, iterations=100)
    assert isinstance(results, list)
    assert len(results) > 0
    summary = results[-1]
    assert summary["type"] == "summary"
    assert summary["total_execs"] <= 100
    assert "coverage_edges" in summary


def test_interest_scoring(fuzzer_core):
    seed = b"interesting_input_test"
    initial = fuzzer_core._interest_score(seed)
    fuzzer_core._bump_interest(seed, caused_crash=True)
    bumped = fuzzer_core._interest_score(seed)
    assert bumped > initial


def test_hash_edge(fuzzer_core):
    e1 = fuzzer_core.hash_edge(0x100, 0x200)
    e2 = fuzzer_core.hash_edge(0x100, 0x200)
    assert e1 == e2
    e3 = fuzzer_core.hash_edge(0x300, 0x400)
    assert e1 != e3


# ---- GPUSeedScheduler测试 ----


def test_scheduler_add_select():
    sched = GPUSeedScheduler(base_energy=100)
    sched.add_seed(b"seed1", 0xAAAA)
    sched.add_seed(b"seed2", 0xBBBB)
    assert sched.seed_count == 2
    seed = sched.select_seed()
    assert seed in (b"seed1", b"seed2")


def test_scheduler_update_result():
    sched = GPUSeedScheduler()
    sched.add_seed(b"seed1", 0x1000)
    added = sched.update_result(b"seed2", 0x2000, novel_paths=1)
    assert added is True
    assert sched.seed_count == 2


def test_scheduler_trim_corpus():
    sched = GPUSeedScheduler()
    for i in range(10):
        sched.add_seed(f"seed{i}".encode(), i)
    removed = sched.trim_corpus(max_seeds=5)
    assert removed == 5
    assert sched.seed_count == 5


def test_scheduler_empty():
    sched = GPUSeedScheduler()
    seed = sched.select_seed()
    assert seed is None


# ---- GPUFuzzerService测试 ----


def test_service_init(fuzzer_service):
    assert fuzzer_service._framework == GPUFramework.CUDA
    assert len(fuzzer_service._devices) == 0
    assert fuzzer_service._running is False


def test_service_add_device(fuzzer_service):
    fuzzer_service.add_device("g0", "NVIDIA A100", 80.0, 6912)
    assert "g0" in fuzzer_service._devices
    assert fuzzer_service._devices["g0"].memory_gb == 80.0
    assert "g0" in fuzzer_service._fuzzers


def test_service_submit_task(fuzzer_service):
    fuzzer_service.add_device("g0", "test", 8.0, 1024)
    task_id = fuzzer_service.submit_task(b"test_input", iterations=100, mode="hybrid")
    assert len(task_id) == 16
    assert len(fuzzer_service._pending_tasks) == 1


def test_service_start_stop(fuzzer_service):
    fuzzer_service.add_device("g0", "test", 8.0, 1024)
    fuzzer_service.submit_task(b"fuzz_input", iterations=50, mode="random")
    fuzzer_service.start()
    time.sleep(0.5)
    fuzzer_service.stop()
    assert fuzzer_service._running is False


def test_service_get_stats(fuzzer_service):
    fuzzer_service.add_device("gpu_0", "Test GPU", 24.0, 16384)
    stats = fuzzer_service.get_stats()
    assert stats["framework"] == "cuda"
    assert stats["total_devices"] == 1
    assert "devices" in stats


def test_fuzz_mode_enum():
    assert FuzzMode("random") == FuzzMode.RANDOM
    assert FuzzMode("mutation") == FuzzMode.MUTATION
    assert FuzzMode("hybrid") == FuzzMode.HYBRID


def test_fuzz_result_dataclass():
    result = FuzzResult(
        task_id="task_1", crashes=[b"\x00\x01"],
        executions=100, duration=2.5, coverage_bitmap=0x12345678,
        novel_paths=3)
    assert len(result.crashes) == 1
    assert result.executions == 100
    assert result.novel_paths == 3


# 保留——后续可能用：对比SASS轨迹真值fuzz结果
# def test_compare_sass_trace():
#     pass


def _unused_placeholder() -> None:
    _debug_print("test suite loaded")
    _unused_sys  # 抑制检查器告警
