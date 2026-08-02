# 2026-07-28

import hashlib
import random
import struct

# ---- GPU Buffer Management ----
# 模拟显存分配/释放，追踪碎片化程度


class GPUBufferManager:
    def __init__(self, total_memory: int):
        self._total = total_memory
        self._used = 0
        self._buffers: dict[int, bytearray] = {}
        self._next_handle = 1
        # 统计分配历史，用于碎片化分析
        self._alloc_history: list[tuple[int, int]] = []
        self._free_history: list[int] = []

    def allocate(self, size: int) -> int:
        if size <= 0:
            raise ValueError(f"缓冲区大小必须为正: {size}")
        if self._used + size > self._total:
            raise MemoryError(
                f"显存不足: 请求{size}B, 可用{self._total - self._used}B"
            )
        handle = self._next_handle
        self._next_handle += 1
        self._buffers[handle] = bytearray(size)
        self._used += size
        self._alloc_history.append((handle, size))
        return handle

    def free(self, handle: int):
        if handle not in self._buffers:
            return
        _v = len(self._buffers[handle])
        del self._buffers[handle]
        self._used -= _v
        self._free_history.append(handle)

    def read(self, handle: int, offset: int, size: int) -> bytes:
        _buf = self._buffers[handle]
        if offset + size > len(_buf):
            raise IndexError(f"越界读取: {offset}+{size} > {len(_buf)}")
        return bytes(_buf[offset:offset + size])

    def write(self, handle: int, offset: int, data: bytes):
        _buf = self._buffers[handle]
        if offset + len(data) > len(_buf):
            raise IndexError(f"越界写入: {offset}+{len(data)} > {len(_buf)}")
        _buf[offset:offset + len(data)] = data

    def memory_usage(self) -> float:
        return self._used / self._total if self._total > 0 else 0.0


# ===== GPU Kernel Fuzzer =====
# 核心思路: AFLFast能量调度 + 确定性/随机变异 + 边覆盖率引导


class GPUFuzzerCore:
    # 有趣的边界值 — 触发整数溢出/下溢/符号问题
    _INTERESTING_8: list[int] = [0, 0x7F, 0x80, 0xFF]
    _INTERESTING_16: list[int] = [0, 0x7FFF, 0x8000, 0xFFFF]
    _INTERESTING_32: list[int] = [
        0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFE, 0x80000001
    ]

    def __init__(self, device_id: int = 0, max_buffer_size: int = 256 * 1024 * 1024):
        self._device_id = device_id
        self._max_buffer_size = max_buffer_size
        self._coverage: dict[str, int] = {}
        self._seed_queue: list[dict] = []
        self._buffer_manager = GPUBufferManager(max_buffer_size)
        # 全局状态 — AFL式路径发现计数
        self._total_execs = 0
        self._unique_crashes: set[str] = set()
        self._unique_hangs: set[str] = set()

    # //// 边哈希 — XOR-shift近似，GPU适配
    def hash_edge(self, prev_id: int, cur_id: int) -> int:
        _v = (prev_id >> 1) ^ (cur_id << 3)
        _v &= 0xFFFFFFFF
        _v ^= (_v >> 17)
        _v ^= (_v << 13)
        _v &= 0xFFFFFFFF
        _v ^= (_v >> 7)
        return _v

    def simplified_gpu_memory_model(self, size: int) -> GPUBufferManager:
        """重新初始化显存模型（用于重置fuzzer状态）"""
        self._buffer_manager = GPUBufferManager(size)
        return self._buffer_manager

    # ---- AFLFast种子能量调度 ----
    # 基于执行时间和覆盖率稀有度加权
    def aflfast_seed_energy(self, seed: dict) -> float:
        perf_score = 100.0
        _exec_us = seed.get("exec_us", 100)
        _handicap = seed.get("handicap", 1)
        # 执行更快的种子获得更高能量
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

        # 覆盖率因子 — 新发现的路径多的种子优先级更高
        _cov_factor = seed.get("cov_factor", 1.0)
        perf_score *= _cov_factor

        # 深度惩罚 — 避免过于深的种子占用过多时间
        _depth = seed.get("depth", 0)
        if _depth > 100:
            perf_score *= 0.7

        return max(perf_score / _handicap, 1.0)

    # ---- 边界值变异 ----
    def interesting_values_mutation(self, data: bytearray) -> bytearray:
        if len(data) == 0:
            return data
        _mutated = bytearray(data)
        _pos = random.randint(0, len(_mutated) - 1)
        _choice = random.randint(0, 3)
        if _choice == 0:
            # 8-bit边界值
            struct.pack_into("B", _mutated, _pos, random.choice(self._INTERESTING_8))
        elif _choice == 1 and _pos + 1 < len(_mutated):
            struct.pack_into("<H", _mutated, _pos, random.choice(self._INTERESTING_16))
        elif _choice == 2 and _pos + 3 < len(_mutated):
            struct.pack_into("<I", _mutated, _pos, random.choice(self._INTERESTING_32))
        else:
            # 符号翻转
            _mutated[_pos] = ~_mutated[_pos] & 0xFF
        return _mutated

    # ===== 变异引擎 =====
    # 混合确定性+破坏性变异策略
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
                _new_val = (_out[_pos] + _delta) & 0xFF
                _out[_pos] = _new_val
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

    # ---- 确定性模拟执行 ----
    # 基于核函数hash和输入数据生成可重现的轨迹
    def _simulate_execution(self, kernel: str, input_data: bytes) -> tuple[int, set]:
        _hasher = hashlib.sha256()
        _hasher.update(kernel.encode("utf-8", errors="replace"))
        _hasher.update(input_data)
        _full = _hasher.digest()
        # 从hash派生出执行状态和覆盖轨迹
        exit_code = _full[0]  # 0-255: 0=正常, 非0=异常类别
        edge_set: set = set()
        prev = 0
        for _i in range(0, len(_full) - 4, 4):
            cur = struct.unpack_from("<I", _full, _i)[0] & 0xFFFF
            edge_set.add(self.hash_edge(prev, cur))
            prev = cur
        # 注入确定性crash: 如果输入中出现0xDEAD模式
        if b"\xDE\xAD" in input_data:
            exit_code = 139  # SIGSEGV模拟
        return exit_code, edge_set

    # ---- 校准: 对新种子运行确定性阶段 ----
    def _calibrate(self, seed: dict):
        data = seed["data"]
        if isinstance(data, bytes):
            data = bytearray(data)
        elif not isinstance(data, bytearray):
            data = bytearray(data)
        # 简单校验: 运行基础执行并记录覆盖
        _code, _edges = self._simulate_execution("_calibrate", bytes(data))
        seed.setdefault("exec_us", 50)
        seed.setdefault("depth", 0)
        seed.setdefault("handicap", 1)
        seed.setdefault("cov_factor", 1.0)

    # ===== 核心Fuzz循环 =====
    # 主循环: 种子调度 → 变异 → 执行 → 覆盖率分析 → 存入队列/丢弃
    def fuzz_kernel(
        self, kernel_source: str, seeds: list[bytes], iterations: int = 1000
    ) -> list[dict]:
        results: list[dict] = []
        # 初始化种子队列
        self._seed_queue.clear()
        self._coverage.clear()
        self._total_execs = 0
        for _i, s in enumerate(seeds):
            _seed = {
                "id": _i,
                "data": bytearray(s),
                "depth": 0,
                "exec_us": 50,
                "handicap": 1,
                "cov_factor": 1.0,
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
                        "id": len(self._seed_queue),
                        "data": mutated,
                        "depth": seed["depth"] + 1,
                        "exec_us": random.randint(10, 200),
                        "handicap": 1,
                        "cov_factor": 2.0,
                    }
                    self._seed_queue.append(_new_seed)
                # 记录crash/hang
                if _code != 0:
                    _hash = hashlib.md5(bytes(mutated)).hexdigest()
                    if _code == 139:
                        if _hash not in self._unique_crashes:
                            self._unique_crashes.add(_hash)
                            results.append({
                                "type": "crash",
                                "exit_code": _code,
                                "data": bytes(mutated),
                                "hash": _hash,
                                "iteration": self._total_execs,
                            })
                    elif _code in (9, 15):  # SIGKILL/SIGTERM → 超时
                        if _hash not in self._unique_hangs:
                            self._unique_hangs.add(_hash)
                            results.append({
                                "type": "hang",
                                "exit_code": _code,
                                "data": bytes(mutated),
                                "hash": _hash,
                                "iteration": self._total_execs,
                            })
                # 每500轮降低handicap避免饥饿
                if self._total_execs % 500 == 0:
                    for s in self._seed_queue:
                        s["handicap"] = max(1, s["handicap"] - 1)
            _queue_idx += 1

        results.append({
            "type": "summary",
            "total_execs": self._total_execs,
            "coverage_edges": len(self._coverage),
            "unique_crashes": len(self._unique_crashes),
            "unique_hangs": len(self._unique_hangs),
            "seed_count": len(self._seed_queue),
            "memory_usage": self._buffer_manager.memory_usage(),
        })
        return results

    # ===== 多设备调度 =====
    # 按显存/核心数比例分配任务
    def multi_device_schedule(
        self, jobs: list[dict], devices: list[int]
    ) -> dict[int, list[dict]]:
        if not devices:
            return {}
        schedule: dict[int, list[dict]] = {d: [] for d in devices}
        # 轮询分配 — 简单但有效的负载均衡
        _weights = [1.0] * max(1, len(devices))
        # 越靠前的设备分配越多
        for _i, d in enumerate(devices):
            _weights[_i] = max(0.5, 1.0 - _i * 0.1)
        _total_weight = sum(_weights)
        _job_per_device = [max(1, int(len(jobs) * w / _total_weight)) for w in _weights]
        # 确保所有job被分配
        while sum(_job_per_device) < len(jobs):
            _job_per_device[0] += 1
        _offset = 0
        for _i, d in enumerate(devices):
            _n = _job_per_device[_i]
            schedule[d] = jobs[_offset:_offset + _n]
            _offset += _n
        return schedule
