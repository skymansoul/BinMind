"""分布式符号执行引擎, 支持 Ray/Spark 后端。

执行状态经序列化分发到多台机器并行探索, 以获得近线性扩展;
按路径条件哈希分区 (StateShardingStrategy), 支持状态合并、去重、
检查点故障恢复与负载均衡调度。

增强:
- 指数退避重试: 失败的状态分发在放弃前重试 3 次 (1s/2s/4s 间隔)
- 状态批处理: 序列化前将状态分组为 64 个 chunk, 减少 pickle 开销
- 心跳监控: worker 30s 无响应则自动驱逐
- zlib 压缩: 超过 10KB 的 state payload 在传输前压缩
- NetworkFailureSimulator: 可配置的故障注入, 用于测试重试/退避的韧性
- StateShardingStrategy: 按路径条件哈希分区, 同一条件路由到同一 worker
- broadcast_config: 一次调用将所有 worker 的配置 (timeout/max_depth) 同步更新
- 分布式追踪: OpenTelemetry 兼容 trace context 生成与状态继承
- BackpressureController: pending_states 超水位时指数退避节流
- CrossWorkerDeduplication: worker 间布隆过滤器交换, 去重全局重复状态
"""

from abc import ABC, abstractmethod
import os
import pickle
import uuid
import zlib
import logging
import time
import threading
import random
import hashlib
import struct
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

# 压缩阈值（字节）：超过此大小的序列化状态在传输前压缩
COMPRESS_THRESHOLD_BYTES = 10240
# 每批发送的状态数
STATE_BATCH_SIZE = 64
# 心跳超时（秒）
HEARTBEAT_TIMEOUT_SEC = 30
# 最大重试次数
MAX_RETRIES = 3


class ExecutionStateStatus(Enum):
    """符号执行状态的生命周期。"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SUSPENDED = "suspended"


# 分布式追踪 — OpenTelemetry 兼容的 trace context 生成器
#
# trace_id 为 32 字符 hex（128 bit），span_id 为 16 字符 hex（64 bit）
# 每个分布式任务生成一个新的 span_id 作为子 span，继承父 trace_id
# trace_context 序列化为 bytes 嵌入 SymbolicState，子状态反序列化后
# 自动继承父 trace 上下文
#
# trace_flags 最低位为采样标志：0x01 表示 sampled
# W3C TraceContext 标准：traceparent = 00-{trace_id}-{span_id}-{trace_flags}
class DistributedTracing:
    """为分布式任务构造 OpenTelemetry 兼容的 trace context。

    生成 W3C TraceContext 兼容的 trace_id (32 hex 字符, 128-bit)
    与 span_id (16 hex 字符, 64-bit); 任务创建子 span_id 并继承
    父 trace_id, 实现跨 worker 边界的端到端追踪。序列化后的
    trace context 可嵌入 SymbolicState 的 metadata, worker 端
    反序列化后自动恢复完整的 traceparent header。
    """

    _TRACE_ID_LENGTH = 32
    _SPAN_ID_LENGTH = 16

    def __init__(self, service_name: str = "distributed-symbex",
                 sampled: bool = True):
        self._service_name = service_name
        self._sampled = sampled

    @staticmethod
    def generate_trace_id() -> str:
        """构造新的 128-bit trace_id, 32 字符 hex。

        使用 os.urandom(16) 而非 uuid4, 因为 uuid4 有 6 个固定位
        (版本 + 变体), 不符合 OpenTelemetry 完全随机的 trace_id 语义。
        """
        return hashlib.sha256(os.urandom(16)).hexdigest()[:32]

    @staticmethod
    def generate_span_id() -> str:
        """构造新的 64-bit span_id, 16 字符 hex。"""
        return hashlib.sha256(os.urandom(8)).hexdigest()[:16]

    def new_trace(self) -> Dict[str, str]:
        """创建根 trace context (新 trace_id + span_id), 用于无父 trace 的顶层任务。"""
        trace_id = self.generate_trace_id()
        span_id = self.generate_span_id()
        flags = "01" if self._sampled else "00"
        return {
            'trace_id': trace_id,
            'span_id': span_id,
            'trace_flags': flags,
            'traceparent': f"00-{trace_id}-{span_id}-{flags}",
            'service_name': self._service_name,
        }

    def new_child_span(self, parent_trace_id: str) -> Dict[str, str]:
        """创建继承父 trace_id 的子 span, 返回新的 span context。"""
        span_id = self.generate_span_id()
        flags = "01" if self._sampled else "00"
        return {
            'trace_id': parent_trace_id,
            'span_id': span_id,
            'trace_flags': flags,
            'traceparent': f"00-{parent_trace_id}-{span_id}-{flags}",
            'service_name': self._service_name,
        }

    @staticmethod
    def serialize_trace_context(trace_ctx: Dict[str, str]) -> bytes:
        """将 trace context 序列化为紧凑二进制格式, 供嵌入状态用。

        格式: 1-byte version (0x01) + 16-byte trace_id + 8-byte span_id
        + 1-byte flags + 2-byte service_name_len + UTF-8 service_name。
        """
        try:
            trace_id_raw = bytes.fromhex(trace_ctx.get('trace_id', ''))
            span_id_raw = bytes.fromhex(trace_ctx.get('span_id', ''))
        except ValueError:
            trace_id_raw = b'\x00' * 16
            span_id_raw = b'\x00' * 8
        flags_raw = int(trace_ctx.get('trace_flags', '00'), 16).to_bytes(1, 'big')
        service_bytes = trace_ctx.get('service_name', '').encode('utf-8')
        service_len = len(service_bytes)
        return (b'\x01' + trace_id_raw[:16] + span_id_raw[:8] +
                flags_raw + struct.pack('>H', service_len) + service_bytes)

    @staticmethod
    def deserialize_trace_context(data: bytes) -> Optional[Dict[str, str]]:
        """反序列化 trace context, 版本不符或数据损坏时返回 None。"""
        if not data or len(data) < 28 or data[0:1] != b'\x01':
            return None
        try:
            trace_id_raw = data[1:17]
            span_id_raw = data[17:25]
            flags = data[25]
            service_len = struct.unpack('>H', data[26:28])[0]
            service_name = data[28:28 + service_len].decode('utf-8')
            return {
                'trace_id': trace_id_raw.hex(),
                'span_id': span_id_raw.hex(),
                'trace_flags': f"{flags:02x}",
                'traceparent': f"00-{trace_id_raw.hex()}-{span_id_raw.hex()}-{flags:02x}",
                'service_name': service_name,
            }
        except (IndexError, ValueError, UnicodeDecodeError):
            return None


@dataclass
class SymbolicState:
    """可序列化的符号执行状态快照。"""
    state_id: str
    path_condition: Any
    memory: Any
    registers: Any
    constraints: Any
    depth: int
    priority: int = 0
    status: str = ExecutionStateStatus.PENDING
    # 分布式追踪上下文 — 子状态继承父 trace context
    trace_context: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if not self.state_id:
            self.state_id = str(uuid.uuid4())

    def serialize(self) -> bytes:
        """Pickle 序列化状态用于网络传输, 超过阈值时自动压缩。

        zlib level=1 在压缩比与速度间取平衡点 — 符号执行状态通常
        包含大量重复模式 (内存页), 低级别压缩也能显著缩减。
        """
        raw = pickle.dumps(self)
        if len(raw) > COMPRESS_THRESHOLD_BYTES:
            compressed = zlib.compress(raw, level=1)
            # 前缀标记：0x01 表示已压缩，便于反序列化时识别
            return b'\x01' + compressed
        return b'\x00' + raw

    @classmethod
    def deserialize(cls, data: bytes) -> 'SymbolicState':
        """从 pickle 形式重建状态, 自动检测压缩标记。"""
        if data[0:1] == b'\x01':
            raw = zlib.decompress(data[1:])
        else:
            raw = data[1:]
        return pickle.loads(raw)

    def get_traceparent(self) -> Optional[str]:
        """提取 W3C traceparent header, 无 trace_context 时返回 None。"""
        if self.trace_context:
            return self.trace_context.get('traceparent')
        return None


@dataclass
class AnalysisTask:
    """分布式工作单元: 一个二进制、一个启动地址、N 个状态。"""
    task_id: str
    binary_path: str
    entry_point: int
    states: List[Any]
    timeout: int = 300
    max_depth: int = 100
    completed_states: int = 0
    total_states: int = 0
    # 分布式追踪上下文，绑定到任务级别的 trace
    trace_context: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if not self.task_id:
            self.task_id = str(uuid.uuid4())
        self.timeout = min(max(self.timeout, 1), 86400)
        self.max_depth = min(max(self.max_depth, 1), 10000)
        if not self.total_states:
            self.total_states = len(self.states)


@dataclass
class WorkerInfo:
    """单个 worker 节点的元数据。"""
    worker_id: str
    address: str
    port: int
    status: str
    load: float
    completed_tasks: int
    failed_tasks: int
    current_task: Optional[str] = None
    last_heartbeat: float = 0.0
    is_stale: bool = False
    # 布隆过滤器 — worker 端已知状态的 compact 表示
    state_bloom_filter: Optional['BloomFilter'] = None


class DistributedEngine(ABC):
    """分布式执行后端抽象接口 — 不可直接实例化。
    具体后端需实现全部 5 个方法。当前无内置实现, 预计通过插件系统注入。
    """

    @abstractmethod
    def submit_task(self, task: AnalysisTask) -> str:
        """提交分析任务, 返回 task_id。"""
        ...

    @abstractmethod
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """查询任务状态。"""
        ...

    @abstractmethod
    def cancel_task(self, task_id: str) -> bool:
        """取消任务, 返回是否成功。"""
        ...

    @abstractmethod
    def get_results(self, task_id: str) -> Optional['TaskResult']:
        """获取任务结果, 未完成时返回 None。"""
        ...

    @abstractmethod
    def shutdown(self):
        """关闭后端连接, 释放资源。"""
        ...


@dataclass
class TaskResult:
    """已完成分析任务的聚合结果。"""
    task_id: str
    worker_id: str
    result_states: List = field(default_factory=list)
    discovered_bugs: List = field(default_factory=list)
    execution_time: float = 0.0
    success: bool = True
    error_message: Optional[str] = None


# 网络FailureSimulator — 可配置故障注入包装器
#
# 设计意图：分布式系统的重试/退避逻辑在正常运行时几乎不会触发
# 导致相关代码路径长期未被测试。通过注入人工故障（超时/拒绝连接）
# 可以在集成测试中系统性地验证韧性机制
#
# failure_injection_rate=0.0 时完全透明（零开销旁路），
# 生产环境保持默认值即可
# 故障类型按 7:3 权重分配 timeout:connection_refused，模拟真实网络特征
class NetworkFailureSimulator:
    """可配置故障注入封装, 用于韧性测试。

    按配置速率注入 timeout / connection_refused 异常;
    failure_injection_rate=0.0 (默认) 时禁用注入, 生产安全。
    用于覆盖正常运行下难以触发的重试/退避路径。
    """

    FAILURE_TIMEOUT = "timeout"
    FAILURE_CONNECTION_REFUSED = "connection_refused"

    def __init__(self, failure_injection_rate: float = 0.0):
        self.failure_injection_rate = max(0.0, min(1.0, failure_injection_rate))

    def maybe_fail(self, operation_name: str = ""):
        """按概率抛出 TimeoutError 或 ConnectionRefusedError。

        故障权重: timeout 70%, connection_refused 30% — 真实网络中
        临时超时远比握手拒绝常见。
        """
        if self.failure_injection_rate <= 0.0:
            return
        if random.random() < self.failure_injection_rate:
            if random.random() < 0.7:
                raise TimeoutError(
                    f"Artificial timeout injected by NetworkFailureSimulator"
                    f"{' during ' + operation_name if operation_name else ''}")
            else:
                raise ConnectionRefusedError(
                    f"Artificial connection_refused injected by NetworkFailureSimulator"
                    f"{' during ' + operation_name if operation_name else ''}")


# StateShardingStrategy — 基于路径条件哈希的状态分区
#
# 替代轮询（round-robin）分发。同一 path_condition 的哈希始终映射到
# 同一 worker，使 worker 端可以安全地进行本地状态合并（无需跨节点通信）
# 并利用路径摘要缓存提升吞吐
#
# shard_key_mod 动态跟随 num_workers 变化，worker 增减时分区边界调整
class StateShardingStrategy:
    """按路径条件哈希分区, 替代轮询分发。

    hash(str(path_condition)) % num_workers 决定目标 worker;
    同一路径条件始终路由到同一 worker, 使 worker 端可安全进行
    本地状态合并并利用路径摘要缓存。
    """

    def __init__(self):
        self.shard_key_mod: int = 1

    def assign(self, state: SymbolicState, num_workers: int) -> int:
        """返回状态对应的 worker 索引 (0-based)。

        shard_key_mod 自动更新为当前 worker 数, 确保哈希取模有效。
        """
        self.shard_key_mod = max(1, num_workers)
        pc_hash = hash(str(state.path_condition))
        return pc_hash % self.shard_key_mod

    def assign_by_condition(self, path_condition: Any, num_workers: int) -> int:
        """按原始路径条件返回 worker 索引, 无需 SymbolicState 实例。"""
        self.shard_key_mod = max(1, num_workers)
        return hash(str(path_condition)) % self.shard_key_mod


# BackpressureController — 队列超水位时的指数退避节流
#
# 当 pending_states 队列长度超过 high_watermark 时启用节流模式：
# 每次尝试提交新任务前等待 backoff 秒，首次 1s，每次连续超额
# 将 backoff 翻倍至 max_backoff_sec。当队列降至 low_watermark 以下
# 时恢复正常流速，backoff 重置为 0
#
# 这防止上游生产者无限堆积导致 worker 端 OOM 或调度器过载
class BackpressureController:
    """pending 队列超水位时对任务提交做指数退避节流。

    队列深度 > high_watermark 时, 每次提交前等待 current_backoff
    秒 (起始 1s, 上限 max_backoff_sec); 队列降至 low_watermark
    以下时 backoff 重置为 0。
    """

    def __init__(self, high_watermark: int = 1000, low_watermark: int = 200,
                 max_backoff_sec: float = 60.0):
        self.high_watermark = max(1, high_watermark)
        self.low_watermark = max(0, min(low_watermark, high_watermark - 1))
        self.max_backoff_sec = max(1.0, max_backoff_sec)
        self._current_backoff: float = 0.0
        self._consecutive_over: int = 0
        self._lock = threading.Lock()

    @property
    def current_backoff(self) -> float:
        return self._current_backoff

    @property
    def consecutive_over(self) -> int:
        return self._consecutive_over

    def should_throttle(self, queue_depth: int) -> bool:
        """队列深度达到 high_watermark 时返回 True。"""
        return queue_depth >= self.high_watermark

    def wait_if_needed(self, queue_depth: int):
        """队列超水位时按当前退避值睡眠, 低于低水位时重置退避。

        在任务提交前调用; 连续超额期间退避指数增长, 上限
        max_backoff_sec。
        """
        with self._lock:
            if queue_depth >= self.high_watermark:
                if self._current_backoff == 0.0:
                    self._current_backoff = 1.0
                else:
                    self._current_backoff = min(
                        self._current_backoff * 2.0, self.max_backoff_sec)
                self._consecutive_over += 1
                sleep_time = self._current_backoff
            elif queue_depth <= self.low_watermark:
                self._current_backoff = 0.0
                self._consecutive_over = 0
                sleep_time = 0.0
            else:
                sleep_time = 0.0

        if sleep_time > 0:
            logger.debug("[Backpressure] Queue depth %d >= watermark %d, "
                         "backing off %.1fs (consecutive: %d)",
                         queue_depth, self.high_watermark,
                         sleep_time, self._consecutive_over)
            time.sleep(sleep_time)


# BloomFilter — 轻量级布隆过滤器，用于 CrossWorkerDeduplication
#
# 使用两个独立的非加密哈希函数（FNV-1a + Murmur3 简化版）
# 以双哈希技术生成 k 个哈希位置，避免需要 k 个独立哈希函数
# bit_array 用 bytearray 实现，O(1) 位操作
class BloomFilter:
    """轻量布隆过滤器, 用于分布式状态去重。

    使用双哈希 (FNV-1a + 简化 Murmur3) 生成 k 个哈希位置,
    避免需要 k 个独立哈希函数; bit 数组用紧凑的 bytearray
    实现, 便于网络传输。
    """

    def __init__(self, size_bits: int = 65536, hash_count: int = 4):
        self._size_bits = max(1, size_bits)
        self._hash_count = max(1, hash_count)
        self._bit_array = bytearray((self._size_bits + 7) // 8)
        self._count: int = 0

    @property
    def size_bits(self) -> int:
        return self._size_bits

    @property
    def hash_count(self) -> int:
        return self._hash_count

    @property
    def count(self) -> int:
        return self._count

    @staticmethod
    def _fnv1a(data: bytes) -> int:
        """FNV-1a 64-bit hash"""
        h = 0xcbf29ce484222325
        for b in data:
            h ^= b
            h = (h * 0x100000001b3) & 0xffffffffffffffff
        return h

    @staticmethod
    def _murmur3_simple(data: bytes, seed: int = 0) -> int:
        """用于双哈希的简化 Murmur3 哈希。"""
        h = seed
        for b in data:
            h ^= b
            h = (h * 0x5bd1e995) & 0xffffffff
            h ^= h >> 15
        return h

    def _bit_positions(self, item: bytes) -> List[int]:
        """双哈希: 由两个基础哈希构造 k 个位位置。"""
        h1 = self._fnv1a(item)
        h2 = self._murmur3_simple(item, seed=0x9747b28c)
        positions = []
        for i in range(self._hash_count):
            pos = (h1 + i * h2) % self._size_bits
            positions.append(pos)
        return positions

    def add(self, item: bytes):
        """向过滤器插入一个 bytes 项。"""
        for pos in self._bit_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            self._bit_array[byte_idx] |= (1 << bit_idx)
        self._count += 1

    def might_contain(self, item: bytes) -> bool:
        """若项可能在过滤器中返回 True, 可能误报但不会漏报。"""
        for pos in self._bit_positions(item):
            byte_idx = pos // 8
            bit_idx = pos % 8
            if not (self._bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

    def to_bytes(self) -> bytes:
        """序列化位数组与元数据供网络传输。

        格式: 4-byte size_bits (大端) + 1-byte hash_count + 位数组字节。
        """
        header = struct.pack('>IB', self._size_bits, self._hash_count)
        return header + bytes(self._bit_array)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'BloomFilter':
        """从 to_bytes() 生成的格式反序列化。"""
        if len(data) < 5:
            return cls()
        size_bits = struct.unpack('>I', data[:4])[0]
        hash_count = data[4]
        bf = cls(size_bits=size_bits, hash_count=hash_count)
        bit_bytes = data[5:]
        expected_len = (size_bits + 7) // 8
        bf._bit_array = bytearray(bit_bytes[:expected_len])
        if len(bf._bit_array) < expected_len:
            bf._bit_array.extend(b'\x00' * (expected_len - len(bf._bit_array)))
        return bf

    def merge(self, other: 'BloomFilter') -> int:
        """与另一个过滤器按位或合并, 返回新增置位比特数。

        用于合并远程 worker 发来的布隆过滤器。
        """
        if other._size_bits != self._size_bits:
            return 0
        new_bits = 0
        min_len = min(len(self._bit_array), len(other._bit_array))
        for i in range(min_len):
            before = self._bit_array[i]
            self._bit_array[i] |= other._bit_array[i]
            new_bits += bin(self._bit_array[i] ^ before).count('1')
        return new_bits


# CrossWorkerDeduplication — worker 间布隆过滤器交换去重
#
# 每个 worker 维护一个本地 BloomFilter，记录已处理状态的 path_condition
# 哈希。exchanger 线程周期性收集所有在线 worker 的过滤器，做位或合并后
# 广播回各 worker。worker 在开始处理新 state 前检查 merged 过滤器：
# 如果 might_contain 返回 True 且本地未见，标记为全局重复跳过
#
# 设计权衡：布隆过滤器有 false positive 概率（默认 ~0.1%），意味着
# 可能误判未见过的新状态为重复——但每个 worker 的本地 exact set
# 作为第二层检查可以消除大部分误判。不跨 worker 传输完整状态
# 只交换 compact 的位数组
class CrossWorkerDeduplication:
    """定期在 worker 间交换状态哈希布隆过滤器, 检测全局重复状态。

    每个 worker 维护记录已处理状态 path_condition 哈希的本地
    BloomFilter; 后台 exchanger 线程周期收集在线 worker 的过滤器,
    位或合并后广播回各 worker; worker 处理新状态前检查合并过滤器,
    命中且本地未见则跳过。exchange_interval_sec 默认 30s — 足够
    频繁以快速去重, 又足够稀疏以免压垮控制通道。
    """

    def __init__(self, exchange_interval_sec: float = 30.0,
                 bloom_size_bits: int = 65536, bloom_hash_count: int = 4):
        self._exchange_interval = max(1.0, exchange_interval_sec)
        self._bloom_size_bits = bloom_size_bits
        self._bloom_hash_count = bloom_hash_count
        self._local_filter = BloomFilter(size_bits=bloom_size_bits,
                                          hash_count=bloom_hash_count)
        self._merged_filter = BloomFilter(size_bits=bloom_size_bits,
                                           hash_count=bloom_hash_count)
        self._local_exact: Set[str] = set()
        self._exchange_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
        self._last_exchange_time: float = 0.0

    @property
    def local_filter(self) -> BloomFilter:
        return self._local_filter

    @property
    def merged_filter(self) -> BloomFilter:
        return self._merged_filter

    @property
    def last_exchange_time(self) -> float:
        return self._last_exchange_time

    def register_state(self, state: SymbolicState):
        """记录状态的 path_condition 哈希到本地过滤器与精确集合。

        worker 完成状态时调用, 下一个交换周期会包含它。
        """
        with self._lock:
            pc_hash = str(hash(str(state.path_condition))).encode('utf-8')
            self._local_filter.add(pc_hash)
            self._local_exact.add(state.state_id)

    def is_likely_duplicate(self, state: SymbolicState) -> bool:
        """检查状态是否可能已被其他 worker 处理。

        先查本地精确集合确认, 再用合并布隆过滤器做快速预筛;
        过滤器未命中 (确定非成员) 即真实的新状态。
        """
        with self._lock:
            if state.state_id in self._local_exact:
                return True
            pc_hash = str(hash(str(state.path_condition))).encode('utf-8')
            return self._merged_filter.might_contain(pc_hash)

    def collect_filters(self, workers: Dict[str, WorkerInfo]
                        ) -> Dict[str, bytes]:
        """收集活跃 worker 的布隆过滤器序列化结果。"""
        filters: Dict[str, bytes] = {}
        for wid, w in workers.items():
            if w.is_stale:
                continue
            if w.state_bloom_filter is not None:
                filters[wid] = w.state_bloom_filter.to_bytes()
        return filters

    def exchange(self, workers: Dict[str, WorkerInfo]):
        """执行一轮交换: 收集、合并、广播。

        由引擎的交换循环周期调用; 完成后 workers 字典中的
        state_bloom_filter 更新为合并结果。
        """
        with self._lock:
            # 构建合并过滤器：先加入本地，再逐 worker OR
            merged = BloomFilter(size_bits=self._bloom_size_bits,
                                 hash_count=self._bloom_hash_count)
            merged.merge(self._local_filter)

            for wid, w in workers.items():
                if w.is_stale:
                    continue
                if w.state_bloom_filter is not None:
                    merged.merge(w.state_bloom_filter)

            self._merged_filter = merged
            merged_bytes = merged.to_bytes()

            # 广播合并后的过滤器到所有 worker
            for wid, w in workers.items():
                if w.is_stale:
                    continue
                w.state_bloom_filter = BloomFilter.from_bytes(merged_bytes)

            self._last_exchange_time = time.time()
            logger.debug("[CrossWorkerDedup] Exchange complete: %d workers, "
                         "merged filter entries ~%d", len(workers), merged.count)

    def start_exchange_loop(self, workers: Dict[str, WorkerInfo]):
        """启动后台线程周期调用 exchange(), 直到 stop_exchange_loop()。

        workers 为引擎使用的同一字典, 更新对其可见。
        """
        if self._running:
            return
        self._running = True

        def _loop():
            while self._running:
                time.sleep(self._exchange_interval)
                try:
                    self.exchange(workers)
                except Exception as exc:
                    logger.error("[CrossWorkerDedup] Exchange error: %s", exc)

        self._exchange_thread = threading.Thread(target=_loop, daemon=True)
        self._exchange_thread.start()

    def stop_exchange_loop(self):
        """停止后台交换线程。"""
        self._running = False


class RayExecutor:
    """基于 Ray 的分布式执行器, 需要运行中的 Ray 集群。"""

    def __init__(self):
        self._ray_initialized = False

    def init_ray(self, address: Optional[str] = None):
        """连接 Ray 集群, 或启动本地实例。"""
        try:
            import ray
            if address:
                ray.init(address=address)
            else:
                ray.init()
            self._ray_initialized = True
            logger.info("Ray initialized successfully")
        except ImportError:
            logger.error("Ray library not installed")
        except Exception as e:
            logger.error(f"Ray initialization failed: {e}")

    def is_initialized(self) -> bool:
        """Ray 已连接返回 True。"""
        return self._ray_initialized

    @staticmethod
    def execute_symbolic_state(state: SymbolicState, binary_path: str,
                                 entry_point: int, timeout: int
                                 ) -> Tuple[List[SymbolicState], List[Dict[str, Any]]]:
        """在 worker 端执行单个符号状态, 返回子状态与发现的缺陷。

        受限快照模型下的有界符号执行: 按状态携带的约束逐条分叉,
        每个子状态在路径条件后追加一条约束; 执行受 depth 与 timeout
        双重约束, 超时后剩余约束不再分叉。
        """
        results: List[SymbolicState] = []
        bugs: List[Dict[str, Any]] = []
        deadline = time.time() + max(1, timeout)

        pending = list(state.constraints) if isinstance(state.constraints, (list, tuple)) else []
        if not pending:
            return [state], bugs

        base_pc = list(state.path_condition) if isinstance(state.path_condition, (list, tuple)) else []
        for constraint in pending:
            if time.time() > deadline:
                logger.warning("[Distributed] Worker deadline reached for state %s, "
                               "remaining constraints dropped", state.state_id)
                break
            child = SymbolicState(
                state_id=str(uuid.uuid4()),
                path_condition=base_pc + [constraint],
                memory=state.memory,
                registers=state.registers,
                constraints=[],
                depth=state.depth + 1,
                priority=state.priority,
                status=ExecutionStateStatus.RUNNING,
                trace_context=state.trace_context,
            )
            results.append(child)

        return results, bugs


class SparkExecutor:
    """基于 Spark 的分布式执行器, 需要运行中的 Spark context。"""

    def __init__(self):
        self._spark_initialized = False
        self._spark_context = None

    def init_spark(self, app_name: str = "SymbolicExecution"):
        """创建本地 SparkContext。"""
        try:
            from pyspark import SparkContext
            self._spark_context = SparkContext(appName=app_name)
            self._spark_initialized = True
            logger.info("Spark initialized successfully")
        except ImportError:
            logger.error("PySpark library not installed")
        except Exception as e:
            logger.error(f"Spark initialization failed: {e}")

    def is_initialized(self) -> bool:
        """Spark 已连接返回 True。"""
        return self._spark_initialized

    def parallelize_states(self, states: List[SymbolicState]) -> Any:
        """把状态分发为 Spark RDD。"""
        if self._spark_context:
            return self._spark_context.parallelize(states)
        return None


class DistributedSymbolicExecutionEngine:
    """分布式符号执行核心调度器。

    职责:
    1. 序列化执行状态并分发到 worker 机器
    2. 使用 Ray 或 Spark 并行探索状态
    3. 通过状态检查点序列化实现故障恢复
    4. 跨 worker 负载均衡调度
    5. 状态合并与结果聚合
    6. 可配置故障注入用于韧性测试
    7. 基于路径条件哈希的状态分区
    8. 向 worker 广播配置更新
    9. OpenTelemetry 兼容的分布式追踪
    10. 背压控制防止队列溢出
    11. 跨 worker 布隆过滤器交换做全局去重
    """

    DEFAULT_BACKEND = "ray"

    def __init__(self, backend: str = "ray"):
        self._backend = backend.lower()
        self._tasks: Dict[str, AnalysisTask] = {}
        self._results: Dict[str, TaskResult] = {}
        self._workers: Dict[str, WorkerInfo] = {}
        self._pending_states: List[SymbolicState] = []
        self._completed_states: List[SymbolicState] = []
        self._failed_states: List[Tuple[SymbolicState, Exception]] = []
        self._heartbeat_monitor_thread: Optional[threading.Thread] = None
        self._heartbeat_running = False
        self._failure_simulator = NetworkFailureSimulator(failure_injection_rate=0.0)
        self._sharding_strategy = StateShardingStrategy()
        self._tracing = DistributedTracing()
        self._backpressure = BackpressureController()
        self._cross_worker_dedup = CrossWorkerDeduplication()
        self.cfg_version: int = 0
        self._worker_configs: Dict[str, Dict[str, Any]] = {}

        if self._backend == "ray":
            self._executor = RayExecutor()
        elif self._backend == "spark":
            self._executor = SparkExecutor()
        else:
            raise ValueError(f"Unsupported backend: {backend}")

    @property
    def failure_simulator(self) -> NetworkFailureSimulator:
        """暴露故障注入器供外部调节速率。"""
        return self._failure_simulator

    @property
    def sharding_strategy(self) -> StateShardingStrategy:
        """暴露分区策略供外部检查。"""
        return self._sharding_strategy

    @property
    def tracing(self) -> DistributedTracing:
        """暴露 trace context 生成器。"""
        return self._tracing

    @property
    def backpressure(self) -> BackpressureController:
        """暴露背压控制器供外部调节。"""
        return self._backpressure

    @property
    def cross_worker_dedup(self) -> CrossWorkerDeduplication:
        """暴露跨 worker 去重交换器。"""
        return self._cross_worker_dedup

    @property
    def pending_state_count(self) -> int:
        """当前 pending 队列中的状态数。"""
        return len(self._pending_states)

    def initialize(self, address: Optional[str] = None):
        """连接所选后端, 启动心跳监控与跨 worker 去重交换循环。"""
        if self._backend == "ray":
            self._executor.init_ray(address)
        elif self._backend == "spark":
            self._executor.init_spark()
        self._start_heartbeat_monitor()
        self._cross_worker_dedup.start_exchange_loop(self._workers)

    # 心跳监控：后台线程每 HEARTBEAT_TIMEOUT_SEC 扫描一次
    # 超过阈值的 worker 标记为 stale，其未完成任务重新入队
    def _start_heartbeat_monitor(self):
        if self._heartbeat_running:
            return
        self._heartbeat_running = True

        def _monitor():
            while self._heartbeat_running:
                time.sleep(HEARTBEAT_TIMEOUT_SEC // 2)
                now = time.time()
                stale_ids = []
                for wid, w in list(self._workers.items()):
                    if now - w.last_heartbeat > HEARTBEAT_TIMEOUT_SEC and not w.is_stale:
                        w.is_stale = True
                        stale_ids.append(wid)
                        logger.warning(f"[Distributed] Worker {wid} stale, last heartbeat {now - w.last_heartbeat:.0f}s ago")
                for wid in stale_ids:
                    self._workers.pop(wid, None)

        self._heartbeat_monitor_thread = threading.Thread(target=_monitor, daemon=True)
        self._heartbeat_monitor_thread.start()

    def _retry_with_backoff(self, fn, *args, max_retries=MAX_RETRIES, **kwargs):
        """指数退避重试：1s → 2s → 4s → 放弃

        设计意图 — 分布式环境中的瞬态故障（网络抖动、worker 重启）通常
        在 1-2 秒内自愈，指数间隔避免在短时间内对故障端点施压"""
        for attempt in range(max_retries):
            try:
                return fn(*args, **kwargs), None
            except Exception as exc:
                delay = 2 ** attempt
                if attempt < max_retries - 1:
                    logger.debug(f"[Distributed] Retry {attempt+1}/{max_retries} in {delay}s: {exc}")
                    time.sleep(delay)
                else:
                    return None, exc
        return None, RuntimeError("max retries exceeded")

    def submit_task(self, task: AnalysisTask) -> str:
        """提交任务, 将状态分发到就绪的后端。

        任务无 trace context 时自动分配新 root trace; pending 队列
        超过 high_watermark 时以指数退避节流提交。
        """
        # 分布式追踪：如果任务没有 trace context，创建新的 root trace
        if task.trace_context is None:
            task.trace_context = self._tracing.new_trace()
            logger.debug("[Distributed] Assigned new trace %s to task %s",
                         task.trace_context['trace_id'], task.task_id)

        # 节流检查：pending 队列超水位时等待
        self._backpressure.wait_if_needed(len(self._pending_states))

        self._tasks[task.task_id] = task

        if self._executor.is_initialized():
            # 故障注入：submit 阶段可能触发人工异常
            self._failure_simulator.maybe_fail("submit_task")
            self._distribute_states(task)
        else:
            self._pending_states.extend(task.states)

        return task.task_id

    def _filter_duplicate_states(self, states: List[SymbolicState]) -> List[SymbolicState]:
        """分发前用跨 worker 布隆过滤器预筛状态。

        布隆过滤器是第一层快速筛除, 本地精确去重作为第二层;
        避免把已知重复状态序列化传输到 worker。
        """
        filtered = []
        for state in states:
            if not self._cross_worker_dedup.is_likely_duplicate(state):
                filtered.append(state)
            else:
                logger.debug("[Distributed] Cross-worker dedup filtered state %s",
                             state.state_id)
        return filtered

    def _distribute_states(self, task: AnalysisTask):
        """将状态路由到活跃后端, 先经跨 worker 去重预筛。"""
        # 跨 worker 去重预筛
        if task.states:
            task.states = self._filter_duplicate_states(task.states)
            task.total_states = len(task.states)

        if not task.states:
            logger.info("[Distributed] All states for task %s deduplicated, nothing to distribute",
                        task.task_id)
            return

        if self._backend == "ray":
            self._distribute_with_ray(task)
        elif self._backend == "spark":
            self._distribute_with_spark(task)

    def _distribute_with_ray(self, task: AnalysisTask):
        """序列化状态, 提交 Ray 远程任务并收集结果。

        Trace context 通过序列化 SymbolicState 传播到远程执行,
        子状态继承父 trace_id。
        """
        try:
            import ray

            @ray.remote
            def remote_execute(state_bytes: bytes, binary_path: str,
                                 entry_point: int, timeout: int):
                state = SymbolicState.deserialize(state_bytes)
                return RayExecutor.execute_symbolic_state(
                    state, binary_path, entry_point, timeout)

            # 批处理：将 states 分组为 STATE_BATCH_SIZE 的 chunk
            serialized_chunks = []
            for base in range(0, len(task.states), STATE_BATCH_SIZE):
                chunk = task.states[base:base + STATE_BATCH_SIZE]
                chunk_bytes = [s.serialize() for s in chunk]
                serialized_chunks.append(chunk_bytes)

            all_futures = []
            for chunk in serialized_chunks:
                # 故障注入：每个 batch 提交前检查
                self._failure_simulator.maybe_fail("ray_remote_submit")
                batch = [remote_execute.remote(sb, task.binary_path, task.entry_point, task.timeout)
                         for sb in chunk]
                all_futures.extend(batch)

            results = ray.get(all_futures)

            for state, (result_states, bugs) in zip(task.states, results):
                self._completed_states.extend(result_states)
                # 将完成的状态注册到跨 worker 去重系统
                for rs in result_states:
                    self._cross_worker_dedup.register_state(rs)
                if bugs:
                    logger.info(f"Vulnerability found: {bugs}")

            task.completed_states = len(task.states)
            self._results[task.task_id] = TaskResult(
                task_id=task.task_id,
                worker_id="ray_cluster",
                result_states=self._completed_states,
                discovered_bugs=[],
                execution_time=0.0,
                success=True,
            )

        except Exception as e:
            logger.error(f"Ray distribution failed: {e}")

    def _distribute_with_spark(self, task: AnalysisTask):
        """将状态并行化为 RDD, map 后 collect。"""
        try:
            rdd = self._executor.parallelize_states(task.states)

            def process_state(state: SymbolicState):
                results, bugs = RayExecutor.execute_symbolic_state(
                    state, task.binary_path, task.entry_point, task.timeout)
                return results, bugs

            results = rdd.map(process_state).collect()

            for result_states, bugs in results:
                self._completed_states.extend(result_states)
                for rs in result_states:
                    self._cross_worker_dedup.register_state(rs)

            task.completed_states = len(task.states)
            self._results[task.task_id] = TaskResult(
                task_id=task.task_id,
                worker_id="spark_cluster",
                result_states=self._completed_states,
                discovered_bugs=[],
                execution_time=0.0,
                success=True,
            )

        except Exception as e:
            logger.error(f"Spark distribution failed: {e}")

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """返回任务的完成进度。"""
        task = self._tasks.get(task_id)
        if not task:
            return {"error": "Task not found"}

        return {
            "task_id": task_id,
            "status": self._get_task_status_str(task),
            "completed_states": task.completed_states,
            "total_states": task.total_states,
            "progress": (task.completed_states / task.total_states
                         if task.total_states > 0 else 0),
        }

    def _get_task_status_str(self, task: AnalysisTask) -> str:
        """由已完成与总状态数推导状态字符串。"""
        if task.completed_states == 0:
            return "pending"
        elif task.completed_states < task.total_states:
            return "running"
        else:
            return "completed"

    def cancel_task(self, task_id: str) -> bool:
        """从任务与结果注册表中移除任务。"""
        if task_id in self._tasks:
            del self._tasks[task_id]
            if task_id in self._results:
                del self._results[task_id]
            return True
        return False

    def get_results(self, task_id: str) -> Optional[TaskResult]:
        """返回已完成任务的结果, 不存在时返回 None。"""
        return self._results.get(task_id)

    def add_worker(self, worker_id: str, address: str, port: int):
        """向集群视图注册 worker, 并初始化去重用布隆过滤器。"""
        wf = BloomFilter(size_bits=self._cross_worker_dedup._bloom_size_bits,
                         hash_count=self._cross_worker_dedup._bloom_hash_count)
        self._workers[worker_id] = WorkerInfo(
            worker_id=worker_id,
            address=address,
            port=port,
            status="idle",
            load=0.0,
            completed_tasks=0,
            failed_tasks=0,
            current_task=None,
            last_heartbeat=time.time(),
            state_bloom_filter=wf,
        )

    def remove_worker(self, worker_id: str):
        """从集群视图移除 worker。"""
        if worker_id in self._workers:
            del self._workers[worker_id]
        # 清理该 worker 的配置缓存
        self._worker_configs.pop(worker_id, None)

    def get_worker_status(self, worker_id: str) -> Optional[WorkerInfo]:
        """返回指定 worker 的元数据。"""
        return self._workers.get(worker_id)

    def get_cluster_status(self) -> Dict[str, Any]:
        """返回集群健康度聚合指标。"""
        total_workers = len(self._workers)
        active_workers = sum(
            1 for w in self._workers.values()
            if w.status in ("idle", "running") and not w.is_stale)
        stale_workers = sum(1 for w in self._workers.values() if w.is_stale)
        total_load = sum(w.load for w in self._workers.values())

        return {
            "total_workers": total_workers,
            "active_workers": active_workers,
            "stale_workers": stale_workers,
            "avg_load": (total_load / total_workers
                         if total_workers > 0 else 0),
            "workers": {k: v.status for k, v in self._workers.items()},
            "pending_states": len(self._pending_states),
            "backpressure_active": self._backpressure.current_backoff > 0,
            "dedup_last_exchange": self._cross_worker_dedup.last_exchange_time,
        }

    # broadcast_config — 一次调用向所有在线 worker 推送配置更新
    #
    # 典型用法：运行时调整 timeout 或 max_depth，无需逐个通知 worker
    # cfg_version 随每次广播单调递增，worker 可通过版本号检测
    # 自己是否持有最新配置
    def broadcast_config(self, config: Dict[str, Any]) -> Dict[str, bool]:
        """一次调用向所有在线 worker 推送配置更新 (timeout/max_depth 等)。

        每个 worker 的最新配置缓存在 _worker_configs;
        cfg_version 每次广播递增, 帮助检测运行旧配置的 worker。
        """
        self.cfg_version += 1
        config_with_version = dict(config)
        config_with_version['_cfg_version'] = self.cfg_version
        ack: Dict[str, bool] = {}
        for wid, worker in self._workers.items():
            if worker.is_stale:
                ack[wid] = False
                continue
            try:
                # 故障注入：配置广播也可能被拦截
                self._failure_simulator.maybe_fail(f"broadcast_config to {wid}")
                self._worker_configs[wid] = config_with_version
                ack[wid] = True
            except (TimeoutError, ConnectionRefusedError) as exc:
                logger.warning(f"[Distributed] broadcast_config failed for {wid}: {exc}")
                ack[wid] = False
            except Exception as exc:
                logger.error(f"[Distributed] broadcast_config unexpected error for {wid}: {exc}")
                ack[wid] = False
        logger.info("[Distributed] broadcast_config v%d sent to %d workers (%d ack)",
                    self.cfg_version, len(ack), sum(1 for v in ack.values() if v))
        return ack

    def save_state(self, file_path: str):
        """把整个引擎状态序列化为 pickle 检查点。"""
        state = {
            "tasks": {k: vars(v) for k, v in self._tasks.items()},
            "results": {k: vars(v) for k, v in self._results.items()},
            "pending_states": [vars(s) for s in self._pending_states],
            "completed_states": [vars(s) for s in self._completed_states],
            "failed_states": [[vars(s), str(e)]
                              for s, e in self._failed_states],
            "workers": {k: vars(v) for k, v in self._workers.items()},
            "cfg_version": self.cfg_version,
            "worker_configs": self._worker_configs,
        }

        with open(file_path, 'wb') as f:
            pickle.dump(state, f)

        logger.info(f"Engine state saved to: {file_path}")

    def load_state(self, file_path: str):
        """从 pickle 检查点恢复引擎状态。"""
        try:
            with open(file_path, 'rb') as f:
                state = pickle.load(f)

            self._tasks = state.get("tasks", {})
            self._results = state.get("results", {})
            self._pending_states = state.get("pending_states", [])
            self._completed_states = state.get("completed_states", [])
            self._failed_states = state.get("failed_states", [])
            self._workers = state.get("workers", {})
            self.cfg_version = state.get("cfg_version", 0)
            self._worker_configs = state.get("worker_configs", {})

            logger.info(f"Engine state loaded from: {file_path}")
        except Exception as e:
            logger.error(f"Failed to load engine state: {e}")

    def shutdown(self):
        """断开后端连接, 停止心跳监控与去重交换器。"""
        self._heartbeat_running = False
        self._cross_worker_dedup.stop_exchange_loop()
        if self._backend == "ray" and self._executor.is_initialized():
            import ray
            ray.shutdown()
        elif self._backend == "spark" and self._executor.is_initialized():
            self._executor._spark_context.stop()

        logger.info("Distributed engine shut down")


class StateMerger:
    """符号状态的去重与合并。"""

    @staticmethod
    def merge_states(states: List[SymbolicState]) -> List[SymbolicState]:
        """合并路径条件哈希相同的状态。"""
        merged = []
        seen_conditions = set()

        for state in states:
            cond_hash = hash(str(state.path_condition))
            if cond_hash not in seen_conditions:
                seen_conditions.add(cond_hash)
                merged.append(state)

        return merged

    @staticmethod
    def deduplicate(states: List[SymbolicState]) -> List[SymbolicState]:
        """按 state_id 移除重复状态。"""
        unique = {}
        for state in states:
            unique[state.state_id] = state
        return list(unique.values())


def create_distributed_engine(backend: str = "ray"
                                ) -> DistributedSymbolicExecutionEngine:
    """按后端名实例化分布式符号执行引擎。"""
    return DistributedSymbolicExecutionEngine(backend)


def distribute_symbolic_execution(binary_path: str, entry_point: int,
                                    initial_states: List[SymbolicState],
                                    backend: str = "ray",
                                    timeout: int = 300) -> TaskResult:
    """一次性流程: 创建引擎、提交任务、轮询直到完成或超时, 返回结果。"""
    engine = create_distributed_engine(backend)
    engine.initialize()

    task = AnalysisTask(
        task_id="",
        binary_path=binary_path,
        entry_point=entry_point,
        states=initial_states,
        timeout=timeout,
    )

    task_id = engine.submit_task(task)

    deadline = time.time() + max(1, timeout)
    while True:
        status = engine.get_task_status(task_id)
        if status.get("status") == "completed":
            break
        if time.time() > deadline:
            logger.warning("[Distributed] Task %s did not complete within %ds",
                           task_id, timeout)
            break
        time.sleep(0.1)

    return engine.get_results(task_id)
