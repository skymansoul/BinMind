# 2026-07-18

"""Fuzzing核心数据结构 -- Seed/FuzzConfig/FuzzResult/CorpusStats."""

import hashlib
import time
from dataclasses import dataclass, field
from uuid import uuid4

# ---- 种子对象 ----
# 代表一次模糊测试的输入，携带覆盖率、适应度、能量等元信息
@dataclass
class Seed:
    id: str = field(default_factory=lambda: uuid4().hex)
    data: bytes = b""
    fitness: float = 0.0
    energy: float = 1.0           # AFL式功率调度
    coverage: set = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    parent_id: str | None = None
    generation: int = 0
    metadata: dict = field(default_factory=dict)
    mutation_count: int = 0

    def age(self) -> float:
        return time.time() - self.created_at

    def __hash__(self) -> int:
        return hash(self.id)

# ---- 模糊测试配置 ----
@dataclass
class FuzzConfig:
    target_path: str = ""
    target_args: list[str] = field(default_factory=list)
    work_dir: str = "/tmp/fuzz_work"
    timeout_ms: int = 1000
    memory_limit_mb: int = 2048
    dict_path: str | None = None       # AFL字典路径
    seed_dir: str | None = None
    output_dir: str = "./fuzz_out"
    max_seeds: int = 10000
    mutation_ratio: float = 0.5
    deterministic_steps: bool = True
    use_cmplog: bool = False            # CmpLog插桩开关


# ---- 模糊测试结果 ----
@dataclass
class FuzzResult:
    seed_id: str = ""
    exit_code: int = 0
    signal: int | None = None
    execution_time_ms: float = 0.0
    stdout: bytes = b""
    stderr: bytes = b""
    coverage: set = field(default_factory=set)
    is_crash: bool = False
    is_hang: bool = False
    classification: str = "normal"   # normal / crash / hang / unique_crash
    crash_hash: str | None = None


# ---- 语料库统计 ----
@dataclass
class CorpusStats:
    total_seeds: int = 0
    total_executions: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    edges_covered: int = 0
    total_coverage: int = 0          # 位图非零字节计数
    cycles_completed: int = 0
    execs_per_second: float = 0.0
    uptime_seconds: float = 0.0
    last_new_find: float = field(default_factory=time.time)


# ===== 辅助函数 =====

def compute_crash_hash(seed_data: bytes, crash_signal: int, crash_addr: int | None) -> str:
    """基于SHA256的崩溃去重哈希 -- 种子数据+信号+地址 """
    _h = hashlib.sha256()
    _h.update(seed_data)
    _h.update(str(crash_signal).encode())
    if crash_addr is not None:
        _h.update(crash_addr.to_bytes(8, "little"))
    return _h.hexdigest()[:16]


# //// 退出分类器 ////
# 根据退出码和信号判定执行结果的类别
_SIGNAL_CRASH_MAP = frozenset({
    4,   # SIGILL
    6,   # SIGABRT
    8,   # SIGFPE
    11,  # SIGSEGV
})


def classify_exit(exit_code: int, signal_num: int, timeout: bool) -> tuple[str, str]:
    """返回 (分类标签, 描述文字)

    分类规则：
    - 超时 → hang
    - 有崩溃信号(SIGILL/SIGABRT/SIGFPE/SIGSEGV) → crash
    - 其他情况 → normal
    """
    if timeout:
        return ("hang", "execution timed out")
    if signal_num in _SIGNAL_CRASH_MAP:
        return ("crash", f"signal {signal_num}")
    # 某些程序通过 exit code 表达崩溃，但这里不过度猜测
    if exit_code < 0:
        return ("crash", f"negative exit code {exit_code}")
    return ("normal", "clean exit")


# //// 简单的数据变异原语 ////
# 这些函数可被 mutation 引擎直接调用
def _flip_bit(data: bytearray, pos: int, bit: int) -> None:
    data[pos] ^= (1 << bit)


def _flip_byte(data: bytearray, pos: int) -> None:
    data[pos] ^= 0xFF


def _arith_inc(data: bytearray, pos: int, delta: int = 1) -> None:
    _v = data[pos] + delta
    data[pos] = _v & 0xFF


def _arith_dec(data: bytearray, pos: int, delta: int = 1) -> None:
    _v = data[pos] - delta
    data[pos] = _v & 0xFF


def _interesting_bytes(data: bytearray, pos: int) -> list[int]:
    """在指定位置注入有趣的边界值"""
    _interesting = [0, 1, 0x7F, 0x80, 0xFF]
    _orig = data[pos]
    return [_v for _v in _interesting if _v != _orig]


def _insert_bytes(data: bytearray, pos: int, insertion: bytes) -> bytearray:
    _new = bytearray(len(data) + len(insertion))
    _new[:pos] = data[:pos]
    _new[pos:pos + len(insertion)] = insertion
    _new[pos + len(insertion):] = data[pos:]
    return _new


def _delete_bytes(data: bytearray, pos: int, length: int) -> bytearray:
    if pos + length > len(data):
        length = len(data) - pos
    return data[:pos] + data[pos + length:]


def _splice(data_a: bytes, data_b: bytes) -> bytes:
    """两个种子交叉拼接"""
    if not data_a or not data_b:
        return data_a or data_b
    _split = len(data_a) // 2
    return data_a[:_split] + data_b[_split:]


# //// 确定性变异阶段 ////
def deterministic_stage(seed: Seed, config: FuzzConfig) -> list[bytes]:
    """AFL风格的确定性子阶段 -- bitflip/byteflip/arithmetic/interesting

    不依赖随机数，systematic地遍历所有可能位置。
    """
    _results: list[bytes] = []
    _orig = bytearray(seed.data)
    _l = len(_orig)

    if _l == 0:
        return _results

    # ---- bitflip 1/1 ----
    for _pos in range(min(_l, 2048)):
        for _bit in range(8):
            _cpy = bytearray(_orig)
            _flip_bit(_cpy, _pos, _bit)
            _results.append(bytes(_cpy))

    # ---- byteflip 1/1 ----
    for _pos in range(min(_l, 2048)):
        _cpy = bytearray(_orig)
        _flip_byte(_cpy, _pos)
        _results.append(bytes(_cpy))

    # ---- arithmetic inc/dec ----
    for _pos in range(min(_l, 1024)):
        for _delta in (1, 35):
            _cpy_inc = bytearray(_orig)
            _arith_inc(_cpy_inc, _pos, _delta)
            _results.append(bytes(_cpy_inc))
            _cpy_dec = bytearray(_orig)
            _arith_dec(_cpy_dec, _pos, _delta)
            _results.append(bytes(_cpy_dec))

    # ---- interesting values 8-bit ----
    for _pos in range(min(_l, 1024)):
        _interesting = _interesting_bytes(_orig, _pos)
        for _v in _interesting:
            _cpy = bytearray(_orig)
            _cpy[_pos] = _v
            _results.append(bytes(_cpy))

    return _results


# //// 非确定性变异（havoc阶段）////
def havoc_stage(seed: Seed, config: FuzzConfig, rounds: int = 32) -> list[bytes]:
    """随机变异 -- 随机选择操作叠加多次"""
    import random

    _results: list[bytes] = []
    _l = len(seed.data)
    if _l == 0:
        return _results

    _actions = [
        lambda d, r: _flip_bit(d, r.randint(0, len(d) - 1), r.randint(0, 7)),
        lambda d, r: _flip_byte(d, r.randint(0, len(d) - 1)),
        lambda d, r: _arith_inc(d, r.randint(0, len(d) - 1), r.randint(1, 35)),
        lambda d, r: _arith_dec(d, r.randint(0, len(d) - 1), r.randint(1, 35)),
    ]

    for _ in range(rounds):
        _cpy = bytearray(seed.data)
        _rng = random.Random()
        # 随机叠加多层变异
        _stack = random.randint(1, 16)
        for __ in range(_stack):
            _action = random.choice(_actions)
            _action(_cpy, _rng)
        _results.append(bytes(_cpy))

    # ---- 偶尔做splice ----
    if len(_results) > 1 and random.random() < 0.05:
        _a = random.choice(_results)
        _b = random.choice(_results)
        _results.append(_splice(_a, _b))

    return _results


# //// 字典辅助变异 ////
def mutate_with_dict(seed: Seed, dictionary: list[bytes], max_inserts: int = 5) -> list[bytes]:
    """利用字典中的token进行插入/覆写变异"""
    import random

    if not dictionary or len(seed.data) == 0:
        return [seed.data]

    _results: list[bytes] = []
    _orig = bytearray(seed.data)
    _l = len(_orig)

    for _token in dictionary[:max_inserts]:
        _tlen = len(_token)
        if _tlen == 0:
            continue

        # 随机位置插入token
        _pos = random.randint(0, _l)
        _results.append(bytes(_insert_bytes(_orig, _pos, _token)))

        # 随机位置覆写
        if _pos + _tlen <= _l:
            _cpy = bytearray(_orig)
            _cpy[_pos:_pos + _tlen] = _token
            _results.append(bytes(_cpy))

    return _results
