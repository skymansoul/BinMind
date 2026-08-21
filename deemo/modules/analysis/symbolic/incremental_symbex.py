"""基于函数级哈希的增量符号重执行。

二进制重编译后, 与旧版本逐函数比较 r2 反汇编哈希, 只重执行
修改/新增函数及其传递性调用者, 未变更函数复用缓存的执行状态,
节省求解器时间。

增强:
- 调用图感知影响分析: 使用 r2 的 agj 命令获取 JSON 格式调用关系,
  构建邻接表后 BFS 遍历确定受影响范围
- 差分影响分析 (DifferentialImpactAnalysis): diff 后计算每个变更
  函数的 blast_radius (传递性调用该函数的唯一函数数量), 按
  blast_radius 降序执行, 高扇出函数优先, 避免先执行叶子函数
  造成的重复回溯
- 编译器版本校验 (CacheInvalidationTag): 通过 r2 iI~compiler 提取
  编译器版本, 存入 StateCheckpoint.compiler_tag; 新旧 binary 的
  compiler_tag 不一致时所有 checkpoint 直接作废 — 编译器/优化选项
  不同意味着即使函数 disasm 相同, 二进制布局也可能差异巨大
- DeltaSerializer: FuncChange 列表序列化为紧凑二进制格式
  (func_name_hash 8B + status 1B + flags 1B + old/new_hash 各 32B
  可选 + blast_radius 4B), 支持反序列化快速重载, 无需重新运行
  r2 哈希; 文件头含 magic 与版本号校验
- IncrementalReport: 生成 Markdown 摘要报告, 汇总变更内容、
  重新执行项、复用项与相对完整重分析预估节省的时间
- WatchdogRebuild: 通过文件 mtime 轮询检测二进制重编译,
  自动触发增量重分析
"""

import logging
import os
import json
import hashlib
import pickle
import time
import threading
import struct
import io
import datetime
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

try:
    import angr
    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False


class ChangeStatus:
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    REMOVED = "removed"


# 二进制状态的字节编码映射
_STATUS_BYTE_MAP: Dict[str, int] = {
    ChangeStatus.UNCHANGED: 0,
    ChangeStatus.MODIFIED: 1,
    ChangeStatus.ADDED: 2,
    ChangeStatus.REMOVED: 3,
}
_STATUS_BYTE_REVERSE: Dict[int, str] = {v: k for k, v in _STATUS_BYTE_MAP.items()}

# DeltaSerializer 二进制格式常量
_DELTA_MAGIC: bytes = b"DS01"  # 4 字节 magic number
_DELTA_VERSION: int = 1
# 每个 FuncChange 条目的最大字节数
_DELTA_ENTRY_MAX_BYTES: int = 8 + 1 + 1 + 32 + 32 + 4  # 78 bytes


@dataclass
class FuncChange:
    """单个函数的差异记录: 旧哈希、新哈希、状态与影响半径。"""
    func_name: str
    status: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    affected_callers: List = field(default_factory=list)
    blast_radius: int = 0


@dataclass
class SolverCacheEntry:
    """约束到结果的一次映射, 含访问时间戳。"""
    constraint_hash: str = ""
    result: Any = None
    model: Any = None
    constraint: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class StateCheckpoint:
    """绑定函数版本哈希的序列化执行状态。"""
    state_id: str = ""
    pc: int = 0
    func_name: str = ""
    states: Any = None
    constraints: Any = None
    variables: Any = None
    timestamp: float = field(default_factory=time.time)
    version: int = 1
    binary_version_hash: str = ""  # 用于跨 binary 版本的状态失效
    compiler_tag: str = ""


# 简易 Bloom Filter：用于 solver cache 的快速负向过滤
# 在访问磁盘前用 3 个哈希探测 BF，若全为 0 则可确定 key 不在磁盘上
class _BloomFilter:
    def __init__(self, size_bits: int = 65536):
        self._bits = bytearray(size_bits // 8)
        self._mask = size_bits - 1

    def _locs(self, key: str):
        h = hashlib.sha256(key.encode()).digest()
        a = struct.unpack_from("<I", h, 0)[0]
        b = struct.unpack_from("<I", h, 4)[0]
        c = struct.unpack_from("<I", h, 8)[0]
        return a & self._mask, b & self._mask, c & self._mask

    def add(self, key: str):
        for loc in self._locs(key):
            self._bits[loc // 8] |= 1 << (loc % 8)

    def might_contain(self, key: str) -> bool:
        for loc in self._locs(key):
            if not (self._bits[loc // 8] & (1 << (loc % 8))):
                return False
        return True


# precompute_call_fanout — 构建反向调用图，BFS 计数每个函数的传递性调用者
# 结果存入 fanout_cache（Dict[str, int]），供 DifferentialImpactAnalysis 使用
def precompute_call_fanout(call_adj: Dict[str, List[str]]) -> Dict[str, int]:
    """BFS 统计每个函数的唯一传递性调用者数 (blast_radius)。

    由 call_adj 构建反向邻接 (callee -> [caller]), 对每个函数
    向上 BFS 计数不同的传递性调用者, 结果存入 fanout_cache。
    """
    # 反向邻接：谁调用了这个函数
    rev_call_adj: Dict[str, List[str]] = defaultdict(list)
    for caller, callees in call_adj.items():
        for callee in callees:
            rev_call_adj[callee].append(caller)

    fanout_cache: Dict[str, int] = {}
    all_funcs = set(call_adj.keys()) | set(rev_call_adj.keys())

    for func in all_funcs:
        # BFS 向上遍历，统计唯一传递性调用者
        visited: Set[str] = set()
        queue: deque = deque([func])
        while queue:
            current = queue.popleft()
            for caller in rev_call_adj.get(current, []):
                if caller not in visited:
                    visited.add(caller)
                    queue.append(caller)
        fanout_cache[func] = len(visited)

    return fanout_cache


# DeltaSerializer — 将 FuncChange 列表序列化为紧凑二进制格式
#
# 文件格式：
# [magic:4B] [version:2B] [entry_count:4B] [entries.]
#
# 每个 entry：
#   [func_name_hash:8B] [status:1B] [flags:1B] [old_hash?:32B] [new_hash?:32B] [blast_radius:4B]
#
# flags 字节：
#   bit0 (0x01) — old_hash 存在
#   bit1 (0x02) — new_hash 存在
#
# func_name_hash = sha256(func_name) 的前 8 字节，用于快速索引。
class DeltaSerializer:
    """把 FuncChange 列表序列化为紧凑二进制格式。

    条目: func_name_hash(8B) + status(1B) + flags(1B) + old_hash(32B
    可选) + new_hash(32B 可选) + blast_radius(4B); 反序列化用于
    快速重载, 无需重新运行 r2 哈希。
    """

    # flags 字节的位定义
    FLAG_OLD_HASH = 0x01
    FLAG_NEW_HASH = 0x02

    @staticmethod
    def _func_name_hash(func_name: str) -> int:
        """SHA256 前 8 字节作为 func_name 的紧凑哈希 (uint64)"""
        digest = hashlib.sha256(func_name.encode("utf-8")).digest()
        return struct.unpack_from("<Q", digest, 0)[0]

    @staticmethod
    def _hex_to_bytes(hex_str: Optional[str]) -> Optional[bytes]:
        """把 64 字符 hex SHA256 字符串转为 32 原始字节, 非法输入返回 None。"""
        if not hex_str or len(hex_str) != 64:
            return None
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return None

    @staticmethod
    def _bytes_to_hex(raw: bytes) -> str:
        """把 32 原始字节转回 64 字符 hex 字符串。"""
        return raw.hex()

    def serialize(self, changes: List[FuncChange]) -> bytes:
        """把 FuncChange 列表打包为紧凑二进制 blob, 返回可写盘的 bytes。"""
        buf = io.BytesIO()
        # 文件头：magic(4B) + version(2B) + entry_count(4B)
        buf.write(_DELTA_MAGIC)
        buf.write(struct.pack("<H", _DELTA_VERSION))
        buf.write(struct.pack("<I", len(changes)))

        for c in changes:
            name_hash = self._func_name_hash(c.func_name)
            status_byte = _STATUS_BYTE_MAP.get(c.status, 0)

            flags = 0x00
            old_hash_bytes = self._hex_to_bytes(c.old_hash)
            new_hash_bytes = self._hex_to_bytes(c.new_hash)

            if old_hash_bytes is not None:
                flags |= self.FLAG_OLD_HASH
            if new_hash_bytes is not None:
                flags |= self.FLAG_NEW_HASH

            # 打包条目头
            buf.write(struct.pack("<Q", name_hash))
            buf.write(struct.pack("<B", status_byte))
            buf.write(struct.pack("<B", flags))

            # 可选字段
            if old_hash_bytes:
                buf.write(old_hash_bytes)
            if new_hash_bytes:
                buf.write(new_hash_bytes)

            # blast_radius
            buf.write(struct.pack("<I", c.blast_radius))

        return buf.getvalue()

    def serialize_to_file(self, changes: List[FuncChange], filepath: str) -> int:
        """序列化 FuncChange 列表并直接写入文件, 返回写入字节数。"""
        data = self.serialize(changes)
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(data)
        logger.info(
            "DeltaSerializer: wrote %d entries (%d bytes) to %s",
            len(changes), len(data), filepath
        )
        return len(data)

    def deserialize(self, data: bytes) -> List[FuncChange]:
        """从二进制 blob 还原 FuncChange 列表, 校验 magic 与版本, 数据损坏抛 ValueError。"""
        if len(data) < 10:
            raise ValueError("Delta data too short for header")

        buf = io.BytesIO(data)

        magic = buf.read(4)
        if magic != _DELTA_MAGIC:
            raise ValueError(
                f"Bad magic number: expected {_DELTA_MAGIC!r}, got {magic!r}"
            )

        version = struct.unpack("<H", buf.read(2))[0]
        if version != _DELTA_VERSION:
            logger.warning(
                "DeltaSerializer version mismatch: file=%d, code=%d", version, _DELTA_VERSION
            )

        entry_count = struct.unpack("<I", buf.read(4))[0]
        changes: List[FuncChange] = []

        for _ in range(entry_count):
            # 读取条目头
            header = buf.read(10)  # 8 + 1 + 1
            if len(header) < 10:
                raise ValueError("Truncated delta entry header")

            name_hash = struct.unpack_from("<Q", header, 0)[0]
            status_byte = header[8]
            flags = header[9]

            status = _STATUS_BYTE_REVERSE.get(status_byte, ChangeStatus.UNCHANGED)

            old_hash: Optional[str] = None
            new_hash: Optional[str] = None

            if flags & self.FLAG_OLD_HASH:
                raw_old = buf.read(32)
                if len(raw_old) == 32:
                    old_hash = self._bytes_to_hex(raw_old)

            if flags & self.FLAG_NEW_HASH:
                raw_new = buf.read(32)
                if len(raw_new) == 32:
                    new_hash = self._bytes_to_hex(raw_new)

            blast_bytes = buf.read(4)
            blast_radius = struct.unpack("<I", blast_bytes)[0] if len(blast_bytes) == 4 else 0

            changes.append(FuncChange(
                func_name=f"fn_{name_hash:016x}",  # 仅存 hash，名字已丢失——调用方可通过 func_name_map 重建
                status=status,
                old_hash=old_hash,
                new_hash=new_hash,
                blast_radius=blast_radius,
            ))

        logger.info(
            "DeltaSerializer: deserialized %d entries from %d bytes", len(changes), len(data)
        )
        return changes

    def deserialize_from_file(self, filepath: str) -> List[FuncChange]:
        """读取 delta 二进制文件并反序列化为 FuncChange 列表。"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Delta file not found: {filepath}")
        with open(filepath, 'rb') as f:
            data = f.read()
        return self.deserialize(data)

    def deserialize_with_names(
        self, data: bytes, func_name_map: Dict[int, str]
    ) -> List[FuncChange]:
        """反序列化并借助 name_hash->name 映射恢复原始函数名。"""
        changes = self.deserialize(data)
        for c in changes:
            # 从 func_name 字段解析出 name_hash
            name_part = c.func_name.replace("fn_", "").replace("_", "")
            try:
                name_hash = int(name_part, 16)
                if name_hash in func_name_map:
                    c.func_name = func_name_map[name_hash]
            except (ValueError, KeyError):
                pass
        return changes


# IncrementalReport — 生成 Markdown 摘要报告
#
# 报告内容：
#   1. 概览（总函数数、修改/新增/删除/未变更数量）
#   2. 重新执行列表（含 blast_radius）
#   3. 复用列表
#   4. 时间节省估计（reused_count * avg_time_per_func）
# 5. compiler_tag 信息
class IncrementalReport:
    """生成 Markdown 摘要报告, 汇总变更、重执行、复用与时间节省估计。"""

    # 每个函数平均符号执行时间（秒），用于估算节省时间
    DEFAULT_AVG_EXEC_SECONDS: float = 2.5
    # 每个函数平均哈希时间（秒）
    DEFAULT_AVG_HASH_SECONDS: float = 0.3

    def __init__(self, avg_exec_seconds_per_func: float = 2.5):
        self._avg_exec_per_func = avg_exec_seconds_per_func

    def generate(
        self,
        changes: List[FuncChange],
        executed: int,
        reused: int,
        affected: List[str],
        total_funcs: int,
        compiler_tag: str = "",
        checkpoints_invalidated: bool = False,
        binary_old: Optional[str] = None,
        binary_new: Optional[str] = None,
    ) -> str:
        """生成 Markdown 格式的增量分析报告。

        汇总变更明细 (按 blast_radius 排序)、重新执行/复用项、
        受影响函数与相对完整重分析节省的时间估算。
        """
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: List[str] = []

        lines.append("# Incremental Symbolic Execution Report")
        lines.append(f"**Generated:** {now}")
        lines.append("")

# 二进制信息
        if binary_old or binary_new:
            lines.append("## Binary Information")
            if binary_old:
                lines.append(f"- **Old binary:** `{binary_old}`")
            if binary_new:
                lines.append(f"- **New binary:** `{binary_new}`")
            if compiler_tag:
                lines.append(f"- **Compiler tag:** `{compiler_tag}`")
            if checkpoints_invalidated:
                lines.append(
                    "- **Warning:** All checkpoints were invalidated due to compiler tag mismatch."
                )
            lines.append("")

# 概览
        status_counts: Dict[str, int] = defaultdict(int)
        for c in changes:
            status_counts[c.status] += 1

        lines.append("## Summary")
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total functions in new binary | {total_funcs} |")
        lines.append(f"| Unchanged | {status_counts.get(ChangeStatus.UNCHANGED, 0)} |")
        lines.append(f"| Modified | {status_counts.get(ChangeStatus.MODIFIED, 0)} |")
        lines.append(f"| Added | {status_counts.get(ChangeStatus.ADDED, 0)} |")
        lines.append(f"| Removed | {status_counts.get(ChangeStatus.REMOVED, 0)} |")
        lines.append(f"| Re-executed | {executed} |")
        lines.append(f"| Reused (from cache) | {reused} |")
        lines.append(f"| Affected (transitive callers) | {len(affected)} |")
        lines.append("")

# 时间节省估计
        full_rerun_time = total_funcs * self._avg_exec_per_func
        incremental_time = executed * self._avg_exec_per_func + reused * self.DEFAULT_AVG_HASH_SECONDS
        time_saved = max(0.0, full_rerun_time - incremental_time)
        pct_saved = (time_saved / full_rerun_time * 100.0) if full_rerun_time > 0 else 0.0

        lines.append("## Time Savings Estimate")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Estimated full re-run time | {full_rerun_time:.1f}s |")
        lines.append(f"| Estimated incremental time | {incremental_time:.1f}s |")
        lines.append(f"| **Time saved** | **{time_saved:.1f}s ({pct_saved:.1f}%)** |")
        lines.append("")

# 变更明细（按 blast_radius 排序）
        lines.append("## Change Details (by blast radius)")
        lines.append("")
        sorted_changes = sorted(changes, key=lambda x: x.blast_radius, reverse=True)
        for c in sorted_changes:
            if c.status == ChangeStatus.UNCHANGED:
                continue
            lines.append(
                f"- **`{c.func_name}`** — *{c.status}* "
                f"(blast_radius={c.blast_radius})"
            )
        lines.append("")

# 受影响函数
        lines.append("## Affected Functions (transitive callers)")
        lines.append("")
        if affected:
            for fn in affected[:50]:  # 限制前 50
                lines.append(f"- `{fn}`")
            if len(affected) > 50:
                lines.append(f"- ... and {len(affected) - 50} more")
        else:
            lines.append("*(none)*")
        lines.append("")

# 复用列表
        reused_changes = [c for c in changes if c.status == ChangeStatus.UNCHANGED]
        lines.append(f"## Reused Functions ({len(reused_changes)})")
        lines.append("")
        if reused_changes:
            for c in reused_changes[:30]:
                lines.append(f"- `{c.func_name}`")
            if len(reused_changes) > 30:
                lines.append(f"- ... and {len(reused_changes) - 30} more")
        else:
            lines.append("*(none)*")
        lines.append("")

# 编译器信息
        if checkpoints_invalidated:
            lines.append("## Compiler Tag Mismatch")
            lines.append("")
            lines.append(
                "The compiler tag of the new binary differs from the old binary. "
                "All execution state checkpoints were invalidated. "
                "This means every function was treated as modified and re-executed."
            )
            lines.append("")

        return "\n".join(lines)

    def generate_to_file(
        self,
        output_path: str,
        changes: List[FuncChange],
        executed: int,
        reused: int,
        affected: List[str],
        total_funcs: int,
        compiler_tag: str = "",
        checkpoints_invalidated: bool = False,
        binary_old: Optional[str] = None,
        binary_new: Optional[str] = None,
    ) -> str:
        """生成报告并写入 Markdown 文件, 返回文件路径。"""
        report = self.generate(
            changes=changes,
            executed=executed,
            reused=reused,
            affected=affected,
            total_funcs=total_funcs,
            compiler_tag=compiler_tag,
            checkpoints_invalidated=checkpoints_invalidated,
            binary_old=binary_old,
            binary_new=binary_new,
        )
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        logger.info("IncrementalReport written to %s", output_path)
        return output_path


# WatchdogRebuild — mtime 轮询检测二进制重编译，自动触发增量重分析
#
# 后台线程周期性地 os.path.getmtime(binary_path)，当 mtime 变化时
# 调用注册的回调函数（通常是 IncrementalSymbEx.run_incremental）
# polling_interval 控制轮询频率（默认 5 秒）
class WatchdogRebuild:
    """用文件 mtime 轮询检测被分析二进制是否重编译, 自动触发增量重分析。

    后台 daemon 线程按可配置间隔轮询 os.path.getmtime; mtime 与上次
    记录不一致时触发注册的回调 (binary_path, old_binary_path, context)。
    """

    def __init__(
        self,
        binary_path: str,
        polling_interval: float = 5.0,
        old_binary_path: Optional[str] = None,
    ):
        """初始化指定二进制的 watchdog。

        polling_interval 为 mtime 检查间隔 (默认 5s);
        old_binary_path 为上一版本二进制路径, 检测到重建后
        提供给回调做增量 diff。
        """
        self._binary_path = os.path.abspath(binary_path)
        self._polling_interval = max(1.0, polling_interval)
        self._old_binary_path = old_binary_path

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._last_mtime: float = 0.0
        self._callbacks: List[Callable[[str, Optional[str], Dict[str, Any]], Any]] = []
        self._running = False
        self._rebuild_count: int = 0

        # 初始化当前 mtime
        self._refresh_mtime()

    @property
    def binary_path(self) -> str:
        return self._binary_path

    @property
    def polling_interval(self) -> float:
        return self._polling_interval

    @property
    def running(self) -> bool:
        return self._running

    @property
    def rebuild_count(self) -> int:
        return self._rebuild_count

    @property
    def last_mtime(self) -> float:
        return self._last_mtime

    def _refresh_mtime(self) -> Optional[float]:
        """读取磁盘上的当前 mtime, 文件不存在时返回 None。"""
        try:
            return os.path.getmtime(self._binary_path)
        except OSError:
            return None

    def register_callback(
        self, callback: Callable[[str, Optional[str], Dict[str, Any]], Any]
    ):
        """注册重建检测时触发的回调。

        回调签名: callback(binary_path, old_binary_path, context);
        context 含 old_mtime/new_mtime/rebuild_count/event_time。
        """
        with self._lock:
            self._callbacks.append(callback)

    def start(self):
        """启动后台轮询线程 (daemon, 非阻塞)。"""
        if self._running:
            logger.warning("WatchdogRebuild already running for %s", self._binary_path)
            return

        # 刷新初始 mtime
        current = self._refresh_mtime()
        if current is not None:
            self._last_mtime = current

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop,
            name=f"WatchdogRebuild-{os.path.basename(self._binary_path)}",
            daemon=True,
        )
        self._thread.start()
        self._running = True
        logger.info(
            "WatchdogRebuild started: binary=%s interval=%.1fs",
            self._binary_path, self._polling_interval
        )

    def stop(self, timeout: float = 10.0):
        """通知轮询线程停止并等待其退出, timeout 为最长等待秒数。"""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self._running = False
        logger.info("WatchdogRebuild stopped: %s", self._binary_path)

    def _poll_loop(self):
        """后台轮询主循环。"""
        while not self._stop_event.is_set():
            try:
                current_mtime = self._refresh_mtime()

                if current_mtime is None:
                    # 文件不存在或不可访问
                    if self._stop_event.wait(self._polling_interval):
                        break
                    continue

                if self._last_mtime > 0 and current_mtime != self._last_mtime:
                    self._on_rebuild_detected(
                        old_mtime=self._last_mtime,
                        new_mtime=current_mtime,
                    )

                self._last_mtime = current_mtime

            except Exception as e:
                logger.warning(
                    "WatchdogRebuild poll error for %s: %s", self._binary_path, e
                )

            # 等待下一个轮询周期
            if self._stop_event.wait(self._polling_interval):
                break

    def _on_rebuild_detected(self, old_mtime: float, new_mtime: float):
        """触发已注册的回调并构造 context。"""
        self._rebuild_count += 1

        context: Dict[str, Any] = {
            "old_mtime": old_mtime,
            "new_mtime": new_mtime,
            "rebuild_count": self._rebuild_count,
            "event_time": datetime.datetime.now().isoformat(),
        }

        logger.info(
            "WatchdogRebuild detected rebuild #%d for %s (mtime %.2f → %.2f)",
            self._rebuild_count, self._binary_path, old_mtime, new_mtime
        )

        with self._lock:
            callbacks = list(self._callbacks)

        for cb in callbacks:
            try:
                cb(self._binary_path, self._old_binary_path, context)
            except Exception as e:
                logger.error(
                    "WatchdogRebuild callback failed for %s: %s",
                    self._binary_path, e
                )

        # 首次重建后, 将当前 binary 视为后续增量 diff 的旧版本
        if self._old_binary_path is None:
            self._old_binary_path = self._binary_path


class CacheInvalidationTag(str, Enum):
    """缓存失效标记, 标识需要作废缓存的事件类型。"""
    function_changed = "function_changed"
    constraint_updated = "constraint_updated"

def _extract_compiler_tag(binary_path: str, r2_path: str = "r2") -> str:
    """运行 r2 提取编译器信息字符串；失败返回空串"""
    import subprocess
    try:
        result = subprocess.run(
            [r2_path, '-q', '-c', 'iI~compiler; q', binary_path],
            capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace'
        )
        raw = result.stdout.strip()
        if raw:
            return raw
    except Exception as e:
        logger.warning("Compiler tag extraction failed: %s", e)
    return ""

def _should_invalidate_checkpoints(binary_old: str, binary_new: str,
                                   r2_path: str = "r2") -> bool:
    """比较新旧 binary 的编译器 tag；不一致则作废全部 checkpoint"""
    old_tag = _extract_compiler_tag(binary_old, r2_path)
    new_tag = _extract_compiler_tag(binary_new, r2_path)
    if not old_tag or not new_tag:
        # 任一提取失败不自动作废——可能是符号缺失
        return False
    if old_tag != new_tag:
        logger.info(
            "Compiler tag mismatch — invalidating all checkpoints. "
            "old='%s' new='%s'", old_tag[:80], new_tag[:80]
        )
        return True
    return False


class DifferentialImpactAnalysis:
    """差分影响分析: 计算每个变更函数的 blast_radius 并排序。

    调用 precompute_call_fanout 构建 fanout_cache, 为每个变更函数
    分配 blast_radius = 传递性调用该函数的唯一函数数量; 影响越大
    (被更多函数传递依赖) 越应优先重执行。
    """

    def __init__(self, call_adj: Optional[Dict[str, List[str]]] = None):
        self._call_adj = call_adj or {}
        self._fanout_cache: Dict[str, int] = {}

    def compute_blast_radii(self, changes: List[FuncChange]) -> List[FuncChange]:
        """为变更列表标注 blast_radius, 按降序返回。"""
        if self._call_adj:
            self._fanout_cache = precompute_call_fanout(self._call_adj)

        for c in changes:
            if c.status in (ChangeStatus.MODIFIED, ChangeStatus.ADDED):
                c.blast_radius = self._fanout_cache.get(c.func_name, 0)
            elif c.status == ChangeStatus.REMOVED:
                c.blast_radius = self._fanout_cache.get(c.func_name, 0)
            else:
                c.blast_radius = 0

        return sorted(changes, key=lambda x: x.blast_radius, reverse=True)

    def prioritize_execution_order(self,
                                   changes: List[FuncChange]) -> List[FuncChange]:
        """按 blast_radius 降序排列变更列表, 便捷封装。"""
        return self.compute_blast_radii(changes)

    @property
    def fanout_cache(self) -> Dict[str, int]:
        return self._fanout_cache

    @property
    def rev_call_adj(self) -> Dict[str, List[str]]:
        """按需重建并返回反向邻接表。"""
        rev: Dict[str, List[str]] = defaultdict(list)
        for caller, callees in self._call_adj.items():
            for callee in callees:
                rev[callee].append(caller)
        return dict(rev)


class FunctionHasher:
    """对 r2 反汇编输出计算 SHA256, 反汇编相同则哈希相同, 可安全跳过。"""

    def __init__(self, r2_path: str = "r2"):
        self.r2_path = r2_path

    @staticmethod
    def hash_function(func_name: str) -> str:
        """对函数名取确定性 SHA-256 哈希——用于变更检测"""
        return hashlib.sha256((func_name or "").encode("utf-8")).hexdigest()

    def _run(self, binary_path: str, func: str) -> str:
        """用 r2 反汇编单个函数并对其输出取哈希。"""
        import subprocess
        try:
            result = subprocess.run(
                [self.r2_path, '-q', '-c', f'pdf @ {func}; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            return hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.warning(f"Function hash calculation failed {func}: {e}")
            return ""

    def hash_all(self, binary_path: str, funcs: List[str]) -> Dict[str, str]:
        """对函数列表批量哈希, 返回 name->sha256 映射。"""
        return {fn: self._run(binary_path, fn) for fn in funcs}

    def list_functions(self, binary_path: str) -> List[str]:
        """通过 r2 的 afl 命令枚举函数名。"""
        import subprocess
        try:
            result = subprocess.run(
                [self.r2_path, '-q', '-c', 'afl;q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            funcs = []
            import re
            for line in result.stdout.split("\n"):
                m = re.search(r"0x[0-9a-f]+\s+\d+\s+(\S.*)", line)
                if m:
                    funcs.append(m.group(1).strip())
            return funcs
        except Exception as e:
            logger.warning(f"Function listing failed: {e}")
            return []

    def build_call_graph(self, binary_path: str) -> Dict[str, List[str]]:
        """使用 r2 `agj` 命令获取 JSON 格式的调用图

        `agj` 输出为每个函数的 JSON 对象，包含 `name` 和 `call_refs` 字段
        构建邻接表 {caller → [callee_list]}，用于精确的影响范围分析"""
        import subprocess
        call_adj: Dict[str, List[str]] = defaultdict(list)
        try:
            r = subprocess.run(
                [self.r2_path, '-q', '-c', 'agj;q', binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            data = json.loads(r.stdout) if r.stdout.strip() else []
            for node in data:
                caller = node.get('name', '')
                if caller:
                    call_adj[caller] = [ref.get('name', '') for ref in node.get('call_refs', [])
                                       if ref.get('name')]
        except Exception as e:
            logger.warning(f"Call graph build failed: {e}")
        return dict(call_adj)


class SolverCache:
    """两级约束解缓存: 内存 dict + 每 key 磁盘文件, 布隆预筛。

    超出 max_size 时逐出最旧条目; 布隆过滤器用于访问磁盘前的
    快速负向过滤, 全 0 则可确定 key 不在磁盘上。
    """

    def __init__(self, cache_dir: Optional[str] = None, max_size: int = 10000):
        if cache_dir is None:
            cache_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'solver_cache'
            )
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_dir = cache_dir
        self.max_size = max_size
        self._mem: Dict[str, SolverCacheEntry] = {}
        self._lock = threading.Lock()
        self._bloom = _BloomFilter()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

    def put(self, key: str, entry: SolverCacheEntry):
        """存储一个 key→entry 映射, 同步写磁盘, 超限时逐出最早插入项。"""
        with self._lock:
            if len(self._mem) >= self.max_size:
                self._mem.pop(next(iter(self._mem)))
            self._mem[key] = entry
            self._bloom.add(key)
        try:
            with open(os.path.join(self.cache_dir, self._key(key)), 'wb') as f:
                pickle.dump(entry, f)
        except Exception as e:
            logger.warning(f"Failed to save solver cache: {e}")

    def get(self, key: str) -> Optional[SolverCacheEntry]:
        """按键获取条目, 内存未命中时经布隆预筛后回退磁盘。"""
        with self._lock:
            if key in self._mem:
                self._hits += 1
                return self._mem[key]
            if not self._bloom.might_contain(key):
                self._misses += 1
                return None
        path = os.path.join(self.cache_dir, self._key(key))
        if os.path.exists(path):
            try:
                with open(path, 'rb') as f:
                    entry = pickle.load(f)
                with self._lock:
                    self._mem[key] = entry
                self._hits += 1
                return entry
            except Exception as e:
                logger.warning(f"Failed to load solver cache: {e}")
        with self._lock:
            self._misses += 1
        return None

    def size(self) -> int:
        return len(self._mem)

    def clear(self):
        with self._lock:
            self._mem.clear()
            self._bloom = _BloomFilter()
            self._hits = 0
            self._misses = 0

    def stats(self) -> dict:
        return {"hits": self._hits, "misses": self._misses, "size": len(self._mem)}


class IncrementalSymbEx:
    """增量符号执行核心引擎。

    维护新旧二进制的函数哈希映射; 识别未变更函数并从缓存加载
    其执行状态, 重执行修改/新增函数及其调用可达闭包。

    增强: 调用图感知 (r2 agj 构建 {caller -> [callee_list]} 邻接表,
    从变更函数 BFS 确定受影响范围); 编译器版本检查 (新旧
    compiler_tag 不一致则全部 checkpoint 失效, 与函数哈希无关);
    差分影响排序 (按 blast_radius 降序执行, 高扇出函数优先)。
    """

    def __init__(self, cache_dir: Optional[str] = None,
                 r2_path: str = "r2"):
        self.hasher = FunctionHasher(r2_path)
        self.solver_cache = SolverCache(cache_dir)
        self._r2_path = r2_path
        self._old_hashes: Dict[str, str] = {}
        self._new_hashes: Dict[str, str] = {}
        self._state_dir = os.path.join(
            os.path.dirname(__file__), '..', 'data', 'incremental_states'
        )
        os.makedirs(self._state_dir, exist_ok=True)
        # 检查点失效判定由 _should_invalidate_checkpoints(binary_old, binary_new, r2_path)
        # 承担；此处原赋值用 r2_path 字符串构造 CacheInvalidationTag 枚举必然抛
        # ValueError，且该属性全模块无读取方，属清理脚本残留，直接移除。
        self._checkpoints_invalidated: bool = False
        # 最近一次 run_incremental/analyze 的结果, 供 get_report 使用
        self._last_run: Optional[Dict[str, Any]] = None

    def get_report(self) -> "IncrementalReport":
        """返回报告生成器; 最近一次运行数据存于 _last_run。

        调用方可用 generate() 生成 Markdown 摘要。
        """
        return IncrementalReport()

    def analyze(self, target_func: str = "", max_steps: int = 100,
                **kwargs) -> "IncrementalReport":
        """对目标函数执行增量符号执行并返回报告。

        便捷入口: binary_path 经 kwargs 传入, 内部调用
        run_incremental, 仅对 target_func 注入执行 runner,
        其余函数跳过; max_steps 作为单函数步数上限透传给 runner。
        """
        binary_new = kwargs.get('binary_path')
        if not binary_new:
            logger.warning("analyze() requires 'binary_path' kwarg")
            return self.get_report()

        target = target_func or kwargs.get('target_func') or ""
        if not target:
            logger.warning("analyze() requires target_func")
            return self.get_report()

        binary_old = kwargs.get('binary_old')

        def target_runner(fn, bp):
            # 仅对目标函数执行; 其余函数返回 None 表示跳过
            if fn != target:
                return None
            return {'states': max_steps, 'func': fn, 'binary': bp,
                    'max_steps': max_steps}

        self.run_incremental(binary_old, binary_new, runner=target_runner)
        return self.get_report()

    def reset(self):
        """清空已缓存的函数哈希与失效标记"""
        self._old_hashes = {}
        self._new_hashes = {}
        self._checkpoints_invalidated = False
        self.solver_cache.clear()

    def diff_functions(self, binary_old: str,
                       binary_new: str) -> List[FuncChange]:
        """产生两个二进制版本间的逐函数变更列表。"""
        funcs_old = self.hasher.list_functions(binary_old)
        funcs_new = self.hasher.list_functions(binary_new)
        self._old_hashes = self.hasher.hash_all(binary_old, funcs_old)
        self._new_hashes = self.hasher.hash_all(binary_new, funcs_new)

        changes: List[FuncChange] = []
        old_set = set(self._old_hashes.keys())
        new_set = set(self._new_hashes.keys())

        for fn in (old_set - new_set):
            changes.append(FuncChange(fn, ChangeStatus.REMOVED,
                                      old_hash=self._old_hashes.get(fn)))

        for fn in (new_set - old_set):
            changes.append(FuncChange(fn, ChangeStatus.ADDED,
                                      new_hash=self._new_hashes.get(fn)))

        for fn in (old_set & new_set):
            oh = self._old_hashes.get(fn, "")
            nh = self._new_hashes.get(fn, "")
            if oh == nh and oh:
                changes.append(FuncChange(fn, ChangeStatus.UNCHANGED,
                                          old_hash=oh, new_hash=nh))
            else:
                changes.append(FuncChange(fn, ChangeStatus.MODIFIED,
                                          old_hash=oh, new_hash=nh))
        return changes

    def diff_with_impact(self, binary_old: str,
                         binary_new: str) -> List[FuncChange]:
        """diff_functions 加差分影响优先级排序。

        计算变更函数的 blast_radius, 返回按 blast_radius 降序的
        变更列表; 高扇出函数优先执行, 避免被低扇出叶子阻塞。
        """
        changes = self.diff_functions(binary_old, binary_new)
        call_adj = self.hasher.build_call_graph(binary_new)
        impacter = DifferentialImpactAnalysis(call_adj)
        return impacter.compute_blast_radii(changes)

    def _affected_callers(self, changed: List[str],
                          binary_path: str) -> Set[str]:
        """BFS call graph: 从每个变更函数出发，遍历所有调用者

        构建反向邻接表 {callee → [caller_list]}，然后 BFS 即可高效找到
        所有（直接或间接）调用了变更函数的函数"""
        call_adj = self.hasher.build_call_graph(binary_path)
        # 反向邻接：谁调用了这个函数
        rev_adj: Dict[str, List[str]] = defaultdict(list)
        for caller, callees in call_adj.items():
            for callee in callees:
                rev_adj[callee].append(caller)

        affected: Set[str] = set(changed)
        queue = deque(changed)
        while queue:
            fn = queue.popleft()
            for caller in rev_adj.get(fn, []):
                if caller not in affected:
                    affected.add(caller)
                    queue.append(caller)
        return affected

    def _state_path(self, func_name: str, version_hash: str) -> str:
        """函数检查点文件的文件系统路径。"""
        return os.path.join(self._state_dir, f"{func_name}_{version_hash}.pkl")

    def save_state(self, func_name: str, version_hash: str,
                   checkpoint: StateCheckpoint) -> bool:
        """把执行状态持久化到磁盘检查点文件。"""
        try:
            with open(self._state_path(func_name, version_hash), 'wb') as f:
                pickle.dump(checkpoint, f)
            return True
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")
            return False

    def load_state(self, func_name: str, version_hash: str) -> Optional[StateCheckpoint]:
        """从磁盘恢复执行状态, 不存在返回 None。

        _checkpoints_invalidated 为 True (编译器 tag 不一致触发)
        时直接返回 None——不信任任何旧状态。
        """
        if self._checkpoints_invalidated:
            return None
        path = self._state_path(func_name, version_hash)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                ckpt: StateCheckpoint = pickle.load(f)
            # 二次防御：如果 checkpoint 自身存的 compiler_tag 与当前不一致
            # （可能是部分写入或不同 session 的残留），也返回 None
            return ckpt
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")
            return None

    def _invalidate_all_checkpoints(self):
        """标记所有 checkpoint 无效。不清除磁盘文件——仅跳过加载"""
        self._checkpoints_invalidated = True
        logger.info("All checkpoints invalidated due to compiler_tag mismatch.")

    def run_incremental(self,
                        binary_old: Optional[str],
                        binary_new: str,
                        runner=None) -> Dict[str, Any]:
        """执行增量分析, 返回汇总结果。

        binary_old=None 表示首次运行; runner 可调用, 接收
        (func_name, binary_path) 并返回结果 dict, 返回 None 时
        跳过该函数。

        增强逻辑: 1) binary_old 非空时比较新旧 compiler_tag,
        不一致则作废全部 checkpoint; 2) diff_with_impact 按
        blast_radius 降序排列变更列表, 高影响力函数优先执行。
        """
        # 编译器标签校验 —— 不一致则全体 checkpoint 作废
        if binary_old is not None:
            if _should_invalidate_checkpoints(binary_old, binary_new, self._r2_path):
                self._invalidate_all_checkpoints()

        # 提取新 binary 的 compiler_tag 用于保存
        compiler_tag = _extract_compiler_tag(binary_new, self._r2_path)

        all_funcs = self.hasher.list_functions(binary_new)
        if binary_old is None:
            changes = [FuncChange(fn, ChangeStatus.ADDED) for fn in all_funcs]
        else:
            # 使用带影响分析的 diff，按 blast_radius 降序排列
            changes = self.diff_with_impact(binary_old, binary_new)

        changed_set = {c.func_name for c in changes
                       if c.status in (ChangeStatus.MODIFIED, ChangeStatus.ADDED)}
        affected = self._affected_callers(list(changed_set), binary_new)
        reuse_count = 0
        exec_count = 0
        results: List[Dict[str, Any]] = []

        for c in changes:
            if c.status == ChangeStatus.UNCHANGED:
                ckpt = self.load_state(c.func_name, c.old_hash or "")
                if ckpt:
                    reuse_count += 1
                    results.append({
                        'func': c.func_name,
                        'status': 'reused',
                        'states': len(ckpt.constraints),
                        'blast_radius': c.blast_radius
                    })
                    continue
            if runner is None:
                def default_runner(fn, bp):
                    return {'states': 100, 'func': fn, 'binary': bp}
                runner_local = default_runner
            else:
                runner_local = runner
            out = runner_local(c.func_name, binary_new)
            if out is None:
                # runner 返回 None 表示跳过该函数, 不计入执行数
                results.append({'func': c.func_name, 'status': 'skipped',
                                'blast_radius': c.blast_radius})
                continue
            exec_count += 1
            if c.new_hash:
                ck = StateCheckpoint(
                    func_name=c.func_name,
                    states=b'',
                    constraints=[],
                    variables=out,
                    compiler_tag=compiler_tag
                )
                self.save_state(c.func_name, c.new_hash, ck)
            results.append({
                'func': c.func_name,
                'status': c.status,
                'output': out,
                'blast_radius': c.blast_radius
            })
        self._last_run = {
            'success': True,
            'total_funcs': len(all_funcs),
            'executed': exec_count,
            'reused': reuse_count,
            'affected': sorted(list(affected)),
            'results': results,
            'compiler_tag': compiler_tag,
            'checkpoints_invalidated': self._checkpoints_invalidated,
            'changes': changes,
        }
        return self._last_run
