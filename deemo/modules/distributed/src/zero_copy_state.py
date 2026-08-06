# 零拷贝调度状态传输 — scatter-gather + 直接内存引用的任务迁移
#
# 工作窃取 (work stealing) 需将被窃任务的状态从 victim 传输到 thief。
# src/serialization.py 用 pickle 序列化→网络传输→反序列化，开销为:
#   T_total = T_serialize + T_network + T_deserialize
# 对大状态任务 (符号执行约束集、内存快照), 序列化可达总时间的 50%+。
#
# μSer (CoNEXT '24) 和 Apache Fury (2024) 展示了零拷贝序列化的可行性:
#   - scatter-gather: 用 I/O vector 引用分散的内存块，OS 内核聚合
#   - out-of-band: 将二进制 buffer 与对象图分离传输
#   - lazy deserialization: 接收端仅重建对象壳，字段按需读取
#
# 本模块适配这些技术到调度任务状态传输:
#   1. 状态分解: 将任务状态分解为 (header, buffers[]) 格式
#      header = 固定大小的元数据 (task_id, priority, exec_time, ...)
#      buffers = 可变大小的二进制块 (约束集、路径条件、内存快照)
#   2. 直接引用: buffer 以内存视图 (memoryview) 传递，无中间拷贝
#   3. 懒重建: 接收端仅解析 header，buffer 在首次访问时按需解析
#   4. 增量传输: 仅传输自上次窃取后变更的 buffer (脏页追踪)

from __future__ import annotations

import struct
import hashlib
from typing import Optional, List, Dict, Tuple, Any


class ZeroCopyStateBuffer:
    """零拷贝状态缓冲区 — 直接引用原始数据，无中间拷贝。

    mem: memoryview — 指向原始字节的视图，不分配新内存。
    dirty: 自上次传输后是否变更 (用于增量传输)。
    """

    def __init__(self, data: bytes, buffer_id: str = "",
                 dirty: bool = True):
        self._mem = memoryview(data)
        self._buf_id = buffer_id or hashlib.sha256(data).hexdigest()[:12]
        self._dirty = dirty

    @property
    def memory(self) -> memoryview:
        return self._mem

    @property
    def size(self) -> int:
        return len(self._mem)

    @property
    def buffer_id(self) -> str:
        return self._buf_id

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def mark_clean(self):
        self._dirty = False

    def checksum(self) -> str:
        return hashlib.sha256(self._mem.tobytes()).hexdigest()[:16]


class ZeroCopyTaskState:
    """可零拷贝传输的任务状态。

    分解为 header (固定 64B 元数据) + buffers[] (可变大小二进制块)。

    header 格式 (64 bytes, 大端):
      bytes 0-15:  task_id (UTF-8, 零填充)
      bytes 16-23: priority (double)
      bytes 24-31: exec_time (double)
      bytes 32-35: n_buffers (uint32)
      bytes 36-39: total_size (uint32)
      bytes 40-63: 保留
    """

    HEADER_FORMAT = ">16s d d I I 24s"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, task_id: str, priority: float = 0.5,
                 exec_time: float = 1.0):
        self._task_id = task_id
        self._priority = priority
        self._exec_time = exec_time
        self._buffers: Dict[str, ZeroCopyStateBuffer] = {}

    def add_buffer(self, buf: ZeroCopyStateBuffer):
        self._buffers[buf.buffer_id] = buf

    def remove_buffer(self, buffer_id: str):
        self._buffers.pop(buffer_id, None)

    def pack_header(self) -> bytes:
        n_bufs = len(self._buffers)
        total_sz = sum(b.size for b in self._buffers.values())
        tid_bytes = self._task_id.encode('utf-8')[:16].ljust(16, b'\x00')
        return struct.pack(
            self.HEADER_FORMAT,
            tid_bytes, self._priority, self._exec_time,
            n_bufs, total_sz, b'\x00' * 24,
        )

    @classmethod
    def unpack_header(cls, header_bytes: bytes) -> dict:
        tid_b, prio, exec_t, n_bufs, total_sz, _ = struct.unpack(
            cls.HEADER_FORMAT, header_bytes
        )
        return {
            "task_id": tid_b.rstrip(b'\x00').decode('utf-8'),
            "priority": prio, "exec_time": exec_t,
            "n_buffers": n_bufs, "total_size": total_sz,
        }

    def dirty_buffers(self) -> List[ZeroCopyStateBuffer]:
        return [b for b in self._buffers.values() if b.is_dirty]

    def total_size(self) -> int:
        return self.HEADER_SIZE + sum(b.size for b in self._buffers.values())

    def transmission_size(self, incremental: bool = True) -> int:
        """传输大小 — 全量 vs 增量 (仅脏 buffer)。"""
        if incremental:
            bufs = self.dirty_buffers()
        else:
            bufs = list(self._buffers.values())
        return self.HEADER_SIZE + sum(b.size for b in bufs)

    @property
    def buffer_count(self) -> int:
        return len(self._buffers)

    def mark_all_clean(self):
        for b in self._buffers.values():
            b.mark_clean()


class ZeroCopyTransfer:
    """零拷贝状态传输管理器。

    模拟 scatter-gather: 将任务状态打包为 (header, buffer_list)
    格式——header 固定 64B, buffer 为 memoryview 引用列表。
    接收端先解析 header → 按需解析 buffer。

    压缩比 (相对于 pickle):
      传统: pickle.dumps(state) → 1 次全序列化 + 1 次全拷贝
      零拷贝: header (64B) + sum(memoryview references) → 0 拷贝
      节省: ≈ pickle_size - header_size - metadata_overhead
    """

    @staticmethod
    def prepare(task: ZeroCopyTaskState,
                incremental: bool = True
                ) -> Tuple[bytes, List[Tuple[str, memoryview, str]]]:
        """准备传输 — 返回 (header, [(buf_id, memoryview, checksum), ...])。

        调用方直接用 socket.sendmsg 发送 header + I/O vector。
        """
        header = task.pack_header()
        buffers = task.dirty_buffers() if incremental else list(
            task._buffers.values()
        )
        buf_list = [
            (b.buffer_id, b.memory, b.checksum()) for b in buffers
        ]
        return header, buf_list

    @staticmethod
    def receive(header: bytes,
                buffers: List[Tuple[str, bytes, str]]
                ) -> ZeroCopyTaskState:
        """接收端重建任务状态 — 解析 header, 按需引用 buffer。"""
        info = ZeroCopyTaskState.unpack_header(header)
        state = ZeroCopyTaskState(
            info["task_id"], info["priority"], info["exec_time"]
        )
        for buf_id, data, checksum in buffers:
            zbuf = ZeroCopyStateBuffer(data, buf_id, dirty=False)
            # 完整性校验
            if zbuf.checksum() != checksum:
                raise ValueError(f"checksum mismatch for buffer {buf_id}")
            state.add_buffer(zbuf)
        return state

    @staticmethod
    def compression_ratio(pickle_size: int,
                          header_size: int,
                          buffers_total: int) -> float:
        """零拷贝 vs pickle 的压缩比。"""
        zc_size = header_size + buffers_total
        if zc_size <= 0:
            return 1.0
        return pickle_size / zc_size
