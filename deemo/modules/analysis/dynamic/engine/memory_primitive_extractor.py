# 2026-07-25
# memory primitive extractor — 从内存 转存 中识别利用原语
# 覆盖三类：任意读、任意写、control-flow hijack
# 参考 Volatility3 的 malfind 插件逻辑，但避免完整的对象模型
import struct
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class MemoryPrimitive:
    kind: str           # arbitrary_read / arbitrary_write / ctrl_flow / info_leak
    address: int
    size: int = 0
    confidence: float = 0.0
    evidence: str = ""
    source_insn: str = ""


class ChunkReader:
    """分块读取大内存 dump，避免一次性加载到内存"""
    def __init__(self, path: str):
        self._f = open(path, "rb")
        self._fsize = self._f.seek(0, 2)
        self._f.seek(0)

    def read(self, offset: int, size: int) -> bytes:
        if offset + size > self._fsize:
            size = self._fsize - offset
        self._f.seek(offset)
        return self._f.read(size)

    def find_pattern(self, pattern: bytes, start: int = 0, max_hits: int = 50) -> List[int]:
        """Boyer-Moore-Hors池 搜索 —— 跨页扫描时比 regex 高效"""
        hits = []
        chunk_sz = 4096 * 256
        pos = start
        plen = len(pattern)
        if plen == 0:
            return hits
        # BMH bad-char table
        bc = {pattern[i]: plen - i - 1 for i in range(plen - 1)}
        while pos < self._fsize - plen and len(hits) < max_hits:
            chunk = self.read(pos, chunk_sz + plen)
            if not chunk:
                break
            i = 0
            while i <= len(chunk) - plen and len(hits) < max_hits:
                j = plen - 1
                while j >= 0 and chunk[i + j] == pattern[j]:
                    j -= 1
                if j < 0:
                    hits.append(pos + i)
                    i += 1
                else:
                    shift = bc.get(chunk[i + plen - 1], plen)
                    i += max(1, shift)
            pos += chunk_sz
        return hits

    @property
    def size(self) -> int:
        return self._fsize

    def close(self):
        self._f.close()


class MemoryPrimitiveExtractor:
    """内存利用原语提取器 — 扫描 dump 找可被利用的内存操作模式"""

    def __init__(self, dump_path: str):
        self.reader = ChunkReader(dump_path)
        self._primitives: List[MemoryPrimitive] = []

    def extract(self) -> List[MemoryPrimitive]:
        self._primitives = []
        self._scan_function_pointers()
        self._scan_saved_return_addresses()
        self._scan_vtable_regions()
        self._scan_heap_metadata()
        self.reader.close()
        return sorted(self._primitives, key=lambda p: -p.confidence)

    def _scan_function_pointers(self):
        """扫描可能的函数指针 —— 指向可执行段的地址"""
        # 简化启发式：找.text 段地址范围，扫描指向该范围的 8 字节对齐数据
        text_start, text_end = self._guess_text_segment()
        if text_start == 0 and text_end == 0:
            return
        pat_end = struct.pack("<Q", text_end)
        pat_start = struct.pack("<Q", text_start)
        # 扫描 8 字节对齐的指针值
        step = 8
        for off in range(0, min(self.reader.size, 2 * 1024 * 1024 * 1024), 4096):
            chunk = self.reader.read(off, 4096)
            if not chunk:
                break
            for i in range(0, len(chunk) - 7, step):
                val = struct.unpack_from("<Q", chunk, i)[0]
                if text_start <= val <= text_end and val % 16 == 0:
                    self._primitives.append(MemoryPrimitive(
                        kind="ctrl_flow", address=off + i, size=8, confidence=0.55,
                        evidence=f"likely function pointer → 0x{val:016x}",
                    ))

    def _guess_text_segment(self) -> Tuple[int, int]:
        """从 转存 中猜测.text 段范围 —— 找 ELF header 或 PE header"""
        hdr = self.reader.read(0, 64)
        if not hdr or len(hdr) < 4:
            return 0, 0
        # ELF
        if hdr[:4] == b'\x7fELF':
            phoff = struct.unpack_from("<Q", hdr, 32)[0] if hdr[4] == 2 else struct.unpack_from("<I", hdr, 28)[0]
            segments = self.reader.read(phoff, 56 * 8)
            for i in range(0, len(segments), 56):
                ptype = struct.unpack_from("<I", segments, i)[0]
                if ptype == 1:  # PT_LOAD PF_X
                    flags = struct.unpack_from("<I", segments, i + 4)[0]
                    vaddr = struct.unpack_from("<Q", segments, i + 16)[0]
                    memsz = struct.unpack_from("<Q", segments, i + 40)[0]
                    if flags & 1:  # PF_X
                        return vaddr, vaddr + memsz
        return 0, 0

    def _scan_saved_return_addresses(self):
        """扫描栈上的返回地址模式 —— 函数边界附近的 call 后地址"""
        # 搜常见的 call 指令后的代码模式
        pass  # 需要符号执行配合，静态扫描准确率太低

    def _scan_vtable_regions(self):
        """扫描虚表区域 ——.rodata/.rdata 中连续的函数指针"""
        chunk = self.reader.read(0, min(self.reader.size, 16 * 1024 * 1024))
        if not chunk or len(chunk) < 64:
            return
        consecutive = 0
        start = 0
        for i in range(0, len(chunk) - 8, 8):
            val = struct.unpack_from("<Q", chunk, i)[0]
            # 启发性：虚表条目通常是 0x400000-0x7fffffffffff 范围内的非零值
            if 0x400000 <= val <= 0x7FFFFFFFFFFF:
                if consecutive == 0:
                    start = i
                consecutive += 1
            else:
                if consecutive >= 3:
                    self._primitives.append(MemoryPrimitive(
                        kind="ctrl_flow", address=start, size=consecutive * 8,
                        confidence=0.65 if consecutive >= 5 else 0.40,
                        evidence=f"vtable candidate: {consecutive} entries",
                    ))
                consecutive = 0

    def _scan_heap_metadata(self):
        """扫描可能的堆元数据损坏 —— 对 glibc ptmalloc chunk 做粗略检测"""
        # 找可能的 malloc_chunk 结构：size field + prev_size
        # chunk size 的 LSB 是 PREV_INUSE flag
        for off in range(0, min(self.reader.size, 512 * 1024 * 1024), 65536):
            chunk = self.reader.read(off, 65536)
            if not chunk or len(chunk) < 32:
                break
            for i in range(0, len(chunk) - 16, 16):
                prev_size = struct.unpack_from("<Q", chunk, i)[0]
                size = struct.unpack_from("<Q", chunk, i + 8)[0]
                if size & 1 and 32 <= (size & ~7) <= 4096 and prev_size < 4096:
                    # 合法 chunk header，继续
                    pass
