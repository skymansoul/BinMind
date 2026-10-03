import os, mmap, json, threading, time
from dataclasses import dataclass, field
from typing import Dict, Callable, Iterator, Optional, List
from pathlib import Path
from enum import Enum


class ChunkType(Enum):
    CODE = "code"; DATA = "data"; HEADER = "header"; SECTION = "section"

@dataclass
class BinaryChunk:
    offset: int = 0; size: int = 0
    chunk_type: ChunkType = ChunkType.SECTION
    data: Optional[bytes] = None
    metadata: dict = field(default_factory=dict); processed: bool = False


class ChunkCache:
    """LRU chunk cache, 避免对大文件的重复 mmap 读取"""
    __slots__ = ('_max', '_store', '_order')
    def __init__(self, max_entries: int = 32):
        self._max = max_entries; self._store: Dict[str, BinaryChunk] = {}
        self._order: List[str] = []
    def get(self, key: str) -> Optional[BinaryChunk]:
        v = self._store.get(key)
        if v is not None and key in self._order:
            self._order.remove(key); self._order.append(key)
        return v
    def put(self, key: str, chunk: BinaryChunk):
        if key in self._store: self._order.remove(key)
        elif len(self._store) >= self._max:
            oldest = self._order.pop(0); del self._store[oldest]
        self._store[key] = chunk; self._order.append(key)


class LazyBinaryLoader:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path); self.file_size = self.file_path.stat().st_size
        self.mmap_file = None; self._fd = None
        self.loaded_chunks: Dict[str, BinaryChunk] = {}
        self._cache = ChunkCache(max_entries=32)

    def open(self):
        self._fd = open(self.file_path, "rb")
        self.mmap_file = mmap.mmap(self._fd.fileno(), length=0, access=mmap.ACCESS_READ)

    def close(self):
        if self.mmap_file: self.mmap_file.close(); self.mmap_file = None
        if self._fd: self._fd.close(); self._fd = None

    def load_chunk(self, offset: int, size: int) -> BinaryChunk:
        chunk_id = f"{offset}_{size}"
        cached = self._cache.get(chunk_id)
        if cached is not None: return cached
        if self.mmap_file is None: self.open()
        data = self.mmap_file[offset:offset + size]
        chunk = BinaryChunk(offset=offset, size=size, chunk_type=ChunkType.SECTION, data=data)
        self._cache.put(chunk_id, chunk)
        return chunk

    def unload_chunk(self, chunk_id: str):
        if chunk_id in self.loaded_chunks: del self.loaded_chunks[chunk_id]

    def iter_sections(self, section_size: int = 1024 * 1024) -> Iterator[BinaryChunk]:
        offset = 0
        while offset < self.file_size:
            size = min(section_size, self.file_size - offset)
            yield self.load_chunk(offset, size)
            offset += size


class StreamingBinaryAnalyzer:
    def __init__(self, file_path: str):
        self.loader = LazyBinaryLoader(file_path)
        self.analysis_callbacks: Dict[str, Callable] = {}
        self._progress_cb: Optional[Callable] = None

    def register_pass(self, name: str, callback: Callable):
        self.analysis_callbacks[name] = callback

    def on_progress(self, callback: Callable):
        """注册进度回调, 每处理完一个 chunk 后调用，参数为 (chunk_offset, total_chunks, elapsed_seconds)"""
        self._progress_cb = callback

    def analyze(self, section_size: int = 1024 * 1024, max_chunks: int = 0):
        self.loader.open(); results = []; t0 = time.time(); chunk_ctr = 0
        try:
            total_chunks = (self.loader.file_size + section_size - 1) // section_size
            for chunk in self.loader.iter_sections(section_size):
                chunk_results = []
                for name, callback in self.analysis_callbacks.items():
                    try:
                        res = callback(chunk); chunk_results.append({"pass": name, "result": res})
                    except Exception as e:
                        chunk_results.append({"pass": name, "error": str(e)})
                results.append({"chunk_id": f"{chunk.offset}_{chunk.size}", "results": chunk_results})
                chunk_ctr += 1
                if self._progress_cb:
                    self._progress_cb(chunk.offset, total_chunks, time.time() - t0)
                if max_chunks > 0 and chunk_ctr >= max_chunks: break
        finally:
            self.loader.close()
        return results

    def analyze_parallel(self, section_size: int = 1024 * 1024,
                          num_workers: int = 4) -> List[Dict]:
        """多线程并行分析, 将文件分片交给线程池处理。适合 IO 密集型的分析 pass"""
        from concurrent.futures import ThreadPoolExecutor, as_completed
        self.loader.open(); results = [None] * num_workers
        chunk_size = max(section_size, self.loader.file_size // num_workers)
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = {}
            for i in range(num_workers):
                offset = i * chunk_size; size = min(chunk_size, self.loader.file_size - offset)
                if size <= 0: continue
                chunk = self.loader.load_chunk(offset, size)
                futures[executor.submit(self._analyze_chunk, chunk, i)] = i
            for future in as_completed(futures):
                idx = futures[future]
                try: results[idx] = future.result()
                except Exception as e: results[idx] = {"error": str(e)}
        self.loader.close()
        return [r for r in results if r is not None]

    def _analyze_chunk(self, chunk: BinaryChunk, worker_id: int) -> Dict:
        chunk_results = []
        for name, callback in self.analysis_callbacks.items():
            try:
                res = callback(chunk); chunk_results.append({"pass": name, "result": res})
            except Exception as e:
                chunk_results.append({"pass": name, "error": str(e)})
        return {"chunk_id": f"{chunk.offset}_{chunk.size}", "worker": worker_id,
                "results": chunk_results}


__all__ = ["ChunkType","BinaryChunk","LazyBinaryLoader","StreamingBinaryAnalyzer"]
