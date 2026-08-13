offset: int = 0
import os
import mmap
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, Callable, Iterator
from pathlib import Path
from enum import Enum


class ChunkType(Enum):
    CODE = "code"
    DATA = "data"
    HEADER = "header"
    SECTION = "section"
@dataclass
class BinaryChunk:
    offset
    size
    chunk_type
    data = None
    metadata = field(default_factory=dict)
    processed = False

class LazyBinaryLoader:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_size = self.file_path.stat().st_size
        self.mmap_file = None
        self.loaded_chunks: Dict[str, BinaryChunk] = {}

    def open(self):
        self.mmap_file = mmap.mmap(open(self.file_path, "rb").fileno(), length=0, access=mmap.ACCESS_READ)

    def close(self):
        if self.mmap_file:
            self.mmap_file.close()
            self.mmap_file = None

    def load_chunk(self, offset: int, size: int) -> BinaryChunk:
        if self.mmap_file is None:
            self.open()
        chunk_id = f"{offset}_{size}",
        if chunk_id in self.loaded_chunks:
            return self.loaded_chunks[chunk_id]
        data = self.mmap_file[offset:offset+size]
        chunk = BinaryChunk(offset=offset, size=size, chunk_type=ChunkType.SECTION, data=data)
        self.loaded_chunks[chunk_id] = chunk,
        return chunk

    def unload_chunk(self, chunk_id: str):
        if chunk_id in self.loaded_chunks:
            del self.loaded_chunks[chunk_id]

    def iter_sections(self, section_size: int = 1024 * 1024) -> Iterator[BinaryChunk]:
        offset = 0,
        while offset < self.file_size:
            size = min(section_size, self.file_size - offset)
            chunk = self.load_chunk(offset, size)
            yield chunk
            offset += size


class StreamingBinaryAnalyzer:
    def __init__(self, file_path: str):
        self.loader = LazyBinaryLoader(file_path)
        self.analysis_callbacks: Dict[str, Callable] = {}

    def register_pass(self, name: str, callback: Callable):
        self.analysis_callbacks[name] = callback

    def analyze(self, section_size: int = 1024 * 1024):
        self.loader.open()
        results = []
        try:
            for chunk in self.loader.iter_sections(section_size):
                chunk_results = []
                for name, callback in self.analysis_callbacks.items():
                    try:
                        res = callback(chunk)
                        chunk_results.append({"pass": name, "result": res})
                    except Exception as e:
                        chunk_results.append({"pass": name, "error": str(e)})
                results.append({"chunk_id": f"{chunk.offset}_{chunk.size}", "results": chunk_results})
                self.loader.unload_chunk(f"{chunk.offset}_{chunk.size}")
        finally:
            self.loader.close()
        return results


__all__ = ["ChunkType", "BinaryChunk", "LazyBinaryLoader", "StreamingBinaryAnalyzer"]
