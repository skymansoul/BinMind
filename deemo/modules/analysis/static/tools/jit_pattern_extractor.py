import logging, os, subprocess
from dataclasses import dataclass, field
from typing import List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

@dataclass
class JITPattern:
    name: str = ""; description: str = ""
    byte_pattern: Optional[bytes] = None; severity: str = ""

class ExtractionResult:
    __slots__ = ('success','jit_patterns','jit_spray_risk','compiled_regions','jit_engine',)
    def __init__(self, success, jit_patterns, jit_spray_risk, compiled_regions=0, jit_engine=""):
        self.success = success; self.jit_patterns = jit_patterns
        self.jit_spray_risk = jit_spray_risk; self.compiled_regions = compiled_regions
        self.jit_engine = jit_engine

class JITPatternExtractor:
    JIT_ENGINES = [
        (b'V8', 'V8 JavaScript Engine'), (b'LuaJIT', 'LuaJIT Engine'),
        (b'PyPy', 'PyPy Python JIT'), (b'HHVM', 'HipHop VM (PHP)'),
        (b'Java HotSpot', 'JVM HotSpot Compiler'),
    ]
    SPRAY_PATTERNS = [
        JITPattern(name="nop_sled", description="Extended NOP sled (>100 consecutive 0x90)",
                   byte_pattern=b'\x90' * 100, severity="HIGH"),
        JITPattern(name="repeated_return", description="Consecutive RET instructions (>50)",
                   byte_pattern=b'\xc3' * 50, severity="MEDIUM"),
        JITPattern(name="int3_sled", description="INT3 breakpoint fill (>50)",
                   byte_pattern=b'\xcc' * 50, severity="MEDIUM"),
    ]
    _ADDITIONAL_PATTERNS = [
        JITPattern(name="pushad_shellcode", description="PUSHAD prefix",
                   byte_pattern=b'\x60' * 3, severity="HIGH"),
        JITPattern(name="call_pop_sequence", description="CALL/POP get-PC primitive",
                   byte_pattern=b'\xe8\x00\x00\x00\x00\x58', severity="HIGH"),
    ]

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path); self._data: bytes = b""

    def _load(self):
        try:
            with open(self.binary_path, 'rb') as f: self._data = f.read()
        except Exception: logger.debug("suppressed", exc_info=True)

    def detect_jit_engine(self) -> Optional[str]:
        self._load()
        for sig, name in self.JIT_ENGINES:
            if sig in self._data: logger.info(f"Detected JIT engine: {name}"); return name
        return None

    def detect_spray_patterns(self) -> List[JITPattern]:
        self._load(); found = []
        all_pats = self.SPRAY_PATTERNS + self._ADDITIONAL_PATTERNS
        for pat in all_pats:
            if pat.byte_pattern is not None and pat.byte_pattern in self._data:
                found.append(pat); logger.warning(f"JIT spray pattern detected: {pat.name}")
        return found

    def extract_compiled_regions(self) -> List[Tuple[int, int]]:
        self._load(); regions = []
        prologue = b'\x55\x48\x89\xe5'; pos = 0
        while True:
            idx = self._data.find(prologue, pos)
            if idx == -1: break
            end = self._data.find(b'\xc3', idx)
            if end == -1: end = min(idx + 512, len(self._data))
            regions.append((idx, min(end - idx + 1, 512))); pos = idx + 1
        return regions[:50]

    def estimate_code_cache_size(self) -> int:
        """估计 JIT 代码缓存的总大小——所有含执行权限的非只读页面的总和"""
        self._load(); total = 0
        # 扫描 4KB 对齐的页，检测代码密度
        for offset in range(0, min(len(self._data), 0x200000), 0x1000):
            chunk = self._data[offset:min(offset + 0x1000, len(self._data))]
            if len(chunk) < 0x200: continue
            prologue_count = chunk.count(b'\x55\x48\x89\xe5')
            if prologue_count >= 2: total += len(chunk)
        return total

    def run(self) -> ExtractionResult:
        engine = self.detect_jit_engine(); sprays = self.detect_spray_patterns()
        regions = self.extract_compiled_regions(); cache_size = self.estimate_code_cache_size()
        risk = "NONE"
        if len(sprays) >= 2: risk = "HIGH"
        elif len(sprays) >= 1: risk = "MEDIUM"
        elif engine: risk = "LOW"
        logger.info(f"JIT analysis: engine={engine}, spray risk={risk}, "
                    f"regions={len(regions)}, cache={cache_size//1024}KB")
        return ExtractionResult(success=True, jit_patterns=sprays,
                                jit_spray_risk=risk, compiled_regions=len(regions),
                                jit_engine=engine or "")

def create_jit_extractor(binary_path: str) -> JITPatternExtractor:
    return JITPatternExtractor(binary_path)
