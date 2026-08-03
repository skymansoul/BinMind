import logging
import os
import json
import re
import time
import math
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set
from collections import Counter

logger = logging.getLogger(__name__)


class DictionaryFormat(str, Enum):
    AFL = "afl"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    JSON = "json"
    RAW = "raw"


@dataclass
class DictEntry:
    value: bytes
    tag: str = ""
    confidence: float = 0.5
    source: str = ""
    level: Optional[int] = None  # 嵌套层级 (结构感知解析使用)


@dataclass
class DictionaryInfo:
    format: DictionaryFormat
    entries: List[DictEntry]
    target_binary: str = ""
    generated_at: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── 文件魔数签名库 ──────────────────────────────────────────────

_MAGIC_SIGNATURES: List[Tuple[bytes, str]] = [
    (b'\x89PNG\r\n\x1a\n', 'PNG'),
    (b'\xff\xd8\xff', 'JPEG'),
    (b'GIF8', 'GIF'),
    (b'%PDF', 'PDF'),
    (b'PK\x03\x04', 'ZIP/DOCX'),
    (b'\x1f\x8b', 'GZIP'),
    (b'BZh', 'BZIP2'),
    (b'\x7fELF', 'ELF'),
    (b'MZ', 'PE/EXE'),
    (b'\xca\xfe\xba\xbe', 'Mach-O'),
    (b'\x00\x00\x01\xba', 'MPEG'),
    (b'RIFF', 'WAV/AVI'),
    (b'\xff\xfb', 'MP3'),
    (b'SQLite format 3', 'SQLite'),
    (b'<!DOC', 'HTML'),
]


class StringExtractor:
    """从二进制提取可打印字符串 — 优先调系统 strings，失败则回退逐字节扫描"""

    MIN_STRING_LEN = 3
    MAX_STRING_LEN = 256

    @staticmethod
    def extract(binary_path: str) -> List[str]:
        strings = []
        try:
            import subprocess
            result = subprocess.run(
                ["strings", "-n", str(StringExtractor.MIN_STRING_LEN), binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if len(line) >= StringExtractor.MIN_STRING_LEN:
                    if StringExtractor._is_printable(line):
                        strings.append(line)
        except Exception as e:
            logger.warning(f"stringextractfailed: {e}")
            # 回退方案: 逐字节扫描原始文件
            strings = StringExtractor._simple_scan(binary_path)
        return list(set(strings))

    @staticmethod
    def _is_printable(s: str) -> bool:
        printable = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                       "!@#$%^&*()_+-=[]{}|;':\",./<>?\\`~ ")
        return sum(1 for c in s if c in printable) / max(1, len(s)) > 0.8

    @staticmethod
    def _simple_scan(path: str) -> List[str]:
        strings = []
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError:
            return strings

        current = []
        for byte in data:
            if 0x20 <= byte <= 0x7E:
                current.append(chr(byte))
            else:
                if len(current) >= StringExtractor.MIN_STRING_LEN:
                    s = ''.join(current)
                    if StringExtractor._is_printable(s):
                        strings.append(s)
                current = []
        if len(current) >= StringExtractor.MIN_STRING_LEN:
            s = ''.join(current)
            if StringExtractor._is_printable(s):
                strings.append(s)
        return strings


# ── 多编码字符串检测 ────────────────────────────────────────────

class MultiEncodingExtractor:
    """扫描原始字节流，识别 UTF‑16LE/BE、UTF‑32 和 Shift‑JIS 编码段。

    二进制中嵌入的宽字符字符串(如 Windows 资源节中的 UNICODE 文本)
    常被常规 strings 忽略，导致字典缺失路径/注册表键等关键标记。"""

    @staticmethod
    def extract_utf16le(data: bytes, min_len: int = 3) -> List[str]:
        strings = []
        i = 0
        buf: List[str] = []
        while i < len(data) - 1:
            lo, hi = data[i], data[i + 1]
            cp = lo | (hi << 8)
            if 0x20 <= cp < 0x7F:
                buf.append(chr(cp))
                i += 2
                continue
            if len(buf) >= min_len:
                strings.append(''.join(buf))
            buf = []
            i += 2
        if len(buf) >= min_len:
            strings.append(''.join(buf))
        return strings

    @staticmethod
    def extract_utf16be(data: bytes, min_len: int = 3) -> List[str]:
        strings = []
        i = 0
        buf: List[str] = []
        while i < len(data) - 1:
            hi, lo = data[i], data[i + 1]
            cp = lo | (hi << 8)
            if 0x20 <= cp < 0x7F:
                buf.append(chr(cp))
                i += 2
                continue
            if len(buf) >= min_len:
                strings.append(''.join(buf))
            buf = []
            i += 2
        if len(buf) >= min_len:
            strings.append(''.join(buf))
        return strings

    @staticmethod
    def extract_all(data: bytes, min_len: int = 3) -> List[str]:
        all_strings: List[str] = []
        all_strings.extend(MultiEncodingExtractor.extract_utf16le(data, min_len))
        all_strings.extend(MultiEncodingExtractor.extract_utf16be(data, min_len))
        return list(set(all_strings))


# ── 熵基令牌边界检测 ────────────────────────────────────────────

class EntropyBoundaryDetector:
    """基于字节熵的滑动窗口检测字段/令牌边界。

    原理: 结构化数据(如 HTTP 头、JSON 键)与纯随机数据(如加密载荷、
    压缩段)的局部熵差异显著。通过滑动窗口计算香农熵，在熵值跳跃处
    标记候选分割点，这些位置往往对应字段边界。

    AFL++ 的 token detection (afl-analyze) 基于直方图差异，
    此处扩展为熵视角以捕获隐蔽的结构分界。"""

    @staticmethod
    def shannon_entropy(window: bytes) -> float:
        if not window:
            return 0.0
        cnt = Counter(window)
        total = len(window)
        ent = 0.0
        log2 = math.log2
        for c in cnt.values():
            p = c / total
            ent -= p * log2(p)
        return ent

    @staticmethod
    def detect_boundaries(
        data: bytes, window_size: int = 16, stride: int = 8
    ) -> List[int]:
        """返回候选边界偏移量列表。

        在 window_size 窗口上以 stride 步进，计算相邻窗口的熵差绝对值。
        熵差 >1.5 bit/byte 的位置标记为边界候选。"""
        if len(data) < window_size * 2:
            return []
        positions: List[int] = []
        prev_ent = EntropyBoundaryDetector.shannon_entropy(data[:window_size])
        i = stride
        while i + window_size <= len(data):
            cur_ent = EntropyBoundaryDetector.shannon_entropy(
                data[i:i + window_size]
            )
            if abs(cur_ent - prev_ent) > 1.5:
                positions.append(i)
            prev_ent = cur_ent
            i += stride
        return positions


# ── TLV 模式推断 ────────────────────────────────────────────────

class TLVParser:
    """轻量 TLV (Type‑Length‑Value) 结构探测。

    启发式: 在字节流中寻找 <1‑byte‑tag> <1‑byte‑length> <data> 的重复模式。
    若连续 3+ 次成功解析（即 length 字节之后的 length 字节数据恰好在
    字节流边界内且下一字节也是已知 tag 集合的成员），则视为 TLV 结构。"""

    @staticmethod
    def probe(data: bytes, known_tags: Optional[Set[int]] = None) -> Optional[Dict[str, Any]]:
        if len(data) < 10:
            return None
        tags = known_tags or set(range(0x01, 0x20))
        # 采样前 4KB
        sample = data[:4096]
        matches = 0
        i = 0
        while i < len(sample) - 2:
            tag = sample[i]
            length = sample[i + 1]
            if tag not in tags:
                i += 1
                continue
            if i + 2 + length <= len(sample):
                # 检查下一段的 tag 是否也在已知集合
                next_pos = i + 2 + length
                if next_pos < len(sample) and sample[next_pos] in tags:
                    matches += 1
                i = next_pos
            else:
                i += 1
        if matches >= 3:
            return {
                'detected': True,
                'field_count': matches,
                'tag_offset': 0,
                'length_offset': 1,
                'value_offset': 2,
            }
        return None


class FormatInferencer:
    """基于正则匹配推断字符串数据格式 — HTTP/JSON/XML/URL/IP/UUID 等"""

    FORMAT_PATTERNS = {
        "HTTP": [
            r"^GET\s+\S+\s+HTTP/\d\.\d$",
            r"^POST\s+\S+\s+HTTP/\d\.\d$",
            r"^Host:\s+\S+",
            r"^Content-Length:\s+\d+",
            r"^Content-Type:\s+\S+",
        ],
        "JSON": [
            r"^\{.*\}$",
            r"^\[.*\]$",
            r"\"[^\"]+\":",
        ],
        "XML": [
            r"^<[^>]+>",
            r"</[^>]+>$",
        ],
        "URL": [
            r"^https?://",
            r"^ftp://",
        ],
        "PATH": [
            r"^/[\w/.-]+$",
            r"^[A-Za-z]:\\[\w\\/.-]+$",
        ],
        "UUID": [
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        ],
        "IP": [
            r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
            r"^[0-9a-f:.]+$",  # IPv6
        ],
        "EMAIL": [
            r"^[\w.-]+@[\w.-]+\.\w+$",
        ],
        "HEX": [
            r"^0x[0-9a-fA-F]+$",
            r"^[0-9a-fA-F]{8,}$",
        ],
        "NUMERIC": [
            r"^\d+$",
            r"^\d+\.\d+$",
        ],
    }

    def __init__(self):
        self.patterns = {k: [re.compile(p) for p in v]
                         for k, v in self.FORMAT_PATTERNS.items()}

    def infer(self, string: str) -> List[str]:
        types = []
        for fmt, patterns in self.patterns.items():
            for p in patterns:
                if p.match(string):
                    types.append(fmt)
                    break
        return types


class LLMBasedGenerator:
    """基于 Ollama API 的 LLM 字典条目生成"""

    PROMPT_TEMPLATE = """
分析以下从二进制提取的字符串，生成高语义正确性的模糊测试字典条目。

字符串列表:
{strings}

输出 JSON 数组格式的字典条目。每项包含:
- value: 字典值
- tag: 分类标签（header, path, number, string 等）
- confidence: 置信度 (0-1)
- source: 来源说明

准则:
1. 生成与目标程序语义相关的值
2. 包含边界值、特殊字符、协议关键字
3. 覆盖常见编码格式
4. 排除无意义值

严格输出 JSON 数组:
"""

    def __init__(self, model: str = "qwen2.5-coder:7b", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host.rstrip("/")

    def generate(self, strings: List[str], max_entries: int = 200) -> List[Dict[str, Any]]:
        if not strings:
            return []
        # 2026-08-02 fix: 原 import hashlib 在模块级缩进导致 IndentationError
        # hashlib 现已在模块顶部导入，此处清理遗留的缩进异常
        try:
            import requests
            sample_strings = strings[:50]
            prompt = self.PROMPT_TEMPLATE.format(strings="\n".join(f"- {s}" for s in sample_strings))
            r = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ],
                    "format": "json",
                    "stream": False
                },
                timeout=120
            )
            r.raise_for_status()
            content = r.json()["message"]["content"]
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    return data[:max_entries]
            except json.JSONDecodeError:
                logger.warning("LLM 输出非有效 JSON")
        except Exception as e:
            logger.warning("LLM 生成失败: %s", e)
        return self._fallback_generate(strings, max_entries)

    def _fallback_generate(self, strings: List[str], max_entries: int) -> List[Dict[str, Any]]:
        result = []
        inferencer = FormatInferencer()
        for s in strings[:max_entries]:
            types = inferencer.infer(s)
            tag = types[0] if types else "string"
            result.append({
                "value": s,
                "tag": tag,
                "confidence": 0.7 + len(types) * 0.1,
                "source": "fallback"
            })
        return result


# ── 基于执行反馈的变异回收 ──────────────────────────────────────

class FeedbackMutationRecycler:
    """从运行时覆盖反馈中提取高价值字节序列并回注到字典。

    参考 AFL 的 effector map 和 LibAFL 的 Observer 模式:
    未被覆盖分支附近的字面量是高质量字典候选，因为更改它们更可能
    触发新路径。"""

    @staticmethod
    def extract_interesting_literals(
        raw_data: bytes,
        coverage_heat: Dict[int, int],
        min_len: int = 2,
        max_len: int = 32,
    ) -> List[bytes]:
        """从高覆盖热度区域(heat > median)提取连续字面量 byte 序列。

        coverage_heat: offset → hit_count 的映射"""
        if not coverage_heat:
            return []
        median_heat = sorted(coverage_heat.values())[len(coverage_heat) // 2]
        hot_ranges: List[Tuple[int, int]] = []
        # 合并相邻高热度偏移为区间
        sorted_offsets = sorted(o for o, h in coverage_heat.items()
                                if h >= median_heat)
        if not sorted_offsets:
            return []
        start = sorted_offsets[0]
        end = sorted_offsets[0]
        for off in sorted_offsets[1:]:
            if off <= end + 16:
                end = max(end, off)
            else:
                hot_ranges.append((start, end))
                start = end = off
        hot_ranges.append((start, end))

        literals: List[bytes] = []
        seen: Set[bytes] = set()
        for s, e in hot_ranges:
            span = raw_data[s:e + 1]
            for seg_len in range(min_len, min(max_len + 1, len(span))):
                seg = span[:seg_len]
                if seg not in seen:
                    seen.add(seg)
                    literals.append(seg)
        return literals


class DictionaryGenerator:
    """字典生成调度器: 字符串提取 → 格式推断 → LLM 增强 → 去重"""

    def __init__(self, llm_host: str = "http://localhost:11434", llm_model: str = "qwen2.5-coder:7b"):
        self.extractor = StringExtractor()
        self.inferencer = FormatInferencer()
        self.llm = LLMBasedGenerator(model=llm_model, host=llm_host)
        self._recycler = FeedbackMutationRecycler()

    def _generate_special_values(self) -> List[Dict[str, Any]]:
        specials = [
            # 字节级边界值
            {"value": "\x00", "tag": "null_byte", "confidence": 0.9, "source": "special"},
            {"value": "\xff", "tag": "max_byte", "confidence": 0.9, "source": "special"},
            {"value": "\x7f", "tag": "max_ascii", "confidence": 0.9, "source": "special"},
            {"value": "\x80", "tag": "negative_byte", "confidence": 0.9, "source": "special"},
            # HTTP 方法与协议版本
            {"value": "GET ", "tag": "http_method", "confidence": 0.8, "source": "http"},
            {"value": "POST ", "tag": "http_method", "confidence": 0.8, "source": "http"},
            {"value": "PUT ", "tag": "http_method", "confidence": 0.8, "source": "http"},
            {"value": "DELETE ", "tag": "http_method", "confidence": 0.8, "source": "http"},
            {"value": "HTTP/1.1", "tag": "http_version", "confidence": 0.8, "source": "http"},
            {"value": "HTTP/2", "tag": "http_version", "confidence": 0.8, "source": "http"},
            # 常见分隔符
            {"value": "/", "tag": "separator", "confidence": 0.9, "source": "special"},
            {"value": "\\", "tag": "separator", "confidence": 0.9, "source": "special"},
            {"value": ":", "tag": "separator", "confidence": 0.9, "source": "special"},
            {"value": "=", "tag": "separator", "confidence": 0.9, "source": "special"},
            {"value": "&", "tag": "separator", "confidence": 0.9, "source": "special"},
            {"value": "?", "tag": "separator", "confidence": 0.9, "source": "special"},
            # 数值边界（整型极限）
            {"value": "0", "tag": "number", "confidence": 0.9, "source": "boundary"},
            {"value": "1", "tag": "number", "confidence": 0.9, "source": "boundary"},
            {"value": "-1", "tag": "number", "confidence": 0.8, "source": "boundary"},
            {"value": "65535", "tag": "number", "confidence": 0.8, "source": "boundary"},
            {"value": "4294967295", "tag": "number", "confidence": 0.8, "source": "boundary"},
            {"value": "2147483647", "tag": "number", "confidence": 0.8, "source": "boundary"},
            {"value": "-2147483648", "tag": "number", "confidence": 0.8, "source": "boundary"},
            # 常见文件系统路径
            {"value": "/etc/passwd", "tag": "path", "confidence": 0.7, "source": "unix"},
            {"value": "/proc/self/environ", "tag": "path", "confidence": 0.7, "source": "unix"},
            {"value": "/dev/null", "tag": "path", "confidence": 0.7, "source": "unix"},
            {"value": "C:\\", "tag": "path", "confidence": 0.7, "source": "windows"},
        ]
        return specials

    # ── 魔数检测 ────────────────────────────────────────────────

    def _extract_magic_signatures(self, binary_path: str) -> List[DictEntry]:
        entries: List[DictEntry] = []
        try:
            with open(binary_path, 'rb') as f:
                head = f.read(4096)
        except OSError:
            return entries
        for magic, label in _MAGIC_SIGNATURES:
            if head.startswith(magic):
                entries.append(DictEntry(
                    value=magic, tag=f"magic_{label.lower()}",
                    confidence=0.95, source="magic"
                ))
                # 若为容器格式则追加内部常见魔数
                if label == 'ZIP/DOCX':
                    for inner_tag, inner_label in [
                        (b'\x50\x4b\x03\x04', 'zip_entry'),
                        (b'\x50\x4b\x01\x02', 'zip_central'),
                    ]:
                        entries.append(DictEntry(
                            value=inner_tag, tag=inner_label,
                            confidence=0.9, source="magic"
                        ))
        return entries

    def generate(self, binary_path: str, format_type: DictionaryFormat = DictionaryFormat.JSON,
                 use_llm: bool = True,
                 coverage_feedback: Optional[Dict[int, int]] = None) -> DictionaryInfo:
        strings = self.extractor.extract(binary_path)
        entries: List[DictEntry] = []

        # 阶段零: 魔数检测
        for magic_entry in self._extract_magic_signatures(binary_path):
            entries.append(magic_entry)

        # 阶段一: 注入手工构造的特殊值
        for item in self._generate_special_values():
            entries.append(DictEntry(
                value=item["value"].encode("utf-8"),
                tag=item["tag"],
                confidence=item["confidence"],
                source=item["source"]
            ))

        # 阶段二: 从二进制提取字符串并分类
        for s in strings[:100]:
            types = self.inferencer.infer(s)
            tag = types[0] if types else "string"
            entries.append(DictEntry(
                value=s.encode("utf-8"),
                tag=tag,
                confidence=0.6 + len(types) * 0.1,
                source="binary"
            ))

        # 阶段二b: 多编码字符串提取
        try:
            with open(binary_path, 'rb') as f:
                raw_data = f.read()
            wide_strings = MultiEncodingExtractor.extract_all(raw_data)
            for ws in wide_strings[:50]:
                if StringExtractor._is_printable(ws):
                    entries.append(DictEntry(
                        value=ws.encode("utf-8"),
                        tag="wide_string",
                        confidence=0.55,
                        source="unicode"
                    ))
        except OSError:
            pass

        # 阶段二c: 熵边界检测 — 生成边界位置附近的分隔符字典项
        try:
            if 'raw_data' not in dir():
                with open(binary_path, 'rb') as f:
                    raw_data = f.read()
            boundary_offsets = EntropyBoundaryDetector.detect_boundaries(raw_data)
            for bo in boundary_offsets[:20]:
                end = min(bo + 8, len(raw_data))
                chunk = raw_data[bo:end]
                if len(chunk) >= 2:
                    entries.append(DictEntry(
                        value=chunk,
                        tag="entropy_boundary",
                        confidence=0.45,
                        source="entropy"
                    ))
        except OSError:
            pass

        # 阶段三: LLM 增强生成
        if use_llm:
            llm_entries = self.llm.generate(strings, max_entries=50)
            for item in llm_entries:
                try:
                    entries.append(DictEntry(
                        value=item["value"].encode("utf-8"),
                        tag=item.get("tag", "llm"),
                        confidence=item.get("confidence", 0.5),
                        source="llm"
                    ))
                except (KeyError, ValueError):
                    continue

        # 阶段四: 反馈驱动的字面量回收
        if coverage_feedback:
            try:
                with open(binary_path, 'rb') as f:
                    raw_data = f.read()
                feedback_lits = self._recycler.extract_interesting_literals(
                    raw_data, coverage_feedback
                )
                for lit in feedback_lits[:30]:
                    entries.append(DictEntry(
                        value=lit,
                        tag="feedback_literal",
                        confidence=0.65,
                        source="feedback"
                    ))
            except OSError:
                pass

        # 按 (value, tag) 组合键去重
        seen = set()
        unique_entries = []
        for e in entries:
            key = (e.value, e.tag)
            if key not in seen:
                seen.add(key)
                unique_entries.append(e)

        return DictionaryInfo(
            format=format_type,
            entries=unique_entries,
            target_binary=binary_path,
            generated_at=time.time(),
            metadata={
                "binary_strings_count": len(strings),
                "special_values_count": len(self._generate_special_values()),
                "llm_entries_count": sum(1 for e in unique_entries if e.source == "llm"),
                "total_entries": len(unique_entries),
                "unicode_strings_count": sum(1 for e in unique_entries if e.source == "unicode"),
                "entropy_boundaries_count": sum(1 for e in unique_entries if e.source == "entropy"),
                "feedback_literals_count": sum(1 for e in unique_entries if e.source == "feedback"),
            }
        )

    def format_output(self, info: DictionaryInfo) -> str:
        if info.format == DictionaryFormat.AFL:
            return self._format_afl(info)
        elif info.format == DictionaryFormat.LIBFUZZER:
            return self._format_libfuzzer(info)
        elif info.format == DictionaryFormat.HONGGFUZZ:
            return self._format_honggfuzz(info)
        elif info.format == DictionaryFormat.JSON:
            return self._format_json(info)
        else:
            return self._format_raw(info)

    def _format_afl(self, info: DictionaryInfo) -> str:
        lines = []
        for e in info.entries:
            escaped = e.value.decode("utf-8", errors="replace").replace("\\", "\\\\").replace("\"", "\\\"")
            tag = f"#{e.tag}" if e.tag else ""
            lines.append(f'"{escaped}"{tag}')
        return "\n".join(lines)

    def _format_libfuzzer(self, info: DictionaryInfo) -> str:
        lines = []
        for e in info.entries:
            escaped = e.value.decode("utf-8", errors="replace")
            # LibFuzzer 格式: 标签=值
            tag = e.tag or "auto"
            lines.append(f"{tag}={escaped}")
        return "\n".join(lines)

    def _format_honggfuzz(self, info: DictionaryInfo) -> str:
        lines = []
        for e in info.entries:
            escaped = e.value.decode("utf-8", errors="replace").replace("\\", "\\\\").replace("\"", "\\\"")
            lines.append(f'"{escaped}"')
        return "\n".join(lines)

    def _format_json(self, info: DictionaryInfo) -> str:
        data = {
            "format": info.format.value,
            "target_binary": info.target_binary,
            "generated_at": info.generated_at,
            "entries": [
                {
                    "value": e.value.decode("utf-8", errors="replace"),
                    "tag": e.tag,
                    "confidence": e.confidence,
                    "source": e.source
                }
                for e in info.entries
            ],
            "metadata": info.metadata
        }
        return json.dumps(data, ensure_ascii=False, indent=2)

    def _format_raw(self, info: DictionaryInfo) -> str:
        return "\n".join(e.value.decode("utf-8", errors="replace") for e in info.entries)


def generate_fuzz_dictionary(
    binary_path: str,
    output_path: Optional[str] = None,
    format_type: str = "json",
    use_llm: bool = True,
    coverage_feedback: Optional[Dict[int, int]] = None,
) -> Dict[str, Any]:
    try:
        fmt = DictionaryFormat(format_type.lower())
    except ValueError:
        fmt = DictionaryFormat.JSON

    generator = DictionaryGenerator()
    info = generator.generate(binary_path, fmt, use_llm,
                              coverage_feedback=coverage_feedback)
    output = generator.format_output(info)

    if output_path:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(output)
            return {
                'success': True,
                'entries_count': len(info.entries),
                'output_path': output_path,
                'format': fmt.value,
                'metadata': info.metadata
            }
        except Exception as e:
            logger.warning(f"savedictionaryfailed: {e}")
            return {'success': False, 'error': str(e)}

    return {
        'success': True,
        'entries_count': len(info.entries),
        'format': fmt.value,
        'metadata': info.metadata,
        'content': output
    }

def _debug_print(*a,**kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):print(*a,**kw)
