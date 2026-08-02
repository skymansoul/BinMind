# 2026-07-30
# Fuzzing 字典构建器 — 从二进制/样本中自动提取变异 token
# 核心方法:
#   1. 字符串提取: 扫描二进制中长度 ≥3 的 ASCII/UTF-16 可打印序列
#   2. 常量扫描: 识别 LE/BE 编码的常见整数边界值 (0, 0xFF, INT_MAX 等)
#   3. 语料 token: 对多份样本做 n-gram 频率分析 → 高频 token → 字典条目
#   4. 结构 token: 基于已知协议/格式模板注入分隔符、length 前缀等
# 参考:
#   - AFL/AFL++ dictionary 文件格式 (https://github.com/AFLplusplus/AFLplusplus)
#   - LibFuzzer -dict 参数的字典驱动变异
#   - ChatAFL (NDSS 2024) 的机器可读语法提取、AIFORE 的字段分类
import re
import struct
import os
from typing import List, Dict, Set, Optional, Tuple
from collections import Counter, defaultdict


class TokenExtractor:
    """从各类数据源中提取字典 token。各方法独立，可组合使用。"""

    # 常见边界值常数 (little-endian & big-endian)
    _BOUNDARY_CONSTANTS = [
        0x00000000, 0x00000001, 0x000000FF, 0x0000FFFF,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
        0x0000000000000001, 0xFFFFFFFFFFFFFFFF,
        0x00000100, 0x00001000, 0x00100000, 0x01000000,
    ]

    @staticmethod
    def extract_strings(binary_data: bytes,
                        min_len: int = 3,
                        max_len: int = 128) -> List[str]:
        """从二进制数据中提取可打印字符串（ASCII + UTF-16 LE/BE）。
        返回去重并按长度排序的列表。"""
        strings: Set[str] = set()

        # ASCII 可打印序列
        current: List[str] = []
        for b in binary_data:
            if 0x20 <= b <= 0x7E:
                current.append(chr(b))
            else:
                if len(current) >= min_len:
                    s = ''.join(current[:max_len])
                    strings.add(s)
                current = []
        if len(current) >= min_len:
            strings.add(''.join(current[:max_len]))

        # UTF-16 LE 可打印序列 (每 2 字节一个字符)
        if len(binary_data) >= 2:
            current_utf16: List[str] = []
            for i in range(0, len(binary_data) - 1, 2):
                char_code = binary_data[i] | (binary_data[i + 1] << 8)
                if 0x20 <= char_code <= 0x7E:
                    current_utf16.append(chr(char_code))
                else:
                    if len(current_utf16) >= min_len:
                        strings.add(''.join(current_utf16[:max_len]))
                    current_utf16 = []
            if len(current_utf16) >= min_len:
                strings.add(''.join(current_utf16[:max_len]))

        return sorted(strings, key=lambda s: (-len(s), s))

    @staticmethod
    def extract_constants(binary_data: bytes) -> List[bytes]:
        """扫描常见整数边界值的 LE/BE 编码出现位置。"""
        found: Set[bytes] = set()
        for const in TokenExtractor._BOUNDARY_CONSTANTS:
            for byte_len in (4, 8):
                if const.bit_length() <= byte_len * 8:
                    for endian in ('little', 'big'):
                        token = const.to_bytes(byte_len, endian)
                        if token in binary_data:
                            found.add(token)
        return sorted(found, key=len)

    @staticmethod
    def extract_magic_bytes(binary_data: bytes) -> List[bytes]:
        """识别常见文件格式魔数字节。"""
        magic_patterns = [
            b'\x7fELF', b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff',
            b'GIF87a', b'GIF89a', b'PK\x03\x04',
            b'\x00\x00\x01\xBA', b'\x00\x00\x01\xB3',  # MPEG
            b'%PDF', b'Rar!\x1a\x07', b'\x1f\x8b\x08',  # gzip
            b'BZh', b'\xFD\x37\x7A\x58\x5A\x00',  # bzip2 / xz
            b'MZ', b'PE\x00\x00',  # Windows PE
            b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce',  # Mach-O
        ]
        found = []
        for magic in magic_patterns:
            if magic in binary_data:
                found.append(magic)
        return found


class CorpusTokenAnalyzer:
    """对语料集合做 token 频率分析，自动发现值得加入字典的重复片段。
    同时支持 AFL 格式字典 (.dict) 的导入/导出。

    AFL 字典格式:
      # comment
      key="value"
      hex_key="hex_value"   (对于不可打印字节)
    """

    def __init__(self, min_frequency: int = 3):
        self._min_freq = min_frequency
        self._tokens: Dict[str, Dict] = {}  # hex_key → {freq, raw, type}
        self._ngram_range = (2, 16)  # token 长度范围

    def analyze_corpus(self, samples: List[bytes]) -> Dict[str, Dict]:
        """对样本集做 n-gram 频率分析，保留 ≥min_frequency 的 token。"""
        self._tokens.clear()
        freq: Dict[str, Counter] = defaultdict(Counter)

        for n in range(self._ngram_range[0], self._ngram_range[1] + 1):
            for sample in samples:
                for i in range(len(sample) - n + 1):
                    ngram = sample[i:i + n]
                    hex_key = ngram.hex()
                    freq[str(n)][hex_key] += 1

        for n_str, counter in freq.items():
            n = int(n_str)
            for hex_key, cnt in counter.items():
                if cnt >= self._min_freq:
                    self._tokens[hex_key] = {
                        'freq': cnt, 'length': n,
                        'raw': bytes.fromhex(hex_key),
                        'type': 'ngram',
                    }
        return self._tokens

    def analyze_corpus_file(self, corpus_dir: str) -> int:
        """从语料目录加载全部文件并分析。返回提取的 token 数。"""
        samples = []
        if os.path.isdir(corpus_dir):
            for fname in os.listdir(corpus_dir):
                fpath = os.path.join(corpus_dir, fname)
                try:
                    with open(fpath, 'rb') as fh:
                        data = fh.read()
                    if data:
                        samples.append(data)
                except OSError:
                    pass
        if samples:
            self.analyze_corpus(samples)
        return len(self._tokens)

    def add_typed_token(self, raw: bytes, token_type: str) -> None:
        """手工注入特定类型的 token（如协议分隔符、关键字）"""
        hex_key = raw.hex()
        if hex_key not in self._tokens:
            self._tokens[hex_key] = {
                'freq': 1, 'length': len(raw),
                'raw': raw, 'type': token_type,
            }

    def export_afl_dict(self, output_path: str) -> int:
        """导出为 AFL 兼容的 .dict 文件。返回写入的条目数。"""
        count = 0
        with open(output_path, 'w', encoding='utf-8') as fh:
            fh.write('# Auto-generated dictionary by BinMind\n')
            fh.write(f'# Tokens: {len(self._tokens)}\n\n')
            for hex_key, info in sorted(
                    self._tokens.items(),
                    key=lambda kv: (-kv[1]['freq'], kv[1]['length'])):
                raw = info['raw']
                if _is_printable(raw):
                    val = raw.decode('ascii', errors='replace')
                    val = val.replace('"', '\\"')
                    fh.write(f'{info["type"]}="{val}"\n')
                else:
                    fh.write(f'{info["type"]}="{hex_key}"\n')
                count += 1
        return count

    def export_libfuzzer_dict(self) -> str:
        """返回 LibFuzzer 风格的字典文本（可直接写入文件）"""
        lines = ['# LibFuzzer dictionary']
        for hex_key, info in self._tokens.items():
            lines.append(f'"{info["raw"].decode("ascii", errors="replace")}"')
        return '\n'.join(lines)

    def import_afl_dict(self, dict_path: str) -> int:
        count = 0
        try:
            with open(dict_path, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    m = re.match(
                        r'(?:(\w+)="((?:[^"\\]|\\.)*)"|(\w+)="([0-9a-fA-F]+)")',
                        line)
                    if m:
                        count += 1
                        token_type = m.group(1) or m.group(3) or 'imported'
                        str_val = m.group(2)
                        hex_val = m.group(4)
                        if str_val:
                            raw = str_val.encode('ascii', errors='replace')
                        elif hex_val:
                            raw = bytes.fromhex(hex_val)
                        else:
                            continue
                        self._tokens[raw.hex()] = {
                            'freq': 1, 'length': len(raw),
                            'raw': raw, 'type': token_type,
                        }
        except Exception:
            return count  # silently return partial count on parse error
        return count

    def top_tokens(self, k: int = 20) -> List[Dict]:
        """返回频率最高的前 k 个 token"""
        sorted_tokens = sorted(
            self._tokens.values(),
            key=lambda t: (-t['freq'], -t['length']))
        return sorted_tokens[:k]

    @property
    def token_count(self) -> int:
        return len(self._tokens)


class StructuralTokenTemplates:
    """根据常见二进制/网络协议结构生成 token 模板。
    这些模板可直接注入 CorpusTokenAnalyzer 作为类型化 token。

    覆盖: 长度字段前缀 (1B/2B/4B LE/BE)、常见分隔符、终止符、
    HTTP 头字段、TLS 记录类型等。"""

    @staticmethod
    def all_templates() -> List[Tuple[bytes, str]]:
        templates = []

        # 长度字段模板 (纯结构 token，值为空，fuzzer 会在变异时填充)
        templates.append((b'\x00\x00', 'len2_be'))
        templates.append((b'\x00\x00\x00\x00', 'len4_be'))
        templates.append((b'\x00\x00', 'len2_le'))
        templates.append((b'\x00\x00\x00\x00', 'len4_le'))

        # 常见分隔符
        for sep in (b'\r\n', b'\n', b'\t', b' ', b'\x00', b':', b'='):
            templates.append((sep, 'separator'))

        # HTTP/网络协议 token
        for tok in (b'GET ', b'POST ', b'HTTP/1.1', b'Host: ',
                    b'Content-Type: ', b'User-Agent: ',
                    b'application/json', b'text/plain',
                    b'Connection: '):
            templates.append((tok, 'http'))

        # 二进制格式 token
        for tok in (b'\x00\x00\x00\x01', b'\xff\xff\xff\xff',
                    b'\x00\x01\x00\x00', b'\x00\x00\x00\x00'):
            templates.append((tok, 'binary_const'))

        return templates

    @staticmethod
    def inject_into(analyzer: CorpusTokenAnalyzer) -> int:
        """将所有模板注入一个 CorpusTokenAnalyzer 实例。返回注入数。"""
        count = 0
        for raw, token_type in StructuralTokenTemplates.all_templates():
            analyzer.add_typed_token(raw, token_type)
            count += 1
        return count


def _is_printable(data: bytes) -> bool:
    """检查字节序列是否全部为可打印 ASCII（不含控制字符 < 0x20）"""
    return all(0x20 <= b <= 0x7E for b in data)


def quick_dict_from_binary(binary_path: str) -> CorpusTokenAnalyzer:
    """便捷入口：从单个二进制文件快速生成 token 字典。
    同时提取字符串 + 常量 + 魔数，合并返回。"""
    try:
        with open(binary_path, 'rb') as fh:
            data = fh.read()
    except OSError:
        return CorpusTokenAnalyzer()

    ana = CorpusTokenAnalyzer(min_frequency=1)
    strings = TokenExtractor.extract_strings(data)
    for s in strings:
        ana.add_typed_token(s.encode('ascii', errors='replace'), 'string')

    consts = TokenExtractor.extract_constants(data)
    for c in consts:
        ana.add_typed_token(c, 'constant')

    magics = TokenExtractor.extract_magic_bytes(data)
    for m in magics:
        ana.add_typed_token(m, 'magic')

    return ana
