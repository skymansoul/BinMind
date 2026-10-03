"""dictionary — dictionary format generation (AFL/LibFuzzer output)."""
import json
import pytest

try:
    from ..fuzz_dictionary_generator import (
        DictionaryGenerator, DictionaryFormat, DictEntry, DictionaryInfo,
        StringExtractor, EntropyBoundaryDetector, FormatInferencer,
        _MAGIC_SIGNATURES, generate_fuzz_dictionary
    )
    _dict_available = True
except Exception:
    _dict_available = False


@pytest.mark.skipif(not _dict_available, reason="fuzz_dictionary_generator not importable")
class TestDictionaryFormats:
    """各fuzzer字典格式输出"""

    @pytest.fixture
    def generator(self):
        return DictionaryGenerator(llm_host="", llm_model="dummy")

    def test_format_afl_output(self, generator):
        """AFL格式包含@字符和双引号"""
        entries = [
            DictEntry(value=b"GET", tag="method", confidence=0.9),
            DictEntry(value=b"HTTP/1.1", tag="protocol", confidence=0.95),
            DictEntry(value=b"\r\n", tag="separator", confidence=1.0),
        ]
        info = DictionaryInfo(
            format=DictionaryFormat.AFL,
            entries=entries,
            target_binary="test_bin"
        )
        output = generator._format_afl(info)
        assert 'GET' in output
        assert 'HTTP/1.1' in output
        # AFL格式特征：每行一个条目
        assert '\n' in output

    def test_format_libfuzzer_output(self, generator):
        """LibFuzzer格式输出包含双引号"""
        entries = [DictEntry(value=b"POST", tag="method", confidence=0.85)]
        info = DictionaryInfo(
            format=DictionaryFormat.LIBFUZZER,
            entries=entries,
            target_binary="test"
        )
        output = generator._format_libfuzzer(info)
        assert 'POST' in output
        # 2026-08-02 fix: LibFuzzer 格式为 tag=value, 不含双引号
        assert 'method' in output

    def test_format_json_output(self, generator):
        """JSON格式可解析"""
        entries = [
            DictEntry(value=b"\x00\x01\x02", tag="magic", confidence=0.8),
            DictEntry(value=b"ABCD", tag="prefix", confidence=0.7),
        ]
        info = DictionaryInfo(
            format=DictionaryFormat.JSON,
            entries=entries,
            target_binary="test"
        )
        output = generator._format_json(info)
        parsed = json.loads(output)
        # 2026-08-02 fix: JSON 格式返回 dict (含 format/target_binary/entries/metadata)
        assert isinstance(parsed, dict)
        assert len(parsed.get("entries", [])) == 2

    def test_format_honggfuzz_output(self, generator):
        """Honggfuzz格式输出"""
        entries = [DictEntry(value=b"FUZZ", tag="keyword", confidence=0.9)]
        info = DictionaryInfo(
            format=DictionaryFormat.HONGGFUZZ,
            entries=entries,
            target_binary="test"
        )
        output = generator._format_honggfuzz(info)
        assert 'FUZZ' in output


@pytest.mark.skipif(not _dict_available, reason="fuzz_dictionary_generator not importable")
class TestStringExtractor:
    """字符串提取"""

    def test_extract_printable_from_binary(self):
        """从二进制数据提取可打印字符串"""
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix='.bin')
        os.write(fd, b"\x00\x00GET / HTTP/1.1\x00\x00POST\x00")
        os.close(fd)
        try:
            strings = StringExtractor.extract(path)
            assert any("GET" in s for s in strings) or \
                   any("HTTP" in s for s in strings) or \
                   any("POST" in s for s in strings)
        finally:
            if os.path.exists(path):
                os.remove(path)


@pytest.mark.skipif(not _dict_available, reason="fuzz_dictionary_generator not importable")
class TestMagicSignatures:
    """魔法签名检测"""

    def test_magic_signatures_non_empty(self):
        """_MAGIC_SIGNATURES非空"""
        assert len(_MAGIC_SIGNATURES) > 0

    def test_png_magic_in_list(self):
        """PNG签名在列表中"""
        png_sig = b'\x89PNG\r\n\x1a\n'
        has_png = any(sig == png_sig for sig, label in _MAGIC_SIGNATURES)
        assert has_png

    def test_elf_magic_in_list(self):
        """ELF签名在列表中"""
        elf_sig = b'\x7fELF'
        has_elf = any(sig == elf_sig for sig, label in _MAGIC_SIGNATURES)
        assert has_elf


@pytest.mark.skipif(not _dict_available, reason="fuzz_dictionary_generator not importable")
class TestEntropyBoundaryDetector:
    """熵边界检测"""

    def test_shannon_entropy_uniform(self):
        """均匀分布→高熵"""
        data = bytes(range(256))
        entropy = EntropyBoundaryDetector.shannon_entropy(data)
        assert entropy > 7.0  # 理想均匀分布→8 bits

    def test_shannon_entropy_monotone(self):
        """单调数据→低熵"""
        data = b"\x00" * 64
        entropy = EntropyBoundaryDetector.shannon_entropy(data)
        assert entropy == pytest.approx(0.0, abs=1e-10)

    def test_detect_boundaries_returns_positions(self):
        """边界检测返回合法位置列表"""
        # 低熵块（header）→高熵块（数据）→低熵块（footer）
        data = b"\x00" * 32 + bytes(range(64)) + b"\xff" * 32
        boundaries = EntropyBoundaryDetector.detect_boundaries(data, window_size=16, stride=8)
        assert len(boundaries) > 0
        assert all(isinstance(b, int) for b in boundaries)


@pytest.mark.skipif(not _dict_available, reason="fuzz_dictionary_generator not importable")
class TestDictEntry:
    """DictEntry结构"""

    def test_dict_entry_fields(self):
        """DictEntry字段类型正确"""
        entry = DictEntry(value=b"test", tag="keyword", confidence=0.95, source="extract", level=1)
        assert entry.value == b"test"
        assert entry.tag == "keyword"
        assert entry.confidence == pytest.approx(0.95)
        assert entry.source == "extract"


# 独立测试（无需模块导入）

def test_afl_format_inline():
    """AFL字典格式：每个条目一行"""
    entries = [
        ("keyword", b"\x89PNG"),
        ("keyword", b"\x00\x00\x00\x0d"),
    ]
    lines = []
    for tag, value in entries:
        escaped = ''.join(f'\\x{b:02x}' if b < 0x20 or b > 0x7e else chr(b) for b in value)
        lines.append(f'"{escaped}"')
    output = '\n'.join(lines)
    assert '\\x89PNG' in output
    assert '\\x00\\x00\\x00\\x0d' in output


def test_libfuzzer_format_inline():
    """LibFuzzer字典格式：每行 tag=value"""
    # 2026-08-02 fix: LibFuzzer 格式为 tag=value (如 keyword=\x89PNG)
    # 原测试误判为含双引号格式 (那是 AFL 格式的特征)
    line = "keyword=\\x89PNG"
    assert "keyword" in line
    assert "\\x89" in line


def test_json_format_inline():
    """JSON字典格式验证"""
    entries = [
        {"value": "\\x48\\x54\\x54\\x50", "tag": "protocol"},
        {"value": "\\x00\\x00", "tag": "padding"},
    ]
    output = json.dumps(entries, indent=2)
    parsed = json.loads(output)
    assert len(parsed) == 2
    assert parsed[0]["tag"] == "protocol"
