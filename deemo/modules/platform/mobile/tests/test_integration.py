"""移动端——集成测试"""
import pytest
import os
import sys
import tempfile
import struct

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from mobile_analysis import analyze_mobile_binary, OAT_MAGIC, MACHO_MAGICS
from wasm_analyzer import WasmParser, SectionType
from pac_bypass_analyzer import PACBypassAnalyzer, PAC_OPCODES, XPAC_OPCODES


def _build_minimal_oat():
    buf = bytearray()
    buf.extend(OAT_MAGIC)
    buf.extend(b'\x00' * 256)
    data_begin = struct.pack('<Q', 0x1000)
    exec_offset = struct.pack('<Q', 0x2000)
    image_base = struct.pack('<Q', 0x7000000000)
    dex_count = struct.pack('<I', 2)
    buf[16:24] = data_begin
    buf[24:32] = exec_offset
    buf[32:40] = image_base
    buf[48:52] = dex_count
    return bytes(buf)


_WASM_MAGIC = b'\x00asm'
_WASM_VERSION = struct.pack('<I', 1)


class TestCrossAnalyzerIntegration:
    """跨分析器集成测试。"""

    def test_mobile_and_wasm_can_coexist(self):
        """mobile_analysis与wasm_analyzer应在同一进程中协同工作。"""
        # mobile
        mob_result = analyze_mobile_binary('/nonexistent/file.bin')
        assert 'error' in mob_result

        # wasm
        wasm_data = _WASM_MAGIC + _WASM_VERSION
        parser = WasmParser(wasm_data)
        result = parser.parse()
        assert result.version == 1

    def test_oat_parsing_pipeline(self):
        """端到端OAT分析管道。"""
        buf = _build_minimal_oat()
        with tempfile.NamedTemporaryFile(suffix='.oat', delete=False) as f:
            f.write(buf)
            f.flush()
            try:
                result = analyze_mobile_binary(f.name, platform='android')
                assert result['platform'] == 'android'
                assert 'runtime_type' in result
                assert 'classes' in result
                assert 'vulnerabilities' in result
            finally:
                os.unlink(f.name)

    def test_macho_platform_detection(self):
        """Mach-O二进制应被正确识别为iOS。"""
        for magic in MACHO_MAGICS:
            with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
                f.write(magic + b'\x00' * 256)
                f.flush()
                try:
                    result = analyze_mobile_binary(f.name, platform='auto')
                    assert result['platform'] == 'ios'
                finally:
                    os.unlink(f.name)


class TestPACPipeline:
    """PAC旁路端到端分析管道。"""

    def test_pac_analyze_empty_binary(self):
        """空二进制应产生空结果。"""
        analyzer = PACBypassAnalyzer()
        leaks = analyzer.analyze(b'')
        assert len(leaks) == 0
        result = analyzer.result
        assert len(result.signing_gadgets) == 0

    def test_pac_multiple_gadgets_categorized(self):
        """混合PAC指令应被正确分类。"""
        from src.pac_bypass_analyzer import PAC_OPCODES, XPAC_OPCODES
        # 构建包含PACIA和XPACD的二进制
        pacia_val = list(PAC_OPCODES.values())[0]
        xpacd_val = list(XPAC_OPCODES.values())[0]
        buf = struct.pack('<II', pacia_val, xpacd_val)
        analyzer = PACBypassAnalyzer()
        analyzer.analyze(buf)
        result = analyzer.result
        assert len(result.signing_gadgets) >= 1
        assert len(result.strip_gadgets) >= 1


class TestWASMPipeline:
    """WASM端到端解析管道。"""

    def test_full_wasm_module_parse(self):
        """完整WASM模块解析——header + type + import + export + memory。"""
        data = _WASM_MAGIC + _WASM_VERSION
        # Type段: 1个函数类型 (0参数, 1返回i32)
        data += bytes([SectionType.TYPE, 4, 1, 0x60, 0, 1, 0x7F])
        # Import段: 1个导入 (env, fd_write, function, index 0)
        data += bytes([SectionType.IMPORT, 15, 3]) + b'env' + bytes([7]) + b'fd_write' + bytes([0, 0])
        # Memory段: 1个memory (initial=256)
        data += bytes([SectionType.MEMORY, 4, 1, 0, 128, 2])
        # Export段: 1个导出 ("memory", kind=2, index=0)
        data += bytes([SectionType.EXPORT, 8, 6]) + b'memory' + bytes([2, 0])
        parser = WasmParser(data)
        result = parser.parse()
        assert result.version == 1
        assert len(result.imports) >= 1
        assert len(result.exports) >= 1
        assert len(result.memories) >= 1


class TestErrorRecovery:
    """错误恢复与边界场景测试。"""

    def test_nonexistent_file_all_analyzers(self):
        """所有分析器应对不存在的文件优雅降级。"""
        # mobile
        r1 = analyze_mobile_binary('/nonexistent/file.bin')
        assert 'error' in r1
        # wasm——直接解析空数据
        parser = WasmParser(b'')
        r2 = parser.parse()
        assert r2.version == 0

    def test_empty_data_handling(self):
        """空数据输入不应崩溃。"""
        from wasm_analyzer import WasmParser
        parser = WasmParser(b'')
        result = parser.parse()
        assert len(result.functions) == 0
        assert len(result.vulnerabilities) == 0

    def test_invalid_wasm_magic(self):
        """无效WASM魔数应被正确拒绝。"""
        parser = WasmParser(b'XXXX' + _WASM_VERSION)
        assert parser.parse_header() is False
