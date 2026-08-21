"""移动端: WASM解析器测试"""
import struct
import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wasm_analyzer import WasmParser, WasmAnalysisResult, WASIAnalyzer, SectionType, ValType
from src.wasm_analyzer import Memory, Import, Export, Function, TypeEntry, Global

_MAGIC = b'\x00asm'
_VERSION = struct.pack('<I', 1)


def _build_wasm(*sections: bytes) -> bytes:
  return _MAGIC + _VERSION + b''.join(sections)


class TestWasmMagic:
  """验证WASM魔数与版本解析。"""

  def test_valid_magic_and_version(self):
    data = _MAGIC + _VERSION
    parser = WasmParser(data)
    assert parser.parse_header() is True
    assert parser.result.version == 1

  def test_invalid_magic_rejected(self):
    parser = WasmParser(b'XXXX' + _VERSION)
    assert parser.parse_header() is False

  def test_short_data_returns_default(self):
    parser = WasmParser(b'\x00')
    parser.parse_header()
    assert parser.result.version == 0


class TestSectionParsing:
  """验证各WASM段类型的解析。"""

  def test_empty_type_section(self):
    data = _build_wasm(
      bytes([SectionType.TYPE, 0])
    )
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.types) == 0

  def test_single_func_type(self):
    data = _build_wasm(
      bytes([SectionType.TYPE,
        1,            # count = 1
        0x60,         # form = func
        0,            # param count = 0
        1, 0x7F,      # return count = 1, type = i32
      ])
    )
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.types) == 1
    assert result.types[0].return_type == ValType.I32

  def test_import_section_wasi(self):
    data = _build_wasm(
      bytes([SectionType.IMPORT,
        1,                                    # count = 1
        3, ord('e'), ord('n'), ord('v'),      # module "env"
        7,                                    # name length
        ord('f'), ord('d'), ord('_'),
        ord('w'), ord('r'), ord('i'),
        ord('t'), ord('e'),                   # name "fd_write"
        0,                                    # kind = function
        0,                                    # index
      ])
    )
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.imports) == 1
    imp = result.imports[0]
    assert imp.module == 'env'
    assert imp.name == 'fd_write'

  def test_memory_section(self):
    data = _build_wasm(
      bytes([SectionType.MEMORY,
        1,         # count = 1
        0,         # flags = 0 (无max)
        2,         # initial pages = 2
      ])
    )
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.memories) == 1
    assert result.memories[0].initial == 2
    assert result.memories[0].maximum == 0

  def test_export_section(self):
    data = _build_wasm(
      bytes([SectionType.EXPORT,
        1,                                    # count = 1
        6,                                    # name length
        ord('m'), ord('e'), ord('m'),
        ord('o'), ord('r'), ord('y'),         # name "memory"
        2,                                    # kind = memory
        0,                                    # index
      ])
    )
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.exports) == 1
    assert result.exports[0].name == 'memory'
    assert result.exports[0].kind == 2


class TestVulnerabilityDetection:
  """验证漏洞检测逻辑。"""

  def test_dangerous_import_detected(self):
    data = _build_wasm(
      bytes([SectionType.IMPORT,
        1, 3, ord('e'), ord('n'), ord('v'), 7,
        ord('f'), ord('d'), ord('_'),
        ord('w'), ord('r'), ord('i'),
        ord('t'), ord('e'), 0, 0,
      ])
    )
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.vulnerabilities) >= 1
    assert any('fd_write' in str(v.get('description', '')) for v in result.vulnerabilities)

  def test_unbounded_memory_detected(self):
    data = _build_wasm(
      bytes([SectionType.MEMORY, 1, 0, 2])
    )
    parser = WasmParser(data)
    result = parser.parse()
    mem_vulns = [v for v in result.vulnerabilities if '无上限' in v.get('type', '')]
    assert len(mem_vulns) >= 1

  def test_no_vulns_on_clean_module(self):
    data = _build_wasm()
    parser = WasmParser(data)
    result = parser.parse()
    assert len(result.vulnerabilities) == 0


class TestWASI:
  """验证WASI分析器功能。"""

  def test_wasi_usage_basic(self):
    data = _build_wasm(
      bytes([SectionType.IMPORT,
        1, 21,
        ord('w'), ord('a'), ord('s'), ord('i'),
        ord('_'), ord('s'), ord('n'), ord('a'),
        ord('p'), ord('s'), ord('h'), ord('o'),
        ord('t'), ord('_'), ord('p'), ord('r'),
        ord('e'), ord('v'), ord('i'), ord('e'),
        ord('w'),                                         # module
        8,
        ord('f'), ord('d'), ord('_'),
        ord('w'), ord('r'), ord('i'),
        ord('t'), ord('e'),                               # name
        0, 0,
      ])
    )
    wasi = WASIAnalyzer(data)
    info = wasi.analyze_wasi_usage()
    assert 'fd_write' in info

  def test_capability_classification(self):
    data = _build_wasm(
      bytes([SectionType.IMPORT,
        2,                             # 两个导入
        21,
        ord('w'), ord('a'), ord('s'), ord('i'),
        ord('_'), ord('s'), ord('n'), ord('a'),
        ord('p'), ord('s'), ord('h'), ord('o'),
        ord('t'), ord('_'), ord('p'), ord('r'),
        ord('e'), ord('v'), ord('i'), ord('e'),
        ord('w'),
        8,
        ord('f'), ord('d'), ord('_'),
        ord('w'), ord('r'), ord('i'),
        ord('t'), ord('e'),
        0, 0,
        3, ord('e'), ord('n'), ord('v'),
        8,
        ord('f'), ord('d'), ord('_'),
        ord('r'), ord('e'), ord('a'), ord('d'),
        0, 0,
      ])
    )
    wasi = WASIAnalyzer(data)
    caps = wasi.analyze_capabilities()
    assert len(caps['file_system']) >= 2
