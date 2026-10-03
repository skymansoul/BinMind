# 只测了PE MZ头，ELF/Mach-O的按需补充

import unittest
import os as _os
import tempfile as _tmp
import importlib.util as _iu

_PARENT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_MOD_PATH = _os.path.join(_PARENT, 'modules', 'binary_format_loader.py')


def _load_mod():
    """动态加载模块 -- conftest那边有时候路径不对，手动来"""
    spec = _iu.spec_from_file_location('binary_format_loader', _MOD_PATH)
    mod = _iu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestBinaryFormatLoader(unittest.TestCase):

    def test_loader_initialization(self):
        mod = _load_mod()
        loader = mod.BinaryFormatLoader()
        self.assertIsNotNone(loader)

    def test_detect_format_pe(self):
        """MZ头 -> PE格式"""
        mod = _load_mod()
        loader = mod.BinaryFormatLoader()
        if loader is None:
            self.skipTest("loader init failed")

        with _tmp.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(b'MZ\x90\x00' + bytes([0x00] * 100))
            tp = f.name

        try:
            result = loader.detect_format(tp)
            self.assertEqual(result, mod.BinaryFormat.PE)
        finally:
            _os.unlink(tp)


if __name__ == '__main__':
    unittest.main()
