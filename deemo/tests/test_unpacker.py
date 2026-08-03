"""
Unpacker module tests -- enriched with NRV2B decompressor, entropy analysis.
"""
import unittest
import os
_MOD_DEBUG = False
import tempfile
from unittest.mock import patch, MagicMock

from modules.analysis.deobfuscation.unpacker import (
    Unpacker,
    _shannon_entropy,
    _block_entropy_profile,
    _nrv2b_decompress,
    _find_oep_heuristic,
)


class TestUnpacker(unittest.TestCase):
    def setUp(self):
        self.unpacker = Unpacker()
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_detect_packer_empty_path(self):
        result = self.unpacker.detect_packer("")
        self.assertEqual(result, ('unknown', 0.0))

    def test_detect_packer_nonexistent_file(self):
        result = self.unpacker.detect_packer("/nonexistent/file.bin")
        self.assertEqual(result, ('unknown', 0.0))

    def test_detect_packer_elf_file(self):
        elf_header = b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        test_file = os.path.join(self.m_tmp, 'test.elf')
        with open(test_file, 'wb') as f:
            f.write(elf_header)
        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result[0], 'unknown')

    def test_detect_packer_pe_file(self):
        pe_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
        test_file = os.path.join(self.m_tmp, 'test.exe')
        with open(test_file, 'wb') as f:
            f.write(pe_header)
        result = self.unpacker.detect_packer(test_file)
        self.assertEqual(result[0], 'unknown')

    def test_is_packed_empty_path(self):
        result = self.unpacker.is_packed("")
        self.assertFalse(result)

    def test_unpack_if_needed_nonexistent(self):
        result = self.unpacker.unpack_if_needed("/nonexistent/file.bin")
        self.assertIsNone(result)

    @patch('subprocess.run')
    def test_unpack_with_upx_success(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_run.return_value = mock_result
        test_file = os.path.join(self.m_tmp, 'packed.exe')
        with open(test_file, 'wb') as f:
            f.write(b'MZ\x90')
        with patch.object(self.unpacker, 'detect_packer', return_value=('UPX', 0.9)):
            result = self.unpacker.unpack_if_needed(test_file)
            self.assertIsNotNone(result)
            self.assertTrue(result.get('unpacked', False))

    @patch('subprocess.run')
    def test_unpack_with_upx_failure(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        test_file = os.path.join(self.m_tmp, 'packed.exe')
        with open(test_file, 'wb') as f:
            f.write(b'MZ\x90')
        with patch.object(self.unpacker, 'detect_packer', return_value=('UPX', 0.9)):
            result = self.unpacker.unpack_if_needed(test_file)
            self.assertIsNotNone(result)
            self.assertFalse(result.get('unpacked', False))

    def test_calculate_entropy(self):
        high_entropy_data = os.urandom(256)
        low_entropy_data = b'\x00' * 256
        high_entropy = self.unpacker._calculate_entropy(high_entropy_data)
        low_entropy = self.unpacker._calculate_entropy(low_entropy_data)
        self.assertTrue(high_entropy > 7.0)
        self.assertTrue(low_entropy < 1.0)

    def test_detect_obfuscation_no_binary(self):
        result = self.unpacker.detect_obfuscation(None)
        self.assertEqual(result, {'obfuscated': False, 'techniques': [], 'severity': 'low'})

    def test_detected_packer_property(self):
        self.assertIsNone(self.unpacker.detected_packer)

    def test_detection_method_property(self):
        self.assertIsInstance(self.unpacker.detection_method, str)


class TestShannonEntropy(unittest.TestCase):
    def test_uniform_data_max_entropy(self):
        import random
        data = bytes(random.getrandbits(8) for _ in range(256))
        entropy = _shannon_entropy(data)
        self.assertGreater(entropy, 5.0)

    def test_all_zeros_min_entropy(self):
        entropy = _shannon_entropy(b'\x00' * 1000)
        self.assertAlmostEqual(entropy, 0.0, places=1)

    def test_empty_data(self):
        entropy = _shannon_entropy(b'')
        self.assertEqual(entropy, 0.0)


class TestBlockEntropyProfile(unittest.TestCase):
    def test_uniform_data(self):
        profile = _block_entropy_profile(b'\x41' * 1024, block_size=256)
        self.assertIsInstance(profile, dict)

    def test_empty_data(self):
        profile = _block_entropy_profile(b'', block_size=256)
        self.assertIsInstance(profile, dict)


class TestNRV2BDecompress(unittest.TestCase):
    def test_empty_data(self):
        result = _nrv2b_decompress(b'', 100)
        self.assertIsNone(result)

    def test_short_data(self):
        result = _nrv2b_decompress(b'\x00\x01', 10)
        self.assertIsNone(result)


class TestFindOEP(unittest.TestCase):
    def test_no_ret_pattern(self):
        result = _find_oep_heuristic(b'\x90' * 100)
        self.assertIsNone(result)

    def test_small_data(self):
        result = _find_oep_heuristic(b'\x90')
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
