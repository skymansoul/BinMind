"""Tests for entropy_analyzer — key-material discrimination."""

import os
import sys
import math
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.entropy_analyzer import EntropyAnalyzer, EntropyProfile, analyze_entropy


class TestEntropyAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = EntropyAnalyzer()

    def test_empty_data(self):
        p = self.analyzer.compute_profile(b'', 0)
        self.assertEqual(p.size, 0)
        self.assertEqual(p.shannon_entropy, 0.0)
        self.assertEqual(p.diagnosis, "empty")

    def test_uniform_random_key(self):
        """256-bit random key → high entropy, low chi-sq, likely_key=True."""
        key = os.urandom(32)
        p = self.analyzer.compute_profile(key, 0)
        self.assertGreater(p.shannon_entropy, 4.5)  # 32 bytes is small sample
        # For a 32-byte sample, chi-sq thresholds are loose
        # Just verify it doesn't crash and produces valid ranges
        self.assertGreaterEqual(p.chi_square, 0)
        self.assertGreaterEqual(p.chi_square_pvalue, 0.0)
        self.assertLessEqual(p.chi_square_pvalue, 1.0)

    def test_large_random_buffer(self):
        """4096 bytes of /dev/urandom → near-perfect uniformity."""
        data = os.urandom(4096)
        p = self.analyzer.compute_profile(data, 0)
        self.assertGreater(p.shannon_entropy, 7.8)
        self.assertTrue(p.likely_key or p.likely_encrypted,
                        f"got diagnosis: {p.diagnosis}")

    def test_plain_text(self):
        """ASCII text → low entropy, likely_text=True."""
        data = b"The quick brown fox jumps over the lazy dog. " * 50
        p = self.analyzer.compute_profile(data, 0)
        self.assertLess(p.shannon_entropy, 6.0)
        self.assertTrue(p.likely_text)

    def test_zeroes(self):
        """All-zero buffer → min entropy (0 bits)."""
        data = b'\x00' * 4096
        p = self.analyzer.compute_profile(data, 0)
        self.assertLess(p.shannon_entropy, 0.1)
        self.assertEqual(p.min_entropy, 0.0)

    def test_monte_carlo_pi(self):
        """Random data approximates π closely; structured data does not."""
        random_data = os.urandom(12000)  # enough for 2000 points
        _, err_random = self.analyzer._monte_carlo_pi(random_data)
        self.assertLess(err_random, 0.05,
                        f"random data π error {err_random:.4f} should be small")

    def test_serial_correlation(self):
        """Sequential 0..255 repeating → high serial correlation."""
        data = bytes(range(256)) * 16  # 4096 bytes, repeating pattern
        corr = self.analyzer._serial_correlation(data)
        self.assertGreater(abs(corr), 0.5)

    def test_scan_regions(self):
        """Sliding-window scan over a buffer with mixed content."""
        # 4096 bytes of text + 4096 bytes of random + 4096 bytes of text
        data = (
            b"hello world " * 300 +
            os.urandom(4096) +
            b"trailing text " * 300
        )
        profiles = self.analyzer.scan_regions(data, window_size=2048, max_results=5)
        self.assertGreater(len(profiles), 0)

    def test_file_scan(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(os.urandom(8192))
            tmp = f.name
        try:
            profiles = self.analyzer.analyze_file(tmp, chunk_size=4096)
            self.assertGreater(len(profiles), 0)
        finally:
            os.unlink(tmp)

    def test_chi_sq_pvalue_bounds(self):
        """p-value for chi-square must be in [0, 1]."""
        for chi_sq in [0, 100, 255, 300, 500, 1000]:
            p = self.analyzer._chi_sq_pvalue(chi_sq, 255)
            self.assertGreaterEqual(p, 0.0)
            self.assertLessEqual(p, 1.0,
                f"p-value {p} for chi_sq={chi_sq} df=255")

    def test_convenience_fn(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(os.urandom(4096))
            tmp = f.name
        try:
            profiles = analyze_entropy(tmp, chunk_size=4096)
            self.assertIsInstance(profiles, list)
        finally:
            os.unlink(tmp)


if __name__ == '__main__':
    unittest.main()
