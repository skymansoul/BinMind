# Tests: deduplication
import hashlib
import unittest

from src.dedup import (
    SimHashDedup, SimHashIndex, MinHashDedup, OPHMinHash,
    cdc_chunk, cdc_chunk_iter, cdc_chunk_stats,
    BloomFilter, CuckooFilter, HyperLogLog, TDigest,
    _fnv1a_64, _hamming_dist,
)


class TestBloomFilter(unittest.TestCase):

    def test_add_and_check(self):
        bf = BloomFilter(m_bits=1024, k_hashes=4)
        bf.add(b"hello")
        self.assertTrue(bf.might_contain(b"hello"))
        self.assertFalse(bf.might_contain(b"world"))

    def test_no_false_negative(self):
        bf = BloomFilter(m_bits=8192, k_hashes=5)
        for i in range(500):
            bf.add(f"item_{i}".encode())
        for i in range(500):
            self.assertTrue(bf.might_contain(f"item_{i}".encode()))

    def test_approx_count(self):
        bf = BloomFilter(m_bits=4096, k_hashes=4)
        for i in range(200):
            bf.add(f"x_{i}".encode())
        self.assertEqual(bf.approx_count, 200)

    def test_estimated_fpr(self):
        bf = BloomFilter(m_bits=4096, k_hashes=4)
        self.assertEqual(bf.estimated_fpr(), 0.0)
        for i in range(50):
            bf.add(f"fpr_{i}".encode())
        fpr = bf.estimated_fpr()
        self.assertGreater(fpr, 0.0)
        self.assertLess(fpr, 1.0)


class TestCuckooFilter(unittest.TestCase):

    def test_insert_and_contains(self):
        cf = CuckooFilter(capacity=4096)
        self.assertTrue(cf.insert(b"alpha"))
        self.assertTrue(cf.contains(b"alpha"))
        self.assertFalse(cf.contains(b"beta"))

    def test_delete(self):
        cf = CuckooFilter(capacity=4096)
        cf.insert(b"omega")
        self.assertTrue(cf.contains(b"omega"))
        self.assertTrue(cf.delete(b"omega"))
        self.assertFalse(cf.contains(b"omega"))

    def test_delete_nonexistent(self):
        cf = CuckooFilter(capacity=4096)
        self.assertFalse(cf.delete(b"ghost"))

    def test_capacity(self):
        cf = CuckooFilter(capacity=256)
        inserted = 0
        for i in range(500):
            if cf.insert(f"item_{i}".encode()):
                inserted += 1
        self.assertGreater(inserted, 0)
        self.assertLessEqual(cf.load_factor, 1.0)


class TestHyperLogLog(unittest.TestCase):

    def test_estimate_small(self):
        hll = HyperLogLog(p=8)
        for i in range(200):
            hll.add(f"u_{i}".encode())
        est = hll.estimate()
        self.assertGreater(est, 150)
        self.assertLess(est, 300)

    def test_merge(self):
        a = HyperLogLog(p=8)
        b = HyperLogLog(p=8)
        for i in range(100):
            a.add(f"a_{i}".encode())
        for i in range(100):
            b.add(f"b_{i}".encode())
        merged = a.merge(b)
        self.assertGreater(merged.estimate(), 150)

    def test_density(self):
        hll = HyperLogLog(p=8)
        self.assertAlmostEqual(hll.density(), 0.0)
        for i in range(50):
            hll.add(f"d_{i}".encode())
        self.assertGreater(hll.density(), 0.0)


class TestTDigest(unittest.TestCase):

    def test_basic_quantiles(self):
        td = TDigest(delta=50.0)
        for i in range(1000):
            td.add(float(i))
        p50 = td.quantile(0.50)
        p95 = td.quantile(0.95)
        self.assertGreater(p50, 400)
        self.assertLess(p50, 600)
        self.assertGreater(p95, 900)

    def test_merge(self):
        a = TDigest(delta=50.0)
        b = TDigest(delta=50.0)
        for i in range(300):
            a.add(float(i))
        for i in range(300, 600):
            b.add(float(i))
        merged = a.merge(b)
        self.assertEqual(len(merged), 600)
        # 验证合并后仍能返回分位数（不崩溃）
        _ = merged.quantile(0.50)
        _ = merged.quantile(0.99)

    def test_add_many(self):
        td = TDigest(delta=50.0)
        td.add_many([float(i) for i in range(500)])
        self.assertEqual(len(td), 500)
        self.assertGreater(td.quantile(0.90), 400)


class TestSimHash(unittest.TestCase):

    def setUp(self):
        self.sh = SimHashDedup(bits=128)

    def test_identical_data(self):
        data = b"A" * 10000
        fp1 = self.sh.fingerprint(data)
        fp2 = self.sh.fingerprint(data)
        self.assertEqual(fp1, fp2)
        self.assertAlmostEqual(self.sh.similarity(fp1, fp2), 1.0)

    def test_different_data(self):
        fp1 = self.sh.fingerprint(b"A" * 10000)
        fp2 = self.sh.fingerprint(b"B" * 10000)
        sim = self.sh.similarity(fp1, fp2)
        self.assertLess(sim, 0.7)

    def test_similar_data(self):
        base = bytearray(10000)
        modified = bytearray(base)
        modified[5000:5005] = b'\xFF\xFF\xFF\xFF\xFF'
        fp1 = self.sh.fingerprint(bytes(base))
        fp2 = self.sh.fingerprint(bytes(modified))
        sim = self.sh.similarity(fp1, fp2)
        self.assertGreater(sim, 0.85)

    def test_small_data(self):
        fp = self.sh.fingerprint(b"hi")
        self.assertIsInstance(fp, int)
        self.assertGreater(fp, 0)

    def test_band_fingerprint(self):
        fp = 0xABCDEF0123456789ABCDEF0123456789
        bands = SimHashDedup.band_fingerprint(fp, bits=128, bands=16)
        self.assertEqual(len(bands), 16)
        for bk in bands:
            self.assertLess(bk, 256)


class TestSimHashIndex(unittest.TestCase):

    def test_add_and_query_identical(self):
        idx = SimHashIndex(bands=16, threshold=0.85)
        sh = SimHashDedup(bits=128)
        data = b"X" * 8192
        fp = sh.fingerprint(data)
        fp_id = idx.add(fp)
        results = idx.query(fp, k=5)
        self.assertGreaterEqual(len(results), 1)
        self.assertEqual(results[0][0], fp_id)

    def test_query_no_match(self):
        idx = SimHashIndex(bands=16, threshold=0.95)
        sh = SimHashDedup(bits=128)
        fp_a = sh.fingerprint(b"A" * 8192)
        fp_b = sh.fingerprint(b"B" * 8192)
        idx.add(fp_a)
        results = idx.query(fp_b, k=5)
        self.assertEqual(len(results), 0)

    def test_stats(self):
        idx = SimHashIndex()
        for i in range(10):
            idx.add(i * 0x11111111)
        s = idx.stats()
        self.assertEqual(s["total"], 10)


class TestMinHash(unittest.TestCase):

    def setUp(self):
        self.mh = MinHashDedup(num_perm=64)

    def test_identical_sets(self):
        s = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
        sig1 = self.mh.signature(s)
        sig2 = self.mh.signature(s)
        self.assertEqual(sig1, sig2)

    def test_disjoint_sets(self):
        s1 = set(range(100))
        s2 = set(range(100, 200))
        sim = self.mh.similarity(self.mh.signature(s1), self.mh.signature(s2))
        self.assertLess(sim, 0.1)

    def test_empty_set(self):
        sig = self.mh.signature(set())
        self.assertEqual(len(sig), 64)


class TestOPHMinHash(unittest.TestCase):

    def test_signature_size(self):
        oph = OPHMinHash(num_bins=64)
        sig = oph.signature()
        self.assertEqual(len(sig), 64)

    def test_add_and_similarity(self):
        a = OPHMinHash(num_bins=128)
        b = OPHMinHash(num_bins=128)
        for i in range(500):
            a.add(hash(f"set_a_{i}"))
            b.add(hash(f"set_a_{i}"))
        sim = a.similarity(b)
        self.assertGreater(sim, 0.8)

    def test_disjoint_similarity(self):
        a = OPHMinHash(num_bins=128)
        b = OPHMinHash(num_bins=128)
        for i in range(200):
            a.add(hash(f"x_{i}"))
        for i in range(200, 400):
            b.add(hash(f"x_{i}"))
        sim = a.similarity(b)
        self.assertLess(sim, 0.3)

    def test_add_many(self):
        oph = OPHMinHash(num_bins=64)
        oph.add_many({hash(f"m_{i}") for i in range(100)})
        self.assertEqual(len(oph.signature()), 64)


class TestCDCChunk(unittest.TestCase):

    def test_small_data(self):
        chunks = cdc_chunk(b"small", min_chunk=1024)
        self.assertEqual(len(chunks), 1)

    def test_large_data(self):
        data = b"A" * 50
        chunks = cdc_chunk(data, min_chunk=4, max_chunk=16, mask_bits=2)
        self.assertGreaterEqual(len(chunks), 1)

    def test_empty(self):
        self.assertEqual(len(cdc_chunk(b"")), 1)

    def test_normalize_disabled(self):
        data = b"B" * 8192 + b"C" * 8192
        chunks = cdc_chunk(data, min_chunk=512, max_chunk=4096, mask_bits=10, normalize=False)
        self.assertGreaterEqual(len(chunks), 1)

    def test_cdc_chunk_iter(self):
        data = b"D" * 5000
        chunks = list(cdc_chunk_iter(data, min_chunk=256, max_chunk=2048, mask_bits=8))
        total = sum(len(c) for _, c in chunks)
        self.assertEqual(total, len(data))

    def test_cdc_chunk_stats(self):
        data = b"E" * 8192
        chunks = cdc_chunk(data, min_chunk=256, max_chunk=2048, mask_bits=9)
        stats = cdc_chunk_stats(chunks)
        self.assertIn("p50", stats)


class TestFNV1a(unittest.TestCase):

    def test_known_value(self):
        h = _fnv1a_64(b"hello")
        self.assertEqual(h, _fnv1a_64(b"hello"))

    def test_different_inputs(self):
        self.assertNotEqual(_fnv1a_64(b"abc"), _fnv1a_64(b"abd"))

    def test_seed_variation(self):
        self.assertNotEqual(_fnv1a_64(b"test", seed=42), _fnv1a_64(b"test", seed=99))


class TestHammingDist(unittest.TestCase):

    def test_identical(self):
        self.assertEqual(_hamming_dist(0xFFFF, 0xFFFF), 0)

    def test_all_different(self):
        self.assertEqual(_hamming_dist(0x0000, 0xFFFF), 16)

    def test_one_bit(self):
        self.assertEqual(_hamming_dist(0x0001, 0x0000), 1)


if __name__ == "__main__":
    unittest.main()
