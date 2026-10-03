# hardware_hash 正确性测试集
import pytest
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.hardware_hash import (
    FastHasher, HashAlgorithm, HashManager, HashResult,
    compute_data_hash, compute_fast_hash, verify_file_integrity,
    generate_hash_signature, get_hash_manager,
)

SAMPLE_DATA = b'The quick brown fox jumps over the lazy dog. ' * 50
SHORT_DATA = b'Hello, BinMind crypto module!'


class TestFastHasher:
    def test_sha256_correctness(self):
        hasher = FastHasher(HashAlgorithm.SHA256)
        hasher.update(SAMPLE_DATA)
        expected = hashlib.sha256(SAMPLE_DATA).hexdigest()
        assert hasher.hexdigest() == expected

    def test_sha512_correctness(self):
        hasher = FastHasher(HashAlgorithm.SHA512)
        hasher.update(SAMPLE_DATA)
        expected = hashlib.sha512(SAMPLE_DATA).hexdigest()
        assert hasher.hexdigest() == expected

    def test_md5_correctness(self):
        hasher = FastHasher(HashAlgorithm.MD5)
        hasher.update(SAMPLE_DATA)
        expected = hashlib.md5(SAMPLE_DATA).hexdigest()
        assert hasher.hexdigest() == expected

    def test_sha1_correctness(self):
        hasher = FastHasher(HashAlgorithm.SHA1)
        hasher.update(SAMPLE_DATA)
        expected = hashlib.sha1(SAMPLE_DATA).hexdigest()
        assert hasher.hexdigest() == expected

    def test_reset_functionality(self):
        hasher = FastHasher(HashAlgorithm.SHA256)
        hasher.update(b'data1')
        d1 = hasher.hexdigest()
        hasher.reset()
        hasher.update(b'data2')
        d2 = hasher.hexdigest()
        assert d1 != d2

    def test_incremental_update(self):
        hasher1 = FastHasher(HashAlgorithm.SHA256)
        hasher1.update(SAMPLE_DATA[:1000])
        hasher1.update(SAMPLE_DATA[1000:])
        hasher2 = FastHasher(HashAlgorithm.SHA256)
        hasher2.update(SAMPLE_DATA)
        assert hasher1.hexdigest() == hasher2.hexdigest()

    def test_digest_size(self):
        hasher = FastHasher(HashAlgorithm.SHA256)
        assert hasher.get_digest_size() == 32
        hasher_md5 = FastHasher(HashAlgorithm.MD5)
        assert hasher_md5.get_digest_size() == 16


class TestHashManager:
    def test_compute_data_hash(self):
        mgr = HashManager()
        result = mgr.compute_data_hash(SHORT_DATA, HashAlgorithm.SHA256)
        assert isinstance(result, HashResult)
        assert result.hex_digest == hashlib.sha256(SHORT_DATA).hexdigest()
        assert result.file_size == len(SHORT_DATA)

    def test_cache_functionality(self):
        mgr = HashManager()
        mgr.clear_cache()
        result1 = mgr.compute_data_hash(b'test_data_42', HashAlgorithm.SHA256)
        result2 = mgr.compute_data_hash(b'test_data_42', HashAlgorithm.SHA256)
        assert result1.hex_digest == result2.hex_digest


class TestConvenienceFunctions:
    def test_compute_data_hash_top_level(self):
        result = compute_data_hash(SHORT_DATA, 'sha256')
        assert result.hex_digest == hashlib.sha256(SHORT_DATA).hexdigest()

    def test_compute_fast_hash(self):
        digest = compute_fast_hash(SAMPLE_DATA)
        # xxhash64=16字符hex(可用时)，否则MD5/SHA256降级=32/64
        assert len(digest) >= 16

    def test_generate_hash_signature(self):
        sig = generate_hash_signature(SAMPLE_DATA, length=8)
        assert len(sig) == 8
        assert all(c in '0123456789abcdef' for c in sig)

    def test_hash_manager_singleton(self):
        mgr1 = get_hash_manager()
        mgr2 = get_hash_manager()
        assert mgr1 is mgr2
