# binarysign和同源性search的test: BinarySigner / HomologySearcher / convenience function
# 注意: _calculate_import_hashdependencybinary_info里的'imports'field格式

import os
import tempfile
import shutil
import unittest
import json
from unittest.mock import patch, MagicMock

from modules.binary_signing import (
    BinarySigner,
    HomologySearcher,
    BinarySignature,
    HomologyMatch,
    generate_binary_signature,
    search_homology,
    SSDEEP_AVAILABLE,
    TLSH_AVAILABLE,
    NUMPY_AVAILABLE
)


class TestBinarySignature(unittest.TestCase):
    """BinarySignature dataclass: 基本field + hashes + functions"""

    def test_init(self):
        sig = BinarySignature(
            binary_path="/path/to/binary",
            binary_name="test_binary"
        )
        self.assertEqual(sig.binary_path, "/path/to/binary")
        self.assertEqual(sig.binary_name, "test_binary")
        self.assertEqual(sig.sha256, "")

    def test_with_hashes(self):
        sig = BinarySignature(
            binary_path="/path/to/binary",
            binary_name="test",
            sha256="abc123",
            sha1="def456",
            md5="ghi789",
            ssdeep_hash="3:abc:def"
        )
        self.assertEqual(sig.sha256, "abc123")
        self.assertEqual(sig.ssdeep_hash, "3:abc:def")

    def test_with_functions(self):
        sig = BinarySignature(
            binary_path="/path/to/binary",
            binary_name="test",
            function_count=10,
            function_signatures=[
                {'name': 'main', 'address': '0x1000'}
            ]
        )
        self.assertEqual(sig.function_count, 10)
        self.assertEqual(len(sig.function_signatures), 1)


class TestHomologyMatch(unittest.TestCase):
    """HomologyMatch: similarity_score/match_type/可选field"""

    def test_init(self):
        match = HomologyMatch(
            matched_binary="similar_binary",
            matched_signature_id=1,
            similarity_score=0.85,
            match_type="ssdeep"
        )
        self.assertEqual(match.matched_binary, "similar_binary")
        self.assertEqual(match.similarity_score, 0.85)
        self.assertEqual(match.match_type, "ssdeep")

    def test_with_details(self):
        """勒索软件家族, critical威胁, match到了2functions"""
        match = HomologyMatch(
            matched_binary="test",
            matched_signature_id=1,
            similarity_score=0.9,
            match_type="combined",
            malware_family="ransomware",
            threat_level="critical",
            matched_functions=["func1", "func2"]
        )
        self.assertEqual(match.malware_family, "ransomware")
        self.assertEqual(match.threat_level, "critical")
        self.assertEqual(len(match.matched_functions), 2)


class TestBinarySigner(unittest.TestCase):
    """BinarySigner: hash计算/signature生成/save/get"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_signatures.db')

        self.temp_binary = os.path.join(self.temp_dir, 'test_binary')
        with open(self.temp_binary, 'wb') as f:
            f.write(b'\x7fELF')
            f.write(b'\x00' * 100)
            f.write(b'malware_string')
            f.write(b'\x00' * 100)

        self.signer = BinarySigner(db_path=self.db_path)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_init(self):
        self.assertIsNotNone(self.signer.db_path)
        self.assertTrue(os.path.exists(self.db_path))

    def test_calculate_hashes(self):
        """sha256=64, sha1=40, md5=32 字节"""
        hashes = self.signer._calculate_hashes(self.temp_binary)
        self.assertIn('sha256', hashes)
        self.assertIn('sha1', hashes)
        self.assertIn('md5', hashes)
        self.assertEqual(len(hashes['sha256']), 64)
        self.assertEqual(len(hashes['sha1']), 40)
        self.assertEqual(len(hashes['md5']), 32)

    @unittest.skipIf(not SSDEEP_AVAILABLE, "ssdeep not installed")
    def test_calculate_ssdeep(self):
        ssdeep_hash = self.signer._calculate_ssdeep(self.temp_binary)
        if ssdeep_hash:
            self.assertGreater(len(ssdeep_hash), 0)

    @unittest.skipIf(not TLSH_AVAILABLE, "tlsh not installed")
    def test_calculate_tlsh(self):
        """TLSH需要>=256字节"""
        large_binary = os.path.join(self.temp_dir, 'large_binary')
        with open(large_binary, 'wb') as f:
            f.write(b'\x00' * 300)

        tlsh_hash = self.signer._calculate_tlsh(large_binary)
        if tlsh_hash:
            self.assertEqual(len(tlsh_hash), 72)

    def test_calculate_import_hash(self):
        """有imports的binary_info => 32字符hash"""
        binary_info = {
            'imports': {
                'libc.so.6': ['printf', 'malloc'],
                'libpthread': ['pthread_create'],
                'dangerous_functions': ['gets', 'strcpy']
            }
        }
        import_hash = self.signer._calculate_import_hash(binary_info)
        self.assertGreater(len(import_hash), 0)
        self.assertEqual(len(import_hash), 32)

    def test_calculate_import_hash_empty(self):
        """空dict => 空string"""
        import_hash = self.signer._calculate_import_hash({})
        self.assertEqual(import_hash, "")

    def test_calculate_section_hash(self):
        binary_info = {
            'sections': [
                {'name': '.text', 'size': 100, 'permissions': 'r-x'},
                {'name': '.data', 'size': 50, 'permissions': 'rw-'}
            ]
        }
        section_hash = self.signer._calculate_section_hash(binary_info)
        self.assertGreater(len(section_hash), 0)

    def test_generate_feature_vector(self):
        """gets(buf) + strcpy => vectorlength==VECTOR_DIM, strcpy count>0"""
        code = """
        int main() {
            char buf[100];
            gets(buf);
            strcpy(buf, "test");
            return 0;
        }
        """
        vector = self.signer._generate_feature_vector(code)
        self.assertEqual(len(vector), self.signer.VECTOR_DIM)
        self.assertGreater(vector[8], 0)

    def test_extract_function_signatures(self):
        binary_info = {
            'symbols': {
                'main': {'address': 0x1000, 'size': 100},
                'func1': {'address': 0x2000, 'size': 50}
            }
        }
        signatures = self.signer._extract_function_signatures(binary_info)
        self.assertGreater(len(signatures), 0)

    def test_generate_signature(self):
        """生成signature后binary_name要对, sha256不能空"""
        binary_info = {
            'arch': 'x86_64',
            'bits': 64,
            'format': 'ELF',
            'imports': {'libc': ['printf']},
            'symbols': {'main': 0x1000}
        }
        signature = self.signer.generate_signature(
            binary_path=self.temp_binary,
            binary_info=binary_info
        )
        self.assertEqual(signature.binary_name, 'test_binary')
        self.assertGreater(len(signature.sha256), 0)

    def test_save_signature(self):
        signature = BinarySignature(
            binary_path=self.temp_binary,
            binary_name="test",
            sha256="abc123",
            function_count=5,
            function_signatures=[{'name': 'main'}]
        )
        sig_id = self.signer.save_signature(signature)
        self.assertIsNotNone(sig_id)
        self.assertGreater(sig_id, 0)

    def test_get_signature_by_sha256(self):
        """先save再get, 取出来的binary_name要对"""
        signature = BinarySignature(
            binary_path=self.temp_binary,
            binary_name="test",
            sha256="test_sha256_value"
        )
        self.signer.save_signature(signature)

        result = self.signer.get_signature_by_sha256("test_sha256_value")
        self.assertIsNotNone(result)
        self.assertEqual(result['binary_name'], 'test')


class TestHomologySearcher(unittest.TestCase):
    """HomologySearcher: 各种search和比较"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_signatures.db')

        self.temp_binary = os.path.join(self.temp_dir, 'test_binary')
        with open(self.temp_binary, 'wb') as f:
            f.write(b'\x00' * 300)

        self.signer = BinarySigner(db_path=self.db_path)
        self.searcher = HomologySearcher(db_path=self.db_path)

        self.test_signature = BinarySignature(
            binary_path=self.temp_binary,
            binary_name="test_binary",
            sha256="test_hash_123",
            import_hash="import_hash_abc",
            malware_family="test_family",
            threat_level="high"
        )
        self.signer.save_signature(self.test_signature)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_init(self):
        self.assertIsNotNone(self.searcher.db_path)

    def test_compare_vectors(self):
        """两个一样的vector => similarity~=1.0"""
        vec1 = [1.0, 2.0, 3.0, 4.0]
        vec2 = [1.0, 2.0, 3.0, 4.0]
        similarity = self.searcher._compare_vectors(vec1, vec2)
        self.assertAlmostEqual(similarity, 1.0, places=2)

    def test_compare_vectors_different(self):
        """正交vector => similarity~=0.0"""
        vec1 = [1.0, 0.0, 0.0]
        vec2 = [0.0, 1.0, 0.0]
        similarity = self.searcher._compare_vectors(vec1, vec2)
        self.assertAlmostEqual(similarity, 0.0, places=2)

    def test_search_by_import_hash(self):
        matches = self.searcher.search_by_import_hash("import_hash_abc")
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].match_type, 'import_hash')
        self.assertEqual(matches[0].similarity_score, 1.0)

    def test_search_by_import_hash_no_match(self):
        matches = self.searcher.search_by_import_hash("nonexistent_hash")
        self.assertEqual(len(matches), 0)

    @unittest.skipIf(not SSDEEP_AVAILABLE, "ssdeep not installed")
    def test_compare_ssdeep(self):
        """相同hash => 100"""
        hash1 = "3:abc:def"
        hash2 = "3:abc:def"
        similarity = self.searcher._compare_ssdeep(hash1, hash2)
        self.assertEqual(similarity, 100)

    @unittest.skipIf(not TLSH_AVAILABLE, "tlsh not installed")
    def test_compare_tlsh(self):
        """相同hash => distance=0"""
        hash1 = "T1A0B0C0D0E0F0G0H0I0J0K0L0M0N0O0P0Q0R0S0T0U0V0W0X0Y0Z0"
        hash2 = "T1A0B0C0D0E0F0G0H0I0J0K0L0M0N0O0P0Q0R0S0T0U0V0W0X0Y0Z0"
        distance = self.searcher._compare_tlsh(hash1, hash2)
        self.assertEqual(distance, 0)

    def test_search_by_semantic_vector(self):
        """128维全1vector, threshold=0.9"""
        sig = BinarySignature(
            binary_path=self.temp_binary,
            binary_name="vector_test",
            sha256="vector_hash",
            semantic_vector=[1.0] * 128
        )
        self.signer.save_signature(sig)

        query_vector = [1.0] * 128
        matches = self.searcher.search_by_semantic_vector(query_vector, threshold=0.9)
        self.assertGreater(len(matches), 0)

    def test_comprehensive_search(self):
        """综合search应该foundimport_hashmatch"""
        signature = BinarySignature(
            binary_path=self.temp_binary,
            binary_name="search_test",
            sha256="search_hash",
            import_hash="import_hash_abc"
        )
        matches = self.searcher.comprehensive_search(signature, limit=5)
        self.assertGreater(len(matches), 0)

    def test_update_threat_intel(self):
        """update后get出来的malware_family要变成updated_family"""
        result = self.signer.get_signature_by_sha256("test_hash_123")
        sig_id = result['id']

        success = self.searcher.update_threat_intel(
            signature_id=sig_id,
            malware_family="updated_family",
            threat_level="critical"
        )
        self.assertTrue(success)

        result = self.signer.get_signature_by_sha256("test_hash_123")
        self.assertEqual(result['malware_family'], 'updated_family')

    def test_get_search_summary(self):
        """2个match: 1个high_similarity, 1个family1"""
        matches = [
            HomologyMatch(
                matched_binary="test1",
                matched_signature_id=1,
                similarity_score=0.9,
                malware_family="family1",
                threat_level="high"
            ),
            HomologyMatch(
                matched_binary="test2",
                matched_signature_id=2,
                similarity_score=0.7,
                threat_level="medium"
            )
        ]
        summary = self.searcher.get_search_summary(matches)
        self.assertEqual(summary['total_matches'], 2)
        self.assertEqual(summary['high_similarity_count'], 1)
        self.assertIn('family1', summary['malware_families'])


class TestConvenienceFunctions(unittest.TestCase):
    """convenience function: generate_binary_signature / search_homology"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.temp_binary = os.path.join(self.temp_dir, 'test')
        with open(self.temp_binary, 'wb') as f:
            f.write(b'\x00' * 100)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_generate_binary_signature(self):
        """不save到db, 但返回的signature不能是None"""
        signature = generate_binary_signature(
            binary_path=self.temp_binary,
            binary_info={'arch': 'x86'},
            save_to_db=False
        )
        self.assertIsNotNone(signature)
        self.assertEqual(signature.binary_name, 'test')

    def test_search_homology(self):
        """返回list"""
        signature = BinarySignature(
            binary_path=self.temp_binary,
            binary_name="test"
        )
        matches = search_homology(signature, limit=5)
        self.assertIsInstance(matches, list)


if __name__ == '__main__':
    unittest.main()
