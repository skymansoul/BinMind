# 二进制签名和同源性搜索的测试: BinarySigner / HomologySearcher / 便捷函数
# 注意: _calculate_import_hash依赖binary_info里的'imports'字段格式

import os
import tempfile
import shutil
import unittest
import json
# import sys
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

_DEBUG_FLAG = False


class TestBinarySignature(unittest.TestCase):
    """BinarySignature dataclass: 基本字段 + hashes + functions"""

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
    """HomologyMatch: similarity_score/match_type/可选字段"""

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
        """勒索软件家族, critical威胁, 匹配到了2个函数"""
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


