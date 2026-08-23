import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import struct

from src.signature_tampering_detector import (
    SignatureTamperingDetector, PESignatureParser,
    SignatureInfo, SignatureStatus, detect_signature_tampering
)


class TestSignatureStatus(unittest.TestCase):

    def test_enum_values(self):
        self.assertEqual(SignatureStatus.VALID.value, "valid")
        self.assertEqual(SignatureStatus.INVALID.value, "invalid")
        self.assertEqual(SignatureStatus.SELF_SIGNED.value, "self_signed")

    def test_enum_membership(self):
        statuses = set(SignatureStatus)
        self.assertIn(SignatureStatus.MISSING, statuses)
        self.assertIn(SignatureStatus.EXPIRED, statuses)


class TestSignatureTambringDetector(unittest.TestCase):

    def setUp(self):
        self.det = SignatureTamperingDetector()

    def test_missing_signature(self):
        info = self.det.detect_tampering("test.exe", has_signature=False)
        self.assertEqual(info.status, SignatureStatus.MISSING)

    def test_self_signed(self):
        info = self.det.detect_tampering(
            "test.exe", has_signature=True, signer="Unknown Vendor")
        self.assertEqual(info.status, SignatureStatus.SELF_SIGNED)

    def test_valid_signature(self):
        info = self.det.detect_tampering(
            "test.exe", has_signature=True, signer="Microsoft Corporation")
        self.assertEqual(info.status, SignatureStatus.VALID)

    def test_invalid_cert(self):
        info = self.det.detect_tampering(
            "test.exe", has_signature=True, cert_valid=False)
        self.assertEqual(info.status, SignatureStatus.INVALID)

    def test_expired_cert(self):
        info = self.det.detect_tampering(
            "test.exe", has_signature=True, signer="Microsoft Corporation",
            expired=True)
        self.assertEqual(info.status, SignatureStatus.EXPIRED)

    def test_signer_reputation(self):
        rep = self.det.check_signer_reputation("Microsoft Corporation")
        self.assertTrue(rep['known_trusted'])
        rep2 = self.det.check_signer_reputation("Random Vendor")
        self.assertFalse(rep2['known_trusted'])

    def test_analyze_empty(self):
        result = self.det.analyze(files=[])
        self.assertEqual(result['total_files'], 0)
        self.assertEqual(result['risk_level'], 'low')

    def test_analyze_with_files(self):
        files = [
            {'path': 'a.exe', 'has_signature': True, 'signer': 'Microsoft Corporation'},
            {'path': 'b.exe', 'has_signature': False},
        ]
        result = self.det.analyze(files=files)
        self.assertEqual(result['total_files'], 2)
        self.assertEqual(result['valid'], 1)
        self.assertEqual(result['missing'], 1)

    def test_top_level_function(self):
        result = detect_signature_tampering([
            {'path': 'test.dll', 'has_signature': True,
             'signer': 'Google LLC', 'cert_valid': True}
        ])
        self.assertTrue(result['success'])
        self.assertEqual(result['valid'], 1)


class TestPEParser(unittest.TestCase):

    def test_empty_data(self):
        parser = PESignatureParser()
        result = parser.parse(b'')
        self.assertIsNone(result)

    def test_invalid_pe(self):
        parser = PESignatureParser()
        result = parser.parse(b'\x00' * 128)
        self.assertIsNone(result)

    def test_minimal_pe_no_signature(self):
        parser = PESignatureParser()
        mz = b'MZ\x00\x00' + b'\x00' * 56
        mz = bytearray(mz)
        mz[0x3C:0x40] = struct.pack('<I', 0x40)
        pe_sig = b'PE\x00\x00'
        opt_hdr_sz = 112
        coff = struct.pack('<HHIIIHH', 0x8664, 0, 0, 0, 0, opt_hdr_sz, 0)
        opt_header = b'\x00' * (opt_hdr_sz + 128)
        pe_data = bytes(mz) + pe_sig + coff + opt_header
        result = parser.parse(pe_data)
        self.assertIsNotNone(result)
        self.assertFalse(result['signed'])


if __name__ == '__main__':
    unittest.main()
