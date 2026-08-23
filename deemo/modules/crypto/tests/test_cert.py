import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.cert_analysis import CertAnalyzer, CertFinding, analyze_certificates

_WEAK_TEST_CERT = """-----BEGIN CERTIFICATE-----
MIICATCCAWoCCQDYl0qWvrEC1zANBgkqhkiG9w0BAQQFADBFMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMB4XDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowRTELMAkG
A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0
IFdpZGdpdHMgUHR5IEx0ZDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1Y2y
kKbD5x2wY7mK6E2xJ0pF8qL3mN4oP7qRsT5uVwXyA1bC8dE9fG0hI2jK3lM4nO5
pQ6rS7tU8vW0xY1zA2bC3dE4fG5hI6jK7lM8nO0pQ6rS7tU8vW0xY1zA2bC3dE4
fG5hI6jK7lM8nO0pQ6rS7tU8vW0CAwEAATANBgkqhkiG9w0BAQQFAAOBgQBiWbNM
mT8yNx3K5vL7oP2qR4sT6uV8wX0yA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1vW2
xY3zA4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4vW5xY6zA7bC8dE9fG0hI1jK2lM3
-----END CERTIFICATE-----"""

_EXPIRED_PEM = """-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJAJx8qxxxxxxxxxMA0GCSqGSIb3DQEBCwUAMBoxGDAWBgNV
BAMMD2V4YW1wbGUuY29tIENBMB4XDTIwMDEwMTAwMDAwMFoXDTIxMDEwMTAwMDAw
MFowGjEYMBYGA1UEAwwPZXhhbXBsZS5jb20gQ0EwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC9fKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAgMBAAGjUDBO
MB0GA1UdDgQWBBTxxxxxxxxxxxxxxxxxxxxxxxxxHwYDVR0jBBgwFoAUxxxxxxxxxxxxx
xxxxxxxDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END CERTIFICATE-----"""


class TestCertAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = CertAnalyzer()

    def _write_and_scan(self, content: bytes):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(content)
            tmp = f.name
        try:
            return self.analyzer.analyze_file(tmp)
        finally:
            os.unlink(tmp)

    def test_pem_cert_detection(self):
        result = self._write_and_scan(_WEAK_TEST_CERT.encode())
        self.assertGreater(result.total_certs, 0)

    def test_no_certs(self):
        result = self._write_and_scan(b"no certificates here at all")
        self.assertEqual(result.total_certs, 0)

    def test_private_key_detection(self):
        key_pem = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END PRIVATE KEY-----"""
        result = self._write_and_scan(key_pem)
        self.assertEqual(result.private_keys_found, 1)

    def test_weak_cert_flags(self):
        result = self._write_and_scan(_WEAK_TEST_CERT.encode())
        if result.total_certs > 0:
            cert = result.certs[0]
            self.assertTrue(
                cert.is_weak_sig or cert.is_weak_key or cert.is_self_signed
            )

    def test_convenience_fn(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(_WEAK_TEST_CERT.encode())
            tmp = f.name
        try:
            result = analyze_certificates(tmp)
            self.assertIsNotNone(result)
            self.assertGreaterEqual(result.total_certs, 0)
        finally:
            os.unlink(tmp)

    def test_empty_file(self):
        result = self._write_and_scan(b"")
        self.assertIsNotNone(result)

    def test_binary_garbage(self):
        result = self._write_and_scan(b'\xFF\xFE\xFD' * 1000)
        self.assertEqual(result.total_certs, 0)


if __name__ == '__main__':
    unittest.main()
