"""Tests for jwt_analyzer — token detection and vulnerability scanning."""

import os
import sys
import json
import base64
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.jwt_analyzer import JWTAnalyzer, JWTResult, analyze_jwt


def _make_jwt(header: dict, payload: dict, secret: bytes = b"secret") -> str:
    """Build a valid HS256-signed JWT for testing."""
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    import hmac, hashlib
    msg = f"{h}.{p}".encode()
    sig = base64.urlsafe_b64encode(
        hmac.HMAC(secret, msg, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{h}.{p}.{sig}"


class TestJWTAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = JWTAnalyzer()

    def _write_and_scan(self, token: str) -> list:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(token.encode())
            tmp = f.name
        try:
            return self.analyzer.scan_file(tmp)
        finally:
            os.unlink(tmp)

    def test_detect_valid_hs256(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user", "iat": 1000000})
        result = self._write_and_scan(token)
        self.assertEqual(result.total_tokens, 1)

    def test_detect_alg_none(self):
        h = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "admin"}).encode()).rstrip(b"=").decode()
        token = f"{h}.{p}."
        result = self._write_and_scan(token)
        self.assertTrue(any(t.vulnerability == "alg:none" for t in result.tokens))

    def test_weak_hmac_detection(self):
        secret = b"secret"
        token = _make_jwt({"alg": "HS256"}, {"sub": "user"}, secret=secret)
        result = self._write_and_scan(token)
        self.assertTrue(any(t.vulnerability == "weak-hmac" for t in result.tokens))

    def test_expired_token(self):
        token = _make_jwt(
            {"alg": "HS256"},
            {"sub": "user", "exp": 1}  # 1970 — definitely expired
        )
        result = self._write_and_scan(token)
        self.assertTrue(
            any(t.is_expired for t in result.tokens),
            "Expired token should be flagged"
        )

    def test_no_tokens(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b"no jwt tokens here at all")
            tmp = f.name
        try:
            result = self.analyzer.scan_file(tmp)
            self.assertEqual(result.total_tokens, 0)
        finally:
            os.unlink(tmp)

    def test_multiple_tokens(self):
        t1 = _make_jwt({"alg": "HS256"}, {"n": 1})
        t2 = _make_jwt({"alg": "none"}, {"n": 2})
        data = f"prefix {t1} middle {t2} suffix".encode()
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(data)
            tmp = f.name
        try:
            result = self.analyzer.scan_file(tmp)
            self.assertGreaterEqual(result.total_tokens, 2)
        finally:
            os.unlink(tmp)

    def test_jku_header_flag(self):
        h = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "jku": "https://evil.com/jwks.json"}).encode()
        ).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "x"}).encode()).rstrip(b"=").decode()
        token = f"{h}.{p}.sig"
        result = self._write_and_scan(token)
        self.assertTrue(
            any("jku" in (n or "") for t in result.tokens for n in t.notes)
        )

    def test_corrupt_header(self):
        token = "!!!!!.aaaa.bbbb"  # completely invalid base64
        result = self._write_and_scan(token)
        self.assertTrue(
            all(not t.decodable for t in result.tokens)
        )

    def test_convenience_fn(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(_make_jwt({"alg": "HS256"}, {"x": 1}).encode())
            tmp = f.name
        try:
            result = analyze_jwt(tmp)
            self.assertEqual(result.total_tokens, 1)
        finally:
            os.unlink(tmp)


if __name__ == '__main__':
    unittest.main()
