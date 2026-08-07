"""
CAAWP单元测试 — 上下文敏感仿射证明器.
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.caawp_prover import prove_candidate
from core.caawp_interpreter import CAAWPInterpreter, _parse_size_expr


def test_parse_size_expr():
    coefs, const = _parse_size_expr("64")
    assert const == 64.0 and not coefs

    coefs, const = _parse_size_expr("n")
    assert coefs.get("n") == 1.0 and const == 0.0

    coefs, const = _parse_size_expr("n*2")
    assert coefs.get("n") == 2.0 and const == 0.0

    coefs, const = _parse_size_expr("2*n+8")
    assert coefs.get("n") == 2.0 and const == 8.0

    coefs, const = _parse_size_expr("nmemb*size")
    assert coefs.get("nmemb") == 1.0 and coefs.get("size") == 1.0
    print("[OK] test_parse_size_expr")


def test_constant_safe():
    code = """
    void foo() {
        char *buf = malloc(128);
        memcpy(buf, src, 64);
    }
    """
    r = prove_candidate(code, "buf", "buf", "128", "64")
    assert r.proven_safe, f"expected safe, got: {r.reason}"
    print(f"[OK] test_constant_safe: {r.reason}")


def test_constant_overflow():
    code = """
    void foo() {
        char *buf = malloc(64);
        memcpy(buf, src, 128);
    }
    """
    r = prove_candidate(code, "buf", "buf", "64", "128")
    assert r.proven_overflow, f"expected overflow, got: {r.reason}"
    print(f"[OK] test_constant_overflow: {r.reason}")


def test_affine_safe():
    code = """
    void foo(int n) {
        char *buf = malloc(n);
        memcpy(buf, src, n);
    }
    """
    r = prove_candidate(code, "buf", "buf", "n", "n")
    assert r.proven_safe, f"expected safe, got: {r.reason}"
    print(f"[OK] test_affine_safe: {r.reason}")


def test_affine_overflow():
    code = """
    void foo(int n) {
        char *buf = malloc(n);
        memcpy(buf, src, n+8);
    }
    """
    r = prove_candidate(code, "buf", "buf", "n", "n+8")
    assert r.proven_overflow, f"expected overflow, got: {r.reason}"
    print(f"[OK] test_affine_overflow: {r.reason}")


def test_coefficient_overflow():
    code = """
    void foo(int n) {
        char *buf = malloc(n);
        memcpy(buf, src, n*2);
    }
    """
    r = prove_candidate(code, "buf", "buf", "n", "n*2")
    assert r.proven_overflow, f"expected overflow, got: {r.reason}"
    print(f"[OK] test_coefficient_overflow: {r.reason}")


def test_coefficient_safe():
    code = """
    void foo(int n) {
        char *buf = malloc(n*2);
        memcpy(buf, src, n);
    }
    """
    r = prove_candidate(code, "buf", "buf", "n*2", "n")
    assert r.proven_safe, f"expected safe, got: {r.reason}"
    print(f"[OK] test_coefficient_safe: {r.reason}")


def test_context_sensitivity():
    code = """
    void helper(char *dst, int sz) {
        memcpy(dst, src, sz);
    }
    void caller_safe() {
        char *buf = malloc(256);
        helper(buf, 128);
    }
    void caller_overflow() {
        char *buf = malloc(64);
        helper(buf, 256);
    }
    """
    interp = CAAWPInterpreter()
    snapshots = interp.analyze(code)
    assert "helper" in snapshots
    assert len(snapshots["helper"]) >= 1
    print(f"[OK] test_context_sensitivity: {len(snapshots.get('helper', []))} contexts")


def test_calloc_safe():
    code = """
    void foo(int n) {
        char *buf = calloc(n, 4);
        memcpy(buf, src, n*4);
    }
    """
    r = prove_candidate(code, "buf", "buf", "n*4", "n*4")
    assert r.proven_safe, f"expected safe, got: {r.reason}"
    print(f"[OK] test_calloc_safe: {r.reason}")


def test_offset_overflow():
    code = """
    void foo(int n) {
        char *buf = malloc(n);
        memcpy(buf+8, src, n);
    }
    """
    r = prove_candidate(code, "buf", "buf", "n", "n", offset=8)
    assert r.proven_overflow, f"expected overflow, got: {r.reason}"
    print(f"[OK] test_offset_overflow: {r.reason}")


def test_chunk_slack_safe():
    code = """
    void foo() {
        char *buf = malloc(24);
        memcpy(buf, src, 24);
    }
    """
    r = prove_candidate(code, "buf", "buf", "24", "24", chunk_slack=8)
    assert r.proven_safe, f"expected safe, got: {r.reason}"
    print(f"[OK] test_chunk_slack_safe: {r.reason}")


if __name__ == "__main__":
    test_parse_size_expr()
    test_constant_safe()
    test_constant_overflow()
    test_affine_safe()
    test_affine_overflow()
    test_coefficient_overflow()
    test_coefficient_safe()
    test_context_sensitivity()
    test_calloc_safe()
    test_offset_overflow()
    test_chunk_slack_safe()
    print("\n[ALL PASS] CAAWP unit tests passed")
