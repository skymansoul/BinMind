#!/usr/bin/env python3
"""
Crypto module command-line interface.

Usage:
  python -m src.cli detect <file>
  python -m src.cli misuse <file>
  python -m src.cli hash <file> [--algo xxhash64]
  python -m src.cli pqc <file>
  python -m src.cli stegano <file>
  python -m src.cli traffic <file>
  python -m src.cli signature <file>
  python -m src.cli cert <file>
  python -m src.cli entropy <file>
  python -m src.cli jwt <file>
  python -m src.cli secrets <file>
  python -m src.cli kdf <file>
  python -m src.cli libs <file>
  python -m src.cli rng <file>
  python -m src.cli rsa <n> <e>
  python -m src.cli all <file>

-q quiet mode, -j compact single-line JSON, --parallel for all mode.
"""

import sys
import os
import json
import argparse
import logging
import time
from typing import Optional

_src_dir = os.path.dirname(os.path.abspath(__file__))
if _src_dir not in sys.path:
    sys.path.insert(0, os.path.dirname(_src_dir))

from .config import load_config, getConfig
from .utils import setup_logging, safeReadBytes

logger = logging.getLogger(__name__)

try:
    from tqdm import tqdm as _tqdm_available
except ImportError:
    _tqdm_available = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="crypto")

    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-o", "--output", choices=["text", "json", "compact-json"], default="text")
    parser.add_argument("--log-config", help="Path to logging configuration file")
    parser.add_argument("--progress", action="store_true")

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("detect", help="Detect cryptographic algorithm signatures")
    p.add_argument("file")

    p = sub.add_parser("misuse", help="Detect cryptographic API misuse")
    p.add_argument("file")
    p.add_argument("--min-severity", default="MEDIUM",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

    p = sub.add_parser("hash", help="Compute file hash")
    p.add_argument("file")
    p.add_argument("--algo", default="xxhash64")

    p = sub.add_parser("pqc", help="Detect post-quantum cryptography")
    p.add_argument("file")

    p = sub.add_parser("stegano", help="Detect steganography / hidden data")
    p.add_argument("file")
    p.add_argument("--extract", action="store_true")
    p.add_argument("--output-dir", default=".")

    p = sub.add_parser("traffic", help="Analyze encrypted traffic")
    p.add_argument("file")

    p = sub.add_parser("signature", help="Detect signature tampering")
    p.add_argument("file", nargs="+")

    p = sub.add_parser("cert", help="Analyze embedded X.509 certificates")
    p.add_argument("file")

    p = sub.add_parser("entropy", help="Entropy profiling for key detection")
    p.add_argument("file")
    p.add_argument("--window", type=int, default=4096)

    p = sub.add_parser("jwt", help="Detect and analyze JWT tokens")
    p.add_argument("file")

    p = sub.add_parser("secrets", help="Scan for hardcoded secrets/keys")
    p.add_argument("file")

    p = sub.add_parser("kdf", help="Detect KDF usage and audit parameters")
    p.add_argument("file")

    p = sub.add_parser("libs", help="Fingerprint linked crypto libraries")
    p.add_argument("file")

    p = sub.add_parser("rng", help="Run NIST randomness tests on data")
    p.add_argument("file")

    p = sub.add_parser("rsa", help="Test RSA key for known weaknesses")
    p.add_argument("n", type=int, help="Modulus (decimal)")
    p.add_argument("e", type=int, nargs="?", default=65537, help="Public exponent")

    p = sub.add_parser("all", help="Run all detection modules")
    p.add_argument("file")
    p.add_argument("--parallel", action="store_true")

    return parser


def _json_convert(o):
    if hasattr(o, '__dict__'):
        return {k: _json_convert(v) for k, v in o.__dict__.items() if not k.startswith('_')}
    if isinstance(o, (list, tuple)):
        return [_json_convert(i) for i in o]
    if isinstance(o, set):
        return list(o)
    if hasattr(o, 'value'):
        return o.value
    return o


def format_json(obj, compact: bool = False) -> str:
    indent = None if compact else 2
    separators = (',', ':') if compact else (', ', ': ')
    return json.dumps(_json_convert(obj), indent=indent, ensure_ascii=False,
                      default=str, separators=separators)


# ── Command handlers (backward-compatible with rewritten modules) ──

def cmd_detect(args):
    from .crypto_detector import CryptoDetector
    det = CryptoDetector()
    return {"detect": det.scan_file(args.file)}


def cmd_misuse(args):
    from .crypto_misuse import detect_crypto_misuse
    result = detect_crypto_misuse(args.file)
    filtered = result.by_severity(args.min_severity)
    return {"misuse": {"total": len(result), "filtered": len(filtered),
                       "issues": [m._asdict() for m in filtered]}}


def cmd_hash(args):
    from .hardware_hash import compute_file_hash
    result = compute_file_hash(args.file, args.algo)
    return {"hash": {"algorithm": result.algorithm.value,
                     "digest": result.hex_digest,
                     "file_size": result.file_size,
                     "elapsed_ms": result.elapsed_ms}}


def cmd_pqc(args):
    from .pqc_detector import detect_pqc
    results = detect_pqc(args.file)
    return {"pqc": [{"algorithm": r.algorithm, "confidence": r.confidence,
                     "evidence": r.evidence} for r in results]}


def cmd_stegano(args):
    from .steganography_detector import SteganographyDetector
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    det = SteganographyDetector(raw)
    findings = det.run_all()
    output = {"steganography": {
        "is_suspicious": len(findings) > 0,
        "findings_count": len(findings),
        "findings": [{"offset": f.offset, "format": f.format,
                       "confidence": round(f.confidence, 3),
                       "description": f.description}
                      for f in findings[:20]],
    }}
    return output


def cmd_traffic(args):
    from .crypto_traffic_decrypt import CryptoTrafficAnalyzer, extract_keys, analyze_traffic
    data = safeReadBytes(args.file)
    if data is None:
        return {"error": "Cannot read {}".format(args.file)}
    analysis = analyze_traffic(data)
    keys = extract_keys(args.file)
    return {"traffic": {"protocols": [a.protocol for a in analysis],
                        "tls_version": analysis[0].tls_version if analysis else "",
                        "ja4_fingerprint": analysis[0].ja4_fingerprint if analysis else "",
                        "keys_found": len(keys)}}


def cmd_cert(args):
    from .cert_analysis import find_certificates, check_weakness
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    certs = find_certificates(raw)
    findings = []
    for c in certs:
        weaknesses = check_weakness(c)
        findings.append({
            "subject": c.subject, "issuer": c.issuer,
            "sig_alg": c.sig_alg, "key_size": c.key_size,
            "is_ca": c.is_ca, "sans": c.sans,
            "weaknesses": [{"severity": w[0].name, "description": w[1]}
                          for w in weaknesses],
        })
    return {"certificates": {"total": len(certs), "findings": findings}}


def cmd_entropy(args):
    from .entropy_analyzer import analyze_entropy
    profiles = analyze_entropy(args.file, chunk_size=args.window)
    return {"entropy": [
        {"offset": p.offset, "size": p.size,
         "shannon": round(p.shannon_entropy, 3),
         "collision": round(p.collision_entropy, 3),
         "pi_error": round(p.pi_error, 4),
         "chi_sq_p": round(p.chi_square_pvalue, 4),
         "diag": p.diagnosis}
        for p in profiles[:15]
    ]}


def cmd_jwt(args):
    from .jwt_analyzer import find_jwt_tokens, decode_jwt
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    tokens = find_jwt_tokens(raw)
    results = []
    for t in tokens:
        r = decode_jwt(t)
        results.append({
            "header": r.header,
            "payload_keys": list(r.payload.keys())[:10] if r.payload else [],
            "vulnerabilities": r.vulnerabilities,
            "signature_verified": r.signature_verified,
        })
    return {"jwt": {"total": len(tokens), "tokens": results[:20]}}


def cmd_signature(args):
    from .signature_tampering_detector import detect_signature_tampering
    files = [{"path": f, "has_signature": os.path.exists(f)} for f in args.file]
    return {"signature": detect_signature_tampering(files)}


def cmd_secrets(args):
    from .secret_auditor import SecretAuditor
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    auditor = SecretAuditor()
    findings = auditor.scan(raw)
    return {"secrets": [
        {"type": f.secret_type, "offset": f.offset,
         "preview": f.value_preview, "confidence": f.confidence}
        for f in findings[:30]
    ]}


def cmd_kdf(args):
    from .key_derivation_analyzer import detect_kdf
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    results = detect_kdf(raw)
    return {"kdf": [
        {"type": f.kdf_type, "params": f.params,
         "meets_owasp": f.meets_owasp, "severity": f.severity,
         "recommendation": f.recommendation}
        for f in results
    ]}


def cmd_libs(args):
    from .crypto_lib_fingerprint import fingerprint_library
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    results = fingerprint_library(raw)
    return {"libraries": [
        {"name": m.lib_name, "version_hint": m.version_hint,
         "confidence": m.confidence, "evidence": m.evidence}
        for m in results
    ]}


def cmd_rng(args):
    from .rng_tester import test_randomness
    raw = safeReadBytes(args.file)
    if raw is None:
        return {"error": "Cannot read {}".format(args.file)}
    sample = raw[:65536]  # cap at 64KB for performance
    return {"rng": test_randomness(sample)}


def cmd_rsa(args):
    from .rsa_attacks import is_weak_rsa_key, auto_attack
    result = auto_attack(args.n, args.e)
    return {"rsa": result}


def cmd_all(args):
    all_results = {}
    _cmds = [
        ("detect", cmd_detect), ("misuse", cmd_misuse),
        ("hash", cmd_hash), ("pqc", cmd_pqc),
        ("stegano", cmd_stegano), ("traffic", cmd_traffic),
        ("signature", cmd_signature), ("cert", cmd_cert),
        ("entropy", cmd_entropy), ("jwt", cmd_jwt),
        ("secrets", cmd_secrets), ("kdf", cmd_kdf),
        ("libs", cmd_libs), ("rng", cmd_rng),
    ]

    if args.parallel:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as pool:
            futures = {pool.submit(handler, args): name for name, handler in _cmds}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    all_results.update(future.result())
                except Exception as e:
                    all_results["{}_error".format(name)] = str(e)
    else:
        iterator = _tqdm_available(_cmds, desc="Scanning", unit="module") if (
            args.progress and _tqdm_available) else _cmds
        for cmd_name, handler in iterator:
            try:
                all_results.update(handler(args))
            except Exception as e:
                all_results["{}_error".format(name)] = str(e)
    return all_results


COMMAND_MAP = {
    "detect": cmd_detect, "misuse": cmd_misuse, "hash": cmd_hash,
    "pqc": cmd_pqc, "stegano": cmd_stegano, "traffic": cmd_traffic,
    "signature": cmd_signature, "cert": cmd_cert, "entropy": cmd_entropy,
    "jwt": cmd_jwt, "secrets": cmd_secrets, "kdf": cmd_kdf,
    "libs": cmd_libs, "rng": cmd_rng, "rsa": cmd_rsa, "all": cmd_all,
}


def main(argv: Optional[list] = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    log_level = "WARNING" if args.quiet else ("DEBUG" if args.verbose else "INFO")
    setup_logging(args.log_config, level=log_level)

    if args.config:
        load_config(args.config)

    handler = COMMAND_MAP.get(args.command)
    if handler is None:
        print("Unknown command: {}".format(args.command), file=sys.stderr)
        return 1

    t0 = time.perf_counter()
    try:
        result = handler(args)
    except Exception as e:
        logger.exception("Command %s failed", args.command)
        result = {"error": str(e)}
    elapsed = time.perf_counter() - t0

    if isinstance(result, dict):
        result["_elapsed_s"] = round(elapsed, 3)

    if args.output == "compact-json":
        print(format_json(result, compact=True))
    elif args.output == "json":
        print(format_json(result))
    else:
        _print_text(args.command, result)

    return 0


def _print_text(command: str, result: dict) -> None:
    if "error" in result:
        print("Error: {}".format(result['error']))
        return

    elapsed = result.pop("_elapsed_s", None)
    print("=== {} results ===".format(command))
    print(format_json(result))
    if elapsed:
        print("\nCompleted in {:.2f}s".format(elapsed))


if __name__ == "__main__":
    sys.exit(main())
