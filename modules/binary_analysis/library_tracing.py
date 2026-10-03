from enum import StrEnum
import logging
import os
import hashlib
from dataclasses import dataclass, field
from typing import List

logger = logging.getLogger(__name__)


class LibraryMatchType(StrEnum):
    EXACT = "exact"
    SEMANTIC = "semantic"
    FUZZY = "fuzzy"


@dataclass
class LibraryFunction:
    name: str
    address: int = 0
    library_name: str = "unknown"
    version: str = "unknown"
    cve_matches: list = field(default_factory=list)
    patch_status: str = "unknown"


@dataclass
class FingerprintMatch:
    library_name: str
    version: str
    confidence: float
    functions: list = field(default_factory=list)


@dataclass
class TracingResult:
    success: bool
    matched_libraries: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    cve_count: int = 0


class LibraryFingerprintMatcher:
    def __init__(self):
        self.fingerprints = {}

    def load_fingerprints(self, db_path: str):
        try:
            import yaml
            with open(db_path, "r") as f:
                self.fingerprints = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load fingerprints: {e}")

    def compute_function_hash(self, code: bytes) -> str:
        return hashlib.sha256(code).hexdigest()


class LibraryTracer:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.matcher = LibraryFingerprintMatcher()
        self.functions: List[LibraryFunction] = []

    def trace_functions(self) -> List[LibraryFunction]:
        logger.info("Tracing library functions...")
        try:
            import subprocess
            cmd = ["nm", "-D", self.binary_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 3 and "U" in parts[1]:
                    func = LibraryFunction(name=parts[-1], address=0, library_name="unknown")
                    self.functions.append(func)
        except Exception as e:
            pass
        return self.functions

    def match_libraries(self) -> List[FingerprintMatch]:
        matches: List[FingerprintMatch] = []
        if not self.functions:
            self.trace_functions()

        KNOWN_SYMBOLS = {
            "openssl": {
                "symbols": ["SSL_new", "SSL_connect", "SSL_read", "SSL_write",
                           "TLS_client_method", "OPENSSL_init_ssl",
                           "EVP_CIPHER_CTX_new", "HMAC_CTX_new"],
                "versions": ["1.0.2", "1.1.0", "1.1.1", "3.0.0", "3.1.0"],
            },
            "libc": {
                "symbols": ["__libc_start_main", "malloc", "free", "calloc",
                           "memcpy", "memset", "printf", "fopen", "fclose"],
                "versions": ["2.17", "2.23", "2.27", "2.31", "2.35", "2.38"],
            },
            "zlib": {
                "symbols": ["deflateInit", "deflate", "inflateInit", "inflate",
                           "compress", "uncompress", "crc32"],
                "versions": ["1.2.3", "1.2.7", "1.2.11", "1.2.13"],
            },
            "libcurl": {
                "symbols": ["curl_easy_init", "curl_easy_setopt",
                           "curl_easy_perform", "curl_easy_cleanup"],
                "versions": ["7.60", "7.74", "7.80", "8.0"],
            },
            "libxml2": {
                "symbols": ["xmlNewDoc", "xmlParseFile", "xmlFreeDoc",
                           "xmlXPathEvalExpression"],
                "versions": ["2.9.1", "2.9.4", "2.9.10", "2.10.0"],
            },
            "libsqlite3": {
                "symbols": ["sqlite3_open", "sqlite3_exec", "sqlite3_close",
                           "sqlite3_prepare_v2", "sqlite3_step"],
                "versions": ["3.20", "3.30", "3.35", "3.40"],
            },
        }

        func_names = {f.name for f in self.functions}

        for lib_name, lib_info in KNOWN_SYMBOLS.items():
            matched_symbols = func_names & set(lib_info["symbols"])
            if len(matched_symbols) >= 3:
                ratio = len(matched_symbols) / max(1, len(lib_info["symbols"]))
                confidence = min(0.95, 0.5 + ratio)
                matched_funcs = [
                    LibraryFunction(
                        name=name, address=0,
                        library_name=lib_name,
                        version=lib_info["versions"][0],
                        cve_matches=[],
                        patch_status="unknown"
                    )
                    for name in matched_symbols
                ]
                matches.append(FingerprintMatch(
                    library_name=lib_name,
                    version=lib_info["versions"][0],
                    confidence=confidence,
                    functions=matched_funcs,
                ))

        self._match_by_strings(matches, func_names)

        return matches

    def _match_by_strings(self, matches: List[FingerprintMatch],
                           func_names: set):
        try:
            import subprocess as _sp
            r = _sp.run(
                ['r2', '-q', '-c', 'izz~openssl; izz~libcurl; izz~zlib; q',
                 self.binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            output = r.stdout.lower()
            string_hints = {
                'openssl': 'openssl' in output,
                'libcurl': 'libcurl' in output or 'curl' in output,
                'zlib': 'zlib' in output or 'deflate' in output,
            }
            for lib, found in string_hints.items():
                if found and not any(m.library_name == lib for m in matches):
                    matches.append(FingerprintMatch(
                        library_name=lib,
                        version="unknown",
                        confidence=0.3,
                        functions=[],
                    ))
        except Exception:
            logger.debug("suppressed", exc_info=True)

    def run(self) -> TracingResult:
        self.trace_functions()
        matches = self.match_libraries()
        cve_count = sum(len(f.cve_matches) for m in matches for f in m.functions)
        return TracingResult(success=True, matched_libraries=matches, functions=self.functions, cve_count=cve_count)


def create_library_tracer(binary_path: str) -> LibraryTracer:
    return LibraryTracer(binary_path)
