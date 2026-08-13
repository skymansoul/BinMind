import logging
import re
import hashlib
from collections import defaultdict, Counter
from typing import Any, Sequence

logger = logging.getLogger(__name__)
function_name: str = ""
name: str = "decomp_ai"
module: str = "decomp_ai"

_LIBRARY_FINGERPRINTS = [
    (re.compile(r"(?:malloc|calloc|realloc|free)\s*\(", re.IGNORECASE), "stdlib_memory",
     "Standard library memory allocation"),
    (re.compile(r"(?:memcpy|memmove|memset|memcmp|memchr)\s*\(", re.IGNORECASE), "stdlib_string",
     "Standard library memory operations"),
    (re.compile(r"(?:strlen|strcpy|strcat|strcmp|strncmp|strncpy|strtok|strstr|strchr|strrchr)\s*\(",
                re.IGNORECASE), "stdlib_string_narrow", "Standard library narrow string operations"),
    (re.compile(r"(?:fopen|fclose|fread|fwrite|fprintf|fscanf|fgets|fputs|fseek|ftell)\s*\(",
                re.IGNORECASE), "stdio", "Standard I/O library"),
    (re.compile(r"(?:socket|bind|connect|listen|accept|send|recv|sendto|recvfrom|setsockopt|gethostbyname)\s*\(",
                re.IGNORECASE), "winsock_bsd_sockets", "Sockets / networking API"),
    (re.compile(r"(?:CreateFile|ReadFile|WriteFile|CloseHandle|WaitForSingleObject|GetLastError)\s*\(",
                re.IGNORECASE), "win32_base", "Windows kernel32 base API"),
    (re.compile(r"(?:RegOpenKey|RegQueryValue|RegSetValue|RegCloseKey|RegCreateKey)\s*\(",
                re.IGNORECASE), "win32_registry", "Windows registry API"),
    (re.compile(r"(?:CreateThread|CreateProcess|OpenProcess|TerminateProcess|GetModuleHandle)\s*\(",
                re.IGNORECASE), "win32_process", "Windows process/thread API"),
    (re.compile(r"(?:AES_|SHA256_|SHA512_|EVP_|RSA_|HMAC\(|PKCS5_|EC_KEY_|DH_)\s*\(",
                re.IGNORECASE), "openssl_crypto", "OpenSSL crypto primitives"),
    (re.compile(r"(?:curl_easy_|curl_global_|curl_multi_)\s*\(", re.IGNORECASE), "libcurl", "libcurl HTTP client"),
    (re.compile(r"(?:zlib|deflate|inflate|compress|uncompress|gzopen|gzwrite|gzread|gzclose)\s*\(",
                re.IGNORECASE), "zlib", "zlib compression"),
    (re.compile(r"(?:xmlParse|xmlDoc|xmlNode|xmlAttr|xmlFree|xmlNew)\s*\(", re.IGNORECASE), "libxml2",
     "libxml2 XML parser"),
    (re.compile(r"(?:sqlite3_open|sqlite3_exec|sqlite3_prepare|sqlite3_step|sqlite3_finalize|sqlite3_close)\s*\(",
                re.IGNORECASE), "sqlite3", "SQLite3 database API"),
]

_VULN_PATTERNS = [
    (re.compile(r"strcpy\s*\(\s*\w+\s*,\s*\w+\s*\)"), "unbounded_strcpy", "CWE-120: unbounded strcpy"),
    (re.compile(r"sprintf\s*\(\s*\w+\s*,\s*\"[^\"]*%s"), "format_string_sprintf", "CWE-134: potential format string"),
    (re.compile(r"gets\s*\("), "gets_call", "CWE-242: use of unsafe gets()"),
    (re.compile(r"memcpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)"), "memcpy_no_check", "CWE-120: memcpy size check needed"),
    (re.compile(r"malloc\s*\(\s*\w+\s*\*\s*\d+\s*\)"), "int_overflow_mul",
     "CWE-190: potential integer overflow in malloc size"),
]

_KNOWN_STRUCT_PATTERNS = [
    (re.compile(r"->(?:next|prev|head|tail)\b"), "linked list node traversal", "linked_list"),
    (re.compile(r"->(?:left|right|parent)\b"), "binary tree traversal", "binary_tree"),
    (re.compile(r"->(?:data|len|size|buf|ptr)\b"), "buffer/array member access", "buffer_struct"),
    (re.compile(r"->(?:refcnt|flags|lock|mutex)\b"), "ref-counted or locked object", "smart_ptr_or_lock"),
]

_VAR_NAME_PATTERNS = [
    (re.compile(r"\b(a1|a2|a3|a4|a5|a6|a7|a8)\b"), "arguments to meaningful names"),
    (re.compile(r"\b(var_\d+|v\d+)\b"), "auto-named locals"),
    (re.compile(r"\b(tmp|temp|buf)\d*\b"), "temporary / buffer variables"),
]


def sanitize_function_name(name_str: str) -> str:
    if not name_str:
        return "sub_0"
    cleaned = "".join(c for c in name_str if c.isalnum() or c == "_")
    cleaned = cleaned.strip("_")
    if not cleaned:
        return "sub_0"
    if cleaned[0].isdigit():
        cleaned = "f_" + cleaned
    return cleaned[:64]


def strip_ansi_escape(s: str) -> str:
    ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    return ansi_re.sub("", str(s))


def _identify_libraries(decompiled: str) -> list[dict]:
    found: list[dict] = []
    for pattern, lib_id, description in _LIBRARY_FINGERPRINTS:
        matches = pattern.findall(decompiled)
        if matches:
            found.append({"library": lib_id, "description": description,
                          "call_count": len(matches),
                          "sample_calls": matches[:3]})
    return found


def _flag_vulnerabilities(decompiled: str) -> list[dict]:
    findings: list[dict] = []
    for pattern, vuln_id, description in _VULN_PATTERNS:
        for match in pattern.finditer(decompiled):
            findings.append({"vuln_id": vuln_id, "description": description,
                             "location": min(100, match.start()),
                             "snippet": match.group(0)[:80]})
    return findings


def _recommend_var_names(decompiled: str) -> dict[str, str]:
    suggestions: dict[str, str] = {}
    count = 0
    for line in decompiled.split("\n"):
        if "=" in line:
            lhs = line.split("=")[0].strip()
            if re.match(r"^(var_\d+|v\d+|a\d+|tmp\d*)$", lhs, re.IGNORECASE):
                if "size" in line.lower() or "len" in line.lower():
                    suggestions[lhs] = f"size_{count}"
                elif "buf" in line.lower() or "ptr" in line.lower():
                    suggestions[lhs] = f"buf_{count}"
                elif "ret" in line.lower() or "result" in line.lower():
                    suggestions[lhs] = f"result_{count}"
                elif "err" in line.lower() or "status" in line.lower():
                    suggestions[lhs] = f"status_{count}"
                elif "count" in line.lower() or "num" in line.lower() or "idx" in line.lower() or "index" in line.lower():
                    suggestions[lhs] = f"idx_{count}"
                elif "flag" in line.lower():
                    suggestions[lhs] = f"flag_{count}"
                else:
                    suggestions[lhs] = f"val_{count}"
                count += 1
    return suggestions


def _identify_structures(decompiled: str) -> list[str]:
    found = []
    for pattern, desc, struct_type in _KNOWN_STRUCT_PATTERNS:
        if pattern.search(decompiled):
            found.append(struct_type)
    return found


def _extract_loop_summaries(decompiled: str) -> list[str]:
    loops = []
    lines = decompiled.split("\n")
    in_loop = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"(?:for|while|do)\s*\(", stripped):
            in_loop = True
            loops.append(stripped[:120])
        elif in_loop and stripped == "}":
            in_loop = False
    return loops


class DecompilerAI:
    def __init__(self):
        self._var_suggestions: dict[str, str] = {}

    def analyze(self, decompiled_code: str) -> dict:
        cleaned = strip_ansi_escape(decompiled_code)
        libs = _identify_libraries(cleaned)
        vulns = _flag_vulnerabilities(cleaned)
        self._var_suggestions = _recommend_var_names(cleaned)
        structs = _identify_structures(cleaned)
        loops = _extract_loop_summaries(cleaned)
        lines = [l for l in cleaned.split("\n") if l.strip()]
        call_sites = len(re.findall(r"\w+\s*\(", cleaned))
        branch_count = len(re.findall(r"\b(?:if|else if|switch|case)\b", cleaned))

        return {
            "line_count": len(lines), "call_sites": call_sites,
            "branch_count": branch_count, "libraries": libs,
            "vulnerabilities": vulns, "variable_suggestions": self._var_suggestions,
            "structures": structs, "loops": loops,
            "complexity_estimate": min(100, (call_sites + branch_count)),
        }

    def rename_variable(self, old_name: str) -> str:
        return self._var_suggestions.get(old_name, old_name)

    def suggest_comment(self, decompiled_code: str, line_number: int) -> str:
        lines = decompiled_code.split("\n")
        if line_number >= len(lines):
            return ""
        line = lines[line_number].strip()
        if not line:
            return ""

        for pattern, vuln_id, desc in _VULN_PATTERNS:
            if pattern.search(line):
                return f"// WARNING: {desc}"

        known_calls = {
            "strcpy": "// copy string (buffer overflow risk)",
            "strncpy": "// bounded string copy",
            "memcpy": "// memory copy",
            "malloc": "// heap allocation",
            "free": "// deallocation",
            "memset": "// zero/initialize memory",
            "memcmp": "// constant-time(?) memory compare",
            "send": "// send data over socket",
            "recv": "// receive data from socket",
            "fopen": "// open file",
            "fread": "// read from file",
            "WriteProcessMemory": "// write to remote process",
            "VirtualAlloc": "// allocate virtual memory",
        }
        for name, comment in known_calls.items():
            if name in line:
                return comment

        for pattern, desc, _ in _KNOWN_STRUCT_PATTERNS:
            if pattern.search(line):
                return f"// {desc}"

        return ""


DecompilerAI_class = DecompilerAI
