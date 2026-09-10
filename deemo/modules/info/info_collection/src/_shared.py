# Shared utilities used across multiple analysis modules.
# Extracted to eliminate the 3× duplication of _shannon_entropy,
# _cosine_similarity, _extract_api_set, etc. flagged in audit.
import math
from collections import Counter
from typing import Dict, List, Set, Optional


def shannon_entropy(data, total=None) -> float:
    """Byte-level Shannon entropy in bits. Returns 0.0 for empty input.
    Also accepts a Counter-like frequency mapping; optional total avoids
    re-summing when the caller already knows the item count."""
    if isinstance(data, (bytes, bytearray)):
        cnt = Counter(data)
        if total is None:
            total = len(data)
    elif hasattr(data, 'values'):
        cnt = data
        if total is None:
            total = sum(cnt.values())
    else:
        cnt = Counter(data)
        if total is None:
            total = len(data)
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in cnt.values() if c > 0)


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two float vectors. Returns 0.0 on zero-norm."""
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x**2 for x in a))
    nb = math.sqrt(sum(y**2 for y in b))
    if na < 1e-9 or nb < 1e-9:
        return 0.0
    return dot / (na * nb)


def cosine_distance(a: List[float], b: List[float]) -> float:
    """1 - cosine_similarity, clamped to [0, 2]."""
    return max(0.0, 1.0 - cosine_similarity(a, b))


def jaccard_similarity(a: Set[str], b: Set[str]) -> float:
    """Jaccard similarity between two string sets."""
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union > 0 else 0.0


def jaccard_distance(a: Set[str], b: Set[str]) -> float:
    """1 - jaccard_similarity."""
    return 1.0 - jaccard_similarity(a, b)


def sigmoid_clamp(raw: float, k: float = 5.0,
                  lo: float = 0.01, hi: float = 0.99) -> float:
    """Sigmoid mapping with hard clamps to avoid 0/1 extremes."""
    v = 1.0 / (1.0 + math.exp(-k * (raw - 0.5)))
    return max(lo, min(hi, v))


def normalize_api_name(name: str) -> str:
    """Strip A/W suffix and lowercase for consistent API name matching."""
    n = name.strip().lower()
    if (n.endswith('a') or n.endswith('w')) and len(n) > 1:
        return n[:-1]
    return n


def extract_api_set(imports: Dict) -> Set[str]:
    """Extract normalized API function names from an import dict.
    Handles both {dll: [funcs]} and {all_imports: {dll: [funcs]}} formats."""
    apis = set()
    src = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    if not isinstance(src, dict):
        return apis
    for funcs in src.values():
        if isinstance(funcs, list):
            for f in funcs:
                apis.add(normalize_api_name(f))
    return apis


def extract_string_set(strings: List) -> Set[str]:
    """Normalize string list to a lowercase set.
    Handles both plain strings and (offset, string) tuples."""
    ss = set()
    for s in (strings or []):
        t = s[1] if isinstance(s, tuple) else str(s)
        ss.add(t.lower())
    return ss


def extract_dangerous_import_set(imports: Dict) -> Set[str]:
    """Extract normalized dangerous function names from imports."""
    s = set()
    dangerous = imports.get("dangerous_functions", []) if isinstance(imports, dict) else []
    for f in dangerous:
        s.add(normalize_api_name(str(f)))
    return s


def section_permissions_signature(sections: List[Dict]) -> str:
    """Build a compact section permission signature string like 'RX,RW,R-'."""
    perms = []
    for s in (sections or []):
        if not isinstance(s, dict):
            continue
        chars = s.get("characteristics", [])
        flags = s.get("flags", 0)
        if isinstance(chars, list):
            p = ""
            if "MEM_READ" in chars: p += "R"
            if "MEM_WRITE" in chars: p += "W"
            if "MEM_EXECUTE" in chars: p += "X"
            perms.append(p or "?")
        elif isinstance(flags, int) and flags > 0:
            p = ""
            if flags & 0x4: p += "R"
            if flags & 0x2: p += "W"
            if flags & 0x1: p += "X"
            perms.append(p or "?")
    return ",".join(perms[:16])
