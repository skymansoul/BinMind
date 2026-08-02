# 2026-08-12 ~ 2026-08-15
# FTS5 CJK tokenizer for CVE descriptions.
# Sqlite's builtin tokenizers (unicode61, ascii) treat each CJK char as
# a separate token — search for "远程代码执行" becomes 6 single-char terms
# which is useless. We split into overlapping bigrams ("远程", "程代",
# "代码"...) during indexing AND query time so FTS5 can actually match.
#
# Optional jieba support: if installed, chinese text is segmented using
# jieba first, then bigram'd. jieba + bigram gives better precision than
# bigram alone (fewer false bigrams across word boundaries). but the
# fallback pure-bigram approach already works well enough for most queries.
#
# _is_cjk uses explicit unicode codepoint ranges (same approach as
# cve_search.py) — python's re module doesn't grok \p{Han} and WILL
# crash at runtime. Direct codepoint ranges are portable and clear.

import re
from typing import List, Optional, Set

# try loading jieba — it's optional
try:
    import jieba
    _HAS_JIEBA = True
except ImportError:
    _HAS_JIEBA = False
    jieba = None  # type: ignore

# ---- CJK unicode ranges (hand-curated, same pattern as cve_search.py) ----
# python's re module doesn't support unicode property escapes (\p{Han})
# so we define explicit ranges. these cover common chinese/japanese/korean
# code blocks encountered in vuln descriptions.

_CJK_RANGES = [
    (0x4E00, 0x9FFF),    # CJK Unified Ideographs
    (0x3400, 0x4DBF),    # CJK Unified Ideographs Extension A
    (0xF900, 0xFAFF),    # CJK Compatibility Ideographs
    (0x3040, 0x309F),    # Hiragana
    (0x30A0, 0x30FF),    # Katakana
    (0xAC00, 0xD7AF),    # Hangul Syllables
]


def _is_cjk_char(ch: str) -> bool:
    """Check if a single char is in a CJK unicode block."""
    cp = ord(ch)
    for lo, hi in _CJK_RANGES:
        if lo <= cp <= hi:
            return True
    return False


# chars that separate tokens in the output
# includes common CJK punctuation
_CJK_PUNCT_RE = re.compile(
    r'[，。！？；：""''（）【】《》〈〉、…—\t\n\r\f\v '
    + r'\-\.\,\!\?\;\:\"\'\(\)\[\]\{\}\<\>/\\\@\#\$\%\^\&\*\+\=\|~`]+'
)


def tokenize_cjk(text: str) -> str:
    """Tokenize text for FTS5 indexing — returns space-separated tokens.
    ASCII words pass through unchanged. CJK runs get split into
    overlapping bigrams. If jieba is available, CJK text is segmented
    first then bigram'd for better precision.

    This is called at both index time (when storing CVE descriptions in FTS5)
    and query time (when the user types a chinese search).
    """
    if not text:
        return ""

    # first pass: segment into [ (segment, is_cjk), ... ]
    segments: List[str] = []
    i = 0
    tlen = len(text)
    while i < tlen:
        ch = text[i]
        if _is_cjk_char(ch):
            # gather consecutive CJK characters
            j = i
            while j < tlen and _is_cjk_char(text[j]):
                j += 1
            cjk_run = text[i:j]
            # strip punctuation from the run
            cjk_run = _CJK_PUNCT_RE.sub('', cjk_run)
            if cjk_run:
                segments.append(cjk_run)
            i = j
        elif ch.isspace() or _CJK_PUNCT_RE.match(ch):
            # add space as token boundary for the FTS5 tokenizer
            segments.append(' ')
            i += 1
        else:
            # ascii/latin run
            j = i
            while j < tlen and not _is_cjk_char(text[j]) and not text[j].isspace() and not _CJK_PUNCT_RE.match(text[j]):
                j += 1
            ascii_run = text[i:j].lower()
            if ascii_run:
                segments.append(ascii_run)
            i = j

    # second pass: bigram CJK segments, leave ascii as-is
    result_parts: List[str] = []
    for seg in segments:
        if seg == ' ':
            result_parts.append(' ')
            continue
        # if it's ascii (starts with a-z0-9), keep as-is
        if seg[0].isascii() and seg[0].isalnum():
            result_parts.append(seg)
            continue
        # CJK segment — bigram it
        # jieba first if available
        if _HAS_JIEBA and jieba is not None:
            words = list(jieba.cut(seg))
            for w in words:
                w = w.strip()
                if not w:
                    continue
                if len(w) == 1:
                    result_parts.append(w)  # single char still useful for FTS5
                else:
                    # overlapping bigrams
                    for k in range(len(w) - 1):
                        result_parts.append(w[k:k+2])
        else:
            # pure bigram — no jieba, just split overlapping pairs
            for k in range(len(seg) - 1):
                result_parts.append(seg[k:k+2])
            # also keep the individual chars for single-char search
            # (e.g. if someone searches just "代")
            for ch in seg:
                result_parts.append(ch)

    return ' '.join(result_parts)


# ---- indexing helpers ----

def index_description_for_fts(desc: str) -> str:
    """Prepare a CVE description for FTS5 insertion.
    Wraps tokenize_cjk — split out in case we need different
    pre-processing later."""
    return tokenize_cjk(desc)


def prepare_query_for_fts(query: str) -> str:
    """Prepare a user search query for FTS5 matching.
    Same tokenization as index time — consistency is what makes
    the search actually work."""
    return tokenize_cjk(query)


# ---- direct sqlite tokenizer callback ----
# fts5 lets you register a custom tokenizer in C, but from python
# we work around it by pre-tokenizing. this function is exposed
# for cve_kb to call during INSERT and SEARCH operations.

def rebuild_fts_index(kb_conn, cve_id: str, description: str):
    """Update the FTS5 index for a single CVE entry.
    Tokenizes description and re-inserts into cve_fts table.
    kb_conn is a raw sqlite3 connection (not the KB object).

    We DELETE then INSERT because FTS5 content tables don't really
    support UPDATE in a clean way — the content sync triggers
    get tangled. Simpler to just recreate the row.
    """
    tokenized = tokenize_cjk(description)
    if not tokenized:
        return
    try:
        kb_conn.execute(
            "DELETE FROM cve_fts WHERE cve_id = ?", (cve_id,)
        )
        kb_conn.execute(
            "INSERT INTO cve_fts (cve_id, description) VALUES (?, ?)",
            (cve_id, tokenized),
        )
        kb_conn.commit()
    except Exception:
        pass  # fts table might not exist yet, that's ok


def search_fts(kb_conn, query: str, limit: int = 50) -> List[str]:
    """Search FTS5 with CJK-aware query tokenization.
    Returns list of matching cve_ids (ranked).

    Uses the FTS5 content table if it exists, falls back to
    a simple LIKE search otherwise.
    """
    tokenized = tokenize_cjk(query)
    if not tokenized:
        return []

    try:
        rows = kb_conn.execute(
            "SELECT cve_id FROM cve_fts WHERE cve_fts MATCH ? "
            "ORDER BY rank LIMIT ?",
            (tokenized, limit),
        ).fetchall()
        return [r[0] for r in rows]
    except Exception:
        # fts table doesn't exist or query syntax error
        # fallback to LIKE — worse but doesn't crash
        try:
            rows = kb_conn.execute(
                "SELECT cve_id FROM cves WHERE description LIKE ? LIMIT ?",
                (f"%{query}%", limit),
            ).fetchall()
            return [r[0] for r in rows]
        except Exception:
            return []


# ---- convenience: detect if text has CJK ----
def has_cjk(text: str) -> bool:
    """Quick check: does this text contain any CJK characters?"""
    if not text:
        return False
    for ch in text:
        if _is_cjk_char(ch):
            return True
    return False
