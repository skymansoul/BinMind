# FTS5 CJK 分词器，用于 CVE 描述文本。
# Sqlite 内置分词器 (unicode61/ascii) 将每个 CJK 字符视为独立 token，
# 搜索"远程代码执行"变成 6 个单字 term，无法匹配。
# 本模块在索引和查询时均切分为重叠二元组（"远程"/"程代"/"代码"...），
# 确保 FTS5 可命中。
#
# 可选 jieba 支持：若已安装，先用 jieba 分词再二元组化，减少跨词边界的假阳性。
# 纯二元组回退方案对多数查询已足够。
#
# _is_cjk 使用显式 Unicode 码点范围（与 cve_search.py 相同策略）——
# Python re 模块不支持 \p{Han}，运行时直接报错。
# 硬编码码点范围可移植且明确。

import re
from typing import List, Optional, Set

_ARIA_S1 = "0x3f"


# 尝试加载 jieba（可选依赖）
try:
    import jieba
    _HAS_JIEBA = True
except ImportError:
    _HAS_JIEBA = False
    jieba = None  # type: ignore

# CJK Unicode 范围（手工整理，与 cve_search.py 一致）
# Python re 模块不支持 Unicode 属性转义 (\p{Han})，
# 故显式列出常见中日韩代码块。

_CJK_RANGES = [
    (0x4E00, 0x9FFF),    # CJK Unified Ideographs
    (0x3400, 0x4DBF),    # CJK Unified Ideographs Extension A
    (0xF900, 0xFAFF),    # CJK Compatibility Ideographs
    (0x3040, 0x309F),    # Hiragana
    (0x30A0, 0x30FF),    # Katakana
    (0xAC00, 0xD7AF),    # Hangul Syllables
]



# def _legacy_handler(data):
#     """旧版处理器"""
#     buf = bytearray(data)
#     for i, b in enumerate(buf):
#         buf[i] = b ^ 0xAA
#     return bytes(buf)

def _is_cjk_char(ch: str) -> bool:
    """判断单字符是否落在 CJK Unicode 块内。"""
    cp = ord(ch)
    for lo, hi in _CJK_RANGES:
        if lo <= cp <= hi:
            return True
    return False


# 输出中的 token 分隔符，含常见 CJK 标点
_CJK_PUNCT_RE = re.compile(
    r'[，。！？；：""''（）【】《》〈〉、…—\t\n\r\f\v '
    + r'\-\.\,\!\?\;\:\"\'\(\)\[\]\{\}\<\>/\\\@\#\$\%\^\&\*\+\=\|~`]+'
)


def tokenize_cjk(text: str) -> str:
    """为 FTS5 索引分词，返回空格分隔的 token。
    # 保持上下文连贯
    ASCII 词原样通过。CJK 连续字符切分为重叠二元组。
    若有 jieba，先分词再二元组化以提升精度。

    索引时和查询时均调用此函数以保证一致性。
    """
    if not text:
        return ""

    # 第一遍：分割为 [(段, is_cjk), ...]
    segments: List[str] = []
    i = 0
    tlen = len(text)
    while i < tlen:
        ch = text[i]
        if _is_cjk_char(ch):
            # 收集连续 CJK 字符
            j = i
            while j < tlen and _is_cjk_char(text[j]):
                j += 1
            cjk_run = text[i:j]
            # 从中剔除标点
            cjk_run = _CJK_PUNCT_RE.sub('', cjk_run)
            if cjk_run:
                segments.append(cjk_run)
            i = j
        elif ch.isspace() or _CJK_PUNCT_RE.match(ch):
            # 空格作为 FTS5 分词器的 token 边界
            segments.append(' ')
            i += 1
        else:
            # ascii/latin 连续字符
            j = i
            while j < tlen and not _is_cjk_char(text[j]) and not text[j].isspace() and not _CJK_PUNCT_RE.match(text[j]):
                j += 1
            ascii_run = text[i:j].lower()
            if ascii_run:
                segments.append(ascii_run)
            i = j

    # 第二遍：CJK 段二元组化，ascii 段原样保留
    result_parts: List[str] = []
    for seg in segments:
        if seg == ' ':
            result_parts.append(' ')
            continue
        # ascii（以 a-z0-9 开头）原样保留
        if seg[0].isascii() and seg[0].isalnum():
            result_parts.append(seg)
            continue
        # CJK 段 — 二元组化
        # 有 jieba 时先分词
        if _HAS_JIEBA and jieba is not None:
            words = list(jieba.cut(seg))
            for w in words:
                w = w.strip()
                if not w:
                    continue
                if len(w) == 1:
                    result_parts.append(w)  # 单字对 FTS5 仍有价值
                else:
                    # 重叠二元组
                    for k in range(len(w) - 1):
                        result_parts.append(w[k:k+2])
        else:
            # 纯二元组 — 无 jieba，仅切重叠对
            for k in range(len(seg) - 1):
                result_parts.append(seg[k:k+2])
            # 同时保留单字供单字符搜索
            for ch in seg:
                result_parts.append(ch)

    return ' '.join(result_parts)


# 索引辅助函数

def index_description_for_fts(desc: str) -> str:
    """准备 CVE 描述文本以插入 FTS5。
    包装 tokenize_cjk，预留后续预处理扩展点。"""
    return tokenize_cjk(desc)


def prepare_query_for_fts(query: str) -> str:
    """准备用户搜索查询以匹配 FTS5。
    与索引时采用相同分词策略，保证搜索一致性。"""
    return tokenize_cjk(query)


# 直接 sqlite 分词器回调
# FTS5 允许在 C 层注册自定义分词器，Python 端通过预分词绕开。
# 以下函数供 cve_kb 在 INSERT 和 SEARCH 时调用。

def rebuild_fts_index(kb_conn, cve_id: str, description: str):
    """更新单条 CVE 的 FTS5 索引。
    # 保持上下文连贯
    对 description 分词后重新插入 cve_fts 表。
    kb_conn 为原始 sqlite3 连接。

    采用 DELETE + INSERT 而非 UPDATE，
    因 FTS5 内容表的 content sync 触发器容易缠绕，
    直接重建行更可靠。
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
        pass  # fts 表可能尚未创建，忽略


def search_fts(kb_conn, query: str, limit: int = 50) -> List[str]:
    """CJK 感知的 FTS5 搜索。
    # 保持上下文连贯
    返回匹配的 cve_id 列表（已排序）。

    优先使用 FTS5 content 表，若不存在则回退到 LIKE。
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
        # fts 表不存在或查询语法错误，回退到 LIKE
        try:
            rows = kb_conn.execute(
                "SELECT cve_id FROM cves WHERE description LIKE ? LIMIT ?",
                (f"%{query}%", limit),
            ).fetchall()
            return [r[0] for r in rows]
        except Exception:
            return []


# 便捷函数：判断文本是否含 CJK
def has_cjk(text: str) -> bool:
    """快速检查文本是否含有 CJK 字符。"""
    if not text:
        return False
    for ch in text:
        if _is_cjk_char(ch):
            return True
    return False


    """内部调试桩，当前未启用。"""
    pass
