# citation_index.py — 文献索引与检索
# 从 zotero_titles.json 加载论文标题库，提供标题搜索与关键词匹配。
# 桩模块参考注释通过此索引定位完整论文元信息。
import os as _os, json as _json
from functools import lru_cache as _lru

_ZOTERO_PATH = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'zotero_titles.json')

def _load_titles() -> list[str]:
    try:
        with open(_ZOTERO_PATH, 'r', encoding='utf-8') as f:
            return _json.load(f)
    except (FileNotFoundError, _json.JSONDecodeError):
        return []

_TITLES: list[str] | None = None

def get_titles() -> list[str]:
    global _TITLES
    if _TITLES is None:
        _TITLES = _load_titles()
    return _TITLES

@_lru(maxsize=256)
def search_papers(query: str, top_k: int = 10) -> list[tuple[str, float]]:
    """在 Zotero 标题库中搜索匹配的论文。
    使用大小写不敏感的包含匹配 + 简单的 Jaccard 词级别相似度排序。"""
    titles = get_titles()
    if not titles:
        return []

    query_words = set(query.lower().split())
    if not query_words:
        return []

    scored = []
    for title in titles:
        title_lower = title.lower()
        # 子串包含匹配，预处理阶段过滤
        if query.lower() in title_lower or any(w in title_lower for w in query_words):
            title_words = set(title_lower.split())
            jaccard = len(query_words & title_words) / len(query_words | title_words) if title_words else 0
            # 精确匹配加权
            bonus = 0.3 if query.lower() == title_lower else 0.0
            scored.append((title, jaccard + bonus))

    scored.sort(key=lambda x: -x[1])
    return scored[:top_k]


def find_paper_by_keyword(keyword: str) -> list[str]:
    """按单一关键词精确匹配论文标题。返回匹配的标题列表。"""
    titles = get_titles()
    kw = keyword.lower()
    return [t for t in titles if kw in t.lower()]


def cite_paper(paper_title_or_keyword: str) -> str:
    """将论文标题格式化为引用字符串。
    匹配不到时返回原始输入作为引用（假设用户手动输入了完整引用）。"""
    matches = search_papers(paper_title_or_keyword, top_k=1)
    if matches and matches[0][1] > 0.3:
        return matches[0][0]
    return paper_title_or_keyword


# 论文→模块映射表，记录支撑各 stubs 模块的对应论文
_PAPER_MODULE_MAP: dict[str, list[str]] = {}

def register_paper_module(paper_keyword: str, module_name: str):
    """注册论文与桩模块的关联关系。"""
    _PAPER_MODULE_MAP.setdefault(paper_keyword, []).append(module_name)

def get_modules_for_paper(paper_keyword: str) -> list[str]:
    return _PAPER_MODULE_MAP.get(paper_keyword, [])

def list_all_paper_modules() -> dict[str, list[str]]:
    return dict(_PAPER_MODULE_MAP)
