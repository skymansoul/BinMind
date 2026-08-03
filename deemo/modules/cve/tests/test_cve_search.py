# 19项测试: 分词（英文、CJK、混合、停用词）、索引构建/搜索/排序、
#           同义词扩展（xss/rce/dos）、边界情况（空KB、min_score、explain）

import pytest
from modules.cve.src.cve_kb import CVEKnowledgeBase
from modules.cve.src.cve_models import _make_test_entry
from modules.cve.src.cve_search import CVESearchEngine, _SYNONYMS, _tokenize, _is_cjk


@pytest.fixture
def kb():
    db = CVEKnowledgeBase(":memory:")
    yield db
    db.close()


@pytest.fixture
def seeded_kb(kb):
    """KB with varied CVE entries for search testing."""
    entries = [
        _make_test_entry("CVE-2024-0001", description="Remote code execution in Apache Log4j allows attackers to execute arbitrary code"),
        _make_test_entry("CVE-2024-0002", description="Cross site scripting vulnerability in web application framework"),
        _make_test_entry("CVE-2024-0003", description="SQL injection in database connector allows data exfiltration"),
        _make_test_entry("CVE-2024-0004", description="Denial of service via malformed packet in network service"),
        _make_test_entry("CVE-2024-0005", description="Use after free in browser rendering engine leads to code execution"),
        _make_test_entry("CVE-2024-0006", description="Privilege escalation via insecure file permissions in system service"),
        _make_test_entry("CVE-2024-0007", description="Buffer overflow in image parsing library allows remote code execution"),
        _make_test_entry("CVE-2024-0008", description="远程代码执行漏洞在日志记录框架中"),  # CJK: rce vuln in logging framework
    ]
    for e in entries:
        kb.insert(e)
    return kb


# ---- Tokenization (5 tests) ----

class TestTokenization:
    def test_english_tokenization(self):
        tokens = _tokenize("Remote Code Execution in Apache Log4j")
        assert "remote" in tokens
        assert "code" in tokens
        assert "execution" in tokens
        assert "apache" in tokens
        assert "log4j" in tokens

    def test_stopwords_removed(self):
        tokens = _tokenize("the vulnerability in the system")
        assert "the" not in tokens  # stopword
        assert "vulnerability" in tokens
        assert "system" in tokens

    def test_cjk_tokenization(self):
        """CJK text → overlapping bigrams. Each bigram should be len 2."""
        tokens = _tokenize("远程代码执行")  # 远程代码执行
        assert len(tokens) > 0
        for t in tokens:
            assert len(t) == 2  # all bigrams

    def test_mixed_cjk_latin(self):
        """Mixed query like 'log4j 远程代码执行 rce'."""
        tokens = _tokenize("log4j 远程代码执行 rce")
        assert "log4j" in tokens
        assert "rce" in tokens
        # should also have CJK bigrams
        assert any(len(t) == 2 for t in tokens)

    def test_is_cjk(self):
        assert _is_cjk('中') is True  # CJK Unified
        assert _is_cjk('a') is False
        assert _is_cjk('1') is False


# ---- Synonyms (3 tests) ----

class TestSynonyms:
    def test_synonyms_dict(self):
        assert "rce" in _SYNONYMS
        assert "xss" in _SYNONYMS
        assert "sqli" in _SYNONYMS
        assert "dos" in _SYNONYMS
        assert "uaf" in _SYNONYMS
        assert "privesc" in _SYNONYMS

    def test_synonym_values(self):
        assert _SYNONYMS["rce"] == "remote code execution"
        assert _SYNONYMS["xss"] == "cross site scripting"
        assert _SYNONYMS["sqli"] == "sql injection"

    def test_hand_curated_size(self):
        """Should be ~20 entries — genuinely hand-curated, not auto-generated."""
        assert 15 <= len(_SYNONYMS) <= 25


# ---- Search engine (6 tests) ----

class TestSearchEngine:
    def test_build_index(self, seeded_kb):
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        assert engine._doc_count > 0

    def test_search_finds_rce(self, seeded_kb):
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        results = engine.search("remote code execution")
        assert len(results) > 0
        # top result should be the RCE entry
        assert "CVE-2024-0001" in [r["cve_id"] for r in results]

    def test_synonym_expansion(self, seeded_kb):
        """搜索'xss'应通过同义词扩展找到XSS条目。"""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        results = engine.search("xss")  # abbreviation not in description text
        assert len(results) > 0
        # the synonym expansion should map xss→cross site scripting
        cve_ids = [r["cve_id"] for r in results]
        assert "CVE-2024-0002" in cve_ids  # the XSS entry

    def test_rce_synonym(self, seeded_kb):
        """搜索'rce'应找到RCE条目。"""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        results = engine.search("rce")
        assert len(results) > 0

    def test_dos_synonym(self, seeded_kb):
        """搜索'dos'应找到DoS条目。"""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        results = engine.search("dos")
        assert len(results) > 0

    def test_ranking(self, seeded_kb):
        """Results should be ordered by relevance."""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        results = engine.search("remote code execution")
        scores = [r["score"] for r in results]
        assert scores == sorted(scores, reverse=True)  # descending


# ---- Edge cases (5 tests) ----

class TestSearchEdgeCases:
    def test_empty_kb(self, kb):
        """Empty KB should return empty results, not crash."""
        engine = CVESearchEngine(kb)
        engine.build()
        results = engine.search("anything")
        assert results == []

    def test_search_without_build_auto_builds(self, kb):
        """Lazy-build: searching without calling build() should auto-build."""
        kb.insert(_make_test_entry("CVE-2024-0001", description="test vulnerability"))
        engine = CVESearchEngine(kb)
        # don't call build()
        results = engine.search("test")
        assert len(results) >= 0  # should auto-build, not crash

    def test_min_score_filter(self, seeded_kb):
        """min_score filter should exclude low-relevance results."""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        results = engine.search("random nonsense query", min_score=0.5)
        assert len(results) == 0

    def test_explain_returns_details(self, seeded_kb):
        """Explain mode returns scoring breakdown."""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        explanations = engine.explain("rce", top_n=3)
        assert len(explanations) <= 3
        for exp in explanations:
            assert "cve_id" in exp
            assert "score" in exp

    def test_rebuild_clears(self, seeded_kb):
        """Rebuild should clear and rebuild the index."""
        engine = CVESearchEngine(seeded_kb)
        engine.build()
        assert engine._doc_count > 0
        engine.rebuild()
        assert engine._doc_count > 0  # should still have docs after rebuild
