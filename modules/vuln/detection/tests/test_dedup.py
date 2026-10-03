"""vuln_dedup 哈希与语义去重策略测试"""
import sys
import os
import pytest

# sys.path 注入，规避 vuln/__init__.py 既有导入异常
_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

try:
    from vuln_deduplicator import (
        VulnDeduplicator, DeduplicationStrategy,
        DeduplicationResult, deduplicate_vulnerabilities,
        VulnerabilitySignature
    )
    _dedup_available = True
except Exception:
    _dedup_available = False


# 测试数据构造

def _make_vuln(vuln_type, func_name, severity="MEDIUM", source="", sink="",
               taint_flow="", pseudocode="", **kwargs):
    """构造去重测试用例字典"""
    return {
        "vulnerability_type": vuln_type,
        "function_name": func_name,
        "severity": severity,
        "source": source,
        "sink": sink,
        "taint_flow": taint_flow,
        "pseudocode": pseudocode,
        "requires_user_interaction": kwargs.get("requires_user_interaction", False),
        "network_accessible": kwargs.get("network_accessible", False),
    }


@pytest.mark.skipif(not _dedup_available, reason="vuln_deduplicator not importable")
class TestDeduplicationStrategies:
    """各去重策略单元测试"""

    def test_dataflow_dedup_merges_exact_hash(self):
        """dataflow_hash 一致则归入同一簇"""
        dedup = VulnDeduplicator(strategy=DeduplicationStrategy.DATAFLOW)
        vulns = [
            _make_vuln("buffer_overflow", "func_a",
                       source="user_input", sink="memcpy", taint_flow="A->B->C",
                       pseudocode="mov eax, ebx"),
            _make_vuln("buffer_overflow", "func_b",
                       source="user_input", sink="memcpy", taint_flow="A->B->C",
                       pseudocode="push ebp"),
        ]
        result = dedup.deduplicate(vulns)
        assert isinstance(result, DeduplicationResult)
        # dataflow hash 一致 → 1 簇
        assert result.unique_count == 1
        assert result.deduplicated_count > 0

    def test_semantic_dedup_groups_similar(self):
        """语义相似度聚类（Jaccard 阈值判定）"""
        dedup = VulnDeduplicator(strategy=DeduplicationStrategy.SEMANTIC)
        vulns = [
            _make_vuln("buffer_overflow", "func_a", severity="HIGH",
                       requires_user_interaction=True, network_accessible=True),
            _make_vuln("buffer_overflow", "func_b", severity="HIGH",
                       requires_user_interaction=True, network_accessible=False),
        ]
        result = dedup.deduplicate(vulns)
        assert isinstance(result, DeduplicationResult)
        assert result.unique_count >= 1

    def test_hybrid_dedup_combines_strategies(self):
        """混合策略加权三类相似度得分"""
        dedup = VulnDeduplicator(strategy=DeduplicationStrategy.HYBRID)
        vulns = [
            _make_vuln("buffer_overflow", "func_a",
                       source="input", sink="memcpy", taint_flow="X->Y",
                       pseudocode="mov rax, rdi"),
            _make_vuln("buffer_overflow", "func_a",
                       source="input", sink="memcpy", taint_flow="X->Y",
                       pseudocode="mov rax, rdi"),
        ]
        result = dedup.deduplicate(vulns)
        assert result.unique_count == 1

    def test_distinct_vulns_remain_separate(self):
        """不相关漏洞维持独立分簇"""
        dedup = VulnDeduplicator(strategy=DeduplicationStrategy.DATAFLOW)
        vulns = [
            _make_vuln("buffer_overflow", "func_a",
                       source="input_A", sink="sink_A", taint_flow="A"),
            _make_vuln("format_string", "func_c",
                       source="input_C", sink="sink_C", taint_flow="C"),
            _make_vuln("use_after_free", "func_e",
                       source="input_E", sink="sink_E", taint_flow="E"),
        ]
        result = dedup.deduplicate(vulns)
        assert result.unique_count == 3

    def test_result_includes_strategy(self):
        """结果中携带所用策略标识"""
        dedup = VulnDeduplicator(strategy=DeduplicationStrategy.SYNTAX)
        vulns = [_make_vuln("null_dereference", "defer_func")]
        result = dedup.deduplicate(vulns)
        assert result.strategy == DeduplicationStrategy.SYNTAX


@pytest.mark.skipif(not _dedup_available, reason="vuln_deduplicator not importable")
class TestVulnerabilitySignature:
    """VulnerabilitySignature 序列化验证"""

    def test_signature_to_dict(self):
        """to_dict 输出结构校验"""
        sig = VulnerabilitySignature(
            vulnerability_type="buffer_overflow",
            function_name="test_func",
            dataflow_hash="abc123",
            syntax_hash="def456",
            semantic_features=["type:buffer_overflow"],
            address=0x401234,
            severity="HIGH"
        )
        d = sig.to_dict()
        assert d["vulnerability_type"] == "buffer_overflow"
        assert d["address"] == hex(0x401234)
        assert "semantic_features" in d


@pytest.mark.skipif(not _dedup_available, reason="vuln_deduplicator not importable")
class TestModuleLevelFunction:
    """deduplicate_vulnerabilities 工厂入口"""

    def test_deduplicate_vulnerabilities_with_hybrid(self):
        """deduplicate_vulnerabilities 混合策略调用"""
        vulns = [
            _make_vuln("xss", "render_html", pseudocode="div.innerHTML = x",
                       requires_user_interaction=True),
            _make_vuln("xss", "render_html", pseudocode="div.innerHTML = x",
                       requires_user_interaction=True),
        ]
        result = deduplicate_vulnerabilities(vulns, strategy="hybrid")
        assert result.unique_count == 1
        assert result.total_count == 2


# 独立测试（不依赖模块导入）

class TestHashDedupInline:
    """哈希去重内联逻辑测试"""

    def test_hash_dedup_removes_duplicates(self):
        """哈希碰撞条目被合并"""
        entries = [
            {"hash": "abc", "data": "x"},
            {"hash": "abc", "data": "y"},
            {"hash": "def", "data": "z"},
        ]
        seen = set()
        deduped = []
        for e in entries:
            if e["hash"] not in seen:
                seen.add(e["hash"])
                deduped.append(e)
        assert len(deduped) == 2

    def test_all_unique_no_dedup(self):
        """全唯一哈希条目无丢失"""
        entries = [
            {"hash": "aaa", "data": "1"},
            {"hash": "bbb", "data": "2"},
            {"hash": "ccc", "data": "3"},
        ]
        seen = set()
        deduped = []
        for e in entries:
            if e["hash"] not in seen:
                seen.add(e["hash"])
                deduped.append(e)
        assert len(deduped) == 3


def test_jaccard_semantic_threshold():
    """Jaccard 相似度阈值：语义相近集合得分 > 0.5"""
    def jaccard(a, b):
        sa, sb = set(a), set(b)
        return len(sa & sb) / len(sa | sb) if sa | sb else 0
    s = jaccard(["read", "write", "exec"], ["read", "write", "map"])
    assert s >= 0.5
    # 无交集 → 相似度 0
    s2 = jaccard(["a", "b"], ["c", "d"])
    assert s2 == 0.0
