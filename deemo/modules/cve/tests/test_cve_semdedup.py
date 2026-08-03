# SemDedup 测试 — 语义嵌入跨源去重 + 字段级不一致性发现
# 覆盖: 归一化 / CVE ID 聚类 / 语义聚类 / 冲突检测 / 结构化抽取 /
#        版本区间嵌入增强 / 一站式流水线 / 后端工厂降级

import os
import pytest

from modules.cve.src.cve_models import CVEEntry
from modules.cve.src.cve_ghsa import GHSAEntry
from modules.cve.src.cve_semdedup import (
    SourceRecord, SemDeduper, FieldConflictDetector, StructuredExtractor,
    VersionRangeEmbeddingEnhancer, SemDedupPipeline, run_semdedup,
    inconsistency_report, get_embedding_backend, LLMEmbeddingBackend,
)


def _nvd_entry(cve_id="CVE-2024-1234", desc="vuln desc", score=8.8,
               products=("example-lib",), affected_ranges=None):
    return CVEEntry(cve_id=cve_id, description=desc, severity="HIGH",
                    cvss_score=score, products=list(products),
                    vendors=["example"], source="nvd",
                    affected_ranges=affected_ranges or [])


class TestSourceRecordNormalization:
    def test_from_cve_entry(self):
        sr = SourceRecord.from_record(_nvd_entry())
        assert sr.source == "nvd"
        assert sr.cve_id == "CVE-2024-1234"
        assert sr.affected_packages[0]["name"] == "example-lib"

    def test_from_ghsa_entry(self):
        gh = GHSAEntry(ghsa_id="GHSA-a-b-c", cve_id="CVE-2024-5555",
                       description="d", vulnerabilities=[
                           {"package": {"ecosystem": "npm", "name": "pkg-x"},
                            "ranges": [{"type": "SEMVER",
                                        "events": [{"introduced": "1.0.0"},
                                                   {"fixed": "1.5.0"}]}]}])
        sr = SourceRecord.from_cve_entry(gh)
        assert sr.source == "ghsa"
        assert sr.affected_packages[0]["ecosystem"] == "npm"
        assert len(sr.affected_ranges) == 1

    def test_from_dict_with_cve_in_description(self):
        # ExploitDB 风格: 无结构化 ID, CVE 出现在描述中
        sr = SourceRecord.from_dict(
            {"source": "exploitdb",
             "description": "exploit for CVE-2024-9999 in lib"})
        assert sr.cve_id == "CVE-2024-9999"


@pytest.fixture
def dup_records():
    nvd = _nvd_entry(cve_id="CVE-2024-1234",
                     desc="A buffer overflow in example-lib allows remote code execution.",
                     score=8.8,
                     affected_ranges=[{"type": "SEMVER",
                                       "events": [{"introduced": "1.0.0"},
                                                  {"fixed": "1.1.0"}]}])
    ghsa = {"source": "ghsa", "cve_id": "CVE-2024-1234",
            "description": "example-lib before 1.2.0 has a buffer overflow.",
            "cvss_score": 9.1, "severity": "CRITICAL",
            "affected_ranges": [{"type": "SEMVER",
                                 "events": [{"introduced": "1.0.0"},
                                            {"fixed": "1.2.0"}]}],
            "published_date": "2024-06-10T00:00:00.000"}
    ghsa_only = {"source": "ghsa",
                 "description": "Apache Log4j2 before 2.17.0 allows remote code execution via JNDI.",
                 "severity": "CRITICAL", "cvss_score": 10.0,
                 "ecosystem": "maven", "products": ["log4j-core"]}
    edb_only = {"source": "exploitdb",
                "description": "Log4j JNDI injection leads to remote code execution, affects log4j-core.",
                "severity": "HIGH", "cvss_score": 9.8,
                "products": ["log4j-core"]}
    other = {"source": "ghsa",
             "description": "Django allows path traversal in template engine.",
             "severity": "MEDIUM", "products": ["django"]}
    return [nvd, ghsa, ghsa_only, edb_only, other]


class TestSemDeduper:
    def test_cve_id_merge(self, dup_records):
        merged = SemDeduper().dedupe(dup_records)
        cve1234 = next(m for m in merged if m.cve_id == "CVE-2024-1234")
        assert {"nvd", "ghsa"} <= set(cve1234.sources)
        assert cve1234.matched_by == "cve_id"
        assert cve1234.merge_confidence == 1.0

    def test_semantic_merge(self, dup_records):
        merged = SemDeduper().dedupe(dup_records)
        sem = next(m for m in merged if m.cve_id is None and "exploitdb" in m.sources)
        assert "ghsa" in sem.sources
        assert sem.matched_by == "semantic"
        assert 0.0 < sem.merge_confidence < 1.0

    def test_unrelated_not_merged(self, dup_records):
        merged = SemDeduper().dedupe(dup_records)
        assert len(merged) == 3
        django = next(m for m in merged if "django" in m.description)
        assert len(django.sources) == 1

    def test_empty_input(self):
        assert SemDeduper().dedupe([]) == []


class TestFieldConflictDetector:
    def test_cvss_and_range_conflict(self, dup_records):
        merged = SemDeduper().dedupe(dup_records)
        detector = FieldConflictDetector()
        all_conf = []
        for m in merged:
            all_conf.extend(detector.detect(m))
        types = {(c.field, c.conflict_type) for c in all_conf}
        assert ("cvss_score", "cvss_numeric_diff") in types
        assert ("version_range", "range_discrepancy") in types
        assert any(c.severity == "high" for c in all_conf)

    def test_single_source_no_conflict(self):
        rec = SourceRecord.from_dict({"source": "nvd", "cve_id": "CVE-2024-1",
                                      "description": "x"})
        merged = SemDeduper().merge_cluster([rec])
        assert FieldConflictDetector().detect(merged) == []


class TestStructuredExtractor:
    def test_rule_extraction(self):
        ex = StructuredExtractor(use_llm=False)
        r = ex.extract("A buffer overflow in example-lib versions 1.0 through 1.9 "
                       "allows remote attacker to run arbitrary code.",
                       hints={"products": ["example-lib"]})
        assert "example-lib" in r["affected_components"]
        assert r["version_ranges"]
        assert r["attack_vectors"]
        assert r["vulnerability_types"]

    def test_llm_degrade(self):
        # 无 CVE_LLM_API_URL 环境变量时, LLM 抽取必须返回 None
        os.environ.pop("CVE_LLM_API_URL", None)
        ex = StructuredExtractor(use_llm=True)
        assert ex.extract_llm("some text") is None


class TestVersionRangeEmbeddingEnhancer:
    def _records(self, n):
        merged = []
        for i in range(n):
            rec = SourceRecord.from_dict({
                "source": "nvd", "cve_id": f"CVE-2024-{7000+i}",
                "description": f"vuln {i} in lib{i}",
                "cvss_score": 5.0 + i, "severity": "HIGH" if i >= 3 else "MEDIUM",
                "products": [f"lib{i}"],
                "affected_ranges": [{"type": "SEMVER",
                                     "events": [{"introduced": "1.0.0"},
                                                {"fixed": f"1.{i}.0"}]}]})
            merged.append(rec)
        return SemDeduper().dedupe([r for r in merged])

    def test_fit_and_embedding(self):
        merged = self._records(6)
        enh = VersionRangeEmbeddingEnhancer()
        stats = enh.fit(merged)
        assert stats["n_entities"] == 6
        assert stats["method"] == "causal_contrastive"
        emb = enh.get_embedding("CVE-2024-7000")
        assert emb and len(emb) == 16

    def test_enhance_unseen_range(self):
        merged = self._records(6)
        enh = VersionRangeEmbeddingEnhancer()
        enh.fit(merged)
        rng = [{"type": "SEMVER", "events": [{"introduced": "1.0.0"},
                                             {"fixed": "9.9.9"}]}]
        vec = enh.enhance_version_range(rng)
        assert len(vec) == 16


class TestPipeline:
    def test_run(self, dup_records):
        res = run_semdedup(dup_records, extract=True, enhance=True)
        assert res["stats"]["merged_entities"] == 3
        assert res["stats"]["conflict_items"] >= 2
        assert res["extractions"]
        assert res["embeddings"]

    def test_inconsistency_report(self, dup_records):
        rep = inconsistency_report(dup_records)
        assert rep["conflict_summary"]
        assert rep["stats"]["merged_entities"] == 3


class TestBackendFactory:
    def test_llm_not_configured_degrade(self):
        os.environ.pop("CVE_EMBEDDING_API_URL", None)
        llm = LLMEmbeddingBackend()
        assert llm.is_configured is False
        assert llm.embed("x") is None

    def test_auto_fallback(self):
        os.environ.pop("CVE_EMBEDDING_API_URL", None)
        be = get_embedding_backend("auto", texts=["alpha beta", "beta gamma"])
        assert be.name in ("tfidf", "char-ngram")
