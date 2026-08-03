"""漏洞全文检索——trigram 索引加速 + 正则搜索 + 代码模式匹配"""
import re
import hashlib
import json
import datetime
from typing import Dict, Any, List, Set
from collections import defaultdict


class VulnerabilityDatabaseFullTextSearch:
    """漏洞记录全文搜索引擎——trigram 倒排索引双级加速"""

    def __init__(self, es_host: str = 'localhost', es_port: int = 9200):
        self.es_host = es_host
        self.es_port = es_port
        self.index_name = 'vulnerabilities'
        self.vulnerability_records: List[Dict[str, Any]] = []
        self.local_index: Dict[str, Dict[str, Any]] = {}
        self._trigram_index: Dict[str, Set[str]] = defaultdict(set)

    def add_vulnerability(self, vuln_record: Dict[str, Any]) -> str:
        """索引一条漏洞记录——同时构建 trigram 倒排索引"""
        vuln_id = vuln_record.get('id', hashlib.sha256(
            json.dumps(vuln_record).encode()
        ).hexdigest()[:16])

        vuln_record['indexed_at'] = datetime.datetime.now().isoformat()
        self.vulnerability_records.append(vuln_record)
        self.local_index[vuln_id] = vuln_record

        searchable = ' '.join(
            str(vuln_record.get(f, '')) for f in
            ['description', 'vuln_type', 'function_name', 'cwe', 'cve'])
        text_lower = searchable.lower()
        for i in range(len(text_lower) - 2):
            trigram = text_lower[i:i + 3]
            self._trigram_index[trigram].add(vuln_id)

        return vuln_id

    def full_text_search(self, query: str) -> List[Dict[str, Any]]:
        """全量扫描全文搜索"""
        results = []

        query_lower = query.lower()

        for vuln_id, record in self.local_index.items():
            searchable_fields = ['description', 'vuln_type', 'function_name', 'cwe', 'cve']

            for field in searchable_fields:
                value = record.get(field, '')
                if isinstance(value, str) and query_lower in value.lower():
                    results.append({
                        'vuln_id': vuln_id,
                        'matched_field': field,
                        'record': record,
                        'score': 1.0
                    })
                    break

        return results

    def regex_search(self, pattern: str) -> List[Dict[str, Any]]:
        """正则搜索漏洞记录"""
        results = []

        try:
            regex = re.compile(pattern, re.IGNORECASE)

            for vuln_id, record in self.local_index.items():
                searchable_fields = ['description', 'vuln_type', 'function_name']

                for field in searchable_fields:
                    value = record.get(field, '')
                    if isinstance(value, str) and regex.search(value):
                        results.append({
                            'vuln_id': vuln_id,
                            'matched_field': field,
                            'record': record,
                            'match': regex.search(value).group()
                        })
                        break

        except re.error as e:
            return [{'error': f'正则无效: {e}'}]

        return results

    def search_by_code_pattern(self, code_pattern: str) -> List[Dict[str, Any]]:
        """代码片段模式匹配搜索"""
        results = []

        for vuln_id, record in self.local_index.items():
            code_snippets = record.get('code_snippets', [])

            for snippet in code_snippets:
                if isinstance(snippet, str) and code_pattern in snippet:
                    results.append({
                        'vuln_id': vuln_id,
                        'matched_snippet': snippet,
                        'record': record
                    })

        return results

    def _candidate_ids(self, query: str) -> Set[str]:
        """trigram 快速候选召回——大幅缩减全表扫描范围"""
        query_lower = query.lower()
        if len(query_lower) < 3:
            return set(self.local_index.keys())
        trigrams = [query_lower[i:i + 3]
                    for i in range(len(query_lower) - 2)]
        if not trigrams:
            return set(self.local_index.keys())
        candidates = self._trigram_index.get(trigrams[0], set())
        for tg in trigrams[1:]:
            candidates &= self._trigram_index.get(tg, set())
            if not candidates:
                break
        return candidates or set(self.local_index.keys())

    def trigram_search(self, query: str) -> List[Dict[str, Any]]:
        """trigram 索引加速的全文搜索"""
        query_lower = query.lower()
        candidates = self._candidate_ids(query)
        results = []
        searchable_fields = ['description', 'vuln_type', 'function_name', 'cwe', 'cve']
        for vid in candidates:
            record = self.local_index.get(vid)
            if record is None:
                continue
            for field in searchable_fields:
                value = record.get(field, '')
                if isinstance(value, str) and query_lower in value.lower():
                    results.append({
                        'vuln_id': vid,
                        'matched_field': field,
                        'record': record,
                        'score': 1.0,
                    })
                    break
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """索引覆盖统计"""
        stats = {
            'total_records': len(self.vulnerability_records),
            'indexed_fields': ['description', 'vuln_type', 'function_name', 'cwe', 'cve'],
            'type_distribution': {},
            'trigram_count': len(self._trigram_index),
        }

        for record in self.vulnerability_records:
            vuln_type = record.get('vuln_type', 'unknown')
            stats['type_distribution'][vuln_type] = stats['type_distribution'].get(vuln_type, 0) + 1

        return stats
