import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

_logger = logging.getLogger(__name__)


def _debug_print(msg): pass  # noqa

_LEGACY_MODE = False  # 保留


class VulnerabilityDatabaseStats:
    """
    漏洞数据库搜索与统计方法（Mixin）

    依赖VulnerabilityDatabaseCore提供:
        - self.connection
        - self._hash_pseudocode()
        - self._row_to_dict()
        - self.jaccard_similarity()
        - self.calculate_dangerous_function_score()
        - self.semantic_search()
    """

    def search_by_function(
        self,
        function_name: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        按函数名搜索相似漏洞

        Args:
            function_name: 函数名
            limit: 返回结果数量限制

        Returns:
            匹配的漏洞记录列表
        """
        if not self.connection:
            return []

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE function_name LIKE ? ORDER BY created_at DESC LIMIT ?",
                (f"%{function_name}%", limit)
            )

            results = []
            for row in cursor.fetchall():
                results.append(self._row_to_dict(row))

            return results
        except Exception as e:
            _logger.error(f"按函数名搜索失败: {e}")
            return []

    def search_by_vulnerability_type(
        self,
        vulnerability_type: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        按漏洞类型搜索

        Args:
            vulnerability_type: 漏洞类型
            limit: 返回结果数量限制

        Returns:
            匹配的漏洞记录列表
        """
        if not self.connection:
            return []

        try:
            cursor = self.connection.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE vulnerability_type LIKE ? ORDER BY created_at DESC LIMIT ?",
                (f"%{vulnerability_type}%", limit)
            )

            results = []
            for row in cursor.fetchall():
                results.append(self._row_to_dict(row))

            return results
        except Exception as e:
            _logger.error(f"按漏洞类型搜索失败: {e}")
            return []

    def search_by_type(
        self,
        vulnerability_type: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        # search_by_vulnerability_type 的别名
        return self.search_by_vulnerability_type(vulnerability_type, limit)

    def search_by_pseudocode(
        self,
        pseudocode: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        按伪代码搜索相似漏洞

        Args:
            pseudocode: 伪代码
            limit: 返回结果数量限制

        Returns:
            匹配的漏洞记录列表
        """
        if not self.connection:
            return []

        try:
            pseudocode_hash = self._hash_pseudocode(pseudocode)

            cursor = self.connection.cursor()
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE pseudocode_hash = ? ORDER BY created_at DESC LIMIT ?",
                (pseudocode_hash, limit)
            )

            results = []
            for row in cursor.fetchall():
                results.append(self._row_to_dict(row))

            return results
        except Exception as e:
            _logger.error(f"按伪代码搜索失败: {e}")
            return []

    def search_similar(
        self,
        pseudocode: str,
        dangerous_functions: List[str] = None,
        binary_format: str = None,
        architecture: str = None,
        limit: int = 10,
        fuzzy_search: bool = True,
        min_jaccard_threshold: float = 0.2
    ) -> List[Dict[str, Any]]:
        """
        综合搜索相似漏洞

        Args:
            pseudocode: 伪代码
            dangerous_functions: 危险函数列表
            binary_format: 文件格式
            architecture: 架构
            limit: 返回结果数量限制
            fuzzy_search: 是否启用模糊搜索（基于危险函数 Jaccard 相似度）
            min_jaccard_threshold: 最小 Jaccard 相似度阈值（0.0-1.0）

        Returns:
            匹配的漏洞记录列表，按相似度排序
        """
        if not self.connection:
            return []

        try:
            exact_matches = []
            fuzzy_matches = []

            if pseudocode:
                pseudocode_hash = self._hash_pseudocode(pseudocode)
                exact_matches = self.search_by_pseudocode(pseudocode, limit=limit * 2)

            if dangerous_functions and fuzzy_search:
                conditions = []
                params = []

                if binary_format:
                    conditions.append("binary_format = ?")
                    params.append(binary_format)

                if architecture:
                    conditions.append("architecture = ?")
                    params.append(architecture)

                if conditions:
                    where_clause = " AND ".join(conditions)
                    query = f"SELECT * FROM vulnerabilities WHERE {where_clause} ORDER BY created_at DESC LIMIT ?"
                    params.append(limit * 5)
                else:
                    query = "SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT ?"
                    params.append(limit * 5)

                cursor = self.connection.cursor()
                cursor.execute(query, params)

                for row in cursor.fetchall():
                    record = self._row_to_dict(row)

                    record_funcs = record.get('dangerous_functions', [])
                    if isinstance(record_funcs, str):
                        try:
                            record_funcs = json.loads(record_funcs)
                        except json.JSONDecodeError:  # 修复: bare except → JSONDecodeError
                            record_funcs = []

                    jaccard_sim = self.jaccard_similarity(dangerous_functions, record_funcs)

                    if jaccard_sim >= min_jaccard_threshold:
                        record['jaccard_similarity'] = jaccard_sim

                        combo_score = self.calculate_dangerous_function_score(
                            record_funcs,
                            record.get('vulnerability_type')
                        )
                        record['combo_score'] = combo_score['score']

                        record['search_score'] = jaccard_sim * 100 + combo_score['score'] * 0.5

                        fuzzy_matches.append(record)

                fuzzy_matches.sort(key=lambda x: x.get('search_score', 0), reverse=True)
                fuzzy_matches = fuzzy_matches[:limit * 2]

            all_results = {}

            for item in exact_matches:
                vid = item.get('id')
                if vid:
                    all_results[vid] = {**item, 'match_type': 'exact', 'search_score': 100.0}

            for item in fuzzy_matches:
                vid = item.get('id')
                if vid:
                    if vid in all_results:
                        all_results[vid]['search_score'] = max(
                            all_results[vid].get('search_score', 0),
                            item.get('search_score', 0)
                        )
                    else:
                        all_results[vid] = {**item, 'match_type': 'fuzzy'}

            sorted_results = sorted(
                all_results.values(),
                key=lambda x: x.get('search_score', 0),
                reverse=True
            )[:limit]

            if sorted_results:
                _logger.debug(
                    f"相似搜索完成: 精确匹配={len(exact_matches)}, "
                    f"模糊匹配={len(fuzzy_matches)}"
                )

            return sorted_results

        except Exception as e:
            _logger.error(f"相似性搜索失败: {e}")
            return []

    def fuzzy_search_by_dangerous_functions(
        self,
        dangerous_functions: List[str],
        vulnerability_type: str = None,
        binary_format: str = None,
        architecture: str = None,
        limit: int = 10,
        min_score: int = 10
    ) -> List[Dict[str, Any]]:
        """
        基于危险函数组合的模糊搜索

        Args:
            dangerous_functions: 危险函数列表
            vulnerability_type: 漏洞类型（可选）
            binary_format: 文件格式（可选）
            architecture: 架构（可选）
            limit: 返回结果数量限制
            min_score: 最小匹配分数

        Returns:
            按评分排序的漏洞记录列表
        """
        if not self.connection:
            return []

        try:
            conditions = []
            params = []

            if dangerous_functions:
                for func in dangerous_functions:
                    conditions.append("dangerous_functions LIKE ?")
                    params.append(f"%{func}%")

            if binary_format:
                conditions.append("binary_format = ?")
                params.append(binary_format)

            if architecture:
                conditions.append("architecture = ?")
                params.append(architecture)

            if conditions:
                where_clause = " OR ".join(conditions)
                query = f"SELECT * FROM vulnerabilities WHERE {where_clause} ORDER BY created_at DESC LIMIT ?"
                params.append(limit * 3)
            else:
                query = "SELECT * FROM vulnerabilities ORDER BY created_at DESC LIMIT ?"
                params.append(limit * 3)

            cursor = self.connection.cursor()
            cursor.execute(query, params)

            results = []
            for row in cursor.fetchall():
                record = self._row_to_dict(row)

                record_funcs = record.get('dangerous_functions', [])
                if isinstance(record_funcs, str):
                    try:
                        record_funcs = json.loads(record_funcs)
                    except json.JSONDecodeError:  # 修复: bare except → JSONDecodeError
                        record_funcs = []

                score_info = self.calculate_dangerous_function_score(
                    record_funcs,
                    record.get('vulnerability_type')
                )

                record['match_score'] = score_info['score']
                record['match_risk'] = score_info['risk_level']
                record['match_notes'] = score_info['notes']

                if record['match_score'] >= min_score:
                    results.append(record)

            results.sort(key=lambda x: x['match_score'], reverse=True)

            return results[:limit]

        except Exception as e:
            _logger.error(f"模糊搜索失败: {e}")
            return []

    def get_statistics(self) -> Dict[str, Any]:
        """
        获取数据库统计信息

        Returns:
            统计信息字典
        """
        if not self.connection:
            return {}

        try:
            cursor = self.connection.cursor()

            stats = {
                'total': 0,
                'by_type': {},
                'by_format': {},
                'by_architecture': {},
                'by_severity': {}
            }

            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            stats['total'] = cursor.fetchone()[0]

            cursor.execute(
                "SELECT vulnerability_type, COUNT(*) FROM vulnerabilities GROUP BY vulnerability_type"
            )
            for row in cursor.fetchall():
                stats['by_type'][row[0]] = row[1]

            cursor.execute(
                "SELECT binary_format, COUNT(*) FROM vulnerabilities GROUP BY binary_format"
            )
            for row in cursor.fetchall():
                stats['by_format'][row[0]] = row[1]

            cursor.execute(
                "SELECT architecture, COUNT(*) FROM vulnerabilities GROUP BY architecture"
            )
            for row in cursor.fetchall():
                stats['by_architecture'][row[0]] = row[1]

            cursor.execute(
                "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
            )
            for row in cursor.fetchall():
                stats['by_severity'][row[0]] = row[1]

            return stats
        except Exception as e:
            _logger.error(f"获取统计信息失败: {e}")
            return {}

    def enhanced_search_similar(
        self,
        pseudocode: str = "",
        dangerous_functions: List[str] = None,
        binary_format: str = None,
        architecture: str = None,
        query_embedding: List[float] = None,
        limit: int = 10,
        min_score: int = 10,
        min_similarity: float = 0.7
    ) -> Dict[str, Any]:
        """
        增强版相似漏洞搜索：结合哈希、危险函数评分和语义向量

        Args:
            pseudocode: 伪代码
            dangerous_functions: 危险函数列表
            binary_format: 文件格式
            architecture: 架构
            query_embedding: 查询向量（可选）
            limit: 返回结果数量
            min_score: 最小危险函数评分
            min_similarity: 最小语义相似度

        Returns:
            包含各类搜索结果的字典
        """
        results = {
            'exact_hash_matches': [],
            'fuzzy_dangerous_matches': [],
            'semantic_matches': [],
            'combined_results': []
        }

        if pseudocode:
            results['exact_hash_matches'] = self.search_by_pseudocode(
                pseudocode, limit=limit
            )

        if dangerous_functions:
            results['fuzzy_dangerous_matches'] = self.fuzzy_search_by_dangerous_functions(
                dangerous_functions=dangerous_functions,
                binary_format=binary_format,
                architecture=architecture,
                limit=limit,
                min_score=min_score
            )

        if query_embedding and VECTOR_STORAGE_AVAILABLE:
            results['semantic_matches'] = self.semantic_search(
                query_embedding=query_embedding,
                limit=limit,
                min_similarity=min_similarity
            )

        combined = {}

        for item in results['exact_hash_matches']:
            vid = item.get('id')
            if vid:
                combined[vid] = {**item, 'match_type': 'exact_hash', 'final_score': 100}

        for item in results['fuzzy_dangerous_matches']:
            vid = item.get('id')
            if vid:
                score = item.get('match_score', 0)
                if vid in combined:
                    combined[vid]['final_score'] += score * 0.5
                    combined[vid]['match_type'] += '+dangerous'
                else:
                    combined[vid] = {**item, 'match_type': 'dangerous', 'final_score': score}

        for item in results['semantic_matches']:
            vid = item.get('id')
            if vid:
                sim = item.get('similarity', 0) * 100
                if vid in combined:
                    combined[vid]['final_score'] += sim * 0.7
                    combined[vid]['match_type'] += '+semantic'
                else:
                    combined[vid] = {**item, 'match_type': 'semantic', 'final_score': sim}

        results['combined_results'] = sorted(
            combined.values(),
            key=lambda x: x.get('final_score', 0),
            reverse=True
        )[:limit]

        _logger.info(
            f"增强搜索完成: 精确匹配={len(results['exact_hash_matches'])}, "
            f"模糊匹配={len(results['fuzzy_dangerous_matches'])}, "
            f"语义匹配={len(results['semantic_matches'])}, "
            f"综合结果={len(results['combined_results'])}"
        )

        return results
