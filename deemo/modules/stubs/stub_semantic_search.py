# stub_semantic_search.py — 桩合约语义搜索（含共现查询扩展）
# 创建于 2026-07-31
# 修改于 2026-08-04: 增加共现查询扩展，利用依赖图结构提升召回
#
# 用自然语言描述查找最匹配的桩模块。
# 核心匹配: TF-IDF + n-gram Jaccard + 参数类型重叠
# 查询扩展: 基于依赖图共现关系，搜索词自动扩展关联模块的术语
#
# 共现查询扩展的非显而易见性:
#   传统查询扩展使用WordNet/word2vec等外部语义网络。
#   本模块使用项目自身的依赖图结构作为语义网络:
#     若模块A和B在依赖图中频繁共现（共享调用方/相互导入），
#     则搜索A时应自动纳入B的术语，反之亦然。
#   这捕获了"生态知识": 例如搜索"firmware"时自动关联"binary"，
#   因为firmware_analyzer和binary_format_loader共享调用方。
import math as _math
import re as _re
from collections import Counter as _Ctr, defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContractor as _StubContractor,
    StubContract as _StubContract,
)


@_dc
class SearchResult:
    """单条搜索结果。"""
    module_name: str
    score: float = 0.0
    tfidf_score: float = 0.0
    jaccard_score: float = 0.0
    type_overlap_score: float = 0.0
    # 附加信息
    status: str = ''
    func_count: int = 0
    matching_functions: list = _field(default_factory=list)
    snippet: str = ''  # 最相关函数签名


class SemanticSearchEngine:
    """桩合约语义搜索引擎。

    索引构建: 对所有桩模块的合约文本做 TF-IDF 向量化。
    查询: 对自然语言查询做同样的向量化 → 余弦相似度排序。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            import os
            stubs_dir = os.path.dirname(os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.contractor = _StubContractor(stubs_dir=stubs_dir)
        self._index: dict[str, dict] = {}  # {module: {term: tfidf}}
        self._idf: dict[str, float] = {}
        self._build_index()

    def search(self, query: str, top_k: int = 10,
               expand: bool = True) -> list[SearchResult]:
        """搜索与查询最匹配的桩模块。

        expand=True 时启用共现查询扩展: 用依赖图中关联模块的术语扩充查询。
        """
        query_terms = self._tokenize(query)
        if not query_terms:
            return []

        # 共现查询扩展
        expanded_terms = list(query_terms)
        if expand and hasattr(self, '_cooccurrence'):
            expanded_terms = self._expand_query(query_terms)

        results = []
        for mod_name, index_entry in self._index.items():
            tfidf = self._cosine_similarity(expanded_terms, index_entry['tfidf'])
            jaccard = self._jaccard_similarity(
                expanded_terms, index_entry['name_ngrams'])
            type_overlap = self._type_overlap(
                expanded_terms, index_entry['param_types'])

            score = 0.5 * tfidf + 0.3 * jaccard + 0.2 * type_overlap
            if score > 0.05:
                results.append(SearchResult(
                    module_name=mod_name,
                    score=round(score, 4),
                    tfidf_score=round(tfidf, 4),
                    jaccard_score=round(jaccard, 4),
                    type_overlap_score=round(type_overlap, 4),
                    status=index_entry.get('status', ''),
                    func_count=index_entry.get('func_count', 0),
                    matching_functions=index_entry.get('top_funcs', [])[:3],
                    snippet=index_entry.get('snippet', ''),
                ))

        results.sort(key=lambda r: -r.score)
        return results[:top_k]

# 索引构建
    def _build_index(self) -> None:
        contracts = self.contractor.scan_all()
        # 收集全部文档用于 IDF
        all_docs = []
        for mod_name, contract in contracts.items():
            if mod_name.startswith('stub_'):
                continue
            doc = self._document_text(contract)
            all_docs.append(self._tokenize(doc))

        # IDF
        N = len(all_docs)
        df = _Ctr()
        for tokens in all_docs:
            for t in set(tokens):
                df[t] += 1
        self._idf = {t: _math.log((N + 1) / (df[t] + 1)) + 1
                    for t in df}

        # TF-IDF per module
        for mod_name, contract in contracts.items():
            if mod_name.startswith('stub_'):
                continue
            doc = self._document_text(contract)
            tokens = self._tokenize(doc)
            tf = _Ctr(tokens)
            max_tf = max(tf.values()) if tf else 1
            tfidf = {t: (c / max_tf) * self._idf.get(t, 1.0)
                    for t, c in tf.items()}

            # 额外索引字段
            name_ngrams = set()
            param_types = set()
            top_funcs = []
            for fc in contract.functions:
                name_ngrams.update(self._char_ngrams(fc.name))
                for p in fc.params:
                    base = self._simple_base(p.annotation)
                    if base:
                        param_types.add(base)
                top_funcs.append(self._render_sig(fc))

            self._index[mod_name] = {
                'tfidf': tfidf,
                'name_ngrams': name_ngrams,
                'param_types': param_types,
                'status': contract.status,
                'func_count': len(contract.functions),
                'top_funcs': top_funcs,
                'snippet': top_funcs[0] if top_funcs else '',
            }

        # 构建共现矩阵: 依赖图中共享调用方或相互导入的模块对
        self._cooccurrence = self._build_cooccurrence()

    def _build_cooccurrence(self) -> dict[str, list[tuple[str, float]]]:
        """从依赖图构建模块共现关系。共现 = 共享调用方 或 直接导入。

        返回: {module_name: [(co_module, strength), ...]}
        strength = Jaccard(shared_callers) + direct_import_bonus
        """
        cooc = {}
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph()
            g.build()
        except ImportError:
            return cooc

        # 收集每个模块的调用方集合
        callers_of = {}
        for name, node in g.nodes.items():
            callers_of[name] = set(node.depended_by)

        modules = [n for n in g.nodes if not n.startswith('stub_')]
        for i, a in enumerate(modules):
            for b in modules[i+1:]:
                ca = callers_of.get(a, set())
                cb = callers_of.get(b, set())
                union = ca | cb
                inter = ca & cb
                if not union and not inter:
                    continue
                jaccard = len(inter) / max(len(union), 1)
                # 直接导入加成
                node_a = g.nodes.get(a)
                direct = 0.15 if (node_a and b in node_a.imports_from) else 0.0
                node_b = g.nodes.get(b)
                direct += 0.15 if (node_b and a in node_b.imports_from) else 0.0
                strength = jaccard + direct
                if strength > 0.05:
                    cooc.setdefault(a, []).append((b, strength))
                    cooc.setdefault(b, []).append((a, strength))

        # 每模块保留 top-10 共现
        for mod in cooc:
            cooc[mod].sort(key=lambda x: -x[1])
            cooc[mod] = cooc[mod][:10]
        return cooc

    def _expand_query(self, query_terms: list[str],
                      expansion_weight: float = 0.3) -> list[str]:
        """用共现模块的术语扩展查询。

        对query中的每个term，若匹配到某模块名，将该模块的top共现伙伴的术语
        以 expansion_weight 的权重加入查询。
        """
        if not hasattr(self, '_cooccurrence') or not self._cooccurrence:
            return list(query_terms)

        expanded = list(query_terms)
        for term in query_terms:
            # 查找term是否匹配模块名
            for mod_name in self._index:
                if term in mod_name or mod_name in term:
                    partners = self._cooccurrence.get(mod_name, [])
                    for partner, strength in partners[:3]:
                        if strength < 0.1:
                            continue
                        # 提取伙伴模块的术语
                        partner_terms = self._tokenize(partner)
                        # 以衰减权重加入（约30%的额外术语）
                        n_add = max(1, int(len(partner_terms) * expansion_weight))
                        expanded.extend(partner_terms[:n_add])
                    break  # 每个term只匹配第一个模块
        return expanded

    @staticmethod
    def _document_text(contract: _StubContract) -> str:
        parts = [contract.module_name.replace('_', ' ')]
        if contract.doc:
            parts.append(contract.doc)
        for fc in contract.functions:
            parts.append(fc.name.replace('_', ' '))
            if fc.doc_summary:
                parts.append(fc.doc_summary)
            for p in fc.params:
                parts.append(p.name)
        return ' '.join(parts)

# 相似度计算
    @staticmethod
    def _cosine_similarity(query_terms: list[str],
                           doc_tfidf: dict[str, float]) -> float:
        q_tf = _Ctr(query_terms)
        max_q = max(q_tf.values()) if q_tf else 1

        dot = 0.0
        q_norm = 0.0
        for t, c in q_tf.items():
            w = (c / max_q)
            q_norm += w * w
            dot += w * doc_tfidf.get(t, 0.0)

        d_norm = sum(v * v for v in doc_tfidf.values())
        if q_norm < 1e-9 or d_norm < 1e-9:
            return 0.0
        return dot / (_math.sqrt(q_norm) * _math.sqrt(d_norm))

    @staticmethod
    def _jaccard_similarity(query_terms: list[str],
                            name_ngrams: set) -> float:
        q_ngrams = set()
        for t in query_terms:
            q_ngrams.update(
                [t[i:i+3] for i in range(max(1, len(t) - 2))])
        if not q_ngrams or not name_ngrams:
            return 0.0
        return len(q_ngrams & name_ngrams) / len(q_ngrams | name_ngrams)

    @staticmethod
    def _type_overlap(query_terms: list[str],
                      param_types: set) -> float:
        type_keywords = {'int', 'str', 'bytes', 'bool', 'float',
                        'list', 'dict', 'set', 'tuple', 'none'}
        q_types = set(query_terms) & type_keywords
        if not q_types or not param_types:
            return 0.0
        return len(q_types & param_types) / len(q_types | param_types)

# 分词
    @staticmethod
    def _tokenize(text: str) -> list[str]:
        text = text.lower()
        # 保留 snake_case 拆分
        tokens = []
        for word in _re.split(r'[^a-z0-9_]+', text):
            if word:
                tokens.append(word)
                # snake_case 拆分为独立词
                parts = word.split('_')
                if len(parts) > 1:
                    tokens.extend(p for p in parts if len(p) >= 2)
        return [t for t in tokens if len(t) >= 2]

    @staticmethod
    def _char_ngrams(s: str, n: int = 3) -> list[str]:
        s = s.lower()
        return [s[i:i+n] for i in range(max(1, len(s) - n + 1))]

    @staticmethod
    def _simple_base(ann: str) -> str:
        a = (ann or '').strip().lower()
        m = _re.match(r'([a-z_][a-z0-9_]*)', a)
        return m.group(1) if m else ''

    @staticmethod
    def _render_sig(fc) -> str:
        params = [p.name for p in fc.params
                 if p.kind not in ('varargs', 'varkw')]
        sig = f'{fc.name}({",".join(params)})'
        if fc.return_ann:
            sig += f' -> {fc.return_ann}'
        return sig


# 便捷入口
def find_stub(query: str, top_k: int = 5) -> list[SearchResult]:
    """一行式桩语义搜索。"""
    return SemanticSearchEngine().search(query, top_k)


__all__ = ['SearchResult', 'SemanticSearchEngine', 'find_stub']
