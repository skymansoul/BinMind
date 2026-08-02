# 2026-09-05 ~ 2026-09-08
# Embedding-based semantic CVE search — builds on the BM25 engine in cve_search
# but adds TF-IDF vectorization + cosine similarity so you can find "similar"
# CVEs instead of just keyword-matching them.
#
# The basic path uses TF-IDF (no external deps beyond what we already have).
# TF-IDF vectors are stored as sparse {term_idx: weight} dicts — for 100K docs
# with ~10K vocab, each doc is ~100 non-zero entries. Cosine similarity over
# sparse vectors is fast enough for brute-force top-k without a vector DB.
#
# Optional: sentence-transformers. If installed, generates dense embeddings
# using all-MiniLM-L6-v2 (~80MB download on first use). Quality is much better
# than TF-IDF but adds a pip install. The API is identical either way.
#
# _tokenize reuses the tokenizer from cve_search.py — consistency with BM25
# is more important than having a separate tokenizer for embeddings.

import math
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Set, Union, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase

# try importing numpy — optional, used for faster dot products
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False
    np = None  # type: ignore

# try sentence-transformers — very optional, big dependency
try:
    from sentence_transformers import SentenceTransformer
    _HAS_SBERT = True
except ImportError:
    _HAS_SBERT = False
    SentenceTransformer = None  # type: ignore

# reuse the same tokenizer as the BM25 search engine
# this keeps term vocabularies consistent between the two
try:
    from .cve_search import _tokenize, _expand_tokens, _STOPWORDS, _SYNONYMS
except ImportError:
    # fallback: minimal tokenizer if cve_search isn't available
    import re
    _STOPWORDS = {"a", "an", "the", "and", "or", "in", "on", "at", "to", "for",
                  "of", "with", "by", "is", "are", "was", "were", "be", "been"}
    _SYNONYMS: Dict[str, str] = {}
    def _tokenize(text: str) -> List[str]:
        return [t for t in re.split(r'[^a-z0-9]+', text.lower()) if len(t) >= 2 and t not in _STOPWORDS]
    def _expand_tokens(tokens: List[str]) -> List[str]:
        result = list(tokens)
        for t in tokens:
            if t in _SYNONYMS:
                result.extend(_tokenize(_SYNONYMS[t]))
        return result


# SBERT model name — small, fast, decent quality
_SBERT_MODEL = "all-MiniLM-L6-v2"


class CVEEmbeddingIndex:
    """Semantic search index over CVE descriptions.
    Uses TF-IDF by default, sentence-transformers if available.
    Vectors are sparse {term_idx: tfidf_weight} dicts for the TF-IDF path,
    or dense numpy arrays for the SBERT path."""

    def __init__(self, kb: CVEKnowledgeBase):
        self._kb = kb
        # vocabulary: term → index
        self._vocab: Dict[str, int] = {}
        # inverse document frequency per term
        self._idf: List[float] = []
        # document vectors: list of {term_idx: weight}
        self._doc_vecs: List[Dict[int, float]] = []
        # doc_idx → CVEEntry
        self._docs: Dict[int, CVEEntry] = {}
        # dense vectors (sbert path only)
        self._dense_vecs: Optional[Any] = None  # numpy array if SBERT
        self._sbert_model: Optional[Any] = None
        self._built = False

    # ---- build ----

    def build(self):
        """Build the embedding index from all KB entries.
        Computes TF-IDF vectors. If sentence-transformers is available,
        also generates dense embeddings."""
        self._vocab.clear()
        self._idf.clear()
        self._doc_vecs.clear()
        self._docs.clear()
        self._dense_vecs = None

        entries, total = self._kb.search(limit=100000)
        N = len(entries)
        if N == 0:
            self._built = True
            return

        # ---- pass 1: build vocabulary + document frequencies ----
        doc_term_counts: List[Dict[str, int]] = []  # per-doc raw term counts
        df: Dict[str, int] = defaultdict(int)        # term → doc count

        for idx, entry in enumerate(entries):
            tokens = _expand_tokens(_tokenize(entry.description or ""))
            # also include cve_id tokens (helps "similar to CVE-xxx" queries)
            tokens.extend(_tokenize(entry.cve_id))

            term_counts: Dict[str, int] = defaultdict(int)
            for t in tokens:
                term_counts[t] += 1
            doc_term_counts.append(dict(term_counts))

            for term in term_counts:
                df[term] += 1

            self._docs[idx] = entry

        # ---- build vocabulary (filter rare terms: df >= 2) ----
        vocab_terms = [t for t, d in df.items() if d >= 2]
        self._vocab = {t: i for i, t in enumerate(vocab_terms)}

        # ---- compute idf ----
        vocab_size = len(self._vocab)
        self._idf = [0.0] * vocab_size
        for term, idx in self._vocab.items():
            self._idf[idx] = math.log((N + 1) / (1 + df.get(term, 0)))

        # ---- pass 2: build TF-IDF vectors ----
        for idx, tc in enumerate(doc_term_counts):
            vec: Dict[int, float] = {}
            doc_len = sum(tc.values()) or 1
            for term, count in tc.items():
                term_idx = self._vocab.get(term)
                if term_idx is None:
                    continue
                # sublinear tf scaling: 1 + log(tf)
                tf = 1.0 + math.log(count)
                # normalize by doc length
                tf_norm = tf / (1.0 + math.log(doc_len))
                vec[term_idx] = tf_norm * self._idf[term_idx]

            # L2 normalize
            norm = math.sqrt(sum(w * w for w in vec.values())) or 1.0
            for k in vec:
                vec[k] /= norm

            self._doc_vecs.append(vec)

        # ---- SBERT path (optional) ----
        if _HAS_SBERT and SentenceTransformer is not None:
            try:
                self._sbert_model = SentenceTransformer(_SBERT_MODEL)
                descriptions = [e.description or "" for e in entries]
                self._dense_vecs = self._sbert_model.encode(
                    descriptions, show_progress_bar=False
                )
            except Exception:
                # model download failed or OOM — fall back to TF-IDF
                self._sbert_model = None
                self._dense_vecs = None

        self._built = True

    # ---- search ----

    def search(self, query: str, top_n: int = 10, min_score: float = 0.05) -> List[Tuple[CVEEntry, float]]:
        """Semantic search — find CVEs similar to the query text.
        Uses dense SBERT embeddings if available, otherwise TF-IDF cosine.
        Returns list of (CVEEntry, similarity_score)."""
        if not self._built:
            self.build()

        if not self._doc_vecs and self._dense_vecs is None:
            return []

        if self._dense_vecs is not None and self._sbert_model is not None:
            return self._search_dense(query, top_n, min_score)
        return self._search_sparse(query, top_n, min_score)

    def find_similar(self, cve_id: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
        """Find CVEs similar to a given CVE ID.
        Uses the description of the CVE as the query."""
        entry = self._kb.get(cve_id)
        if not entry:
            return []
        if not self._built:
            self.build()
        desc = entry.description or ""
        if not desc:
            return []
        return self.search(desc, top_n=top_n)

    # ---- internal: sparse TF-IDF search ----

    def _search_sparse(self, query: str, top_n: int, min_score: float) -> List[Tuple[CVEEntry, float]]:
        """TF-IDF cosine similarity search."""
        # build query vector
        tokens = _expand_tokens(_tokenize(query))
        if not tokens:
            return []

        qvec: Dict[int, float] = {}
        q_counts: Dict[str, int] = defaultdict(int)
        for t in tokens:
            q_counts[t] += 1

        for term, count in q_counts.items():
            term_idx = self._vocab.get(term)
            if term_idx is None:
                continue
            tf = 1.0 + math.log(count)
            qvec[term_idx] = tf * self._idf[term_idx]

        # L2 normalize query
        qnorm = math.sqrt(sum(w * w for w in qvec.values())) or 1.0
        for k in qvec:
            qvec[k] /= qnorm

        # score all docs
        scores: List[Tuple[int, float]] = []
        for doc_idx, dvec in enumerate(self._doc_vecs):
            score = self._cosine_sparse(qvec, dvec)
            if score >= min_score:
                scores.append((doc_idx, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [(self._docs[doc_idx], score) for doc_idx, score in scores[:top_n]]

    def _cosine_sparse(self, v1: Dict[int, float], v2: Dict[int, float]) -> float:
        """Cosine similarity between two sparse vectors. Returns 0.0–1.0."""
        # iterate over the smaller vector
        if len(v1) > len(v2):
            v1, v2 = v2, v1
        dot = sum(v1[k] * v2.get(k, 0.0) for k in v1)
        # both vectors are already L2-normalized, so dot = cosine
        return max(0.0, dot)

    # ---- internal: dense SBERT search ----

    def _search_dense(self, query: str, top_n: int, min_score: float) -> List[Tuple[CVEEntry, float]]:
        """Dense embedding cosine similarity search."""
        if self._sbert_model is None or self._dense_vecs is None:
            return self._search_sparse(query, top_n, min_score)

        qvec = self._sbert_model.encode([query], show_progress_bar=False)[0]

        if _HAS_NUMPY and isinstance(self._dense_vecs, getattr(np, 'ndarray', ())):
            # numpy path: vectorized cosine
            qnorm = np.linalg.norm(qvec)
            if qnorm == 0:
                return []
            qvec = qvec / qnorm
            dnorm = np.linalg.norm(self._dense_vecs, axis=1)
            dnorm[dnorm == 0] = 1.0
            similarities = np.dot(self._dense_vecs, qvec) / dnorm
            top_indices = np.argsort(similarities)[::-1][:top_n]
            results = []
            for idx in top_indices:
                score = float(similarities[idx])
                if score >= min_score:
                    results.append((self._docs[int(idx)], score))
            return results
        else:
            # pure python path
            qnorm = math.sqrt(sum(x * x for x in qvec)) or 1.0
            qvec = [x / qnorm for x in qvec]
            scores = []
            for doc_idx, dvec in enumerate(self._dense_vecs):
                dnorm = math.sqrt(sum(x * x for x in dvec)) or 1.0
                dvec_norm = [x / dnorm for x in dvec]
                dot = sum(a * b for a, b in zip(qvec, dvec_norm))
                if dot >= min_score:
                    scores.append((doc_idx, dot))
            scores.sort(key=lambda x: x[1], reverse=True)
            return [(self._docs[doc_idx], score) for doc_idx, score in scores[:top_n]]

    # ---- hybrid: combine BM25 + embedding scores ----

    def search_hybrid(self, query: str, top_n: int = 10, bm25_weight: float = 0.4) -> List[Tuple[CVEEntry, float]]:
        """Combine BM25 and embedding search scores.
        bm25_weight: how much to weight BM25 vs embeddings (0 = embeddings only)."""
        from .cve_search import CVESearchEngine

        if not self._built:
            self.build()

        # run both
        bm25_engine = CVESearchEngine(self._kb)
        bm25_engine.build()
        bm25_results = bm25_engine.search(query, top_n=top_n * 3)
        emb_results = self.search(query, top_n=top_n * 3)

        # normalize scores to 0-1
        bm25_by_cve: Dict[str, float] = {}
        bm25_max = max((s for _, s in bm25_results), default=1.0)
        for entry, score in bm25_results:
            bm25_by_cve[entry.cve_id] = score / bm25_max if bm25_max > 0 else 0.0

        emb_by_cve: Dict[str, float] = {}
        emb_max = max((s for _, s in emb_results), default=1.0)
        for entry, score in emb_results:
            emb_by_cve[entry.cve_id] = score / emb_max if emb_max > 0 else 0.0

        # combine scores
        combined: Dict[str, Tuple[CVEEntry, float]] = {}
        for entry, _ in emb_results:
            cid = entry.cve_id
            bm25_s = bm25_by_cve.get(cid, 0.0)
            emb_s = emb_by_cve.get(cid, 0.0)
            combined[cid] = (entry, bm25_weight * bm25_s + (1 - bm25_weight) * emb_s)

        # add BM25-only results that embeddings missed
        for entry, _ in bm25_results:
            cid = entry.cve_id
            if cid not in combined:
                combined[cid] = (entry, bm25_weight * bm25_by_cve.get(cid, 0.0))

        sorted_results = sorted(combined.values(), key=lambda x: x[1], reverse=True)
        return sorted_results[:top_n]

    @property
    def vocab_size(self) -> int:
        return len(self._vocab)

    @property
    def doc_count(self) -> int:
        return len(self._docs)


# ---- convenience: one-shot similar CVE search ----

def find_similar_cves(kb: CVEKnowledgeBase, cve_id: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
    """One-shot: build index and find CVEs similar to the given CVE ID."""
    index = CVEEmbeddingIndex(kb)
    index.build()
    return index.find_similar(cve_id, top_n=top_n)


def search_semantic(kb: CVEKnowledgeBase, query: str, top_n: int = 10) -> List[Tuple[CVEEntry, float]]:
    """One-shot: build index and semantic-search the given query."""
    index = CVEEmbeddingIndex(kb)
    index.build()
    return index.search(query, top_n=top_n)
