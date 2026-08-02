"""Embedding-space similarity search across binary function representations."""

from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class FunctionEmbedding:
    """A function's embedding vector with metadata."""
    name: str = ""
    address: int = 0
    embedding: List[float] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def vector(self) -> np.ndarray:
        return np.array(self.embedding, dtype=np.float32)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': self.address,
            'embedding': self.embedding,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FunctionEmbedding:
        return cls(
            name=data.get('name', ''),
            address=data.get('address', 0),
            embedding=data.get('embedding', []),
            metadata=data.get('metadata', {}),
        )


class SearchMode:
    """Search mode constants."""
    TFIDF: str = "tfidf"
    EMBEDDING: str = "embedding"
    HYBRID: str = "hybrid"


class SemanticSearchEngine:
    """Brute-force + FAISS semantic search over function embeddings."""

    def __init__(
        self,
        index_dir: str = "",
        dimension: int = 768,
    ) -> None:
        self.index_dir = index_dir or os.path.join(
            os.path.dirname(__file__), "..", "data", "semantic_index"
        )
        self.dimension = dimension
        self.embeddings: List[FunctionEmbedding] = []
        self._name_index: Dict[str, int] = {}
        self._address_index: Dict[int, int] = {}
        self._faiss_index: Any = None
        self._use_faiss = False

        try:
            import faiss
            self._faiss_index = faiss.IndexFlatL2(dimension)
            self._use_faiss = True
            logger.info("FAISS index initialized")
        except ImportError:
            logger.info("FAISS not available, using brute-force search")

    def index_function(
        self,
        name: str,
        address: int,
        embedding: List[float],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a function embedding to the search index.

        Args:
            name: Function name.
            address: Function address.
            embedding: Embedding vector.
            metadata: Optional metadata dictionary.
        """
        emb = FunctionEmbedding(
            name=name,
            address=address,
            embedding=embedding,
            metadata=metadata or {},
        )

        idx = len(self.embeddings)
        self.embeddings.append(emb)
        self._name_index[name] = idx
        self._address_index[address] = idx

        if self._use_faiss and self._faiss_index is not None:
            vector = np.array([embedding], dtype=np.float32)
            self._faiss_index.add(vector)

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 10,
    ) -> List[Tuple[FunctionEmbedding, float]]:
        """Search for similar functions.

        Args:
            query_embedding: Query embedding vector.
            top_k: Number of results to return.

        Returns:
            List of (FunctionEmbedding, similarity_score) tuples.
        """
        if not self.embeddings:
            return []

        query_vec = np.array([query_embedding], dtype=np.float32)

        if self._use_faiss and self._faiss_index is not None:
            try:
                distances, indices = self._faiss_index.search(
                    query_vec, min(top_k, len(self.embeddings))
                )
                results: List[Tuple[FunctionEmbedding, float]] = []
                for i in range(len(indices[0])):
                    idx = indices[0][i]
                    if idx >= 0 and idx < len(self.embeddings):
                        sim = 1.0 / (1.0 + float(distances[0][i]))
                        results.append((self.embeddings[idx], sim))
                return results
            except Exception as e:
                logger.warning(f"FAISS search failed, falling back to brute-force: {e}")

        # Brute-force fallback
        results = []
        for emb in self.embeddings:
            score = self._cosine_sim(query_embedding, emb.embedding)
            results.append((emb, score))
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def search_by_name(
        self,
        function_name: str,
        top_k: int = 10,
    ) -> List[Tuple[FunctionEmbedding, float]]:
        """Search similar to a named function.

        Args:
            function_name: Name of the query function.
            top_k: Number of results.

        Returns:
            Similar functions with scores.
        """
        if function_name not in self._name_index:
            return []

        idx = self._name_index[function_name]
        query = self.embeddings[idx]
        results = self.search(query.embedding, top_k)
        # Remove self-match
        return [(emb, score) for emb, score in results if emb.name != function_name][:top_k - 1]

    def search_by_address(
        self,
        address: int,
        top_k: int = 10,
    ) -> List[Tuple[FunctionEmbedding, float]]:
        """Search similar to a function at an address.

        Args:
            address: Function address.
            top_k: Number of results.

        Returns:
            Similar functions with scores.
        """
        if address not in self._address_index:
            return []

        idx = self._address_index[address]
        query = self.embeddings[idx]
        return self.search(query.embedding, top_k)

    @staticmethod
    def _cosine_sim(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if not a or not b:
            return 0.0
        vec_a = np.array(a, dtype=np.float32)
        vec_b = np.array(b, dtype=np.float32)
        dot = float(np.dot(vec_a, vec_b))
        norm_a = float(np.linalg.norm(vec_a))
        norm_b = float(np.linalg.norm(vec_b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def save(self, filepath: str) -> None:
        """Save index to disk.

        Args:
            filepath: Output file path.
        """
        data = {
            'dimension': self.dimension,
            'embeddings': [emb.to_dict() for emb in self.embeddings],
        }
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(self.embeddings)} embeddings to {filepath}")

    def load(self, filepath: str) -> None:
        """Load index from disk.

        Args:
            filepath: Input file path.
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        self.dimension = data.get('dimension', self.dimension)
        self.embeddings = []
        self._name_index = {}
        self._address_index = {}

        for emb_data in data.get('embeddings', []):
            emb = FunctionEmbedding.from_dict(emb_data)
            idx = len(self.embeddings)
            self.embeddings.append(emb)
            self._name_index[emb.name] = idx
            self._address_index[emb.address] = idx

            if self._use_faiss and self._faiss_index is not None:
                vector = np.array([emb.embedding], dtype=np.float32)
                self._faiss_index.add(vector)

        logger.info(f"Loaded {len(self.embeddings)} embeddings from {filepath}")

    def __len__(self) -> int:
        return len(self.embeddings)

    def clear(self) -> None:
        """Clear all indexed embeddings."""
        self.embeddings.clear()
        self._name_index.clear()
        self._address_index.clear()
        if self._use_faiss:
            try:
                import faiss
                self._faiss_index = faiss.IndexFlatL2(self.dimension)
            except ImportError:
                self._faiss_index = None


class TFIDFVectorizer:
    """TF-IDF vectorizer for text-based function representation."""

    def __init__(self) -> None:
        self.vocabulary_: Dict[str, int] = {}
        self.idf_: Dict[str, float] = {}
        self._document_count: int = 0

    def fit_transform(self, documents: List[str]) -> List[List[float]]:
        """Fit and transform documents in one step.

        Args:
            documents: List of text documents.

        Returns:
            TF-IDF weighted vectors.
        """
        self.fit(documents)
        return self.transform(documents)

    def fit(self, documents: List[str]) -> None:
        """Build vocabulary and compute IDF.

        Args:
            documents: List of text documents.
        """
        doc_freq: Dict[str, int] = {}
        self._document_count = len(documents)

        for doc in documents:
            terms = set(self._tokenize(doc))
            for term in terms:
                doc_freq[term] = doc_freq.get(term, 0) + 1

        sorted_terms = sorted(doc_freq.keys())
        self.vocabulary_ = {term: i for i, term in enumerate(sorted_terms)}

        for term, freq in doc_freq.items():
            self.idf_[term] = math.log(
                (self._document_count + 1) / (freq + 1)
            ) + 1.0

    def transform(self, documents: List[str]) -> List[List[float]]:
        """Transform documents to TF-IDF vectors.

        Args:
            documents: List of text documents.

        Returns:
            TF-IDF weighted vectors.
        """
        if not self.vocabulary_:
            return [[0.0] for _ in documents]

        vectors: List[List[float]] = []
        for doc in documents:
            vec = [0.0] * len(self.vocabulary_)
            terms = self._tokenize(doc)
            term_counts: Dict[str, int] = {}
            for t in terms:
                term_counts[t] = term_counts.get(t, 0) + 1

            for term, count in term_counts.items():
                if term in self.vocabulary_:
                    tf = count / max(len(terms), 1)
                    vec[self.vocabulary_[term]] = tf * self.idf_.get(term, 1.0)

            vectors.append(vec)

        return vectors

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Simple tokenization."""
        import re
        return re.findall(r'[a-zA-Z_]\w*', text.lower())


class VulnerabilityPattern:
    """A known vulnerability pattern for semantic matching."""

    def __init__(self, name: str = "", pattern: str = "") -> None:
        self.name = name
        self.pattern = pattern
        self.severity: str = "medium"
        self.cwe_id: str = ""
        self.description: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            'name': self.name,
            'pattern': self.pattern,
            'severity': self.severity,
            'cwe_id': self.cwe_id,
            'description': self.description,
        }


class TokenEmbedder:
    """Simple token-based embedder."""

    def __init__(self) -> None:
        self.vocab: Dict[str, int] = {}
        self.dim: int = 128

    def embed(self, text: str) -> List[float]:
        tokens = text.lower().split()
        vec = np.zeros(self.dim, dtype=np.float32)
        for token in tokens:
            h = hash(token) % self.dim
            vec[h] += 1.0
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec /= norm
        return vec.tolist()


class CodeBERTEmbedder:
    """Placeholder for CodeBERT-based embedding."""

    def __init__(self) -> None:
        self.model = None

    def embed(self, code: str) -> List[float]:
        return [0.0] * 768


class FunctionEmbedder:
    """Embeds functions into vectors."""

    def __init__(self) -> None:
        self.token_embedder = TokenEmbedder()

    def embed(self, func: Dict[str, Any]) -> List[float]:
        text = func.get('pseudocode', '') or func.get('name', '')
        return self.token_embedder.embed(text)


class FunctionVector:
    """Wrapper for function vector."""

    def __init__(self) -> None:
        self.vec: List[float] = []


class SymbolEmbedder:
    """Embeds symbols (function names, etc.) into vectors."""

    def __init__(self) -> None:
        pass

    def embed(self, symbol: str) -> List[float]:
        return [0.0]


class SearchResult:
    """Search result wrapper."""

    def __init__(
        self,
        name: str = "",
        score: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.score = score
        self.metadata = metadata or {}
        self.embedding: List[float] = []


class SearchIndex:
    """Search index wrapper."""

    def __init__(self, dimension: int = 768) -> None:
        self.dimension = dimension
        self.engine = SemanticSearchEngine(dimension=dimension)

    def add(self, name: str, embedding: List[float], metadata: Optional[Dict[str, Any]] = None) -> None:
        self.engine.index_function(name, 0, embedding, metadata)

    def search(self, query: List[float], k: int = 10) -> List[SearchResult]:
        results = self.engine.search(query, k)
        return [
            SearchResult(name=emb.name, score=score, metadata=emb.metadata)
            for emb, score in results
        ]


class SemanticSearchResult:
    """Complete semantic search result."""

    def __init__(
        self,
        query: str = "",
        results: Optional[List[SearchResult]] = None,
        elapsed_ms: float = 0.0,
    ) -> None:
        self.query = query
        self.results = results or []
        self.elapsed_ms = elapsed_ms


def semantic_search(
    query: str,
    index: SearchIndex,
    embedder: Optional[TokenEmbedder] = None,
    top_k: int = 10,
) -> SemanticSearchResult:
    """Perform semantic search over function embeddings.

    Args:
        query: Search query string.
        index: SearchIndex to query against.
        embedder: Optional embedder for query encoding.
        top_k: Number of results.

    Returns:
        SemanticSearchResult with matched functions.
    """
    if embedder is None:
        embedder = TokenEmbedder()
    query_vec = embedder.embed(query)
    results = index.search(query_vec, top_k)
    return SemanticSearchResult(query=query, results=results)


def format_search_report(result: SemanticSearchResult) -> str:
    """Format search results into a report.

    Args:
        result: SemanticSearchResult to format.

    Returns:
        Formatted report string.
    """
    lines = [
        f"Semantic Search Results for: '{result.query}'",
        "-" * 40,
    ]
    for i, r in enumerate(result.results):
        lines.append(f"{i + 1}. {r.name} (score: {r.score:.4f})")
        if r.metadata:
            for k, v in r.metadata.items():
                lines.append(f"   {k}: {v}")
    return '\n'.join(lines)
