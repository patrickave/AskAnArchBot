"""TF-IDF knowledge retriever.

Builds an in-memory TF-IDF index over knowledge chunks at startup and
retrieves the most relevant chunks for each incoming question.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .chunker import Chunk, chunk_directory

logger = logging.getLogger("gen_ai.rag")

# Rough char-to-token ratio for English prose (~4 chars/token).
_CHARS_PER_TOKEN = 4
_TOKEN_BUDGET = 6_000
_CHAR_BUDGET = _TOKEN_BUDGET * _CHARS_PER_TOKEN


class KnowledgeStore:
    """In-memory TF-IDF index over markdown knowledge chunks."""

    def __init__(self, knowledge_dir: Path) -> None:
        self.chunks = chunk_directory(knowledge_dir)

        corpus = [c.text for c in self.chunks]
        self._vectorizer = TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            max_df=0.9,
            sublinear_tf=True,
        )
        self._tfidf_matrix = self._vectorizer.fit_transform(corpus)

        logger.info(
            "rag.index_built",
            extra={
                "rag.chunk_count": len(self.chunks),
                "rag.vocab_size": len(self._vectorizer.vocabulary_),
            },
        )

    def query(self, question: str, top_k: int = 3) -> list[tuple[Chunk, float]]:
        """Return the *top_k* most relevant chunks for *question*.

        Each result is a ``(chunk, similarity_score)`` tuple, sorted by
        descending similarity.  Chunks are dropped if they would exceed the
        token budget.
        """
        q_vec = self._vectorizer.transform([question])
        scores = cosine_similarity(q_vec, self._tfidf_matrix).flatten()

        ranked = sorted(enumerate(scores), key=lambda t: t[1], reverse=True)

        results: list[tuple[Chunk, float]] = []
        total_chars = 0
        for idx, score in ranked:
            if len(results) >= top_k:
                break
            if score <= 0.0:
                break
            chunk = self.chunks[idx]
            chunk_chars = len(chunk.text)
            if total_chars + chunk_chars > _CHAR_BUDGET:
                continue  # skip this chunk but keep looking for smaller ones
            results.append((chunk, float(score)))
            total_chars += chunk_chars

        logger.info(
            "rag.query",
            extra={
                "rag.question": question,
                "rag.result_count": len(results),
                "rag.results": [
                    {"heading": c.heading_path, "score": round(s, 4)}
                    for c, s in results
                ],
            },
        )

        return results

    @staticmethod
    def format_context(results: list[tuple[Chunk, float]]) -> str:
        """Format retrieved chunks for injection into the system prompt."""
        if not results:
            return ""
        sections = []
        for chunk, _score in results:
            sections.append(f"--- {chunk.heading_path} ---\n{chunk.text}")
        return "\n\n# Reference Knowledge\n\n" + "\n\n".join(sections)
