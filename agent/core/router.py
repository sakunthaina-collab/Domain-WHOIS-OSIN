from __future__ import annotations
import math
import re
from collections import Counter
from core.normalize import normalize_text
from core.registry import Registry, Skill


def _tokenize(text: str) -> list[str]:
    text = text.lower()
    words = re.findall(r"[a-z0-9_+-]+|[\u0e00-\u0e7f]+|[\u4e00-\u9fff]+", text)
    tokens = list(words)
    for w in words:
        if any("\u0e00" <= ch <= "\u0e7f" or "\u4e00" <= ch <= "\u9fff" for ch in w):
            for n in (2, 3):
                if len(w) >= n:
                    tokens.extend(w[i : i + n] for i in range(len(w) - n + 1))
    return tokens


class SimpleBM25:
    def __init__(self, corpus: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.corpus = corpus
        self.k1 = k1
        self.b = b
        self.N = len(corpus)
        self.avgdl = sum(len(doc) for doc in corpus) / max(self.N, 1)
        self.doc_freqs = [Counter(doc) for doc in corpus]
        df: Counter[str] = Counter()
        for doc in self.doc_freqs:
            for term in doc:
                df[term] += 1
        self.idf = {
            term: math.log(1.0 + (self.N - freq + 0.5) / (freq + 0.5))
            for term, freq in df.items()
        }

    def get_scores(self, query_tokens: list[str]) -> list[float]:
        scores = [0.0] * self.N
        for i, doc_counter in enumerate(self.doc_freqs):
            dl = sum(doc_counter.values())
            for q in query_tokens:
                if q in doc_counter:
                    f = doc_counter[q]
                    idf = self.idf.get(q, 0.0)
                    denom = f + self.k1 * (1.0 - self.b + self.b * dl / max(self.avgdl, 1e-6))
                    scores[i] += idf * (f * (self.k1 + 1.0)) / denom
        return scores


def filter_by_category(
    selected: list[str], registry: Registry, profile_categories: list[str] | None
) -> list[str]:
    """Stage-2 category filter ensuring no out-of-profile skill leaks into toolset."""
    if not profile_categories:
        return selected
    allowed = set(profile_categories)
    return [
        name
        for name in selected
        if (s := registry.get(name)) is not None and s.category in allowed
    ]


class Router:
    def __init__(self, registry: Registry, allowed_categories: list[str] | None = None):
        self.reg = registry
        self.allowed_categories = allowed_categories
        self.pool: list[Skill] = registry.subset(allowed_categories)
        self.docs = [
            _tokenize(f"{s.name} {s.category} {s.description} {' '.join(s.triggers)}")
            for s in self.pool
        ]
        self.bm25 = SimpleBM25(self.docs)
        self.last_selection: list[str] = []

    def route(
        self,
        query: str,
        k: int = 12,
        exclude_unconfirmed: list[str] | None = None,
    ) -> list[str]:
        if not self.pool:
            self.last_selection = []
            return []
        query = normalize_text(query)
        q_lower = query.lower()
        q_tokens = _tokenize(q_lower)
        scores = self.bm25.get_scores(q_tokens)

        for idx, s in enumerate(self.pool):
            if s.name.lower() in q_lower:
                scores[idx] += 10.0
            for trig in s.triggers:
                if trig.lower() in q_lower:
                    scores[idx] += 5.0
            if exclude_unconfirmed and s.name in exclude_unconfirmed:
                if s.name.lower() not in q_lower and not any(t.lower() in q_lower for t in s.triggers):
                    scores[idx] -= 5.0

        top = sorted(zip(self.pool, scores), key=lambda x: (-x[1], x[0].name))[:30]
        candidates = [s.name for s, sc in top if sc > 0.0][:k]
        if not candidates:
            candidates = [s.name for s, _ in top[:k]]
        filtered = filter_by_category(candidates, self.reg, self.allowed_categories)
        self.last_selection = list(filtered)
        return filtered
