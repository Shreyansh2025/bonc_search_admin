"""SentenceTransformer singleton owned by the General Search Platform."""
from __future__ import annotations

from functools import lru_cache

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDING_DIM = 384


@lru_cache(maxsize=1)
def get_model():
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(MODEL_NAME)


def warm_up_model() -> None:
    """Load the embedding model immediately during server startup."""
    get_model()
