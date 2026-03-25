"""XenSQL Schema Retrieval Module.

Multi-strategy schema retrieval, ranking, join path discovery,
embedding management, and caching for the NL-to-SQL pipeline.
"""

from .embedding_pipeline import EmbeddingPipeline
from .join_path_discovery import FKGraph, JoinEdge, JoinPath, JoinPathDiscovery
from .ranking_engine import RankingEngine
from .retrieval_cache import RetrievalCache
from .retrieval_pipeline import (
    CatalogSearchClient,
    RetrievalCandidate,
    RetrievalPipeline,
    VectorSearchClient,
)

__all__ = [
    "CatalogSearchClient",
    "EmbeddingPipeline",
    "FKGraph",
    "JoinEdge",
    "JoinPath",
    "JoinPathDiscovery",
    "RankingEngine",
    "RetrievalCache",
    "RetrievalCandidate",
    "RetrievalPipeline",
    "VectorSearchClient",
]
