"""XenSQL Knowledge Graph module -- schema catalog management.

Handles database crawling, schema metadata storage, NL description
generation, domain tagging, and schema change detection.  Does NOT
handle policies, access control, or PII classification (those belong
to QueryVault).
"""

from xensql.app.services.knowledge_graph.change_detector import (
    ChangeReport,
    ChangeType,
    SchemaChange,
    SchemaChangeDetector,
    Severity,
)
from xensql.app.services.knowledge_graph.description_generator import (
    DescriptionGenerator,
    DescriptionResult,
    LLMProvider,
    ReviewableDescription,
)
from xensql.app.services.knowledge_graph.domain_tagger import (
    CrossDomainFK,
    DomainAffinityMap,
    DomainTagger,
)
from xensql.app.services.knowledge_graph.graph_store import (
    GraphStore,
    GraphStoreConfig,
)
from xensql.app.services.knowledge_graph.schema_crawler import (
    BaseCrawler,
    CrawlResult,
    DatabaseConfig,
    SchemaCrawler,
)

__all__ = [
    # KG-001 Schema Crawler
    "BaseCrawler",
    "CrawlResult",
    "DatabaseConfig",
    "SchemaCrawler",
    # KG-002 Description Generator
    "DescriptionGenerator",
    "DescriptionResult",
    "LLMProvider",
    "ReviewableDescription",
    # KG-003 Domain Tagger
    "CrossDomainFK",
    "DomainAffinityMap",
    "DomainTagger",
    # KG-004 Change Detector
    "ChangeReport",
    "ChangeType",
    "SchemaChange",
    "SchemaChangeDetector",
    "Severity",
    # KG-005 Graph Store
    "GraphStore",
    "GraphStoreConfig",
]
