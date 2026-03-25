"""XenSQL SQL Generation Module.

Pure NL-to-SQL pipeline components.  No auth, RBAC, SQL validation,
injection scanning, or query execution -- those are QueryVault's
responsibility.

Submodules:
  SG-001  generator            - LLM call with retry / fallback
  SG-002  response_parser      - SQL extraction from LLM output
  SG-003  dialect_handler       - Dialect hints and detection
  SG-004  conversation_manager - Multi-turn context management
  SG-005  confidence_scorer    - Composite confidence scoring
"""

from xensql.app.services.sql_generation.confidence_scorer import (
    ConfidenceBreakdown,
    ConfidenceScore,
    ConfidenceScorer,
    GenerationMeta,
    IntentResult,
    RetrievalMeta,
)
from xensql.app.services.sql_generation.conversation_manager import (
    ConversationManager,
)
from xensql.app.services.sql_generation.dialect_handler import (
    DialectHandler,
    TableInfo,
)
from xensql.app.services.sql_generation.generator import (
    GenerationError,
    GenerationResult,
    ProviderConfig,
    SQLGenerator,
)
from xensql.app.services.sql_generation.response_parser import (
    ParseResult,
    parse,
)

__all__ = [
    # SG-001
    "SQLGenerator",
    "GenerationResult",
    "ProviderConfig",
    "GenerationError",
    # SG-002
    "parse",
    "ParseResult",
    # SG-003
    "DialectHandler",
    "TableInfo",
    # SG-004
    "ConversationManager",
    # SG-005
    "ConfidenceScorer",
    "ConfidenceScore",
    "ConfidenceBreakdown",
    "RetrievalMeta",
    "IntentResult",
    "GenerationMeta",
]
