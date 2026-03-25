"""Context Construction module for XenSQL NL-to-SQL Pipeline Engine.

Assembles LLM prompts from pre-filtered schema and contextual rules
received from QueryVault.  Manages token budgets, LLM provider
abstraction, and provider fallback chains.

Modules:
  CC-001  prompt_assembler   - Four-section prompt assembly
  CC-002  token_budget       - Token limit enforcement with priority
  CC-003  llm_provider       - Unified LLM provider interface + registry
  CC-004  context_optimizer  - Schema reordering, dedup, join hints
  CC-005  provider_fallback  - Resilient multi-provider fallback chain
"""

from xensql.app.services.context_construction.context_optimizer import (
    ContextOptimizer,
    OptimizedContext,
)
from xensql.app.services.context_construction.llm_provider import (
    AnthropicProvider,
    AzureOpenAIProvider,
    LLMProvider,
    LLMProviderConfig,
    LLMProviderError,
    LLMProviderRegistry,
    LLMResponse,
    OpenAICompatProvider,
)
from xensql.app.services.context_construction.prompt_assembler import (
    AssembledPrompt,
    PromptAssembler,
)
from xensql.app.services.context_construction.provider_fallback import (
    FallbackConfig,
    FallbackResult,
    ProviderFallbackChain,
)
from xensql.app.services.context_construction.token_budget import (
    BudgetResult,
    TokenBudget,
)

__all__ = [
    # CC-001 Prompt Assembler
    "AssembledPrompt",
    "PromptAssembler",
    # CC-002 Token Budget
    "BudgetResult",
    "TokenBudget",
    # CC-003 LLM Provider
    "AnthropicProvider",
    "AzureOpenAIProvider",
    "LLMProvider",
    "LLMProviderConfig",
    "LLMProviderError",
    "LLMProviderRegistry",
    "LLMResponse",
    "OpenAICompatProvider",
    # CC-004 Context Optimizer
    "ContextOptimizer",
    "OptimizedContext",
    # CC-005 Provider Fallback
    "FallbackConfig",
    "FallbackResult",
    "ProviderFallbackChain",
]
