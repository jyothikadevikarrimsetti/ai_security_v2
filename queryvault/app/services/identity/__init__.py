"""
QueryVault Identity Module
==========================

Foundation of the Zero Trust architecture.  Handles:
  - JWT validation (RS256 + JWKS / mock IDP)
  - Role inheritance resolution (DAG traversal, clearance computation)
  - SecurityContext assembly (orchestrates validation, enrichment, signing)
  - Session storage (Redis with in-memory fallback, JTI blacklist)
"""

from queryvault.app.services.identity.token_validator import (
    MockKeyPair,
    TokenValidationError,
    TokenValidator,
    ValidatedClaims,
)
from queryvault.app.services.identity.role_resolver import (
    ResolvedRoles,
    RoleResolver,
)
from queryvault.app.services.identity.session_store import SessionStore
from queryvault.app.services.identity.context_builder import (
    ContextBuildError,
    ContextBuilder,
    InactiveEmployeeError,
    UnknownUserError,
)

__all__ = [
    # Token validation (ZT-001)
    "TokenValidator",
    "TokenValidationError",
    "ValidatedClaims",
    "MockKeyPair",
    # Role resolution (ZT-002)
    "RoleResolver",
    "ResolvedRoles",
    # Session storage
    "SessionStore",
    # Context builder (orchestrator)
    "ContextBuilder",
    "ContextBuildError",
    "UnknownUserError",
    "InactiveEmployeeError",
]
