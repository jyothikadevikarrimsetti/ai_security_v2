"""Enumerations for XenSQL NL-to-SQL Pipeline Engine.

Pure pipeline concerns only -- no auth, RBAC, or security enums.
"""

from enum import Enum


class PipelineStatus(str, Enum):
    """Outcome status of a pipeline execution."""

    GENERATED = "GENERATED"
    AMBIGUOUS = "AMBIGUOUS"
    CANNOT_ANSWER = "CANNOT_ANSWER"
    ERROR = "ERROR"


class PipelineErrorCode(str, Enum):
    """Structured error codes for pipeline failures."""

    NO_TABLES_FOUND = "NO_TABLES_FOUND"
    LLM_PROVIDER_ERROR = "LLM_PROVIDER_ERROR"
    GENERATION_FAILED = "GENERATION_FAILED"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    CONVERSATION_ERROR = "CONVERSATION_ERROR"
    INTENT_CLASSIFICATION_FAILED = "INTENT_CLASSIFICATION_FAILED"
    TOKEN_BUDGET_EXCEEDED = "TOKEN_BUDGET_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class IntentType(str, Enum):
    """Classified intent of the natural-language question."""

    DATA_LOOKUP = "DATA_LOOKUP"
    AGGREGATION = "AGGREGATION"
    COMPARISON = "COMPARISON"
    TREND = "TREND"
    JOIN_QUERY = "JOIN_QUERY"
    EXISTENCE_CHECK = "EXISTENCE_CHECK"
    DEFINITION = "DEFINITION"
    EXPLANATION = "EXPLANATION"


class SQLDialect(str, Enum):
    """Supported SQL dialects for generation."""

    POSTGRESQL = "POSTGRESQL"
    MYSQL = "MYSQL"
    SQLSERVER = "SQLSERVER"
    ORACLE = "ORACLE"


class ConfidenceLevel(str, Enum):
    """Discrete confidence tier for generated SQL."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AmbiguityType(str, Enum):
    """Type of ambiguity detected in a question."""

    VAGUE_QUESTION = "VAGUE_QUESTION"
    MISSING_CONTEXT = "MISSING_CONTEXT"
    MULTIPLE_INTENTS = "MULTIPLE_INTENTS"
    SHORT_QUESTION = "SHORT_QUESTION"


class DomainType(str, Enum):
    """Domain areas that a question or table may belong to."""

    CLINICAL = "CLINICAL"
    BILLING = "BILLING"
    PHARMACY = "PHARMACY"
    LABORATORY = "LABORATORY"
    HR = "HR"
    SCHEDULING = "SCHEDULING"
    FINANCIAL = "FINANCIAL"
