"""SAG -- SQL Accuracy Guard (Module 2).

Runs three independent validation gates on every AI-generated SQL query.
All gates execute independently (no short-circuit). Any gate failure = query blocked.

Gates:
  SAG-001  gate1_structural      -- AST parsing, table/column/join authorisation
  SAG-002  gate2_classification   -- Column sensitivity vs user clearance
  SAG-003  gate3_behavioral      -- Exploit pattern detection

Post-gate:
  SAG-004  query_rewriter        -- Transparent masking/limit rewriting
  SAG-005  hallucination_detector -- Schema reference verification
  SAG-007  violation_reporter    -- Structured audit-trail reporting
"""

from queryvault.app.services.sag.gate1_structural import (
    run as run_gate1,
    GateResult as Gate1Result,
)
from queryvault.app.services.sag.gate2_classification import (
    run as run_gate2,
    GateResult as Gate2Result,
)
from queryvault.app.services.sag.gate3_behavioral import (
    run as run_gate3,
    GateResult as Gate3Result,
)
from queryvault.app.services.sag.query_rewriter import (
    QueryRewriter,
    RewrittenSQL,
)
from queryvault.app.services.sag.hallucination_detector import (
    HallucinationDetector,
    HallucinationResult,
)
from queryvault.app.services.sag.violation_reporter import (
    ViolationReporter,
    ViolationReport,
)

__all__ = [
    "run_gate1",
    "run_gate2",
    "run_gate3",
    "Gate1Result",
    "Gate2Result",
    "Gate3Result",
    "QueryRewriter",
    "RewrittenSQL",
    "HallucinationDetector",
    "HallucinationResult",
    "ViolationReporter",
    "ViolationReport",
]
