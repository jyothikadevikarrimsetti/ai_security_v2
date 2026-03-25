"""Question Understanding module for XenSQL NL-to-SQL pipeline.

Submodules:
- intent_classifier: Rule-based intent classification (8 intents)
- terminology_expander: Domain abbreviation expansion (healthcare + finance)
- question_embedder: Preprocessing + embedding generation with caching
- ambiguity_detector: Detect vague/ambiguous queries before pipeline execution
"""

from xensql.app.services.question_understanding.ambiguity_detector import (
    AmbiguityDetector,
    AmbiguityResult,
)
from xensql.app.services.question_understanding.intent_classifier import (
    IntentClassifier,
)
from xensql.app.services.question_understanding.question_embedder import (
    QuestionEmbedder,
)
from xensql.app.services.question_understanding.terminology_expander import (
    TerminologyExpander,
)

__all__ = [
    "AmbiguityDetector",
    "AmbiguityResult",
    "IntentClassifier",
    "QuestionEmbedder",
    "TerminologyExpander",
]
