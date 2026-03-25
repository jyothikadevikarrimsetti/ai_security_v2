"""Pipeline orchestrator -- end-to-end NL-to-SQL coordinator.

Stages:
  1. Check ambiguity
  2. Expand terminology
  3. Classify intent
  4. Embed question
  5. Retrieve schema candidates
  6. Rank and filter
  7. Optimize context (token budget)
  8. Assemble prompt
  9. Generate SQL
 10. Parse response
 11. Score confidence
 12. Record conversation turn

Accepts PipelineRequest with filtered_schema + contextual_rules.
Returns PipelineResponse with raw SQL.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog

from xensql.app.config import Settings
from xensql.app.models.api import (
    AmbiguityResult,
    ClarificationOption,
    ConfidenceBreakdown,
    ConfidenceScore,
    PipelineMetadata,
    PipelineRequest,
    PipelineResponse,
)
from xensql.app.models.enums import (
    AmbiguityType,
    ConfidenceLevel,
    IntentType,
    PipelineErrorCode,
    PipelineStatus,
)
from xensql.app.clients.llm_client import OpenAICompatClient
from xensql.app.clients.embedding_client import EmbeddingClient
from xensql.app.clients.vector_store import VectorStore

logger = structlog.get_logger(__name__)


class PipelineOrchestrator:
    """End-to-end NL-to-SQL pipeline coordinator.

    Receives pre-filtered schema from QueryVault and returns raw SQL.
    Does NOT handle auth, RBAC, validation, execution, or audit.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._llm_client = OpenAICompatClient(settings)
        self._embedding_client = EmbeddingClient(settings)
        self._vector_store = VectorStore(settings)

    async def execute(self, request: PipelineRequest) -> PipelineResponse:
        """Run the full 12-stage pipeline.

        Args:
            request: PipelineRequest with question, filtered_schema, and contextual_rules.

        Returns:
            PipelineResponse with generated SQL, confidence, and metadata.
        """
        request_id = str(uuid.uuid4())
        start_time = time.monotonic()

        logger.info(
            "pipeline_started",
            request_id=request_id,
            question_len=len(request.question),
        )

        try:
            # -- Stage 1: Check ambiguity --------------------------------------
            ambiguity = await self._check_ambiguity(request.question)
            if ambiguity.is_ambiguous:
                logger.info(
                    "pipeline_ambiguous",
                    request_id=request_id,
                    ambiguity_type=ambiguity.ambiguity_type,
                )
                elapsed = (time.monotonic() - start_time) * 1000
                return PipelineResponse(
                    request_id=request_id,
                    status=PipelineStatus.AMBIGUOUS,
                    ambiguity=ambiguity,
                    metadata=PipelineMetadata(total_latency_ms=round(elapsed, 1)),
                )

            # -- Stage 2: Expand terminology -----------------------------------
            expanded_question = await self._expand_terminology(request.question)

            # -- Stage 3: Classify intent --------------------------------------
            intent, intent_confidence = await self._classify_intent(expanded_question)

            # -- Stage 4: Embed question ---------------------------------------
            await self._embedding_client.connect()
            question_embedding = await self._embedding_client.embed(expanded_question)

            # -- Stage 5: Retrieve schema candidates ---------------------------
            await self._vector_store.connect()
            candidates = await self._vector_store.search(
                embedding=question_embedding,
                top_k=self._settings.retrieval_top_k,
                database_filter=request.tenant_id or None,
            )

            # -- Stage 6: Rank and filter --------------------------------------
            ranked_candidates = self._rank_and_filter(
                candidates, request.filtered_schema
            )
            tables_used = len(ranked_candidates)

            if tables_used == 0:
                elapsed = (time.monotonic() - start_time) * 1000
                return PipelineResponse(
                    request_id=request_id,
                    status=PipelineStatus.CANNOT_ANSWER,
                    error="No relevant tables found in schema",
                    error_code=PipelineErrorCode.NO_TABLES_FOUND,
                    metadata=PipelineMetadata(
                        total_latency_ms=round(elapsed, 1),
                        intent=intent.value,
                        intent_confidence=intent_confidence,
                    ),
                )

            # -- Stage 6b: Enrich with all columns for matched tables ----------
            matched_tables = list({
                c.get("table_name", "").lower()
                for c in ranked_candidates
                if c.get("table_name")
            })
            if matched_tables:
                all_columns = await self._vector_store.get_all_columns_for_tables(
                    matched_tables
                )
                # Replace ranked_candidates with full schema info
                if all_columns:
                    enriched: list[dict] = []
                    seen_fqns: set[str] = set()
                    for tname, entries in all_columns.items():
                        for entry in entries:
                            fqn = entry.get("entity_fqn", "")
                            if fqn in seen_fqns:
                                continue
                            seen_fqns.add(fqn)
                            enriched.append({
                                "table_name": tname,
                                "score": 1.0,
                                "metadata": entry,
                            })
                    if enriched:
                        ranked_candidates = enriched
                        logger.info(
                            "candidates_enriched",
                            tables=matched_tables,
                            total_entries=len(enriched),
                        )

            # -- Stage 7: Optimize context (token budget) ----------------------
            optimized_context = self._optimize_context(
                ranked_candidates,
                request.filtered_schema,
                request.contextual_rules,
            )
            logger.debug(
                "context_built",
                context_length=len(optimized_context),
                candidates_count=len(ranked_candidates),
                tables=list({c.get("table_name", "?") for c in ranked_candidates}),
            )

            # -- Stage 8: Assemble prompt --------------------------------------
            messages = self._assemble_prompt(
                question=request.question,
                context=optimized_context,
                intent=intent,
                dialect_hint=request.dialect_hint,
                conversation_history=request.conversation_history,
            )

            # -- Stage 9: Generate SQL -----------------------------------------
            gen_start = time.monotonic()
            await self._llm_client.connect()
            llm_response = await self._llm_client.generate(
                messages=messages,
                config={
                    "temperature": self._settings.llm_temperature,
                    "max_tokens": self._settings.llm_max_tokens,
                    "provider_override": request.provider_override,
                },
            )
            gen_elapsed = (time.monotonic() - gen_start) * 1000

            # -- Stage 10: Parse response --------------------------------------
            sql, explanation = self._parse_llm_response(llm_response.content)

            if not sql:
                elapsed = (time.monotonic() - start_time) * 1000
                # Include LLM's explanation if available
                error_msg = explanation if explanation else "LLM did not produce valid SQL"
                if not explanation:
                    error_msg += f". LLM response: {llm_response.content[:300]}"
                return PipelineResponse(
                    request_id=request_id,
                    status=PipelineStatus.ERROR,
                    error=error_msg,
                    error_code=PipelineErrorCode.GENERATION_FAILED,
                    metadata=PipelineMetadata(
                        total_latency_ms=round(elapsed, 1),
                        generation_latency_ms=round(gen_elapsed, 1),
                        intent=intent.value,
                        intent_confidence=intent_confidence,
                        llm_model=llm_response.model,
                        llm_provider=llm_response.provider,
                        prompt_tokens=llm_response.prompt_tokens,
                        completion_tokens=llm_response.completion_tokens,
                    ),
                )

            # -- Stage 11: Score confidence ------------------------------------
            retrieval_score = self._compute_retrieval_score(candidates, tables_used)
            confidence = self._score_confidence(
                retrieval_score=retrieval_score,
                intent_confidence=intent_confidence,
                generation_signals=llm_response.generation_quality,
            )

            # -- Stage 12: Record conversation turn ----------------------------
            conversation_turn = await self._record_conversation_turn(
                session_id=request.session_id,
                question=request.question,
                sql=sql,
            )

            # -- Assemble response ---------------------------------------------
            total_elapsed = (time.monotonic() - start_time) * 1000
            metadata = PipelineMetadata(
                generation_latency_ms=round(gen_elapsed, 1),
                total_latency_ms=round(total_elapsed, 1),
                tables_used=tables_used,
                intent=intent.value,
                intent_confidence=intent_confidence,
                llm_model=llm_response.model,
                llm_provider=llm_response.provider,
                prompt_tokens=llm_response.prompt_tokens,
                completion_tokens=llm_response.completion_tokens,
                dialect=request.dialect_hint or "",
                conversation_turn=conversation_turn,
            )

            return PipelineResponse(
                request_id=request_id,
                status=PipelineStatus.GENERATED,
                sql=sql,
                confidence=confidence,
                explanation=explanation,
                metadata=metadata,
            )

        except Exception as exc:
            elapsed = (time.monotonic() - start_time) * 1000
            logger.error("pipeline_failed", request_id=request_id, error=str(exc))
            return PipelineResponse(
                request_id=request_id,
                status=PipelineStatus.ERROR,
                error=str(exc),
                error_code=PipelineErrorCode.INTERNAL_ERROR,
                metadata=PipelineMetadata(total_latency_ms=round(elapsed, 1)),
            )

        finally:
            await self._embedding_client.close()
            await self._vector_store.close()
            await self._llm_client.close()

    # -- Stage implementations -------------------------------------------------

    async def _check_ambiguity(self, question: str) -> AmbiguityResult:
        """Stage 1: Detect ambiguity in the question."""
        stripped = question.strip()

        # Short question heuristic
        if len(stripped.split()) < 3:
            return AmbiguityResult(
                is_ambiguous=True,
                ambiguity_type=AmbiguityType.SHORT_QUESTION,
                confidence=0.9,
                reason="Question is too short to determine intent",
                clarifications=[
                    ClarificationOption(
                        label="Be more specific",
                        rephrased_question=f"Could you provide more detail about: {stripped}?",
                    )
                ],
            )

        # Vague pronoun / reference detection
        vague_patterns = ["show me stuff", "get data", "what about", "the thing"]
        lower = stripped.lower()
        for pattern in vague_patterns:
            if pattern in lower:
                return AmbiguityResult(
                    is_ambiguous=True,
                    ambiguity_type=AmbiguityType.VAGUE_QUESTION,
                    confidence=0.85,
                    reason=f"Question contains vague reference: '{pattern}'",
                )

        return AmbiguityResult(is_ambiguous=False, confidence=0.0)

    async def _expand_terminology(self, question: str) -> str:
        """Stage 2: Expand abbreviations and domain-specific terminology."""
        # Load abbreviation mappings if available
        try:
            from pathlib import Path
            import yaml

            abbrev_path = Path(__file__).resolve().parent.parent.parent / "config" / "abbreviations.yaml"
            if abbrev_path.exists():
                with open(abbrev_path) as fh:
                    abbreviations = yaml.safe_load(fh) or {}
                expanded = question
                for abbrev, full_term in abbreviations.items():
                    if isinstance(full_term, str):
                        # Case-insensitive word boundary replacement
                        import re
                        pattern = rf"\b{re.escape(abbrev)}\b"
                        expanded = re.sub(pattern, full_term, expanded, flags=re.IGNORECASE)
                return expanded
        except Exception as exc:
            logger.debug("terminology_expansion_skipped", error=str(exc))

        return question

    async def _classify_intent(self, question: str) -> tuple[IntentType, float]:
        """Stage 3: Classify the question intent."""
        lower = question.lower()

        # Keyword-based classification with confidence
        intent_keywords: dict[IntentType, list[str]] = {
            IntentType.AGGREGATION: ["total", "sum", "count", "average", "avg", "min", "max", "how many"],
            IntentType.COMPARISON: ["compare", "difference", "versus", "vs", "higher", "lower", "more than", "less than"],
            IntentType.TREND: ["trend", "over time", "monthly", "weekly", "daily", "growth", "change"],
            IntentType.EXISTENCE_CHECK: ["is there", "does", "exists", "any", "has"],
            IntentType.JOIN_QUERY: ["join", "related", "across", "between", "with"],
            IntentType.DEFINITION: ["what is", "define", "describe", "meaning"],
            IntentType.EXPLANATION: ["why", "explain", "reason"],
        }

        best_intent = IntentType.DATA_LOOKUP
        best_score = 0.5  # Default confidence for DATA_LOOKUP

        for intent, keywords in intent_keywords.items():
            matches = sum(1 for kw in keywords if kw in lower)
            if matches > 0:
                score = min(0.6 + matches * 0.15, 0.95)
                if score > best_score:
                    best_intent = intent
                    best_score = score

        return best_intent, best_score

    def _rank_and_filter(
        self,
        candidates: list[dict[str, Any]],
        filtered_schema: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Stage 6: Rank candidates and filter against the pre-filtered schema."""
        schema_tables = set()
        for table in filtered_schema.get("tables", []):
            name = table.get("name", "") if isinstance(table, dict) else str(table)
            schema_tables.add(name.lower())

        if not schema_tables:
            # If no explicit table list, use all candidates
            return candidates[: self._settings.retrieval_rerank_top_n]

        # Filter to only candidates matching the pre-filtered schema
        filtered = [
            c for c in candidates
            if c.get("table_name", "").lower() in schema_tables
        ]

        # Sort by similarity score descending
        filtered.sort(key=lambda c: c.get("score", 0.0), reverse=True)

        return filtered[: self._settings.retrieval_rerank_top_n]

    def _optimize_context(
        self,
        candidates: list[dict[str, Any]],
        filtered_schema: dict[str, Any],
        contextual_rules: list[str],
    ) -> str:
        """Stage 7: Optimize context to fit within token budget.

        Uses a simplified token estimate (4 chars per token) to build the
        context string within the configured token budget.

        Sources schema context from:
          1. filtered_schema.tables (DDL from QueryVault pre-filter)
          2. Retrieved candidates' source_text (from pgvector search)
        """
        budget = self._settings.token_budget
        chars_budget = budget * 4  # rough estimate

        parts: list[str] = []
        used = 0
        seen_tables: set[str] = set()

        # Add schema DDL / descriptions from filtered_schema
        for table in filtered_schema.get("tables", []):
            if isinstance(table, dict):
                ddl = table.get("ddl", "") or table.get("description", "")
                table_name = table.get("name", "unknown")
            else:
                ddl = str(table)
                table_name = str(table)

            entry = f"-- Table: {table_name}\n{ddl}\n"
            if used + len(entry) > chars_budget:
                break
            parts.append(entry)
            used += len(entry)
            seen_tables.add(table_name.lower())

        # If filtered_schema didn't provide DDL, use retrieved candidates' source_text
        # Group candidates by table: table descriptions first, then columns
        if not parts:
            # Collect table descriptions and columns separately
            table_descs: dict[str, str] = {}
            table_columns: dict[str, list[str]] = {}

            for candidate in candidates:
                source_text = candidate.get("metadata", {}).get("source_text", "")
                table_name = candidate.get("table_name", "unknown")
                entity_type = candidate.get("metadata", {}).get("entity_type", "")

                if not source_text:
                    continue

                tkey = table_name.lower()
                if entity_type == "table":
                    table_descs[tkey] = source_text
                elif entity_type == "column":
                    table_columns.setdefault(tkey, []).append(source_text)

            # Build context: table description + its columns
            for tkey in table_descs:
                if tkey in seen_tables:
                    continue

                desc = table_descs[tkey]
                col_lines = table_columns.get(tkey, [])
                col_block = "\n".join(f"  - {c}" for c in col_lines)

                entry = f"-- Table: {tkey}\n{desc}\n"
                if col_block:
                    entry += f"Columns:\n{col_block}\n"

                if used + len(entry) > chars_budget:
                    break
                parts.append(entry)
                used += len(entry)
                seen_tables.add(tkey)

            # Also add tables found only via columns (no table-level embedding)
            for tkey, col_lines in table_columns.items():
                if tkey in seen_tables:
                    continue
                col_block = "\n".join(f"  - {c}" for c in col_lines)
                entry = f"-- Table: {tkey}\nColumns:\n{col_block}\n"
                if used + len(entry) > chars_budget:
                    break
                parts.append(entry)
                used += len(entry)
                seen_tables.add(tkey)

        # Add contextual rules
        if contextual_rules:
            rules_block = "\n-- Rules:\n" + "\n".join(f"-- {r}" for r in contextual_rules) + "\n"
            if used + len(rules_block) <= chars_budget:
                parts.append(rules_block)

        return "\n".join(parts)

    def _assemble_prompt(
        self,
        question: str,
        context: str,
        intent: IntentType,
        dialect_hint: str | None,
        conversation_history: list | None,
    ) -> list[dict[str, str]]:
        """Stage 8: Assemble the LLM prompt messages."""
        dialect = dialect_hint or "PostgreSQL"

        system_prompt = (
            f"You are a SQL query generator for a healthcare analytics database running {dialect}. "
            f"The user's intent is: {intent.value}.\n\n"
            "CRITICAL RULES:\n"
            "- You MUST ALWAYS output a SQL query inside a ```sql code block.\n"
            "- You may ONLY use tables and columns from the provided schema. "
            "NEVER reference tables or columns not listed in the schema.\n"
            "- If the user asks about data not directly available (e.g., individual patient names), "
            "generate the closest relevant query using the available tables. "
            "For example, if asked for 'patient names' but only summary/aggregate tables exist, "
            "query the summary data instead and explain the difference.\n"
            "- After the SQL block, provide a brief explanation of what the query returns.\n"
            "- Do NOT include any DML (INSERT, UPDATE, DELETE) statements.\n"
            "- Use appropriate JOINs when multiple tables are needed.\n"
            "- Always qualify column names with table aliases.\n"
            "- Use ONLY exact column names from the schema. Do NOT guess or invent column names.\n"
        )

        messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]

        # Add conversation history
        if conversation_history:
            for turn in conversation_history[-self._settings.conversation_max_turns :]:
                q = turn.question if hasattr(turn, "question") else turn.get("question", "")
                s = turn.sql if hasattr(turn, "sql") else turn.get("sql", "")
                if q:
                    messages.append({"role": "user", "content": q})
                if s:
                    messages.append({"role": "assistant", "content": f"```sql\n{s}\n```"})

        # Current question with context
        user_msg = f"Database schema:\n{context}\n\nQuestion: {question}"
        messages.append({"role": "user", "content": user_msg})

        return messages

    def _parse_llm_response(self, content: str) -> tuple[str | None, str]:
        """Stage 10: Parse SQL and explanation from LLM response."""
        import re

        sql: str | None = None
        explanation = ""

        # Extract SQL from code block
        sql_match = re.search(r"```sql\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
        if sql_match:
            sql = sql_match.group(1).strip()
            # Extract explanation after the code block
            remainder = content[sql_match.end() :].strip()
            if remainder:
                explanation = remainder
        else:
            # Try bare SQL detection (starts with SELECT, WITH, etc.)
            sql_keywords = re.match(
                r"^\s*(SELECT|WITH|INSERT|UPDATE|DELETE)\b",
                content,
                re.IGNORECASE,
            )
            if sql_keywords:
                sql = content.strip()

        # Basic safety: reject DML
        if sql:
            upper_sql = sql.upper().strip()
            if any(upper_sql.startswith(kw) for kw in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE")):
                logger.warning("pipeline_rejected_dml", sql_preview=sql[:100])
                return None, "Rejected: DML/DDL statements are not allowed"

        return sql, explanation

    def _compute_retrieval_score(
        self, candidates: list[dict[str, Any]], tables_used: int
    ) -> float:
        """Compute retrieval quality score from candidate similarity scores."""
        if not candidates:
            return 0.0
        scores = [c.get("score", 0.0) for c in candidates[:tables_used]]
        if not scores:
            return 0.0
        return sum(scores) / len(scores)

    def _score_confidence(
        self,
        retrieval_score: float,
        intent_confidence: float,
        generation_signals: float,
    ) -> ConfidenceScore:
        """Stage 11: Compute composite confidence score."""
        w = self._settings
        weighted = (
            retrieval_score * w.confidence_retrieval_weight
            + intent_confidence * w.confidence_intent_weight
            + generation_signals * w.confidence_generation_weight
        )
        weighted = max(0.0, min(1.0, weighted))

        flags: list[str] = []
        if retrieval_score < 0.5:
            flags.append("low_retrieval_quality")
        if intent_confidence < 0.6:
            flags.append("uncertain_intent")
        if generation_signals < 0.5:
            flags.append("low_generation_quality")

        if weighted >= 0.75:
            level = ConfidenceLevel.HIGH
        elif weighted >= 0.45:
            level = ConfidenceLevel.MEDIUM
        else:
            level = ConfidenceLevel.LOW

        return ConfidenceScore(
            level=level,
            score=round(weighted, 3),
            breakdown=ConfidenceBreakdown(
                retrieval_score=round(retrieval_score, 3),
                intent_score=round(intent_confidence, 3),
                generation_score=round(generation_signals, 3),
            ),
            flags=flags,
        )

    async def _record_conversation_turn(
        self,
        session_id: str | None,
        question: str,
        sql: str,
    ) -> int:
        """Stage 12: Record the conversation turn in Redis for multi-turn context."""
        if not session_id:
            return 0

        try:
            from xensql.app.main import get_redis
            import json

            redis = get_redis()
            if redis is None:
                return 0

            key = f"xensql:conversation:{session_id}"
            turn_data = json.dumps({"question": question, "sql": sql})

            await redis.rpush(key, turn_data)
            await redis.ltrim(key, -self._settings.conversation_max_turns, -1)
            await redis.expire(key, self._settings.conversation_ttl_seconds)

            turn_count = await redis.llen(key)
            return turn_count

        except Exception as exc:
            logger.warning("conversation_record_failed", error=str(exc))
            return 0
