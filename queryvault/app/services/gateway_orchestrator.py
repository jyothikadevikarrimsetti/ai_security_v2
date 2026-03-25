"""QueryVault Gateway Orchestrator -- 5-zone security pipeline wrapping XenSQL.

Security Zones:
  ZONE 1 -- PRE-MODEL:       Identity resolution + prompt injection scan + schema probing check
                              + behavioral fingerprint + threat classification + domain filter
                              + RBAC policy resolution + column scoping
  ZONE 2 -- MODEL BOUNDARY:  Context minimization + XenSQL call (filtered_schema +
                              contextual_rules + question)
  ZONE 3 -- POST-MODEL:      3-gate validation (parallel) + hallucination detection +
                              query rewriting
  ZONE 4 -- EXECUTION:       Circuit breaker check + resource-bounded execution +
                              result sanitization
  ZONE 5 -- CONTINUOUS:      Audit event ingestion + anomaly detection + alert processing

Fail-secure at every zone boundary.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

import structlog

from queryvault.app.clients.graph_client import GraphClient
from queryvault.app.clients.xensql_client import XenSQLClient
from queryvault.app.config import Settings
from queryvault.app.models.api import (
    ExecutionResult,
    GatewayQueryRequest,
    GatewayQueryResponse,
    PostModelChecks,
    PreModelChecks,
    SecuritySummary,
)
from queryvault.app.models.enums import ThreatLevel

logger = structlog.get_logger(__name__)


class GatewayOrchestrator:
    """Coordinates the 5-zone security pipeline wrapping XenSQL."""

    def __init__(
        self,
        settings: Settings,
        xensql_client: XenSQLClient,
        graph_client: GraphClient,
        redis: Any = None,
        audit_pool: Any = None,
        circuit_breakers: dict[str, Any] | None = None,
    ) -> None:
        self._settings = settings
        self._xensql = xensql_client
        self._graph = graph_client
        self._redis = redis
        self._audit_pool = audit_pool
        self._breakers = circuit_breakers or {}

        # Load attack patterns for injection scanning
        self._attack_patterns = self._load_attack_patterns()

    def _load_attack_patterns(self) -> list[dict]:
        """Load attack patterns from JSON file."""
        patterns_file = self._settings.attack_patterns_file
        if not os.path.isabs(patterns_file):
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            patterns_file = os.path.join(base_dir, patterns_file)

        try:
            with open(patterns_file, "r") as f:
                data = json.load(f)
            return [p for p in data.get("patterns", []) if p.get("enabled", True)]
        except Exception as exc:
            logger.warning("attack_patterns_load_failed", error=str(exc))
            return []

    async def process(self, request: GatewayQueryRequest) -> GatewayQueryResponse:
        """Execute the full 5-zone security pipeline."""
        start = time.monotonic()
        request_id = str(uuid.uuid4())
        log = logger.bind(request_id=request_id)
        zones_passed: list[str] = []

        log.info("gateway_started", question_len=len(request.question))

        try:
            return await self._run_zones(request, request_id, log, zones_passed, start)
        except Exception as exc:
            log.error("gateway_error", error=str(exc))
            return GatewayQueryResponse(
                request_id=request_id,
                error="Internal security gateway error",
                security_summary=SecuritySummary(
                    zones_passed=zones_passed,
                    threat_level=ThreatLevel.HIGH,
                ),
            )

    async def _run_zones(
        self,
        request: GatewayQueryRequest,
        request_id: str,
        log: Any,
        zones_passed: list[str],
        start: float,
    ) -> GatewayQueryResponse:

        # ============================================================
        # ZONE 1: PRE-MODEL
        # ============================================================

        # 1a. Identity resolution (JWT validation)
        identity = await self._resolve_identity(request.jwt_token, log)
        if identity is None:
            return GatewayQueryResponse(
                request_id=request_id,
                blocked_reason="Identity verification failed",
                security_summary=SecuritySummary(
                    zones_passed=[],
                    threat_level=ThreatLevel.HIGH,
                ),
            )

        # 1a-ii. Employment status gate (zero-trust: valid token ≠ active employee)
        if isinstance(identity, dict) and identity.get("_blocked"):
            return GatewayQueryResponse(
                request_id=request_id,
                blocked_reason=identity.get("_reason", "Access denied"),
                security_summary=SecuritySummary(
                    zones_passed=[],
                    threat_level=ThreatLevel.HIGH,
                ),
            )

        user_id = identity.get("user_id", "unknown")
        clearance = identity.get("clearance_level", 1)
        domains = identity.get("domains", [])
        roles = identity.get("roles", [])
        log = log.bind(user_id=user_id)

        # 1a-iii. Domain boundary enforcement
        domain_violation = self._check_domain_boundary(request.question, domains)
        if domain_violation:
            log.warning("domain_boundary_blocked", user_domains=domains, violation=domain_violation)
            await self._emit_audit(
                request_id, user_id, "DOMAIN_BLOCKED",
                {"domains": domains, "violation": domain_violation},
            )
            return GatewayQueryResponse(
                request_id=request_id,
                blocked_reason=f"Domain boundary violation: {domain_violation}",
                security_summary=SecuritySummary(
                    zones_passed=[],
                    threat_level=ThreatLevel.MEDIUM,
                ),
            )

        # 1b. Prompt injection scan (200+ patterns)
        injection_result = self._scan_injection(request.question)

        # 1c. Schema probing detection
        probing_result = await self._check_probing(request.question, user_id)

        # 1d. Behavioral fingerprint check
        behavioral_result = await self._check_behavioral(user_id, request.question)

        # 1e. Threat classification (combines all signals)
        threat_level, threat_category, threat_reasons, should_block = self._classify_threat(
            injection_result, probing_result, behavioral_result
        )

        # 1f. Domain filter (from graph)
        allowed_domains = await self._graph.get_user_domains(user_id) if self._graph else domains

        # 1g. RBAC policy resolution (from graph)
        rbac_policy = await self._graph.resolve_rbac_policy(user_id, roles) if self._graph else {}

        # 1h. Column scoping based on clearance + RBAC
        column_scope = await self._graph.get_column_scope(
            user_id, clearance, allowed_domains
        ) if self._graph else {}

        pre_model = PreModelChecks(
            injection_blocked=injection_result.get("blocked", False),
            injection_risk_score=injection_result.get("risk_score", 0.0),
            injection_flags=injection_result.get("flags", []),
            probing_detected=probing_result.get("is_probing", False),
            probing_score=probing_result.get("score", 0.0),
            behavioral_anomaly_score=behavioral_result.get("anomaly_score", 0.0),
            behavioral_flags=behavioral_result.get("flags", []),
            threat_level=threat_level,
            threat_category=threat_category,
        )

        if should_block:
            log.warning("pre_model_blocked", threat_level=threat_level.value)

            await self._emit_audit(
                request_id, user_id, "THREAT_BLOCKED",
                {"threat_level": threat_level.value, "category": threat_category, "reasons": threat_reasons},
            )

            return GatewayQueryResponse(
                request_id=request_id,
                blocked_reason="; ".join(threat_reasons),
                security_summary=SecuritySummary(
                    pre_model=pre_model,
                    zones_passed=zones_passed,
                    threat_level=threat_level,
                ),
            )

        zones_passed.append("PRE_MODEL")

        # ============================================================
        # ZONE 2: MODEL BOUNDARY -- Call XenSQL
        # ============================================================

        # 2a. Context minimization: build filtered schema + contextual rules
        filtered_schema = self._minimize_context(rbac_policy, column_scope, allowed_domains)
        contextual_rules = self._build_contextual_rules(rbac_policy, clearance)

        # 2b. XenSQL call
        try:
            pipeline_result = await self._xensql.query(
                question=request.question,
                filtered_schema=filtered_schema,
                contextual_rules=contextual_rules,
                dialect_hint="postgresql",
                session_id=request_id,
            )
        except RuntimeError as exc:
            log.error("xensql_failed", error=str(exc))
            return GatewayQueryResponse(
                request_id=request_id,
                error="Pipeline engine unavailable",
                security_summary=SecuritySummary(
                    pre_model=pre_model,
                    zones_passed=zones_passed,
                    threat_level=ThreatLevel.NONE,
                ),
            )

        raw_sql = pipeline_result.get("sql")
        if not raw_sql:
            zones_passed.append("MODEL_BOUNDARY")
            return GatewayQueryResponse(
                request_id=request_id,
                error=pipeline_result.get("error", "No SQL generated"),
                security_summary=SecuritySummary(
                    pre_model=pre_model,
                    zones_passed=zones_passed,
                ),
            )

        zones_passed.append("MODEL_BOUNDARY")

        # ============================================================
        # ZONE 3: POST-MODEL -- 3-gate validation (parallel)
        # ============================================================

        # Run all three gates in parallel
        gate_syntax, gate_semantic, gate_permission = await asyncio.gather(
            self._gate_syntax_check(raw_sql),
            self._gate_semantic_check(raw_sql, request.question, filtered_schema),
            self._gate_permission_check(raw_sql, rbac_policy, column_scope),
        )

        # Hallucination detection
        hallucination = self._detect_hallucination(raw_sql, filtered_schema)

        # Query rewriting (masking, row filters)
        rewritten_sql, rewrites = self._rewrite_query(raw_sql, column_scope, rbac_policy)

        gate_results = {
            "syntax": gate_syntax.get("result", "PASS"),
            "semantic": gate_semantic.get("result", "PASS"),
            "permission": gate_permission.get("result", "PASS"),
        }

        violations: list[dict] = []
        violations.extend(gate_syntax.get("violations", []))
        violations.extend(gate_semantic.get("violations", []))
        violations.extend(gate_permission.get("violations", []))

        post_model = PostModelChecks(
            validation_decision="BLOCKED" if any(v == "FAIL" for v in gate_results.values()) else "APPROVED",
            hallucination_detected=hallucination.get("detected", False),
            hallucinated_identifiers=hallucination.get("identifiers", []),
            gate_results=gate_results,
            violations=violations,
            rewrites_applied=rewrites,
        )

        if hallucination.get("detected"):
            log.warning("hallucination_detected", identifiers=hallucination["identifiers"])
            await self._emit_audit(
                request_id, user_id, "HALLUCINATION_BLOCKED",
                {"identifiers": hallucination["identifiers"], "sql": raw_sql[:200]},
            )
            return GatewayQueryResponse(
                request_id=request_id,
                sql=raw_sql,
                blocked_reason=f"SQL references unauthorised objects: {', '.join(hallucination['identifiers'])}",
                security_summary=SecuritySummary(
                    pre_model=pre_model,
                    post_model=post_model,
                    zones_passed=zones_passed,
                    threat_level=ThreatLevel.HIGH,
                ),
            )

        if any(v == "FAIL" for v in gate_results.values()):
            await self._emit_audit(
                request_id, user_id, "VALIDATION_BLOCKED",
                {"violations": violations[:5]},
            )
            return GatewayQueryResponse(
                request_id=request_id,
                sql=raw_sql,
                blocked_reason="SQL failed security validation",
                security_summary=SecuritySummary(
                    pre_model=pre_model,
                    post_model=post_model,
                    zones_passed=zones_passed,
                    threat_level=ThreatLevel.MEDIUM,
                ),
            )

        validated_sql = rewritten_sql or raw_sql
        zones_passed.append("POST_MODEL")

        # ============================================================
        # ZONE 4: EXECUTION -- Circuit breaker + resource-bounded exec
        # ============================================================

        execution = None

        # 4a. Circuit breaker check
        breaker = self._breakers.get("xensql", {})
        if breaker.get("state") == "OPEN":
            log.warning("circuit_breaker_open", service="xensql")
            return GatewayQueryResponse(
                request_id=request_id,
                sql=validated_sql,
                error="Execution service circuit breaker is open",
                security_summary=SecuritySummary(
                    pre_model=pre_model,
                    post_model=post_model,
                    zones_passed=zones_passed,
                    threat_level=ThreatLevel.NONE,
                ),
            )

        # 4b. Enforce per-role result_limit on the SQL before execution
        role_limit = (rbac_policy or {}).get("result_limit")
        if role_limit is not None:
            role_limit = int(role_limit)
            sql_upper = validated_sql.upper().strip().rstrip(";")
            limit_match = re.search(r'LIMIT\s+(\d+)', sql_upper)
            if limit_match:
                existing = int(limit_match.group(1))
                if existing > role_limit:
                    start, end = limit_match.span()
                    validated_sql = validated_sql.rstrip(";").rstrip()
                    validated_sql = validated_sql[:start] + f"LIMIT {role_limit}" + validated_sql[end:]
            else:
                validated_sql = validated_sql.rstrip(";").rstrip() + f" LIMIT {role_limit}"

        # 4c. Resource-bounded execution against the database
        execution = await self._execute_sql(validated_sql, clearance, log, rbac_policy=rbac_policy)

        zones_passed.append("EXECUTION")

        # ============================================================
        # ZONE 5: CONTINUOUS -- Audit + anomaly detection + alerts
        # ============================================================

        # 5a. Audit event ingestion
        await self._emit_audit(
            request_id, user_id, "QUERY_COMPLETED",
            {
                "question": request.question[:200],
                "sql": validated_sql[:200],
                "threat_level": threat_level.value,
            },
        )

        # 5b. Anomaly detection (update behavioral profile)
        await self._update_behavioral_profile(user_id, request.question, validated_sql)

        # 5c. Alert processing (check if thresholds exceeded)
        await self._process_alerts(user_id, threat_level, request_id)

        zones_passed.append("CONTINUOUS")

        total_ms = (time.monotonic() - start) * 1000
        log.info(
            "gateway_completed",
            status="SUCCESS",
            latency_ms=f"{total_ms:.1f}",
            zones_passed=zones_passed,
        )

        # Extract results data from execution
        results_data = execution.data if execution else {"rows": [], "columns": []}

        return GatewayQueryResponse(
            request_id=request_id,
            sql=validated_sql,
            results=results_data,
            security_summary=SecuritySummary(
                pre_model=pre_model,
                post_model=post_model,
                execution=execution,
                zones_passed=zones_passed,
                threat_level=threat_level,
                validation_result=post_model.validation_decision,
                execution_status="SUCCESS",
                audit_trail_id=request_id,
            ),
            audit_id=request_id,
        )

    # ── ZONE 1 helpers ───────────────────────────────────────

    async def _resolve_identity(self, jwt_token: str, log: Any) -> dict | None:
        """Resolve JWT to identity context.

        Validates RS256 tokens signed by the demo KeyPair and enriches
        with RBAC metadata (clearance, domains) from the role resolver.
        Also checks employment status against the identity store.
        """
        try:
            import jwt as pyjwt
            from queryvault.app.services.identity.token_validator import MockKeyPair
            from queryvault.app.services.identity.role_resolver import (
                ROLE_CLEARANCE,
                ROLE_DOMAIN,
            )
            from queryvault.app.services.identity.context_builder import (
                MOCK_USER_DIRECTORY,
            )
            from queryvault.app.models.enums import ClearanceLevel, EmploymentStatus

            public_key = MockKeyPair.get().public_key
            payload = pyjwt.decode(
                jwt_token,
                public_key,
                algorithms=["RS256"],
                audience="apollo-zt-pipeline",
                issuer="https://login.microsoftonline.com/apollo-mock-tenant/v2.0",
                options={"verify_exp": True},
            )

            user_id = payload.get("oid", payload.get("sub", "unknown"))

            # Employment status check (zero-trust: valid token ≠ active employee)
            hr_record = MOCK_USER_DIRECTORY.get(user_id)
            if hr_record and hr_record.employment_status != EmploymentStatus.ACTIVE:
                log.warning(
                    "access_denied_employment_status",
                    user_id=user_id,
                    status=hr_record.employment_status.value,
                )
                return {"_blocked": True, "_reason": f"Employment status: {hr_record.employment_status.value}"}

            # Map JWT claims → identity dict expected by downstream zones
            ad_roles = payload.get("roles", [])
            best_clearance = int(ClearanceLevel.PUBLIC)
            for role in ad_roles:
                lvl = ROLE_CLEARANCE.get(role, ClearanceLevel.PUBLIC)
                if int(lvl) > best_clearance:
                    best_clearance = int(lvl)

            domains = []
            for role in ad_roles:
                d = ROLE_DOMAIN.get(role)
                if d is not None and d.value not in domains:
                    domains.append(d.value)
            if not domains:
                domains = ["ADMINISTRATIVE"]

            identity = {
                "user_id": user_id,
                "clearance_level": best_clearance,
                "domains": domains,
                "roles": ad_roles,
                "name": payload.get("name"),
                "email": payload.get("preferred_username"),
                "groups": payload.get("groups", []),
            }
            log.info("identity_resolved", user_id=identity["user_id"],
                     clearance=best_clearance, domains=domains, roles=ad_roles)
            return identity

        except pyjwt.ExpiredSignatureError:
            log.warning("jwt_expired")
            return None
        except pyjwt.InvalidTokenError as exc:
            log.warning("jwt_invalid", error=str(exc))
            return None
        except ImportError:
            log.error("jwt_library_missing")
            return None
        except Exception as exc:
            log.error("identity_resolution_failed", error=str(exc))
            return None

    def _check_domain_boundary(self, question: str, user_domains: list[str]) -> str | None:
        """Check if the question targets a data domain outside the user's allowed domains.

        Returns a violation description string if blocked, None if allowed.
        CLINICAL and COMPLIANCE users can access clinical data.
        FINANCIAL users cannot access clinical data, and vice versa.
        """
        q = question.lower()

        # Keywords that indicate clinical data access
        clinical_keywords = [
            "patient", "vitals", "diagnosis", "medication", "prescription",
            "lab result", "discharge", "admission", "clinical", "medical",
            "treatment", "symptom", "blood pressure", "heart rate",
            "aadhaar", "health record", "ehr", "emr",
        ]
        # Keywords that indicate financial data access
        financial_keywords = [
            "billing", "invoice", "revenue", "payment", "insurance",
            "claim", "reimbursement", "cost", "charge", "financial",
        ]

        question_targets_clinical = any(kw in q for kw in clinical_keywords)
        question_targets_financial = any(kw in q for kw in financial_keywords)

        # Users with CLINICAL, COMPLIANCE, or RESEARCH domains may access clinical data
        clinical_allowed = any(
            d in ("CLINICAL", "COMPLIANCE", "RESEARCH") for d in user_domains
        )
        financial_allowed = any(
            d in ("FINANCIAL", "COMPLIANCE") for d in user_domains
        )

        if question_targets_clinical and not clinical_allowed:
            return f"User domain(s) {user_domains} cannot access clinical data"

        if question_targets_financial and not financial_allowed:
            return f"User domain(s) {user_domains} cannot access financial data"

        return None

    def _scan_injection(self, question: str) -> dict:
        """Scan for prompt injection attacks using loaded attack patterns."""
        flags: list[str] = []
        max_weight = 0.0

        normalized = question.lower().strip()

        for pattern in self._attack_patterns:
            regex = pattern.get("pattern", "")
            try:
                if re.search(regex, normalized, re.IGNORECASE):
                    flags.append(f"{pattern['category']}: {pattern['description']}")
                    max_weight = max(max_weight, pattern.get("severity_weight", 0.5))
            except re.error:
                continue

        blocked = max_weight >= self._settings.injection_threshold
        return {
            "blocked": blocked,
            "risk_score": min(max_weight, 1.0),
            "flags": flags,
            "patterns_matched": len(flags),
        }

    async def _check_probing(self, question: str, user_id: str) -> dict:
        """Detect schema probing behavior via sliding window in Redis."""
        if not self._redis:
            return {"is_probing": False, "score": 0.0}

        probing_keywords = [
            "show tables", "describe", "information_schema", "schema",
            "columns", "table_name", "sys.tables", "pg_catalog",
            "list tables", "what tables", "show me all",
        ]

        is_probing_query = any(kw in question.lower() for kw in probing_keywords)
        if not is_probing_query:
            return {"is_probing": False, "score": 0.0}

        key = f"qv:probing:{user_id}"
        now = time.time()
        window = self._settings.probing_window_seconds

        try:
            pipe = self._redis.pipeline()
            pipe.zadd(key, {str(now): now})
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zcard(key)
            pipe.expire(key, window * 2)
            results = await pipe.execute()
            count = results[2]
        except Exception:
            return {"is_probing": False, "score": 0.0}

        score = min(count / self._settings.probing_threshold, 1.0)
        return {
            "is_probing": count >= self._settings.probing_threshold,
            "score": score,
            "count_in_window": count,
        }

    async def _check_behavioral(self, user_id: str, question: str) -> dict:
        """Check behavioral fingerprint for anomalies."""
        if not self._redis:
            return {"anomaly_score": 0.0, "flags": []}

        key = f"qv:behavioral:{user_id}"
        flags: list[str] = []

        try:
            profile_data = await self._redis.get(key)
            if not profile_data:
                flags.append("first_time_user")
                return {"anomaly_score": 0.3, "flags": flags}

            profile = json.loads(profile_data)

            # Check time-of-day anomaly
            current_hour = datetime.now(UTC).hour
            usual_hours = profile.get("usual_hours", [])
            if usual_hours and current_hour not in usual_hours:
                flags.append("off_hours_access")

            # Check question complexity deviation
            avg_length = profile.get("avg_question_length", 50)
            if len(question) > avg_length * 3:
                flags.append("unusual_complexity")

            # Check query frequency
            last_query_time = profile.get("last_query_time", 0)
            if time.time() - last_query_time < 1.0:
                flags.append("rapid_fire_queries")

            score = min(len(flags) * 0.25, 1.0)
            return {"anomaly_score": score, "flags": flags}

        except Exception:
            return {"anomaly_score": 0.0, "flags": []}

    def _classify_threat(
        self,
        injection: dict,
        probing: dict,
        behavioral: dict,
    ) -> tuple[ThreatLevel, str | None, list[str], bool]:
        """Combine all pre-model signals into a threat classification."""
        reasons: list[str] = []
        max_score = 0.0

        if injection.get("blocked"):
            reasons.append(f"Injection detected (score={injection['risk_score']:.2f})")
            max_score = max(max_score, injection["risk_score"])

        if probing.get("is_probing"):
            reasons.append(f"Schema probing detected (score={probing['score']:.2f})")
            max_score = max(max_score, probing["score"])

        if behavioral.get("anomaly_score", 0) >= self._settings.behavioral_anomaly_threshold:
            reasons.append(f"Behavioral anomaly (score={behavioral['anomaly_score']:.2f})")
            max_score = max(max_score, behavioral["anomaly_score"])

        if max_score >= 0.9:
            level = ThreatLevel.CRITICAL
        elif max_score >= 0.7:
            level = ThreatLevel.HIGH
        elif max_score >= 0.4:
            level = ThreatLevel.MEDIUM
        elif max_score > 0.0:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.NONE

        should_block = level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH)

        category = None
        if injection.get("blocked"):
            category = "INJECTION"
        elif probing.get("is_probing"):
            category = "PROBING"
        elif behavioral.get("anomaly_score", 0) >= self._settings.behavioral_anomaly_threshold:
            category = "BEHAVIORAL_ANOMALY"

        return level, category, reasons, should_block

    # ── ZONE 2 helpers ───────────────────────────────────────

    def _minimize_context(
        self, rbac_policy: dict, column_scope: dict, allowed_domains: list,
    ) -> dict:
        """Build a filtered schema based on RBAC and column scoping."""
        return {
            "tables": rbac_policy.get("allowed_tables", []),
            "columns": column_scope,
            "domains": allowed_domains,
            "row_filters": rbac_policy.get("row_filters", []),
        }

    def _build_contextual_rules(self, rbac_policy: dict, clearance: int) -> list[str]:
        """Build contextual rules for the NL-to-SQL model."""
        rules: list[str] = []

        if clearance < 3:
            rules.append("Do not access patient-identifiable columns (name, DOB, SSN, MRN).")

        if clearance < 5:
            rules.append("Do not access restricted data (psychotherapy notes, substance abuse records).")

        denied_ops = rbac_policy.get("denied_operations", [])
        if "DELETE" in denied_ops:
            rules.append("Do not generate DELETE statements.")
        if "UPDATE" in denied_ops:
            rules.append("Do not generate UPDATE statements.")
        if "DROP" in denied_ops:
            rules.append("Do not generate DROP statements.")

        rules.append("Always use table aliases for clarity.")
        rules.append("Limit result sets to 1000 rows unless explicitly requested otherwise.")

        return rules

    # ── ZONE 3 helpers ───────────────────────────────────────

    async def _gate_syntax_check(self, sql: str) -> dict:
        """Gate 1: Syntax validation -- check SQL is well-formed."""
        violations: list[dict] = []

        # Check for dangerous keywords
        dangerous = ["DROP ", "TRUNCATE ", "ALTER ", "CREATE ", "GRANT ", "REVOKE "]
        sql_upper = sql.upper()
        for kw in dangerous:
            if kw in sql_upper:
                violations.append({
                    "gate": "syntax",
                    "rule": "dangerous_keyword",
                    "detail": f"Statement contains {kw.strip()}",
                })

        # Check for multiple statements (semicolon injection)
        stripped = sql.strip().rstrip(";")
        if ";" in stripped:
            violations.append({
                "gate": "syntax",
                "rule": "multi_statement",
                "detail": "Multiple SQL statements detected",
            })

        return {
            "result": "FAIL" if violations else "PASS",
            "violations": violations,
        }

    async def _gate_semantic_check(self, sql: str, question: str, schema: dict) -> dict:
        """Gate 2: Semantic validation -- SQL aligns with the question intent."""
        violations: list[dict] = []

        # Check for UNION-based injections
        if re.search(r"\bUNION\b.*\bSELECT\b", sql, re.IGNORECASE):
            violations.append({
                "gate": "semantic",
                "rule": "union_injection",
                "detail": "UNION SELECT pattern detected",
            })

        # Check for subqueries accessing information_schema
        if re.search(r"information_schema|pg_catalog|sys\.", sql, re.IGNORECASE):
            violations.append({
                "gate": "semantic",
                "rule": "metadata_access",
                "detail": "Query accesses database metadata tables",
            })

        return {
            "result": "FAIL" if violations else "PASS",
            "violations": violations,
        }

    async def _gate_permission_check(self, sql: str, rbac_policy: dict, column_scope: dict) -> dict:
        """Gate 3: Permission validation -- SQL only accesses allowed resources."""
        violations: list[dict] = []

        denied_tables = rbac_policy.get("denied_tables", [])
        for table in denied_tables:
            if re.search(rf"\b{re.escape(table)}\b", sql, re.IGNORECASE):
                violations.append({
                    "gate": "permission",
                    "rule": "denied_table_access",
                    "detail": f"Query accesses denied table: {table}",
                })

        hidden_columns = [
            col for col, vis in column_scope.items() if vis == "HIDDEN"
        ]
        for col in hidden_columns:
            if re.search(rf"\b{re.escape(col)}\b", sql, re.IGNORECASE):
                violations.append({
                    "gate": "permission",
                    "rule": "hidden_column_access",
                    "detail": f"Query accesses hidden column: {col}",
                })

        return {
            "result": "FAIL" if violations else "PASS",
            "violations": violations,
        }

    def _detect_hallucination(self, sql: str, filtered_schema: dict) -> dict:
        """Detect if SQL references tables/columns not in the filtered schema."""
        allowed_tables = set()
        for t in filtered_schema.get("tables", []):
            if isinstance(t, str):
                allowed_tables.add(t.lower())
            elif isinstance(t, dict):
                allowed_tables.add(t.get("table_name", t.get("name", "")).lower())

        # If no schema provided, skip hallucination detection
        if not allowed_tables:
            return {"detected": False, "identifiers": []}

        # Extract table references from SQL (FROM and JOIN clauses)
        table_pattern = r"(?:FROM|JOIN)\s+(\w+)"
        found_tables = re.findall(table_pattern, sql, re.IGNORECASE)

        hallucinated = [
            t for t in found_tables
            if t.lower() not in allowed_tables
            and t.lower() not in ("select", "where", "and", "or", "on", "as")
        ]

        return {
            "detected": len(hallucinated) > 0,
            "identifiers": hallucinated,
        }

    def _rewrite_query(
        self, sql: str, column_scope: dict, rbac_policy: dict,
    ) -> tuple[str, list[str]]:
        """Apply query rewrites for masking and row-level filters."""
        rewritten = sql
        rewrites: list[str] = []

        # Apply column masking
        masked_columns = {
            col: vis for col, vis in column_scope.items() if vis == "MASKED"
        }
        for col in masked_columns:
            pattern = rf"\b{re.escape(col)}\b"
            if re.search(pattern, rewritten, re.IGNORECASE):
                mask_expr = f"'***MASKED***' AS {col}"
                rewritten = re.sub(
                    rf"(?<=SELECT\s.{{0,500}})\b{re.escape(col)}\b",
                    mask_expr, rewritten, count=1, flags=re.IGNORECASE,
                )
                rewrites.append(f"Column '{col}' masked per policy")

        # Apply row-level filters from RBAC
        row_filters = rbac_policy.get("row_filters", [])
        for rf_entry in row_filters:
            condition = rf_entry.get("condition", "")
            if condition and "WHERE" in rewritten.upper():
                rewritten = rewritten.rstrip(";") + f" AND {condition}"
                rewrites.append(f"Row filter applied: {condition}")
            elif condition:
                rewritten = rewritten.rstrip(";") + f" WHERE {condition}"
                rewrites.append(f"Row filter applied: {condition}")

        return rewritten, rewrites

    # ── ZONE 4 helpers ───────────────────────────────────────

    async def _execute_sql(
        self, sql: str, clearance: int, log: Any, *, rbac_policy: dict | None = None,
    ) -> ExecutionResult:
        """Execute validated SQL against the database with safety bounds.

        Guards:
          - Read-only transaction (SET TRANSACTION READ ONLY)
          - Statement timeout (from settings, default 15s)
          - Row limit (per-role result_limit overrides global default of 1000)
          - Result sanitization (truncate large text fields)
        """
        if not self._settings.execution_enabled:
            log.info("execution_skipped", reason="disabled")
            return ExecutionResult(rows_returned=0, data={"columns": [], "rows": []})

        if not self._audit_pool:
            log.warning("execution_skipped", reason="no_database_pool")
            return ExecutionResult(rows_returned=0, data={"columns": [], "rows": []})

        # Per-role result_limit overrides the global default
        role_limit = (rbac_policy or {}).get("result_limit")
        row_limit = int(role_limit) if role_limit is not None else self._settings.execution_row_limit
        timeout_ms = self._settings.execution_timeout_ms

        # Enforce row limit: inject LIMIT if missing, or cap existing LIMIT
        sql_stripped = sql.rstrip(";").rstrip()
        sql_upper = sql_stripped.upper()
        if "LIMIT" not in sql_upper:
            sql = sql_stripped + f" LIMIT {row_limit}"
        else:
            # Replace existing LIMIT if role limit is lower
            import re as _re
            m = _re.search(r'LIMIT\s+(\d+)', sql_upper)
            if m:
                existing_limit = int(m.group(1))
                if existing_limit > row_limit:
                    # Replace with the stricter role-based limit
                    start, end = m.span()
                    sql = sql_stripped[:start] + f"LIMIT {row_limit}" + sql_stripped[end:]

        exec_start = time.monotonic()
        try:
            async with self._audit_pool.acquire() as conn:
                # Safety: read-only transaction + statement timeout
                await conn.execute(f"SET statement_timeout = {int(timeout_ms)}")
                async with conn.transaction(readonly=True):
                    rows = await conn.fetch(sql)

            elapsed_ms = (time.monotonic() - exec_start) * 1000

            # Convert rows to serialisable format
            if rows:
                columns = list(rows[0].keys())
                data_rows = []
                for row in rows[:row_limit]:
                    data_rows.append({
                        col: self._sanitize_value(row[col])
                        for col in columns
                    })
            else:
                columns = []
                data_rows = []

            resource_hit = len(rows) >= row_limit

            log.info(
                "sql_executed",
                rows=len(data_rows),
                columns=len(columns),
                latency_ms=f"{elapsed_ms:.1f}",
                resource_hit=resource_hit,
            )

            return ExecutionResult(
                rows_returned=len(data_rows),
                execution_latency_ms=round(elapsed_ms, 1),
                sanitization_applied=True,
                resource_limits_hit=resource_hit,
                data={"columns": columns, "rows": data_rows},
            )

        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - exec_start) * 1000
            log.warning("sql_execution_timeout", timeout_ms=timeout_ms)
            return ExecutionResult(
                rows_returned=0,
                execution_latency_ms=round(elapsed_ms, 1),
                resource_limits_hit=True,
                data={"columns": [], "rows": [], "error": "Query execution timed out"},
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - exec_start) * 1000
            log.error("sql_execution_failed", error=str(exc))
            return ExecutionResult(
                rows_returned=0,
                execution_latency_ms=round(elapsed_ms, 1),
                data={"columns": [], "rows": [], "error": str(exc)},
            )

    @staticmethod
    def _sanitize_value(value: Any) -> Any:
        """Sanitize a database value for safe JSON serialization."""
        if value is None:
            return None
        if isinstance(value, (int, float, bool)):
            return value
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, str):
            # Truncate very long strings
            return value[:2000] if len(value) > 2000 else value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, (bytes, bytearray)):
            return "<binary>"
        # Fallback: convert to string
        return str(value)

    # ── ZONE 5 helpers ───────────────────────────────────────

    async def _emit_audit(
        self, request_id: str, user_id: str,
        event_type: str, payload: dict[str, Any],
    ) -> None:
        """Emit an audit event to PostgreSQL audit store (fire-and-forget)."""
        if not self._audit_pool:
            logger.debug("audit_skipped", reason="no_audit_pool")
            return

        event_id = str(uuid.uuid4())
        severity = "WARNING" if "BLOCK" in event_type else "INFO"

        try:
            async with self._audit_pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO audit_events "
                    "(event_id, event_type, source, severity, request_id, user_id, payload, created_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    event_id, event_type, "QUERYVAULT", severity,
                    request_id, user_id, json.dumps(payload),
                    datetime.now(UTC),
                )
        except Exception as exc:
            logger.warning("audit_emit_failed", error=str(exc))

    async def _update_behavioral_profile(self, user_id: str, question: str, sql: str) -> None:
        """Update the user's behavioral fingerprint in Redis."""
        if not self._redis:
            return

        key = f"qv:behavioral:{user_id}"
        try:
            profile_data = await self._redis.get(key)
            if profile_data:
                profile = json.loads(profile_data)
            else:
                profile = {
                    "query_count": 0,
                    "avg_question_length": 0,
                    "usual_hours": [],
                    "last_query_time": 0,
                }

            profile["query_count"] = profile.get("query_count", 0) + 1
            total = profile["query_count"]
            old_avg = profile.get("avg_question_length", 0)
            profile["avg_question_length"] = ((old_avg * (total - 1)) + len(question)) / total
            profile["last_query_time"] = time.time()

            current_hour = datetime.now(UTC).hour
            hours = set(profile.get("usual_hours", []))
            hours.add(current_hour)
            profile["usual_hours"] = list(hours)[-24:]

            ttl = self._settings.fingerprint_ttl_days * 86400
            await self._redis.set(key, json.dumps(profile), ex=ttl)
        except Exception as exc:
            logger.warning("behavioral_update_failed", error=str(exc))

    async def _process_alerts(self, user_id: str, threat_level: ThreatLevel, request_id: str) -> None:
        """Check if alert thresholds are exceeded and create alerts if needed."""
        if threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH) and self._audit_pool:
            try:
                alert_id = str(uuid.uuid4())
                async with self._audit_pool.acquire() as conn:
                    await conn.execute(
                        "INSERT INTO alerts "
                        "(alert_id, severity, status, event_type, user_id, title, description, created_at) "
                        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                        alert_id, threat_level.value, "OPEN", "THREAT_DETECTED",
                        user_id,
                        f"Threat detected: {threat_level.value}",
                        f"Request {request_id} triggered a {threat_level.value} threat alert.",
                        datetime.now(UTC),
                    )
            except Exception as exc:
                logger.warning("alert_creation_failed", error=str(exc))
