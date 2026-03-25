# XenSQL + QueryVault — Two-Product Architecture

> **Version:** 2.0 | **Last Updated:** 2026-03-20

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [XenSQL — NL-to-SQL Pipeline Engine](#3-xensql--nl-to-sql-pipeline-engine)
4. [QueryVault — AI Security Framework](#4-queryvault--ai-security-framework)
5. [Integration Flow](#5-integration-flow)
6. [API Reference](#6-api-reference)
7. [Configuration](#7-configuration)
8. [Deployment](#8-deployment)
9. [Testing](#9-testing)

---

## 1. Overview

Two independent products with clear API boundaries:

| Product | Purpose | Port |
|---------|---------|------|
| **XenSQL** | LLM-agnostic NL-to-SQL pipeline engine | 8900 |
| **QueryVault** | AI security framework wrapping any NL-to-SQL pipeline | 8950 |

**Key principle:** XenSQL generates SQL. QueryVault decides if it's safe. Either product can be upgraded or replaced independently.

### Infrastructure

- **Neo4j** — Schema catalog (XenSQL) + RBAC policies (QueryVault)
- **PostgreSQL + pgvector** — Semantic embeddings for schema retrieval
- **Redis** — Caching, sessions, behavioral profiles

---

## 2. Architecture

```
User → QueryVault (JWT-authenticated)
  → Zone 1 PRE-MODEL:   Identity + RBAC + Schema Filtering
  → Zone 2 MODEL:       XenSQL (filtered_schema + rules + question → SQL)
  → Zone 3 POST-MODEL:  3-Gate SQL Validation + Hallucination Check
  → Zone 4 EXECUTION:   Resource-Bounded Query + Result Sanitization
  → Zone 5 CONTINUOUS:  Audit + Anomaly Detection
  → User (results + security_summary)
```

### Directory Structure

```
ai_security_v2/
├── xensql/                    # Product 1: NL-to-SQL Pipeline Engine
│   ├── app/
│   │   ├── main.py            # FastAPI (port 8900)
│   │   ├── config.py
│   │   ├── api/routes.py
│   │   ├── services/
│   │   │   ├── pipeline_orchestrator.py
│   │   │   ├── question_understanding/   # Intent, terminology, embedding, ambiguity
│   │   │   ├── schema_retrieval/         # 3-strategy fusion, ranking, joins, cache
│   │   │   ├── context_construction/     # Prompt assembly, token budget, LLM provider
│   │   │   ├── sql_generation/           # Generator, parser, dialect, confidence
│   │   │   └── knowledge_graph/          # Schema crawling, Neo4j store
│   │   ├── clients/                      # Embedding, LLM, pgvector clients
│   │   └── models/                       # Pydantic models
│   ├── config/                            # YAML configs
│   └── tests/
│
├── queryvault/                # Product 2: AI Security Framework
│   ├── app/
│   │   ├── main.py            # FastAPI (port 8950)
│   │   ├── config.py
│   │   ├── api/               # Gateway, compliance, threat, alert routes
│   │   ├── services/
│   │   │   ├── gateway_orchestrator.py    # 5-zone security pipeline
│   │   │   ├── identity/                  # JWT validation, role resolution, sessions
│   │   │   ├── aqd/                       # Adaptive Query Defense (200+ patterns)
│   │   │   ├── sag/                       # SQL Accuracy Guard (3 gates)
│   │   │   ├── compliance/                # Audit, 7-framework reports, anomaly
│   │   │   ├── rbac/                      # Policy resolver, domain/column/row scoping
│   │   │   └── execution/                 # Read-only executor, resource governor
│   │   ├── clients/                       # XenSQL client, Neo4j graph client
│   │   └── models/
│   ├── data/                              # Attack patterns, compliance controls
│   └── tests/
│
├── k8s/                       # Kubernetes deployment
├── docker-compose.yaml        # Local dev environment
├── start_all.sh / stop_all.sh
└── PRD-*.docx                 # Product requirement documents
```

---

## 3. XenSQL — NL-to-SQL Pipeline Engine

### 12-Stage Pipeline

1. **Ambiguity Detection** — Identifies vague/ambiguous queries (5 checks)
2. **Terminology Expansion** — 80+ healthcare, 50+ finance abbreviations
3. **Intent Classification** — 8 intent types: DATA_LOOKUP, AGGREGATION, COMPARISON, TREND, JOIN_QUERY, EXISTENCE_CHECK, DEFINITION, EXPLANATION
4. **Question Embedding** — Dense vector with L2 normalization, SHA-256 cache key
5. **Schema Retrieval** — 3 concurrent strategies: semantic vector search, keyword match, FK graph walk
6. **Ranking** — Composite scoring: semantic (0.50), domain affinity (0.20), intent match (0.15), join connectivity (0.10), multi-strategy bonus (0.05)
7. **Context Optimization** — Table reordering, rule dedup, join path hints
8. **Prompt Assembly** — 4 sections: system instructions, contextual rules (never truncated), schema DDL, user question + dialect hints
9. **SQL Generation** — LLM call with exponential backoff (0.5s, 1s, 2s) and model fallback
10. **Response Parsing** — SQL extraction from markdown/bare text, CANNOT_ANSWER detection
11. **Confidence Scoring** — Weighted: retrieval (0.4), intent (0.3), generation (0.3). Levels: HIGH ≥ 0.75, MEDIUM ≥ 0.45, LOW < 0.45
12. **Conversation Management** — Redis-backed multi-turn context

### Supported LLM Providers

- OpenAI (GPT-4, GPT-4o)
- Anthropic (Claude)
- Azure OpenAI
- Ollama (local)
- vLLM / TGI (self-hosted)

### Key Design Decisions

- **No security concerns** — XenSQL does NOT handle auth, RBAC, SQL validation, or query execution. It receives pre-filtered schema and returns raw SQL.
- **No write-operation blocking** — That's QueryVault's job.
- **No sensitivity demotion** — QueryVault handles column visibility.

---

## 4. QueryVault — AI Security Framework

### Three Core Modules

#### Module 1: Adaptive Query Defense (AQD)
- **Injection Scanner** — 200+ patterns across 8 categories with URL-decode + NFKC normalization
- **Schema Probing Detector** — Redis sliding window, 8 probing patterns
- **Behavioral Fingerprint** — 30-day rolling profiles, 4 anomaly indicators
- **SQL Injection Analyzer** — Post-LLM AST analysis, 28 detection rules
- **Threat Classifier** — Weighted: injection (50%), probing (30%), behavioral (20%)
- **Alert Engine** — 5 channels: Dashboard, Slack, PagerDuty, Email, Webhooks

#### Module 2: SQL Accuracy Guard (SAG)
- **Gate 1 — Structural** — Table/column authorization against PermissionEnvelope, subquery depth limit
- **Gate 2 — Classification** — Sensitivity vs clearance, Sensitivity-5 always DENIED
- **Gate 3 — Behavioral** — Write ops, UNION, system tables, dynamic SQL, file ops blocked
- **Query Rewriter** — Row-level WHERE injection, column masking (PARTIAL/YEAR_ONLY/HASH/REDACT), auto LIMIT
- **Hallucination Detector** — 100% catch rate target, table/column reference verification

#### Module 3: Compliance & Audit Engine (CAE)
- **Audit Store** — SQLite append-only, SHA-256 hash chain, immutability triggers
- **Compliance Reporter** — 7 frameworks: HIPAA Privacy/Security, 42 CFR Part 2, SOX, GDPR, EU AI Act, ISO 42001
- **Anomaly Detector** — 6 models: volume Z-score, temporal, validation block spike, sanitization spike, BTG duration, sensitivity escalation
- **Retention Manager** — HIPAA 6yr, SOX 7yr, legal hold export

### RBAC & Zero Trust
- **Role Hierarchy** — 17 roles, BFS DAG traversal, clearance levels 1-5
- **Column Visibility** — VISIBLE / MASKED / HIDDEN / COMPUTED per column
- **Row Filtering** — Mandatory WHERE injection based on SecurityContext
- **Domain Filtering** — Silent denial (no info leakage)
- **Break Glass** — 4-hour emergency access, Sensitivity-5 always blocked, mandatory reason

### Identity
- RS256 JWT validation with JWKS
- HMAC-SHA256 signed SecurityContext and PermissionEnvelope
- Redis session store with TTL (900s default, 14400s BTG)

---

## 5. Integration Flow

```
1. User sends question + JWT → QueryVault
2. QueryVault validates JWT → SecurityContext (HMAC-signed)
3. PolicyResolver generates PermissionEnvelope (deny-by-default)
4. DomainFilter + ColumnScoper + RowFilter → filtered_schema + contextual_rules
5. InjectionScanner + SchemaProbing + BehavioralFingerprint → pre-model threat check
6. QueryVault calls XenSQL API: POST /api/v1/pipeline/query
   { question, filtered_schema, contextual_rules, tenant_id, dialect_hint }
7. XenSQL runs 12-stage pipeline → returns { sql, confidence, explanation }
8. QueryVault runs 3-gate validation (structural + classification + behavioral)
9. QueryVault runs hallucination detection
10. QueryRewriter applies masking + row filters + LIMIT
11. Executor runs SQL (read-only, resource-bounded)
12. ResultSanitizer masks PII in results
13. AuditStore logs immutable audit event
14. AnomalyDetector checks for behavioral anomalies
15. User receives { results, security_summary, audit_id }
```

---

## 6. API Reference

### XenSQL (port 8900)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/pipeline/query` | Generate SQL from natural language |
| POST | `/api/v1/pipeline/embed` | Generate embedding for text |
| GET | `/api/v1/pipeline/health` | Health check |
| POST | `/api/v1/schema/crawl` | Crawl database schema |
| GET | `/api/v1/schema/catalog` | Get schema catalog |

### QueryVault (port 8950)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/gateway/query` | Secure query gateway |
| GET | `/api/v1/gateway/health` | Health check |
| GET | `/api/v1/compliance/report` | Generate compliance report |
| GET | `/api/v1/compliance/standards` | List supported standards |
| GET | `/api/v1/compliance/dashboard` | Violation dashboard |
| GET | `/api/v1/threat/analysis` | Threat analysis |
| GET | `/api/v1/threat/patterns` | Attack pattern library |
| GET | `/api/v1/alerts` | List alerts |
| POST | `/api/v1/alerts/{id}/acknowledge` | Acknowledge alert |
| POST | `/api/v1/alerts/{id}/resolve` | Resolve alert |

---

## 7. Configuration

### XenSQL (`XENSQL_` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `XENSQL_APP_NAME` | xensql | Application name |
| `XENSQL_REDIS_URL` | redis://localhost:6379/0 | Redis connection |
| `XENSQL_NEO4J_URI` | bolt://localhost:7687 | Neo4j connection |
| `XENSQL_PG_DSN` | postgresql://... | PostgreSQL (pgvector) |
| `XENSQL_DEFAULT_DIALECT` | postgresql | SQL dialect |
| `XENSQL_MAX_TABLES` | 15 | Max tables in context |
| `XENSQL_TOKEN_BUDGET` | 6000 | Max tokens for prompt |

### QueryVault (`QV_` prefix)

| Variable | Default | Description |
|----------|---------|-------------|
| `QV_APP_NAME` | queryvault | Application name |
| `QV_REDIS_URL` | redis://localhost:6379/1 | Redis connection |
| `QV_NEO4J_URI` | bolt://localhost:7687 | Neo4j connection |
| `QV_XENSQL_URL` | http://localhost:8900 | XenSQL endpoint |
| `QV_JWT_ISSUER` | apollo-idp | Expected JWT issuer |
| `QV_HMAC_SECRET` | (required) | HMAC signing key |
| `QV_INJECTION_THRESHOLD` | 0.6 | Injection risk threshold |
| `QV_MAX_QUERY_TIMEOUT` | 30 | Query timeout (seconds) |
| `QV_MAX_ROW_LIMIT` | 10000 | Max result rows |

---

## 8. Deployment

### Local Development

```bash
# Start all services
./start_all.sh

# Stop all services
./stop_all.sh

# Or with Docker Compose
docker-compose up -d
```

### Kubernetes

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/neo4j.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/redis.yaml
kubectl apply -f k8s/xensql.yaml
kubectl apply -f k8s/queryvault.yaml
kubectl apply -f k8s/ingress.yaml
```

### Swagger UIs

- XenSQL: http://localhost:8900/docs
- QueryVault: http://localhost:8950/docs

---

## 9. Testing

```bash
# XenSQL tests
cd xensql && python -m pytest tests/ -v

# QueryVault tests
cd queryvault && python -m pytest tests/ -v
```

### Test Coverage

**XenSQL:**
- `test_intent_classifier.py` — 18 tests (8 intents, fallback, confidence, domain hints)
- `test_response_parser.py` — 11 tests (markdown, bare SQL, CTE, CANNOT_ANSWER, refusal)
- `test_confidence.py` — 7 tests (HIGH/MEDIUM/LOW thresholds, flags, bounds)

**QueryVault:**
- `test_injection_scanner.py` — 33 tests (SQL injection, encoding evasion, tautology, severity)
- `test_gates.py` — 15 tests (structural, classification, behavioral gates)
- `test_compliance.py` — 12 tests (audit store, hash chain, compliance reports, anomaly)
- `test_rbac.py` — 15 tests (deny-by-default, priority conflicts, BTG, domain/column/row)
