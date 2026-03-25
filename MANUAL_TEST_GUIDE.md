# Manual Test Guide — XenSQL + QueryVault

> **Prerequisites**: All services running via `docker-compose up -d --build`
>
> | Service    | URL                        | Purpose                    |
> |------------|----------------------------|----------------------------|
> | XenSQL     | http://localhost:8900       | NL-to-SQL Pipeline Engine  |
> | QueryVault | http://localhost:8950       | AI Security Framework      |
> | Neo4j      | http://localhost:7474       | Knowledge Graph Browser    |
> | PostgreSQL | localhost:5433              | pgvector Store             |
> | Redis      | localhost:6379              | Cache / Session Store      |

---

## Table of Contents

1. [Infrastructure Health](#1-infrastructure-health)
2. [XenSQL Tests](#2-xensql-tests)
   - 2.1 Pipeline Health
   - 2.2 Pipeline Query
   - 2.3 Pipeline Embed (Single)
   - 2.4 Pipeline Embed (Batch)
   - 2.5 Schema Crawl
   - 2.6 Schema Catalog
3. [QueryVault Tests](#3-queryvault-tests)
   - 3.1 Gateway Health
   - 3.2 Gateway Query (Clean)
   - 3.3 Gateway Query (Injection Attack)
   - 3.4 Gateway Query (Blocked — No Token)
   - 3.5 Compliance Report
   - 3.6 Compliance Standards
   - 3.7 Compliance Dashboard
   - 3.8 Threat Analysis
   - 3.9 Threat Patterns
   - 3.10 Alerts List
   - 3.11 Alert Acknowledge
   - 3.12 Alert Resolve
4. [End-to-End Flow](#4-end-to-end-flow)
5. [Negative / Edge-Case Tests](#5-negative--edge-case-tests)
6. [Dashboard UI Tests](#6-dashboard-ui-tests)

---

## 1. Infrastructure Health

Verify all containers are running before starting tests.

```bash
docker-compose ps
```

**Expected**: All 5 services show `Up` status.

```bash
# Quick health check — all services
curl -s http://localhost:8900/api/v1/pipeline/health | python3 -m json.tool
curl -s http://localhost:8950/api/v1/gateway/health | python3 -m json.tool
```

| Check                 | Expected                                    | Pass/Fail |
|-----------------------|---------------------------------------------|-----------|
| Redis container Up    | STATUS: Up, healthy                         | [ ]       |
| Neo4j container Up    | STATUS: Up                                  | [ ]       |
| PostgreSQL container  | STATUS: Up, port 5433 mapped                | [ ]       |
| XenSQL container Up   | STATUS: Up, port 8900 mapped                | [ ]       |
| QueryVault container  | STATUS: Up, port 8950 mapped                | [ ]       |
| XenSQL health API     | `{"status": "ok"}` or `"degraded"`          | [ ]       |
| QueryVault health API | `{"status": "ok"}` or `"degraded"`          | [ ]       |

---

## 2. XenSQL Tests

### 2.1 Pipeline Health

```bash
curl -s http://localhost:8900/api/v1/pipeline/health | python3 -m json.tool
```

**Expected Response:**
```json
{
    "status": "ok",
    "service": "xensql",
    "version": "1.0.0",
    "dependencies": {
        "redis": true,
        "neo4j": true,
        "pgvector": true
    }
}
```

| Check                          | Expected           | Pass/Fail |
|--------------------------------|---------------------|-----------|
| HTTP status                    | 200                 | [ ]       |
| `status` field                 | `"ok"` or `"degraded"` | [ ]   |
| `service` field                | `"xensql"`          | [ ]       |
| `dependencies.redis`           | `true`              | [ ]       |
| `dependencies.neo4j`           | `true`              | [ ]       |
| `dependencies.pgvector`        | `true`              | [ ]       |

---

### 2.2 Pipeline Query — Basic NL-to-SQL

```bash
curl -s -X POST http://localhost:8900/api/v1/pipeline/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me all active users who signed up this month",
    "filtered_schema": {
      "tables": [
        {
          "name": "users",
          "columns": [
            {"name": "id", "type": "INTEGER", "primary_key": true},
            {"name": "username", "type": "VARCHAR(255)"},
            {"name": "email", "type": "VARCHAR(255)"},
            {"name": "status", "type": "VARCHAR(50)"},
            {"name": "created_at", "type": "TIMESTAMP"}
          ]
        }
      ]
    },
    "dialect_hint": "PostgreSQL",
    "max_tables": 10
  }' | python3 -m json.tool
```

**Expected Response:**
```json
{
    "request_id": "<uuid>",
    "status": "GENERATED",
    "sql": "SELECT * FROM users WHERE status = 'active' AND ...",
    "confidence": {
        "level": "HIGH",
        "score": 0.85,
        "breakdown": {
            "retrieval_score": 0.9,
            "intent_score": 0.85,
            "generation_score": 0.8
        },
        "flags": []
    },
    "explanation": "...",
    "metadata": {
        "generation_latency_ms": 150.0,
        "total_latency_ms": 200.0,
        "tables_used": 1,
        "intent": "data_retrieval",
        "dialect": "PostgreSQL",
        "llm_model": "...",
        "llm_provider": "..."
    }
}
```

| Check                          | Expected                       | Pass/Fail |
|--------------------------------|--------------------------------|-----------|
| HTTP status                    | 200                            | [ ]       |
| `status`                       | `"GENERATED"` or `"ERROR"`     | [ ]       |
| `sql` field present            | Non-null string with SQL       | [ ]       |
| `confidence.level`             | `"LOW"`, `"MEDIUM"`, or `"HIGH"` | [ ]    |
| `confidence.score`             | Float between 0.0 and 1.0      | [ ]       |
| `confidence.breakdown` present | Three sub-scores               | [ ]       |
| `metadata.dialect`             | `"PostgreSQL"`                 | [ ]       |
| `metadata.tables_used`         | >= 1                           | [ ]       |
| `request_id`                   | Non-empty UUID string          | [ ]       |

---

### 2.3 Pipeline Embed — Single Text

```bash
curl -s -X POST http://localhost:8900/api/v1/pipeline/embed \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Find all orders with total amount greater than 1000",
    "batch": false
  }' | python3 -m json.tool
```

| Check                       | Expected                        | Pass/Fail |
|-----------------------------|---------------------------------|-----------|
| HTTP status                 | 200                             | [ ]       |
| `embedding` field           | Array of floats                 | [ ]       |
| `dimensions` field          | Positive integer (e.g., 384+)   | [ ]       |
| Embedding length            | Matches `dimensions` value      | [ ]       |

---

### 2.4 Pipeline Embed — Batch Mode

```bash
curl -s -X POST http://localhost:8900/api/v1/pipeline/embed \
  -H "Content-Type: application/json" \
  -d '{
    "texts": [
      "total revenue by region",
      "customer count per segment",
      "monthly active users trend"
    ],
    "batch": true
  }' | python3 -m json.tool
```

| Check                       | Expected                        | Pass/Fail |
|-----------------------------|---------------------------------|-----------|
| HTTP status                 | 200                             | [ ]       |
| `embeddings` field          | Array of 3 embedding arrays     | [ ]       |
| `count` field               | `3`                             | [ ]       |
| Each embedding length       | Equal dimensions                | [ ]       |

---

### 2.5 Schema Crawl — Index Elements

```bash
curl -s -X POST http://localhost:8900/api/v1/schema/crawl \
  -H "Content-Type: application/json" \
  -d '{
    "elements": [
      {
        "id": "public.orders",
        "text": "Orders table containing customer purchase records with order_id, customer_id, total_amount, status, and created_at columns",
        "metadata": {"database": "ecommerce", "schema": "public", "type": "table"}
      },
      {
        "id": "public.customers",
        "text": "Customers table with customer_id, name, email, segment, and region columns",
        "metadata": {"database": "ecommerce", "schema": "public", "type": "table"}
      },
      {
        "id": "public.products",
        "text": "Products table with product_id, name, category, price, and stock_quantity",
        "metadata": {"database": "ecommerce", "schema": "public", "type": "table"}
      }
    ]
  }' | python3 -m json.tool
```

| Check                       | Expected                        | Pass/Fail |
|-----------------------------|---------------------------------|-----------|
| HTTP status                 | 200                             | [ ]       |
| `status`                    | `"ok"`                          | [ ]       |
| `elements_processed`        | `3`                             | [ ]       |
| `elapsed_ms`                | Positive number                 | [ ]       |

---

### 2.6 Schema Catalog — Retrieve Indexed Schema

```bash
# Without filter
curl -s "http://localhost:8900/api/v1/schema/catalog" | python3 -m json.tool

# With database filter
curl -s "http://localhost:8900/api/v1/schema/catalog?database=ecommerce" | python3 -m json.tool
```

| Check                       | Expected                        | Pass/Fail |
|-----------------------------|---------------------------------|-----------|
| HTTP status                 | 200                             | [ ]       |
| `catalog` field present     | Dict with schema summary        | [ ]       |
| Filtered result             | Only ecommerce entries          | [ ]       |

---

## 3. QueryVault Tests

### 3.1 Gateway Health

```bash
curl -s http://localhost:8950/api/v1/gateway/health | python3 -m json.tool
```

**Expected Response:**
```json
{
    "status": "ok",
    "service": "queryvault",
    "version": "1.0.0",
    "components": {
        "redis": "healthy",
        "neo4j": "healthy",
        "audit_store": "healthy",
        "xensql": "healthy",
        "circuit_breaker_xensql": "CLOSED",
        "circuit_breaker_neo4j": "CLOSED",
        "circuit_breaker_redis": "CLOSED",
        "circuit_breaker_audit_store": "CLOSED"
    }
}
```

| Check                          | Expected                  | Pass/Fail |
|--------------------------------|---------------------------|-----------|
| HTTP status                    | 200                       | [ ]       |
| `status`                       | `"ok"` or `"degraded"`    | [ ]       |
| `service`                      | `"queryvault"`            | [ ]       |
| `components.xensql`            | `"healthy"`               | [ ]       |
| Circuit breakers               | All `"CLOSED"`            | [ ]       |

---

### 3.2 Gateway Query — Clean Request

```bash
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me total revenue by region for last quarter",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsIm5hbWUiOiJKb2huIERvZSIsInJvbGUiOiJhbmFseXN0IiwidGVuYW50X2lkIjoiYWNtZS1jb3JwIiwiYXVkIjoiYXBpOi8vcXVlcnl2YXVsdCIsImlzcyI6Imh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS90ZW5hbnQvdjIuMCIsImV4cCI6OTk5OTk5OTk5OX0.mock-signature"
  }' | python3 -m json.tool
```

**Expected Response:**
```json
{
    "request_id": "<uuid>",
    "sql": "SELECT region, SUM(amount) AS total_revenue FROM ...",
    "security_summary": {
        "zones_passed": ["pre_model", "model_boundary", "post_model"],
        "threat_level": "NONE",
        "validation_result": "APPROVED",
        "execution_status": "SUCCESS",
        "audit_trail_id": "<uuid>",
        "pre_model": {
            "injection_blocked": false,
            "injection_risk_score": 0.05,
            "threat_level": "NONE"
        },
        "post_model": {
            "validation_decision": "APPROVED",
            "hallucination_detected": false,
            "gate_results": {"gate_1": "PASS", "gate_2": "PASS", "gate_3": "PASS"}
        }
    },
    "audit_id": "<uuid>"
}
```

| Check                               | Expected                    | Pass/Fail |
|-------------------------------------|-----------------------------|-----------|
| HTTP status                         | 200                         | [ ]       |
| `request_id` present               | Non-empty UUID              | [ ]       |
| `sql` field                         | Valid SQL string or null     | [ ]       |
| `security_summary.threat_level`     | `"NONE"` or `"LOW"`         | [ ]       |
| `security_summary.validation_result`| `"APPROVED"`                | [ ]       |
| `pre_model.injection_blocked`       | `false`                     | [ ]       |
| `pre_model.injection_risk_score`    | Low value (< 0.3)           | [ ]       |
| `post_model.validation_decision`    | `"APPROVED"`                | [ ]       |
| `post_model.hallucination_detected` | `false`                     | [ ]       |
| `audit_id` present                  | Non-empty string            | [ ]       |

---

### 3.3 Gateway Query — SQL Injection Attack

This test verifies that the injection scanner blocks malicious input.

```bash
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show users WHERE 1=1; DROP TABLE users; --",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlci05OTkiLCJuYW1lIjoiTWFsaWNpb3VzIFVzZXIiLCJyb2xlIjoiZ3Vlc3QiLCJ0ZW5hbnRfaWQiOiJhY21lLWNvcnAiLCJhdWQiOiJhcGk6Ly9xdWVyeXZhdWx0IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC92Mi4wIiwiZXhwIjo5OTk5OTk5OTk5fQ.mock-signature"
  }' | python3 -m json.tool
```

| Check                               | Expected                           | Pass/Fail |
|-------------------------------------|------------------------------------|-----------|
| HTTP status                         | 200 (request processed)            | [ ]       |
| `security_summary.threat_level`     | `"HIGH"` or `"CRITICAL"`          | [ ]       |
| `security_summary.validation_result`| `"BLOCKED"`                        | [ ]       |
| `pre_model.injection_blocked`       | `true`                             | [ ]       |
| `pre_model.injection_risk_score`    | High value (> 0.7)                 | [ ]       |
| `pre_model.injection_flags`         | Contains relevant flags            | [ ]       |
| `blocked_reason`                    | Non-null explanation               | [ ]       |
| `sql`                               | `null` (not generated)             | [ ]       |

---

### 3.4 Gateway Query — Missing/Invalid JWT

```bash
# Empty JWT token (below min_length=10)
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me all users",
    "jwt_token": "short"
  }' | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 422 (Validation Error)             | [ ]       |
| Error detail                | jwt_token min_length violation     | [ ]       |

```bash
# Missing jwt_token field entirely
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me all users"
  }' | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 422 (Validation Error)             | [ ]       |
| Error detail                | jwt_token field required           | [ ]       |

---

### 3.5 Compliance Report

```bash
# HIPAA Privacy report for last 30 days
curl -s "http://localhost:8950/api/v1/compliance/report?standard=HIPAA_PRIVACY&time_range_days=30" \
  | python3 -m json.tool
```

**Expected Response:**
```json
{
    "success": true,
    "report": {
        "standard": "HIPAA_PRIVACY",
        "generated_at": "2026-03-21T...",
        "time_range_days": 30,
        "summary": {
            "total_queries_processed": 0,
            "queries_blocked": 0,
            "block_rate": 0.0,
            "violation_count": 0
        },
        "controls": [
            {"control_id": "...", "name": "...", "zone": "PRE_MODEL", "status": "enforced"}
        ],
        "recent_violations": []
    }
}
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `success`                   | `true`                             | [ ]       |
| `report.standard`           | `"HIPAA_PRIVACY"`                  | [ ]       |
| `report.time_range_days`    | `30`                               | [ ]       |
| `report.summary` present    | Contains 4 metric fields           | [ ]       |
| `report.controls`           | Non-empty array                    | [ ]       |

**Test all 7 standards:**

```bash
for std in HIPAA_PRIVACY HIPAA_SECURITY CFR42_PART2 SOX GDPR EU_AI_ACT ISO_42001; do
  echo "=== $std ==="
  curl -s "http://localhost:8950/api/v1/compliance/report?standard=$std&time_range_days=7" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  success={d[\"success\"]}  controls={len(d.get(\"report\",{}).get(\"controls\",[]))}')"
done
```

| Standard       | Expected                 | Pass/Fail |
|----------------|--------------------------|-----------|
| HIPAA_PRIVACY  | success=True, controls>0 | [ ]       |
| HIPAA_SECURITY | success=True, controls>0 | [ ]       |
| CFR42_PART2    | success=True, controls>0 | [ ]       |
| SOX            | success=True, controls>0 | [ ]       |
| GDPR           | success=True, controls>0 | [ ]       |
| EU_AI_ACT      | success=True, controls>0 | [ ]       |
| ISO_42001      | success=True, controls>0 | [ ]       |

---

### 3.6 Compliance Standards — List All

```bash
curl -s http://localhost:8950/api/v1/compliance/standards | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `standards` array           | 7 standard objects                 | [ ]       |
| Each standard has `id`      | Valid standard identifier          | [ ]       |
| Each standard has `name`    | Human-readable name                | [ ]       |
| Each has `description`      | Non-empty description              | [ ]       |

---

### 3.7 Compliance Dashboard

```bash
curl -s "http://localhost:8950/api/v1/compliance/dashboard?time_range_days=7" | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `time_range_days`           | `7`                                | [ ]       |
| `total_violations`          | Integer >= 0                       | [ ]       |
| `by_type`                   | Dict with string keys, int values  | [ ]       |
| `by_severity`               | Dict with severity levels          | [ ]       |
| `generated_at`              | Valid ISO timestamp                | [ ]       |

---

### 3.8 Threat Analysis

```bash
# General threat analysis (last 7 days)
curl -s "http://localhost:8950/api/v1/threat/analysis?time_range_days=7" | python3 -m json.tool

# Filtered by user_id
curl -s "http://localhost:8950/api/v1/threat/analysis?user_id=user-123&time_range_days=30" \
  | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `time_range_days`           | Matches query param                | [ ]       |
| `total_threats`             | Integer >= 0                       | [ ]       |
| `by_category`               | Dict with category keys            | [ ]       |
| `by_severity`               | Dict with severity keys            | [ ]       |
| `top_users`                 | Dict (may be empty)               | [ ]       |
| `recent_events`             | Array (up to 50)                   | [ ]       |
| `generated_at`              | Valid ISO timestamp                | [ ]       |
| User filter works           | `user_id` matches in response      | [ ]       |

---

### 3.9 Threat Patterns — Attack Pattern Library

```bash
curl -s http://localhost:8950/api/v1/threat/patterns | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `total_patterns`            | Positive integer                   | [ ]       |
| `enabled`                   | Integer >= 0                       | [ ]       |
| `disabled`                  | Integer >= 0                       | [ ]       |
| `enabled + disabled`        | Equals `total_patterns`            | [ ]       |
| `by_category`               | Dict with category counts          | [ ]       |
| `by_severity`               | Dict with CRITICAL/HIGH/MEDIUM/LOW | [ ]       |

---

### 3.10 Alerts — List with Filters

```bash
# Default list (last 7 days, limit 50)
curl -s "http://localhost:8950/api/v1/alerts" | python3 -m json.tool

# Filtered by severity
curl -s "http://localhost:8950/api/v1/alerts?severity=CRITICAL&limit=10" | python3 -m json.tool

# Filtered by status
curl -s "http://localhost:8950/api/v1/alerts?status=OPEN&time_range_days=30" | python3 -m json.tool

# Filtered by user_id
curl -s "http://localhost:8950/api/v1/alerts?user_id=user-123" | python3 -m json.tool

# Pagination
curl -s "http://localhost:8950/api/v1/alerts?limit=5&offset=0" | python3 -m json.tool
curl -s "http://localhost:8950/api/v1/alerts?limit=5&offset=5" | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `alerts` field              | Array of alert objects             | [ ]       |
| `total` field               | Integer >= 0                       | [ ]       |
| `limit` field               | Matches query param                | [ ]       |
| `offset` field              | Matches query param                | [ ]       |
| Each alert has `alert_id`   | Non-empty string                   | [ ]       |
| Each alert has `severity`   | CRITICAL/HIGH/MEDIUM/LOW           | [ ]       |
| Each alert has `status`     | OPEN/ACKNOWLEDGED/RESOLVED         | [ ]       |
| Each alert has `title`      | Non-empty string                   | [ ]       |
| Severity filter works       | Only matching severity returned    | [ ]       |
| Status filter works         | Only matching status returned      | [ ]       |
| Pagination offset works     | Different results per page         | [ ]       |

---

### 3.11 Alert Acknowledge

```bash
# First, get an alert ID from the list
ALERT_ID=$(curl -s "http://localhost:8950/api/v1/alerts?status=OPEN&limit=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['alerts'][0]['alert_id'] if d['alerts'] else 'none')")

echo "Acknowledging alert: $ALERT_ID"

# Acknowledge it
curl -s -X POST "http://localhost:8950/api/v1/alerts/${ALERT_ID}/acknowledge" | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `status`                    | `"acknowledged"`                   | [ ]       |
| `alert_id`                  | Matches requested ID               | [ ]       |
| `acknowledged_at`           | Valid ISO timestamp                | [ ]       |

**Not-found case:**

```bash
curl -s -X POST "http://localhost:8950/api/v1/alerts/nonexistent-id-000/acknowledge" \
  | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| `status`                    | `"not_found"`                      | [ ]       |
| `message`                   | Descriptive message                | [ ]       |

---

### 3.12 Alert Resolve

```bash
# Get an acknowledged alert
ALERT_ID=$(curl -s "http://localhost:8950/api/v1/alerts?status=ACKNOWLEDGED&limit=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['alerts'][0]['alert_id'] if d['alerts'] else 'none')")

echo "Resolving alert: $ALERT_ID"

# Resolve it
curl -s -X POST "http://localhost:8950/api/v1/alerts/${ALERT_ID}/resolve" | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| HTTP status                 | 200                                | [ ]       |
| `status`                    | `"resolved"`                       | [ ]       |
| `alert_id`                  | Matches requested ID               | [ ]       |
| `resolved_at`               | Valid ISO timestamp                | [ ]       |

---

## 4. End-to-End Flow

This tests the complete flow: QueryVault receives a request, runs security checks, calls XenSQL for SQL generation, validates the output, and returns results.

### 4.1 Full Pipeline — Clean Query

```bash
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What are the top 10 customers by total order value?",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyIsIm5hbWUiOiJKb2huIERvZSIsInJvbGUiOiJhbmFseXN0IiwidGVuYW50X2lkIjoiYWNtZS1jb3JwIiwiYXVkIjoiYXBpOi8vcXVlcnl2YXVsdCIsImlzcyI6Imh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS90ZW5hbnQvdjIuMCIsImV4cCI6OTk5OTk5OTk5OX0.mock-signature"
  }' | python3 -m json.tool
```

**Verify the full chain:**

| Step                              | Expected                             | Pass/Fail |
|-----------------------------------|--------------------------------------|-----------|
| 1. JWT decoded                    | User identity extracted              | [ ]       |
| 2. Pre-model injection scan      | `injection_blocked: false`           | [ ]       |
| 3. Pre-model behavioral check    | Low anomaly score                    | [ ]       |
| 4. XenSQL SQL generation         | `sql` field populated                | [ ]       |
| 5. Post-model Gate 1 (structural)| `PASS`                               | [ ]       |
| 6. Post-model Gate 2 (classify)  | `PASS`                               | [ ]       |
| 7. Post-model Gate 3 (behavioral)| `PASS`                               | [ ]       |
| 8. Hallucination check           | `false`                              | [ ]       |
| 9. Audit trail created           | `audit_id` populated                 | [ ]       |
| 10. Overall result               | `validation_result: "APPROVED"`      | [ ]       |

### 4.2 Full Pipeline — Attack Blocked

```bash
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "UNION SELECT username, password FROM admin_users--",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlci05OTkiLCJuYW1lIjoiTWFsaWNpb3VzIFVzZXIiLCJyb2xlIjoiZ3Vlc3QiLCJ0ZW5hbnRfaWQiOiJhY21lLWNvcnAiLCJhdWQiOiJhcGk6Ly9xdWVyeXZhdWx0IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC92Mi4wIiwiZXhwIjo5OTk5OTk5OTk5fQ.mock-signature"
  }' | python3 -m json.tool
```

| Step                              | Expected                             | Pass/Fail |
|-----------------------------------|--------------------------------------|-----------|
| Pre-model blocks request          | `injection_blocked: true`            | [ ]       |
| Threat level                      | `"HIGH"` or `"CRITICAL"`            | [ ]       |
| SQL not generated                 | `sql: null`                          | [ ]       |
| Alert generated                   | Check `/alerts` after                | [ ]       |
| Audit trail created               | `audit_id` populated                 | [ ]       |

### 4.3 Verify Alert Was Generated

After running attack test 4.2, verify an alert was created:

```bash
curl -s "http://localhost:8950/api/v1/alerts?severity=HIGH&time_range_days=1&limit=5" \
  | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| Alert exists for attacker   | `user_id` matches attacker token   | [ ]       |
| Alert severity              | `"HIGH"` or `"CRITICAL"`          | [ ]       |
| Alert status                | `"OPEN"`                           | [ ]       |

---

## 5. Negative / Edge-Case Tests

### 5.1 XenSQL — Empty Question

```bash
curl -s -X POST http://localhost:8900/api/v1/pipeline/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "",
    "filtered_schema": {"tables": []}
  }' | python3 -m json.tool
```

| Check        | Expected                                | Pass/Fail |
|--------------|-----------------------------------------|-----------|
| HTTP status  | 422 (Validation Error)                  | [ ]       |
| Error detail | `question` min_length=3 violation       | [ ]       |

### 5.2 XenSQL — Question Too Long (>2000 chars)

```bash
LONG_Q=$(python3 -c "print('A' * 2001)")
curl -s -X POST http://localhost:8900/api/v1/pipeline/query \
  -H "Content-Type: application/json" \
  -d "{
    \"question\": \"$LONG_Q\",
    \"filtered_schema\": {\"tables\": []}
  }" | python3 -m json.tool
```

| Check        | Expected                                | Pass/Fail |
|--------------|-----------------------------------------|-----------|
| HTTP status  | 422 (Validation Error)                  | [ ]       |
| Error detail | `question` max_length=2000 violation    | [ ]       |

### 5.3 XenSQL — Missing Required Field

```bash
curl -s -X POST http://localhost:8900/api/v1/pipeline/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me users"
  }' | python3 -m json.tool
```

| Check        | Expected                                | Pass/Fail |
|--------------|-----------------------------------------|-----------|
| HTTP status  | 422 (Validation Error)                  | [ ]       |
| Error detail | `filtered_schema` field required        | [ ]       |

### 5.4 XenSQL — Invalid max_tables

```bash
curl -s -X POST http://localhost:8900/api/v1/pipeline/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me users",
    "filtered_schema": {"tables": []},
    "max_tables": 100
  }' | python3 -m json.tool
```

| Check        | Expected                                | Pass/Fail |
|--------------|-----------------------------------------|-----------|
| HTTP status  | 422 (Validation Error)                  | [ ]       |
| Error detail | `max_tables` must be <= 25              | [ ]       |

### 5.5 QueryVault — Encoding Evasion Attack

```bash
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show users %55NION %53ELECT * FROM passwords",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlci05OTkiLCJuYW1lIjoiRXZhc2lvbiBVc2VyIiwicm9sZSI6Imd1ZXN0IiwidGVuYW50X2lkIjoiYWNtZS1jb3JwIiwiYXVkIjoiYXBpOi8vcXVlcnl2YXVsdCIsImlzcyI6Imh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS90ZW5hbnQvdjIuMCIsImV4cCI6OTk5OTk5OTk5OX0.mock-signature"
  }' | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| `injection_blocked`         | `true`                             | [ ]       |
| Injection flags             | Contains encoding-related flag     | [ ]       |

### 5.6 QueryVault — Tautology Attack

```bash
curl -s -X POST http://localhost:8950/api/v1/gateway/query \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show all records where 1=1 OR true",
    "jwt_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlci05OTkiLCJuYW1lIjoiVGF1dG9sb2d5IFVzZXIiLCJyb2xlIjoiZ3Vlc3QiLCJ0ZW5hbnRfaWQiOiJhY21lLWNvcnAiLCJhdWQiOiJhcGk6Ly9xdWVyeXZhdWx0IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi5taWNyb3NvZnRvbmxpbmUuY29tL3RlbmFudC92Mi4wIiwiZXhwIjo5OTk5OTk5OTk5fQ.mock-signature"
  }' | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| `injection_blocked`         | `true`                             | [ ]       |
| `threat_level`              | `"MEDIUM"` or higher               | [ ]       |

### 5.7 Invalid Endpoint

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8900/api/v1/nonexistent
curl -s -o /dev/null -w "%{http_code}" http://localhost:8950/api/v1/nonexistent
```

| Check                       | Expected          | Pass/Fail |
|-----------------------------|-------------------|-----------|
| XenSQL unknown route        | 404               | [ ]       |
| QueryVault unknown route    | 404               | [ ]       |

### 5.8 Wrong HTTP Method

```bash
curl -s -o /dev/null -w "%{http_code}" -X GET http://localhost:8900/api/v1/pipeline/query
curl -s -o /dev/null -w "%{http_code}" -X GET http://localhost:8950/api/v1/gateway/query
```

| Check                       | Expected          | Pass/Fail |
|-----------------------------|-------------------|-----------|
| GET on POST-only endpoint   | 405               | [ ]       |

### 5.9 Compliance Report — Invalid Time Range

```bash
curl -s "http://localhost:8950/api/v1/compliance/report?time_range_days=0" | python3 -m json.tool
curl -s "http://localhost:8950/api/v1/compliance/report?time_range_days=999" | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| time_range_days=0           | 422 (must be >= 1)                 | [ ]       |
| time_range_days=999         | 422 (must be <= 365)               | [ ]       |

### 5.10 Alerts — Invalid Pagination

```bash
curl -s "http://localhost:8950/api/v1/alerts?limit=0" | python3 -m json.tool
curl -s "http://localhost:8950/api/v1/alerts?limit=1000" | python3 -m json.tool
curl -s "http://localhost:8950/api/v1/alerts?offset=-1" | python3 -m json.tool
```

| Check                       | Expected                           | Pass/Fail |
|-----------------------------|------------------------------------|-----------|
| limit=0                     | 422 (must be >= 1)                 | [ ]       |
| limit=1000                  | 422 (must be <= 500)               | [ ]       |
| offset=-1                   | 422 (must be >= 0)                 | [ ]       |

---

## 6. Dashboard UI Tests

Start the dashboard: `cd dashboard && npm run dev`

Open http://localhost:5173 in a browser.

### 6.1 Layout & Navigation

| Check                              | Expected                           | Pass/Fail |
|------------------------------------|------------------------------------|-----------|
| Page loads without errors          | No console errors                  | [ ]       |
| Sidebar visible                    | XenSQL + QueryVault sections       | [ ]       |
| TopBar visible                     | Title, health dots, theme toggle   | [ ]       |
| Health indicators                  | Green/red dots for both services   | [ ]       |
| Dark mode toggle                   | Switches theme, persists on reload | [ ]       |
| Sidebar navigation                 | Clicking items switches panels     | [ ]       |
| Method badges                      | GET=green, POST=blue               | [ ]       |

### 6.2 XenSQL Panels

| Panel                  | Test Action                                    | Expected                    | Pass/Fail |
|------------------------|------------------------------------------------|-----------------------------|-----------|
| Pipeline Query         | Fill form, submit                              | SQL + confidence displayed  | [ ]       |
| Pipeline Query         | Empty question, submit                         | Validation error shown      | [ ]       |
| Pipeline Embed         | Enter text, submit (single mode)               | Embedding array displayed   | [ ]       |
| Pipeline Embed         | Enter texts, submit (batch mode)               | Multiple embeddings shown   | [ ]       |
| Schema Crawl           | Enter elements JSON, submit                    | Elements processed count    | [ ]       |
| Schema Catalog         | Click submit (no filter)                       | Catalog JSON displayed      | [ ]       |
| Health                 | Auto-loads on panel open                       | Service status + deps shown | [ ]       |

### 6.3 QueryVault Panels

| Panel                  | Test Action                                    | Expected                    | Pass/Fail |
|------------------------|------------------------------------------------|-----------------------------|-----------|
| Gateway Query          | Fill question + JWT, submit                    | Security summary displayed  | [ ]       |
| Gateway Query          | Submit injection attack                        | Blocked with threat info    | [ ]       |
| Health                 | Auto-loads on panel open                       | Component status grid       | [ ]       |
| Compliance Report      | Select standard + days, submit                 | Report with controls        | [ ]       |
| Compliance Standards   | Auto-loads on panel open                       | 7 standards listed          | [ ]       |
| Compliance Dashboard   | Select time range, submit                      | Violation breakdown         | [ ]       |
| Threat Analysis        | Submit with default params                     | Threat breakdown shown      | [ ]       |
| Threat Patterns        | Auto-loads on panel open                       | Pattern library stats       | [ ]       |
| Alerts                 | Load list, apply severity filter               | Filtered alerts table       | [ ]       |
| Alerts                 | Click Acknowledge on open alert                | Status changes              | [ ]       |
| Alerts                 | Click Resolve on acknowledged alert            | Status changes              | [ ]       |

### 6.4 Response Display

| Check                              | Expected                           | Pass/Fail |
|------------------------------------|------------------------------------|-----------|
| JSON viewer renders                | Formatted JSON with indentation    | [ ]       |
| Copy button works                  | JSON copied to clipboard           | [ ]       |
| Latency displayed                  | Shows ms after each request        | [ ]       |
| Error states shown                 | Red text/badge for errors          | [ ]       |
| Loading spinner                    | Visible during API calls           | [ ]       |
| Status badges colored              | Green=pass, Red=fail, Yellow=warn  | [ ]       |

---

## Test Summary

| Category                | Total Tests | Passed | Failed | Notes |
|-------------------------|-------------|--------|--------|-------|
| Infrastructure          | 7           |        |        |       |
| XenSQL API              | 22          |        |        |       |
| QueryVault API          | 42          |        |        |       |
| End-to-End Flow         | 18          |        |        |       |
| Negative / Edge Cases   | 16          |        |        |       |
| Dashboard UI            | 25          |        |        |       |
| **Total**               | **130**     |        |        |       |

---

## Environment Notes

- **Docker Compose**: `docker-compose up -d --build`
- **Dashboard Dev**: `cd dashboard && npm run dev` (port 5173)
- **Mock Mode**: QueryVault runs in mock mode by default (`QV_MOCK_MODE=true`), so external connections are simulated
- **Neo4j Browser**: http://localhost:7474 (credentials: neo4j/changeme)
- **PostgreSQL**: `psql -h localhost -p 5433 -U xensql -d xensql` (password: changeme)
