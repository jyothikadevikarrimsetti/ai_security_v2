"""Tests for XenSQL Response Parser."""
import pytest
from xensql.app.services.sql_generation.response_parser import parse


class TestSQLExtraction:
    def test_markdown_code_block(self):
        response = "Here is the SQL:\n```sql\nSELECT * FROM patients WHERE status = 'active'\n```"
        result = parse(response)
        assert result.success
        assert "SELECT * FROM patients" in result.sql
        assert result.confidence == 0.9

    def test_bare_select(self):
        response = "SELECT p.name, p.dob FROM patients p WHERE p.mrn = '12345'"
        result = parse(response)
        assert result.success
        assert "SELECT p.name" in result.sql

    def test_with_cte(self):
        response = "```sql\nWITH recent AS (SELECT * FROM encounters WHERE date > '2025-01-01') SELECT * FROM recent\n```"
        result = parse(response)
        assert result.success
        assert result.sql.startswith("WITH recent")

    def test_cannot_answer_prefix(self):
        response = "CANNOT_ANSWER: The requested data is not available"
        result = parse(response)
        assert result.cannot_answer
        assert result.sql is None

    def test_refusal_phrase(self):
        response = "I cannot generate SQL for this request because it requires unauthorized access"
        result = parse(response)
        assert result.cannot_answer
        assert result.sql is None

    def test_empty_response(self):
        result = parse("")
        assert not result.success
        assert result.parse_error == "Empty LLM response"

    def test_no_sql_found(self):
        response = "This is just a text explanation with no SQL query."
        result = parse(response)
        assert result.sql is None
        assert result.parse_error == "No SQL found in LLM response"

    def test_multiple_code_blocks(self):
        response = "```sql\nSELECT * FROM a\n```\n```sql\nSELECT * FROM b\n```"
        result = parse(response)
        assert result.success
        assert result.confidence == 0.7  # Multiple candidates

    def test_explanation_captured(self):
        response = "This query finds active patients:\n```sql\nSELECT * FROM patients\n```"
        result = parse(response)
        assert result.success
        assert "active patients" in result.explanation

    def test_trailing_semicolon_stripped(self):
        response = "```sql\nSELECT * FROM patients;\n```"
        result = parse(response)
        assert result.success
        assert not result.sql.endswith(";")

    def test_non_select_rejected(self):
        response = "```sql\nHello world this is not SQL\n```"
        result = parse(response)
        assert not result.success
