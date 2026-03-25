"""Tests for XenSQL Intent Classifier."""
import pytest
from xensql.app.services.question_understanding.intent_classifier import IntentClassifier
from xensql.app.models.enums import IntentType, DomainType


@pytest.fixture
def classifier():
    return IntentClassifier()


class TestIntentClassification:
    def test_data_lookup(self, classifier):
        result = classifier.classify("Show me all patients admitted last week")
        assert result.intent == IntentType.DATA_LOOKUP

    def test_aggregation(self, classifier):
        result = classifier.classify("How many patients were admitted this month?")
        assert result.intent == IntentType.AGGREGATION

    def test_comparison(self, classifier):
        result = classifier.classify("Compare revenue between Q1 and Q2")
        assert result.intent == IntentType.COMPARISON

    def test_trend(self, classifier):
        result = classifier.classify("Show admission trends over the last 12 months")
        assert result.intent == IntentType.TREND

    def test_join_query(self, classifier):
        result = classifier.classify("Join patients with their diagnoses and treatments")
        assert result.intent == IntentType.JOIN_QUERY

    def test_existence_check(self, classifier):
        result = classifier.classify("Is there any patient with MRN 12345?")
        assert result.intent == IntentType.EXISTENCE_CHECK

    def test_definition(self, classifier):
        result = classifier.classify("What is the schema of the encounters table?")
        assert result.intent == IntentType.DEFINITION

    def test_explanation(self, classifier):
        result = classifier.classify("Explain why readmission rates increased")
        assert result.intent == IntentType.EXPLANATION

    def test_fallback_to_data_lookup(self, classifier):
        result = classifier.classify("xyz abc 123")
        assert result.intent == IntentType.DATA_LOOKUP
        assert result.confidence == 0.3

    def test_confidence_range(self, classifier):
        result = classifier.classify("Show total count of patients grouped by department")
        assert 0.0 <= result.confidence <= 1.0

    def test_matched_keywords_populated(self, classifier):
        result = classifier.classify("Show me all patients")
        assert len(result.matched_keywords) > 0

    def test_secondary_intents(self, classifier):
        result = classifier.classify("Show total count of patients over time by month")
        assert len(result.secondary_intents) >= 1


class TestDomainHints:
    def test_clinical_domain(self, classifier):
        result = classifier.classify("Show all patient diagnoses")
        assert DomainType.CLINICAL in result.domain_hints

    def test_billing_domain(self, classifier):
        result = classifier.classify("List all billing claims with insurance coverage")
        assert DomainType.BILLING in result.domain_hints

    def test_pharmacy_domain(self, classifier):
        result = classifier.classify("Show medication prescriptions for opioid drugs")
        assert DomainType.PHARMACY in result.domain_hints

    def test_laboratory_domain(self, classifier):
        result = classifier.classify("Get lab test results for blood glucose panel")
        assert DomainType.LABORATORY in result.domain_hints

    def test_hr_domain(self, classifier):
        result = classifier.classify("List employee salary and payroll data")
        assert DomainType.HR in result.domain_hints

    def test_max_three_domains(self, classifier):
        result = classifier.classify("Show patient billing lab employee schedule data")
        assert len(result.domain_hints) <= 3
