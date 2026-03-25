"""Mock Users API routes -- Role-based testing support.

GET  /api/v1/mock-users              -- List all test users with RBAC metadata
POST /api/v1/mock-users/{oid}/token  -- Generate a valid JWT for a test user
"""

from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from queryvault.app.services.identity.context_builder import (
    MOCK_USER_DIRECTORY,
)
from queryvault.app.services.identity.role_resolver import (
    ROLE_CLEARANCE,
    ROLE_DOMAIN,
    ROLE_POLICIES,
)
from queryvault.app.services.identity.token_validator import MockKeyPair
from queryvault.app.models.enums import ClearanceLevel, Domain

router = APIRouter(tags=["mock-users"])


# ─────────────────────────────────────────────────────────
# MOCK USER PROFILES  (AD roles + display metadata)
# ─────────────────────────────────────────────────────────

MOCK_USER_PROFILES: dict[str, dict] = {
    "oid-dr-patel-4521": {
        "display_name": "Dr. Arun Patel",
        "category": "Physician",
        "ad_roles": ["ATTENDING_PHYSICIAN"],
        "groups": ["GRP-CARDIOLOGY", "GRP-FAC-001"],
        "email": "arun.patel@apollo.example.com",
    },
    "oid-dr-sharma-1102": {
        "display_name": "Dr. Meera Sharma",
        "category": "Physician",
        "ad_roles": ["CONSULTING_PHYSICIAN"],
        "groups": ["GRP-ONCOLOGY", "GRP-FAC-002"],
        "email": "meera.sharma@apollo.example.com",
    },
    "oid-dr-reddy-2233": {
        "display_name": "Dr. Vikram Reddy",
        "category": "Physician",
        "ad_roles": ["EMERGENCY_PHYSICIAN"],
        "groups": ["GRP-EMERGENCY", "GRP-FAC-003"],
        "email": "vikram.reddy@apollo.example.com",
    },
    "oid-dr-iyer-3301": {
        "display_name": "Dr. Lakshmi Iyer",
        "category": "Physician",
        "ad_roles": ["PSYCHIATRIST"],
        "groups": ["GRP-PSYCHIATRY", "GRP-FAC-001"],
        "email": "lakshmi.iyer@apollo.example.com",
    },
    "oid-nurse-kumar-2847": {
        "display_name": "Nurse Rajesh Kumar",
        "category": "Nurse",
        "ad_roles": ["REGISTERED_NURSE"],
        "groups": ["GRP-CARDIOLOGY", "GRP-FAC-001"],
        "email": "rajesh.kumar@apollo.example.com",
    },
    "oid-nurse-nair-3102": {
        "display_name": "Nurse Deepa Nair",
        "category": "Nurse",
        "ad_roles": ["ICU_NURSE"],
        "groups": ["GRP-EMERGENCY", "GRP-FAC-003"],
        "email": "deepa.nair@apollo.example.com",
    },
    "oid-nurse-singh-4455": {
        "display_name": "Nurse Harpreet Singh",
        "category": "Nurse",
        "ad_roles": ["HEAD_NURSE"],
        "groups": ["GRP-NEUROLOGY", "GRP-FAC-002"],
        "email": "harpreet.singh@apollo.example.com",
    },
    "oid-bill-maria-5521": {
        "display_name": "Maria Fernandez",
        "category": "Billing",
        "ad_roles": ["BILLING_CLERK"],
        "groups": ["GRP-BILLING", "GRP-FAC-001"],
        "email": "maria.fernandez@apollo.example.com",
    },
    "oid-bill-suresh-5530": {
        "display_name": "Suresh Menon",
        "category": "Billing",
        "ad_roles": ["BILLING_CLERK"],
        "groups": ["GRP-BILLING", "GRP-FAC-002"],
        "email": "suresh.menon@apollo.example.com",
    },
    "oid-rev-james-6601": {
        "display_name": "James D'Souza",
        "category": "Billing",
        "ad_roles": ["REVENUE_CYCLE_MANAGER"],
        "groups": ["GRP-REVENUE", "GRP-FAC-001"],
        "email": "james.dsouza@apollo.example.com",
    },
    "oid-hr-priya-7701": {
        "display_name": "Priya Venkatesh",
        "category": "HR",
        "ad_roles": ["HR_MANAGER"],
        "groups": ["GRP-HR", "GRP-FAC-001"],
        "email": "priya.venkatesh@apollo.example.com",
    },
    "oid-hr-dir-kapoor": {
        "display_name": "Anand Kapoor",
        "category": "HR",
        "ad_roles": ["HR_DIRECTOR"],
        "groups": ["GRP-HR", "GRP-FAC-001"],
        "email": "anand.kapoor@apollo.example.com",
    },
    "oid-it-admin-7801": {
        "display_name": "IT Administrator",
        "category": "IT",
        "ad_roles": ["IT_ADMINISTRATOR"],
        "groups": ["GRP-IT", "GRP-FAC-001"],
        "email": "it.admin@apollo.example.com",
    },
    "oid-hipaa-officer": {
        "display_name": "HIPAA Privacy Officer",
        "category": "Compliance",
        "ad_roles": ["HIPAA_PRIVACY_OFFICER"],
        "groups": ["GRP-COMPLIANCE", "GRP-FAC-001"],
        "email": "hipaa.officer@apollo.example.com",
    },
    "oid-researcher-das": {
        "display_name": "Ananya Das",
        "category": "Research",
        "ad_roles": ["CLINICAL_RESEARCHER"],
        "groups": ["GRP-RESEARCH", "GRP-FAC-005"],
        "email": "ananya.das@apollo.example.com",
    },
    "oid-terminated-user-9999": {
        "display_name": "Terminated User",
        "category": "Terminated",
        "ad_roles": ["REGISTERED_NURSE"],
        "groups": ["GRP-CARDIOLOGY", "GRP-FAC-001"],
        "email": "terminated.user@apollo.example.com",
    },
}


# ─────────────────────────────────────────────────────────
# RESPONSE MODELS
# ─────────────────────────────────────────────────────────

class MockUserSummary(BaseModel):
    oid: str
    display_name: str
    category: str
    department: str
    ad_roles: list[str]
    clearance_level: int
    domain: str
    bound_policies: list[str]
    employment_status: str


class MockUsersResponse(BaseModel):
    users: list[MockUserSummary]


class MockTokenResponse(BaseModel):
    jwt_token: str
    oid: str
    display_name: str
    expires_in: int


# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def _resolve_clearance(ad_roles: list[str]) -> int:
    """Return the highest clearance level across the given AD roles."""
    best = ClearanceLevel.PUBLIC
    for role in ad_roles:
        level = ROLE_CLEARANCE.get(role, ClearanceLevel.PUBLIC)
        if level > best:
            best = level
    return int(best)


def _resolve_domain(ad_roles: list[str]) -> str:
    """Return the domain for the primary (first) AD role."""
    for role in ad_roles:
        domain = ROLE_DOMAIN.get(role)
        if domain is not None:
            return domain.value
    return "UNKNOWN"


def _resolve_policies(ad_roles: list[str]) -> list[str]:
    """Collect all bound policy IDs for the given AD roles."""
    policies: list[str] = []
    seen: set[str] = set()
    for role in ad_roles:
        for pid in ROLE_POLICIES.get(role, []):
            if pid not in seen:
                seen.add(pid)
                policies.append(pid)
    return policies


# ─────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────

@router.get("/mock-users", response_model=MockUsersResponse)
async def list_mock_users() -> MockUsersResponse:
    """List all available test users with RBAC metadata."""
    users: list[MockUserSummary] = []

    for oid, profile in MOCK_USER_PROFILES.items():
        hr = MOCK_USER_DIRECTORY.get(oid)
        if hr is None:
            continue

        ad_roles = profile["ad_roles"]
        users.append(MockUserSummary(
            oid=oid,
            display_name=profile["display_name"],
            category=profile["category"],
            department=hr.department,
            ad_roles=ad_roles,
            clearance_level=_resolve_clearance(ad_roles),
            domain=_resolve_domain(ad_roles),
            bound_policies=_resolve_policies(ad_roles),
            employment_status=hr.employment_status.value,
        ))

    return MockUsersResponse(users=users)


@router.post("/mock-users/{oid}/token", response_model=MockTokenResponse)
async def generate_mock_token(oid: str) -> MockTokenResponse:
    """Generate a valid RS256-signed JWT for a test user."""
    profile = MOCK_USER_PROFILES.get(oid)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Unknown user OID: {oid}")

    now = int(time.time())
    expires_in = 3600  # 1 hour

    payload = {
        "oid": oid,
        "sub": oid,
        "name": profile["display_name"],
        "preferred_username": profile["email"],
        "roles": profile["ad_roles"],
        "groups": profile["groups"],
        "amr": ["pwd", "mfa"],
        "jti": str(uuid.uuid4()),
        "iss": "https://login.microsoftonline.com/apollo-mock-tenant/v2.0",
        "aud": "apollo-zt-pipeline",
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
    }

    token = MockKeyPair.get().sign_jwt(payload, kid="mock-key-1")

    return MockTokenResponse(
        jwt_token=token,
        oid=oid,
        display_name=profile["display_name"],
        expires_in=expires_in,
    )
