"""
token_validator.py -- RS256 JWT Validation Service (ZT-001)
==========================================================

Validates JWTs using RS256 signatures with JWKS endpoint or mock IDP support.

Verification chain:
  1. Fetch JWKS from Azure AD (cached) or use mock RSA keypair
  2. Match kid in JWT header to JWKS key
  3. Verify RS256 signature
  4. Verify standard claims: iss, aud, exp, nbf, iat, jti
  5. Extract identity claims: oid/sub, name, email, roles, groups, amr, jti
  6. Return typed ValidatedClaims dataclass for downstream enrichment

In mock mode (mock_idp_enabled=True):
  Uses a locally generated RSA keypair instead of Azure AD JWKS.
  This removes all external dependencies for dev/test.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt as pyjwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient, PyJWKClientError

logger = logging.getLogger("queryvault.identity.token_validator")


# ─────────────────────────────────────────────────────────
# VALIDATED CLAIMS (typed output of validation)
# ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ValidatedClaims:
    """Typed claims extracted from a validated JWT."""

    oid: str                                        # Azure AD Object ID (oid or sub)
    name: str                                       # Display name
    email: str                                      # preferred_username or email
    roles: list[str] = field(default_factory=list)  # Direct roles from JWT
    groups: list[str] = field(default_factory=list)  # Group memberships
    amr: list[str] = field(default_factory=list)    # Authentication methods (e.g. ["pwd", "mfa"])
    jti: str = ""                                   # JWT ID (unique token identifier)
    raw_claims: dict = field(default_factory=dict)  # Full decoded payload


# ─────────────────────────────────────────────────────────
# TOKEN VALIDATION ERROR
# ─────────────────────────────────────────────────────────

class TokenValidationError(Exception):
    """Raised when JWT validation fails at any step."""
    pass


# ─────────────────────────────────────────────────────────
# MOCK RSA KEYPAIR (dev/test only)
# ─────────────────────────────────────────────────────────

_SHARED_KEY_PATH = "/tmp/queryvault_mock_rsa.pem"


class MockKeyPair:
    """Generates and holds an RSA keypair for local JWT signing/verification.

    The keypair is persisted to a shared file so that all uvicorn worker
    processes use the same key.  The first worker to start generates the
    key and writes it; subsequent workers load it from disk.

    Singleton -- only one keypair exists per process.
    """

    _instance: Optional[MockKeyPair] = None

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        key_size: int = 2048,
    ):
        if private_key_path:
            logger.info("[MockIdP] Loading RSA keypair from %s", private_key_path)
            with open(private_key_path, "rb") as f:
                priv_pem = f.read()
            self._private_key = serialization.load_pem_private_key(
                priv_pem, password=None, backend=default_backend(),
            )
            if public_key_path:
                with open(public_key_path, "rb") as f:
                    pub_pem = f.read()
                self._public_key = serialization.load_pem_public_key(
                    pub_pem, backend=default_backend(),
                )
            else:
                self._public_key = self._private_key.public_key()
        else:
            self._init_shared_keypair(key_size)

    def _init_shared_keypair(self, key_size: int) -> None:
        """Load from shared file if it exists, otherwise generate and persist."""
        import os
        import fcntl

        if os.path.exists(_SHARED_KEY_PATH):
            try:
                with open(_SHARED_KEY_PATH, "rb") as f:
                    priv_pem = f.read()
                self._private_key = serialization.load_pem_private_key(
                    priv_pem, password=None, backend=default_backend(),
                )
                self._public_key = self._private_key.public_key()
                logger.info("[MockIdP] Loaded shared RSA keypair from %s", _SHARED_KEY_PATH)
                return
            except Exception as exc:
                logger.warning("[MockIdP] Failed to load shared key, regenerating: %s", exc)

        logger.info("[MockIdP] Generating RSA-%d keypair for local JWT signing", key_size)
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

        # Persist so other workers share the same key
        try:
            priv_pem = self._private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(_SHARED_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(priv_pem)
            logger.info("[MockIdP] Persisted shared RSA keypair to %s", _SHARED_KEY_PATH)
        except FileExistsError:
            # Another worker wrote it first -- reload from their file
            with open(_SHARED_KEY_PATH, "rb") as f:
                priv_pem = f.read()
            self._private_key = serialization.load_pem_private_key(
                priv_pem, password=None, backend=default_backend(),
            )
            self._public_key = self._private_key.public_key()
            logger.info("[MockIdP] Loaded shared RSA keypair written by sibling worker")
        except Exception as exc:
            logger.warning("[MockIdP] Could not persist key (using in-memory): %s", exc)

    @classmethod
    def get(
        cls,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        key_size: int = 2048,
    ) -> MockKeyPair:
        """Return the singleton MockKeyPair, creating it on first call."""
        if cls._instance is None:
            cls._instance = MockKeyPair(
                private_key_path=private_key_path,
                public_key_path=public_key_path,
                key_size=key_size,
            )
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton (for testing only)."""
        cls._instance = None

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key

    @property
    def public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_jwt(self, payload: dict, kid: str = "mock-key-1") -> str:
        """Sign a JWT payload with the mock private key."""
        return pyjwt.encode(
            payload,
            self._private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )


# ─────────────────────────────────────────────────────────
# TOKEN VALIDATOR
# ─────────────────────────────────────────────────────────

class TokenValidator:
    """
    Validates JWTs against Azure AD JWKS (or mock keypair in dev).

    Usage:
        validator = TokenValidator(
            audience="apollo-zt-pipeline",
            issuer="https://login.microsoftonline.com/apollo-mock-tenant/v2.0",
        )
        claims = validator.validate("eyJ...")
        # claims.oid, claims.name, claims.roles, etc.

    All configuration is passed via constructor -- no global settings dependency.
    """

    def __init__(
        self,
        *,
        audience: str = "apollo-zt-pipeline",
        issuer: str = "https://login.microsoftonline.com/apollo-mock-tenant/v2.0",
        algorithm: str = "RS256",
        leeway_seconds: int = 30,
        jwks_uri: Optional[str] = None,
        jwks_cache_ttl: int = 3600,
        mock_idp_enabled: bool = True,
        mock_idp_key_size: int = 2048,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
    ):
        self._audience = audience
        self._issuer = issuer
        self._algorithm = algorithm
        self._leeway = leeway_seconds
        self._jwks_uri = jwks_uri
        self._jwks_cache_ttl = jwks_cache_ttl
        self._mock_idp_enabled = mock_idp_enabled
        self._mock_idp_key_size = mock_idp_key_size
        self._private_key_path = private_key_path
        self._public_key_path = public_key_path

        self._jwks_client: Optional[PyJWKClient] = None
        self._jwks_last_fetch: float = 0

    # ── JWKS Client (lazy init, cached) ──

    def _get_jwks_client(self) -> Optional[PyJWKClient]:
        """Get or create the JWKS client.  Returns None in mock mode."""
        if self._mock_idp_enabled:
            return None

        now = time.time()
        if (
            self._jwks_client is None
            or (now - self._jwks_last_fetch) > self._jwks_cache_ttl
        ):
            if not self._jwks_uri:
                raise TokenValidationError("JWKS URI not configured and mock IDP is disabled")
            logger.info("Fetching JWKS from %s", self._jwks_uri)
            self._jwks_client = PyJWKClient(self._jwks_uri)
            self._jwks_last_fetch = now

        return self._jwks_client

    # ── Signing Key Resolution ──

    def _resolve_signing_key(self, token: str) -> Any:
        """Resolve the public key to verify the JWT signature.

        Priority order:
          1. If a static public key path is configured, load that key.
          2. If mock mode is active, use the MockKeyPair public key.
          3. Otherwise, fetch from the JWKS URI based on the token's kid.
        """
        # 1. Static public key takes precedence
        if self._public_key_path:
            try:
                with open(self._public_key_path, "rb") as f:
                    pem = f.read()
                return serialization.load_pem_public_key(pem, backend=default_backend())
            except Exception as e:
                logger.error("Failed loading public key from %s: %s", self._public_key_path, e)
                raise TokenValidationError(f"Cannot load public key: {e}")

        # 2. Mock keypair if enabled
        if self._mock_idp_enabled:
            return MockKeyPair.get(
                private_key_path=self._private_key_path,
                public_key_path=None,
                key_size=self._mock_idp_key_size,
            ).public_key

        # 3. Fallback to JWKS endpoint
        client = self._get_jwks_client()
        if client is None:
            raise TokenValidationError("JWKS client not available")

        try:
            signing_key = client.get_signing_key_from_jwt(token)
            return signing_key.key
        except PyJWKClientError as e:
            logger.error("JWKS key resolution failed: %s", e)
            raise TokenValidationError(f"Cannot resolve signing key: {e}")

    # ── Core Validation ──

    def validate(self, token: str) -> ValidatedClaims:
        """
        Validate a JWT and extract claims.

        Verification steps:
          1. Resolve signing key (JWKS or mock)
          2. Verify RS256 signature
          3. Verify iss, aud, exp, nbf, iat, jti
          4. Extract identity claims

        Returns:
            ValidatedClaims with oid, name, email, roles, groups, amr, jti.

        Raises:
            TokenValidationError on any failure.
        """
        try:
            key = self._resolve_signing_key(token)
        except TokenValidationError:
            raise
        except Exception as e:
            raise TokenValidationError(f"Key resolution failed: {e}")

        try:
            decoded = pyjwt.decode(
                token,
                key,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "nbf", "iat", "iss", "aud"],
                },
            )
        except pyjwt.ExpiredSignatureError:
            raise TokenValidationError("Token has expired")
        except pyjwt.InvalidAudienceError:
            raise TokenValidationError("Invalid audience")
        except pyjwt.InvalidIssuerError:
            raise TokenValidationError("Invalid issuer")
        except pyjwt.InvalidSignatureError:
            raise TokenValidationError("Invalid signature")
        except pyjwt.DecodeError as e:
            raise TokenValidationError(f"Token decode failed: {e}")
        except pyjwt.InvalidTokenError as e:
            raise TokenValidationError(f"Token validation failed: {e}")

        # ── Extract Claims ──
        oid = decoded.get("oid") or decoded.get("sub", "")
        name = decoded.get("name", "")
        email = decoded.get("preferred_username") or decoded.get("email", "")
        roles = decoded.get("roles") or decoded.get("direct_roles") or []
        groups = decoded.get("groups", [])
        amr = decoded.get("amr", [])
        jti_val = decoded.get("jti", "")

        if not oid:
            raise TokenValidationError("Token missing required claim: oid or sub")
        if not jti_val:
            raise TokenValidationError("Token missing required claim: jti (required for revocation support)")

        logger.info(
            "Token validated | oid=%s name=%s roles=%s mfa=%s",
            oid, name, roles, "mfa" in amr,
        )

        return ValidatedClaims(
            oid=oid,
            name=name,
            email=email,
            roles=roles if isinstance(roles, list) else [roles],
            groups=groups if isinstance(groups, list) else [groups],
            amr=amr if isinstance(amr, list) else [amr],
            jti=jti_val,
            raw_claims=decoded,
        )
