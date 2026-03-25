"""Break-the-Glass Manager -- Zero Trust Control ZT-009.

Handles emergency 4-hour elevated access with mandatory audit controls.

Security invariants:
  - BTG grants elevated access for a maximum of 4 hours.
  - A reason field is mandatory at activation.
  - Immediate compliance notification is triggered on activation.
  - 24-hour justification is required post-activation (tracked, not enforced here).
  - 42 CFR Part 2 (Sensitivity-5) tables remain BLOCKED even during BTG.
    This is a hard invariant -- no override path exists.
  - BTG tokens carry an explicit ``still_denied`` list of tables that
    cannot be overridden.
  - Expired tokens are automatically invalid.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional

import structlog
from pydantic import BaseModel, Field

from queryvault.app.models.enums import ColumnVisibility, PolicyDecision
from queryvault.app.models.security_context import SecurityContext

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# BTG Token
# ---------------------------------------------------------------------------


class BTGToken(BaseModel):
    """Break-the-Glass token issued upon emergency activation."""

    token_id: str = Field(
        ...,
        description="Unique token identifier.",
    )
    context_id: str = Field(
        ...,
        description="SecurityContext ID this token is bound to.",
    )
    user_id: str = Field(
        ...,
        description="User who activated BTG.",
    )
    reason: str = Field(
        ...,
        description="Mandatory justification provided at activation.",
    )
    patient_id: Optional[str] = Field(
        default=None,
        description="Patient ID triggering BTG (for scoped access).",
    )
    activated_at: str = Field(
        ...,
        description="ISO-8601 timestamp of activation.",
    )
    expires_at: str = Field(
        ...,
        description="ISO-8601 expiry timestamp (activated_at + 4 hours).",
    )
    still_denied: list[str] = Field(
        default_factory=list,
        description=(
            "Table IDs that remain DENIED even under BTG "
            "(e.g. 42 CFR Part 2 / Sensitivity-5)."
        ),
    )
    active: bool = Field(
        default=True,
        description="Whether this token is currently active.",
    )
    justification_due_by: str = Field(
        default="",
        description="ISO-8601 deadline for post-activation justification (24hr).",
    )


# ---------------------------------------------------------------------------
# Compliance notification (pluggable sink)
# ---------------------------------------------------------------------------


class ComplianceNotification(BaseModel):
    """Notification emitted to the compliance system on BTG events."""

    event_type: str  # BTG_ACTIVATED | BTG_DEACTIVATED | BTG_EXPIRED
    token_id: str
    user_id: str
    reason: str
    patient_id: Optional[str] = None
    timestamp: str = ""
    context_id: str = ""


# ---------------------------------------------------------------------------
# Patterns for Sensitivity-5 / 42 CFR Part 2 detection
# ---------------------------------------------------------------------------

_SENSITIVITY5_PATTERNS = frozenset(
    {
        "substance_abuse",
        "behavioral_health_substance",
        "42cfr_part2",
        "psychotherapy_notes",
        "hiv_status",
        "genetic_testing",
    }
)

# BTG duration
_BTG_DURATION_HOURS = 4
_JUSTIFICATION_DEADLINE_HOURS = 24


# ---------------------------------------------------------------------------
# BreakGlassManager
# ---------------------------------------------------------------------------


class BreakGlassManager:
    """Manages Break-the-Glass (BTG) emergency access lifecycle.

    Usage::

        mgr = BreakGlassManager()
        token = await mgr.activate(
            context_id="ctx_abc123",
            reason="Emergency patient care -- cardiac arrest",
            patient_id="MRN-00042",
        )

        is_valid = await mgr.validate(token)

        await mgr.deactivate(context_id="ctx_abc123")

        # Always returns True -- Sensitivity-5 is never accessible
        blocked = mgr.is_sensitivity5_blocked("ehr.substance_abuse_records")
    """

    def __init__(
        self,
        notification_sink: Optional[object] = None,
    ) -> None:
        """Initialise the BTG manager.

        Args:
            notification_sink: Optional object with an
                ``async send(notification: ComplianceNotification)`` method.
                When ``None``, notifications are logged but not dispatched.
        """
        self._sink = notification_sink
        # Active tokens indexed by context_id
        self._active_tokens: dict[str, BTGToken] = {}

    # ------------------------------------------------------------------
    # Activate
    # ------------------------------------------------------------------

    async def activate(
        self,
        context_id: str,
        reason: str,
        patient_id: str | None = None,
    ) -> BTGToken:
        """Activate Break-the-Glass emergency access.

        Args:
            context_id: The SecurityContext ID for this session.
            reason: Mandatory justification (must be non-empty).
            patient_id: Optional patient MRN for scoped BTG access.

        Returns:
            A BTGToken valid for 4 hours.

        Raises:
            ValueError: If reason is empty.
        """
        if not reason or not reason.strip():
            raise ValueError("BTG activation requires a non-empty reason")

        now = datetime.now(UTC)
        expires = now + timedelta(hours=_BTG_DURATION_HOURS)
        justification_due = now + timedelta(hours=_JUSTIFICATION_DEADLINE_HOURS)

        token = BTGToken(
            token_id=f"btg_{uuid.uuid4().hex[:16]}",
            context_id=context_id,
            user_id=context_id,  # will be enriched by caller
            reason=reason.strip(),
            patient_id=patient_id,
            activated_at=now.isoformat() + "Z",
            expires_at=expires.isoformat() + "Z",
            still_denied=[],  # populated by caller from Sensitivity-5 tables
            active=True,
            justification_due_by=justification_due.isoformat() + "Z",
        )

        self._active_tokens[context_id] = token

        # Immediate compliance notification
        notification = ComplianceNotification(
            event_type="BTG_ACTIVATED",
            token_id=token.token_id,
            user_id=token.user_id,
            reason=token.reason,
            patient_id=patient_id,
            timestamp=now.isoformat() + "Z",
            context_id=context_id,
        )
        await self._emit_notification(notification)

        logger.warning(
            "btg_activated",
            token_id=token.token_id,
            context_id=context_id,
            reason=reason,
            patient_id=patient_id,
            expires_at=token.expires_at,
            justification_due_by=token.justification_due_by,
        )

        return token

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------

    async def validate(self, btg_token: BTGToken) -> bool:
        """Validate that a BTG token is currently active and not expired.

        Args:
            btg_token: The token to validate.

        Returns:
            True if the token is active and not expired, False otherwise.
        """
        if not btg_token.active:
            return False

        # Check expiry
        try:
            raw = btg_token.expires_at.rstrip("Z")
            if "+" not in raw and raw[-1].isdigit():
                raw += "+00:00"
            expires = datetime.fromisoformat(raw)
            if datetime.now(UTC) >= expires:
                # Auto-expire
                btg_token.active = False
                await self._handle_expiry(btg_token)
                return False
        except (ValueError, TypeError):
            return False

        # Verify it is still in the active store
        stored = self._active_tokens.get(btg_token.context_id)
        if stored is None or stored.token_id != btg_token.token_id:
            return False

        return True

    # ------------------------------------------------------------------
    # Deactivate
    # ------------------------------------------------------------------

    async def deactivate(self, context_id: str) -> None:
        """Manually deactivate a BTG token before its natural expiry.

        Args:
            context_id: The SecurityContext ID whose BTG should be revoked.
        """
        token = self._active_tokens.pop(context_id, None)
        if token is None:
            logger.info("btg_deactivate_noop", context_id=context_id)
            return

        token.active = False

        notification = ComplianceNotification(
            event_type="BTG_DEACTIVATED",
            token_id=token.token_id,
            user_id=token.user_id,
            reason=token.reason,
            patient_id=token.patient_id,
            timestamp=datetime.now(UTC).isoformat() + "Z",
            context_id=context_id,
        )
        await self._emit_notification(notification)

        logger.warning(
            "btg_deactivated",
            token_id=token.token_id,
            context_id=context_id,
        )

    # ------------------------------------------------------------------
    # Sensitivity-5 check (42 CFR Part 2)
    # ------------------------------------------------------------------

    @staticmethod
    def is_sensitivity5_blocked(table: str) -> bool:
        """Check if a table is blocked under 42 CFR Part 2 / Sensitivity-5.

        This ALWAYS returns True for Sensitivity-5 tables.  There is no
        override path -- not even BTG can unlock these tables.

        Args:
            table: Table identifier (name or FQN).

        Returns:
            True if the table matches a Sensitivity-5 pattern.
        """
        # Always returns True for sensitivity-5 tables.
        # The method name reflects the invariant: these are always blocked.
        table_lower = table.lower()
        return any(pattern in table_lower for pattern in _SENSITIVITY5_PATTERNS)

    def get_still_denied_tables(self, table_ids: list[str]) -> list[str]:
        """Return the subset of table IDs that remain denied even under BTG.

        These are Sensitivity-5 / 42 CFR Part 2 tables that no override
        can unlock.
        """
        return [tid for tid in table_ids if self.is_sensitivity5_blocked(tid)]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _handle_expiry(self, token: BTGToken) -> None:
        """Handle automatic token expiry."""
        self._active_tokens.pop(token.context_id, None)

        notification = ComplianceNotification(
            event_type="BTG_EXPIRED",
            token_id=token.token_id,
            user_id=token.user_id,
            reason=token.reason,
            patient_id=token.patient_id,
            timestamp=datetime.now(UTC).isoformat() + "Z",
            context_id=token.context_id,
        )
        await self._emit_notification(notification)

        logger.warning(
            "btg_expired",
            token_id=token.token_id,
            context_id=token.context_id,
        )

    async def _emit_notification(self, notification: ComplianceNotification) -> None:
        """Dispatch a compliance notification to the configured sink."""
        if self._sink is not None:
            try:
                await self._sink.send(notification)  # type: ignore[union-attr]
            except Exception as exc:
                logger.error(
                    "btg_notification_failed",
                    event=notification.event_type,
                    token_id=notification.token_id,
                    error=str(exc),
                )
        else:
            logger.info(
                "btg_compliance_event",
                event=notification.event_type,
                token_id=notification.token_id,
                user=notification.user_id,
                reason=notification.reason,
            )

    def get_active_token(self, context_id: str) -> BTGToken | None:
        """Retrieve the active BTG token for a context, if any."""
        return self._active_tokens.get(context_id)
