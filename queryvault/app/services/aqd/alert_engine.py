"""AQD-005: Multi-Channel Alert Engine.

Delivers security alerts to multiple channels with configurable
severity thresholds and full attack context.

Supported Channels
------------------
- Dashboard   -- internal event bus / in-app notification
- Slack       -- incoming webhook
- PagerDuty   -- Events API v2 (CRITICAL severity only)
- Email       -- SMTP (async, fire-and-forget)
- Webhook     -- generic HTTP POST to arbitrary endpoints

All outbound HTTP calls use fire-and-forget semantics with a
configurable timeout (default 10 s) so that alert delivery never
blocks the request pipeline.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from queryvault.app.models.enums import Severity

logger = structlog.get_logger(__name__)

# Default HTTP timeout for outbound alert calls (seconds).
_DEFAULT_TIMEOUT = 10.0


class AlertEngine:
    """Multi-channel security alert dispatcher.

    Parameters
    ----------
    slack_webhook_url:
        Slack incoming-webhook URL.  Empty string disables Slack.
    pagerduty_routing_key:
        PagerDuty Events API v2 routing key.  Empty disables PagerDuty.
    email_smtp_host:
        SMTP host for email alerts.  Empty disables email.
    email_from:
        Sender address for email alerts.
    email_recipients:
        Comma-separated list of email recipients.
    webhook_urls:
        Comma-separated list of generic webhook endpoints.
    dashboard_callback:
        Optional async callable to push alerts to an in-app dashboard.
    timeout:
        HTTP timeout in seconds for outbound calls.
    min_severity:
        Minimum severity level that triggers alert dispatch.
    """

    _SEVERITY_ORDER = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def __init__(
        self,
        *,
        slack_webhook_url: str = "",
        pagerduty_routing_key: str = "",
        email_smtp_host: str = "",
        email_from: str = "",
        email_recipients: str = "",
        webhook_urls: str = "",
        dashboard_callback: Any = None,
        timeout: float = _DEFAULT_TIMEOUT,
        min_severity: Severity = Severity.MEDIUM,
    ) -> None:
        self._slack_url = slack_webhook_url
        self._pd_key = pagerduty_routing_key
        self._email_host = email_smtp_host
        self._email_from = email_from
        self._email_to = [
            r.strip() for r in email_recipients.split(",") if r.strip()
        ]
        self._webhook_urls = [
            u.strip() for u in webhook_urls.split(",") if u.strip()
        ]
        self._dashboard_cb = dashboard_callback
        self._timeout = timeout
        self._min_severity = min_severity
        self._http: httpx.AsyncClient | None = None

    # -- lifecycle ----------------------------------------------------------

    async def connect(self) -> None:
        """Create the shared HTTP client."""
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
        )

    async def close(self) -> None:
        """Shut down the HTTP client."""
        if self._http:
            await self._http.aclose()

    # -- severity gate ------------------------------------------------------

    def _above_threshold(self, severity: Severity) -> bool:
        return self._SEVERITY_ORDER.get(severity, 0) >= self._SEVERITY_ORDER.get(
            self._min_severity, 0
        )

    # -- public API ---------------------------------------------------------

    async def dispatch(
        self,
        severity: Severity,
        title: str,
        description: str,
        details: dict[str, Any] | None = None,
    ) -> list[str]:
        """Send alert to all configured channels.

        Parameters
        ----------
        severity:
            Alert severity level.
        title:
            Short alert title.
        description:
            Detailed description including attack context.
        details:
            Optional key-value context (user_id, matched patterns, etc.).

        Returns
        -------
        list[str]
            Names of channels that were successfully notified.
        """
        if not self._above_threshold(severity):
            return []

        notified: list[str] = []

        # Dashboard
        if self._dashboard_cb:
            try:
                await self._dashboard_cb(severity, title, description, details)
                notified.append("dashboard")
            except Exception as exc:
                logger.warning("dashboard_alert_failed", error=str(exc))

        # Slack
        if self._slack_url:
            if await self._send_slack(severity, title, description, details):
                notified.append("slack")

        # PagerDuty (CRITICAL only)
        if self._pd_key and severity == Severity.CRITICAL:
            if await self._send_pagerduty(title, description, details):
                notified.append("pagerduty")

        # Email
        if self._email_host and self._email_to:
            if await self._send_email(severity, title, description, details):
                notified.append("email")

        # Generic webhooks
        for url in self._webhook_urls:
            if await self._send_webhook(url, severity, title, description, details):
                notified.append(f"webhook:{url[:30]}")

        if notified:
            logger.info(
                "alerts_dispatched",
                channels=notified,
                severity=severity.value,
                title=title,
            )
        else:
            logger.debug(
                "no_alert_channels_notified",
                severity=severity.value,
            )

        return notified

    # -- channel implementations --------------------------------------------

    async def _send_slack(
        self,
        severity: Severity,
        title: str,
        description: str,
        details: dict[str, Any] | None,
    ) -> bool:
        if not self._http:
            return False

        emoji_map = {
            Severity.CRITICAL: ":rotating_light:",
            Severity.HIGH: ":red_circle:",
            Severity.MEDIUM: ":warning:",
            Severity.LOW: ":large_blue_circle:",
            Severity.INFO: ":information_source:",
        }
        icon = emoji_map.get(severity, ":bell:")

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{icon} QueryVault: {title}",
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": description},
            },
        ]

        if details:
            detail_lines = [f"*{k}*: {v}" for k, v in list(details.items())[:10]]
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(detail_lines)},
            })

        try:
            resp = await self._http.post(
                self._slack_url,
                json={"blocks": blocks},
            )
            return resp.status_code == 200
        except Exception as exc:
            logger.warning("slack_alert_failed", error=str(exc))
            return False

    async def _send_pagerduty(
        self,
        title: str,
        description: str,
        details: dict[str, Any] | None,
    ) -> bool:
        if not self._http:
            return False

        payload = {
            "routing_key": self._pd_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"QueryVault: {title}",
                "severity": "critical",
                "source": "queryvault-aqd",
                "custom_details": {
                    "description": description,
                    **(details or {}),
                },
            },
        }

        try:
            resp = await self._http.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )
            return resp.status_code in (200, 202)
        except Exception as exc:
            logger.warning("pagerduty_alert_failed", error=str(exc))
            return False

    async def _send_email(
        self,
        severity: Severity,
        title: str,
        description: str,
        details: dict[str, Any] | None,
    ) -> bool:
        """Send email alert via SMTP (fire-and-forget, best-effort)."""
        try:
            import smtplib
            from email.mime.text import MIMEText

            body_parts = [
                f"Severity: {severity.value}",
                f"Title: {title}",
                "",
                description,
            ]
            if details:
                body_parts.append("")
                body_parts.append("Details:")
                for k, v in list(details.items())[:15]:
                    body_parts.append(f"  {k}: {v}")

            msg = MIMEText("\n".join(body_parts))
            msg["Subject"] = f"[QueryVault {severity.value}] {title}"
            msg["From"] = self._email_from
            msg["To"] = ", ".join(self._email_to)

            with smtplib.SMTP(self._email_host, timeout=int(self._timeout)) as smtp:
                smtp.send_message(msg)

            return True
        except Exception as exc:
            logger.warning("email_alert_failed", error=str(exc))
            return False

    async def _send_webhook(
        self,
        url: str,
        severity: Severity,
        title: str,
        description: str,
        details: dict[str, Any] | None,
    ) -> bool:
        if not self._http:
            return False

        payload = {
            "source": "queryvault-aqd",
            "severity": severity.value,
            "title": title,
            "description": description,
            "details": details or {},
        }

        try:
            resp = await self._http.post(url, json=payload)
            return 200 <= resp.status_code < 300
        except Exception as exc:
            logger.warning("webhook_alert_failed", url=url[:50], error=str(exc))
            return False
