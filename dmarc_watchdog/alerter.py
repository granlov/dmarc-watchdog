from __future__ import annotations

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

from .models import Anomaly


class AlertConfig:
    def __init__(
        self,
        enabled: bool = False,
        smtpHost: str = "",
        smtpPort: int = 587,
        smtpUsername: str = "",
        smtpPassword: str = "",
        fromAddress: str = "",
        toAddresses: list[str] | None = None,
    ):
        self.enabled = enabled
        self.smtpHost = smtpHost
        self.smtpPort = smtpPort
        self.smtpUsername = smtpUsername
        self.smtpPassword = smtpPassword
        self.fromAddress = fromAddress
        self.toAddresses = toAddresses or []


def send_alert_email(alertConfig: AlertConfig, anomalies: list[Anomaly], domain: str = "unknown") -> bool:
    """
    Send email alert if anomalies are detected and alerts are enabled.
    Returns True if email was sent, False otherwise.
    """
    if not alertConfig.enabled or not anomalies or not alertConfig.smtpHost:
        return False

    try:
        subject = f"DMARC Alert: {len(anomalies)} anomalie(r) for {domain}"
        body = _build_email_body(anomalies, domain)

        message = MIMEMultipart()
        message["From"] = alertConfig.fromAddress
        message["To"] = ", ".join(alertConfig.toAddresses)
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(alertConfig.smtpHost, alertConfig.smtpPort) as server:
            server.starttls()
            server.login(alertConfig.smtpUsername, alertConfig.smtpPassword)
            server.send_message(message)

        return True
    except Exception as exception:
        print(f"ERROR: Failed to send alert email: {exception}")
        return False


def _build_email_body(anomalies: list[Anomaly], domain: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        f"DMARC Watchdog Alert - {now}",
        f"Domain: {domain}",
        "",
        f"Detected {len(anomalies)} anomalie(s):",
        "",
    ]

    for anomaly in anomalies:
        headerText = _human_header_text(anomaly)
        infoText = _human_info_text(anomaly)
        actionText = _human_action_text(anomaly)
        lines.append(f"- {headerText}")
        lines.append(f"  Info: {infoText}")
        lines.append(f"  Action: {actionText}")
        lines.append("")

    lines.extend(
        [
            "",
            "---",
            "This is an automated alert from dmarc-watchdog.",
        ]
    )

    return "\n".join(lines)


def _human_anomaly_label(anomaly: Anomaly) -> str:
    if anomaly.anomalyType == "unknown-sender":
        return "New sender"
    if anomaly.anomalyType == "unexpected-provider":
        return "Unexpected provider"
    if anomaly.anomalyType == "spf-failure":
        return "SPF failure"
    if anomaly.anomalyType == "dkim-failure":
        return "DKIM failure"
    if anomaly.anomalyType == "alignment-failure":
        return "Alignment failure"
    return anomaly.anomalyType


def _human_header_text(anomaly: Anomaly) -> str:
    confidencePercent = int(round(anomaly.confidence * 100))
    label = _human_anomaly_label(anomaly)

    if anomaly.anomalyType in {"unknown-sender", "unexpected-provider"}:
        rdns = anomaly.reverseDnsHostname or "unresolved"
        return f"[{anomaly.riskLevel.upper()} {confidencePercent}%] {label}: {anomaly.subject} ({rdns})"

    return f"[{anomaly.riskLevel.upper()} {confidencePercent}%] {label}: {anomaly.subject}"


def _human_info_text(anomaly: Anomaly) -> str:
    if anomaly.anomalyType in {"unknown-sender", "unexpected-provider"}:
        provider = anomaly.provider or "unknown"
        if anomaly.authSummary:
            return f"{anomaly.messageCount} messages; provider {provider}; auth {anomaly.authSummary}."
        return f"{anomaly.messageCount} messages; provider {provider}."

    if anomaly.authSummary:
        return f"{anomaly.messageCount} messages; auth {anomaly.authSummary}."
    return f"{anomaly.messageCount} messages."

def _human_action_text(anomaly: Anomaly) -> str:
    if anomaly.recommendation:
        return anomaly.recommendation

    if anomaly.anomalyType == "unknown-sender":
        if anomaly.riskLevel == "low":
            return "Likely legitimate. Monitor and allowlist if expected."
        if anomaly.riskLevel == "medium":
            return "Verify sender ownership and auth, then allowlist if expected."
        return "Investigate sender now and verify SPF/DKIM context."

    if anomaly.anomalyType == "unexpected-provider":
        if anomaly.riskLevel == "low":
            return "Likely new legitimate provider. Verify, then approve if expected."
        if anomaly.riskLevel == "medium":
            return "Review why this provider sends for your domain before approval."
        return "Investigate provider by checking approvedProviders, sender setup, and SPF/DKIM alignment."

    if anomaly.anomalyType == "spf-failure":
        return "Investigate SPF by checking include/redirect chain and sender IP coverage."
    if anomaly.anomalyType == "dkim-failure":
        return "Investigate DKIM by checking selector keys and signing path."
    if anomaly.anomalyType == "alignment-failure":
        return "Urgent: investigate DMARC/SPF/DKIM alignment and possible spoofing."
    return "Review this anomaly."


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------

_DISCORD_COLOR_BY_RISK = {
    "high": 0xED4245,    # red
    "medium": 0xFEE75C,  # yellow
    "low": 0x57F287,     # green
}


def send_discord_alert(discordConfig, anomalies: list[Anomaly], domain: str = "unknown") -> bool:
    """
    Post anomaly embeds to a Discord webhook.
    Returns True if the message was posted, False otherwise.
    """
    if not discordConfig.enabled or not anomalies or not discordConfig.webhookUrl:
        return False

    try:
        embeds = [_build_discord_embed(anomaly, domain) for anomaly in anomalies]

        # Discord allows up to 10 embeds per message; split if needed
        for batch_start in range(0, len(embeds), 10):
            batch = embeds[batch_start : batch_start + 10]
            payload = json.dumps({"embeds": batch}).encode("utf-8")
            request = urllib.request.Request(
                discordConfig.webhookUrl,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status not in (200, 204):
                    print(f"ERROR: Discord webhook returned status {response.status}")
                    return False

        return True
    except Exception as exception:
        print(f"ERROR: Failed to send Discord alert: {exception}")
        return False


def _build_discord_embed(anomaly: Anomaly, domain: str) -> dict:
    color = _DISCORD_COLOR_BY_RISK.get(anomaly.riskLevel, 0xAAAAAA)
    confidencePercent = int(round(anomaly.confidence * 100))
    label = _human_anomaly_label(anomaly)
    headerText = _human_header_text(anomaly)
    infoText = _human_info_text(anomaly)
    actionText = _human_action_text(anomaly)

    fields = [
        {"name": "Domain", "value": domain, "inline": True},
        {"name": "Risk", "value": f"{anomaly.riskLevel.upper()} ({confidencePercent}%)", "inline": True},
        {"name": "Messages", "value": str(anomaly.messageCount), "inline": True},
        {"name": "Details", "value": infoText, "inline": False},
        {"name": "Recommended action", "value": actionText, "inline": False},
    ]

    if anomaly.whyThisAppeared:
        fields.append({"name": "Why this appeared", "value": anomaly.whyThisAppeared, "inline": False})

    if anomaly.evidence:
        fields.append({"name": "Evidence", "value": "\n".join(f"• {e}" for e in anomaly.evidence), "inline": False})

    return {
        "title": f"{label}: {anomaly.subject}" if anomaly.subject else label,
        "description": headerText,
        "color": color,
        "fields": fields,
        "footer": {"text": "dmarc-watchdog"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
