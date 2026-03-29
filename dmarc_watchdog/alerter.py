from __future__ import annotations

import smtplib
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
        confidencePercent = int(round(anomaly.confidence * 100))
        subjectLabel = _subject_label_for_anomaly(anomaly)
        compactAction = _compact_action_for_anomaly(anomaly)
        lines.append(
            f"- [{anomaly.riskLevel.upper()} {confidencePercent}%] "
            f"{anomaly.anomalyType} {subjectLabel}={anomaly.subject} "
            f"messages={anomaly.messageCount} action={compactAction}"
        )

    lines.extend(
        [
            "",
            "---",
            "This is an automated alert from dmarc-watchdog.",
        ]
    )

    return "\n".join(lines)


def _subject_label_for_anomaly(anomaly: Anomaly) -> str:
    if anomaly.anomalyType in {"unknown-sender", "unexpected-provider"}:
        return "ip"
    return "domain"


def _compact_action_for_anomaly(anomaly: Anomaly) -> str:
    if anomaly.anomalyType == "unknown-sender":
        if anomaly.riskLevel == "low":
            return "monitor_or_allowlist"
        if anomaly.riskLevel == "medium":
            return "verify_then_allowlist"
        return "investigate_now"

    if anomaly.anomalyType == "unexpected-provider":
        if anomaly.riskLevel == "low":
            return "validate_provider_then_approve"
        if anomaly.riskLevel == "medium":
            return "review_provider_usage"
        return "investigate_provider_now"

    if anomaly.anomalyType == "spf-failure":
        return "check_spf_records"
    if anomaly.anomalyType == "dkim-failure":
        return "check_dkim_signing"
    if anomaly.anomalyType == "alignment-failure":
        return "urgent_auth_alignment_check"
    return "review"
