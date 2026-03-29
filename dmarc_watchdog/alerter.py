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
        anomalyLabel = _human_anomaly_label(anomaly)
        subjectText = _human_subject_text(anomaly)
        actionText = _human_action_text(anomaly)
        lines.append(
            f"- [{anomaly.riskLevel.upper()} {confidencePercent}%] "
            f"{anomalyLabel}: {subjectText} "
            f"({anomaly.messageCount} messages). Action: {actionText}"
        )

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


def _human_subject_text(anomaly: Anomaly) -> str:
    if anomaly.anomalyType in {"unknown-sender", "unexpected-provider"}:
        provider = anomaly.provider or "unknown"
        rdns = anomaly.reverseDnsHostname or "unresolved"
        return f"{anomaly.subject} via {provider}, rDNS {rdns}"
    return anomaly.subject

def _human_action_text(anomaly: Anomaly) -> str:
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
