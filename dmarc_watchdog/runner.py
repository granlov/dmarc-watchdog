from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .alerter import send_alert_email
from .analyzer import detect_anomalies
from .anomaly_explainer import enrich_anomaly_guidance
from .config import AppConfig, load_allowlist
from .dmarc_parser import extract_xml_documents, parse_dmarc_xml
from .ingest import (
    MailPayload,
    fetch_mail_payloads_from_imap,
    fetch_mail_payloads_from_local_directory,
)
from .models import Anomaly, ParsedRecord
from .sender_identity import enrich_sender_identity
from .state_store import StateStore


class ProcessingError(Exception):
    pass


def run_watchdog(appConfig: AppConfig) -> int:
    stateStore = StateStore(appConfig.paths.stateFile)
    state = stateStore.load_state()

    try:
        mailPayloads = _load_mail_payloads(appConfig, state)
        parsedRecords, processedHashes = _parse_records_with_dedup(mailPayloads, state)
        enrich_sender_identity(
            parsedRecords=parsedRecords,
            providerHostnamePatterns=appConfig.senderIdentity.providerHostnamePatterns,
            enableReverseDns=appConfig.senderIdentity.enableReverseDns,
        )

        allowlist = load_allowlist(appConfig.paths.allowlistFile)
        anomalies = detect_anomalies(
            parsedRecords=parsedRecords,
            allowlist=allowlist,
            alertOnUnknownSender=appConfig.rules.alertOnUnknownSender,
            alertOnUnexpectedProvider=appConfig.rules.alertOnUnexpectedProvider,
            approvedProviders=appConfig.senderIdentity.approvedProviders,
            alertOnSpfFailure=appConfig.rules.alertOnSpfFailure,
            alertOnDkimFailure=appConfig.rules.alertOnDkimFailure,
            alertOnAlignmentFailure=appConfig.rules.alertOnAlignmentFailure,
        )
        enrich_anomaly_guidance(
            anomalies=anomalies,
            parsedRecords=parsedRecords,
            allowlist=allowlist,
            approvedProviders=appConfig.senderIdentity.approvedProviders,
        )

        _print_summary(parsedRecords, anomalies)
        send_alert_email(appConfig.alerts, anomalies, domain="dmarc-watchdog")

        state["processedAttachmentHashes"] = processedHashes
        stateStore.mark_successful_run(state)
        return 0
    except Exception as exception:
        print(f"SYSTEM ERROR: {exception}")
        stateStore.mark_failed_run(state)
        return 1


def _load_mail_payloads(appConfig: AppConfig, state: dict) -> list[MailPayload]:
    mode = appConfig.runtime.mode.lower()
    if mode == "local-files":
        return fetch_mail_payloads_from_local_directory(appConfig.paths.localReportDirectory)

    if mode == "imap":
        lastRunUtc = _parse_last_successful_run(state)
        return fetch_mail_payloads_from_imap(
            host=appConfig.imap.host,
            port=appConfig.imap.port,
            username=appConfig.imap.username,
            password=appConfig.imap.password,
            mailbox=appConfig.imap.mailbox,
            filterSubjectContains=appConfig.imap.filterSubjectContains,
            filterFromContains=appConfig.imap.filterFromContains,
            filterToContains=appConfig.imap.filterToContains,
            sinceUtc=lastRunUtc,
        )

    raise ProcessingError(f"Unsupported runtime mode: {appConfig.runtime.mode}")


def _parse_last_successful_run(state: dict) -> datetime | None:
    lastRunValue = state.get("lastSuccessfulRunUtc")
    if not lastRunValue:
        return None
    return datetime.fromisoformat(lastRunValue)


def _parse_records_with_dedup(
    mailPayloads: list[MailPayload],
    state: dict,
) -> tuple[list[ParsedRecord], list[str]]:
    previouslyProcessedHashes = set(state.get("processedAttachmentHashes", []))
    processedHashes = set(previouslyProcessedHashes)

    parsedRecords: list[ParsedRecord] = []

    for mailPayload in mailPayloads:
        for attachment in mailPayload.attachments:
            hashKey = _build_attachment_hash_key(attachment.attachmentBytes)
            if hashKey in previouslyProcessedHashes:
                continue

            xmlDocuments = extract_xml_documents(attachment.attachmentName, attachment.attachmentBytes)
            for xmlDocument in xmlDocuments:
                parsedRecords.extend(parse_dmarc_xml(xmlDocument))

            processedHashes.add(hashKey)

    return parsedRecords, sorted(processedHashes)


def _build_attachment_hash_key(attachmentBytes: bytes) -> str:
    return hashlib.sha256(attachmentBytes).hexdigest()


def _print_summary(parsedRecords: list[ParsedRecord], anomalies: list[Anomaly]) -> None:
    runTime = datetime.now(timezone.utc).isoformat()

    print(f"Run at UTC: {runTime}")
    print(f"Parsed records: {len(parsedRecords)}")

    if not anomalies:
        print("All good")
        return

    print("Issues detected:")
    for anomaly in anomalies:
        headerText = _human_header_text(anomaly)
        infoText = _human_info_text(anomaly)
        actionText = _human_action_text(anomaly)
        print(f"- {headerText}")
        print(f"  Info: {infoText}")
        print(f"  Action: {actionText}")


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
