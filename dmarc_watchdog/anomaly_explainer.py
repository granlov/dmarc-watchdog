from __future__ import annotations

from collections import defaultdict

from .models import Anomaly, ParsedRecord


def enrich_anomaly_guidance(
    anomalies: list[Anomaly],
    parsedRecords: list[ParsedRecord],
    allowlist: dict[str, list[str]],
    approvedProviders: list[str],
) -> None:
    recordsByIp: dict[str, list[ParsedRecord]] = defaultdict(list)
    recordsByDomain: dict[str, list[ParsedRecord]] = defaultdict(list)
    for record in parsedRecords:
        recordsByIp[record.sourceIp].append(record)
        recordsByDomain[record.headerFromDomain].append(record)

    allowedIps = set(allowlist.get("sourceIps", []))
    approvedProviderSet = {provider.lower() for provider in approvedProviders}

    for anomaly in anomalies:
        if anomaly.anomalyType == "unknown-sender":
            _explain_unknown_sender(anomaly, recordsByIp.get(anomaly.subject, []), allowedIps, approvedProviderSet)
        elif anomaly.anomalyType == "unexpected-provider":
            _explain_unexpected_provider(
                anomaly,
                parsedRecords,
                approvedProviderSet,
            )
        elif anomaly.anomalyType == "spf-failure":
            _explain_auth_failure(anomaly, recordsByDomain.get(anomaly.subject, []), "spf")
        elif anomaly.anomalyType == "dkim-failure":
            _explain_auth_failure(anomaly, recordsByDomain.get(anomaly.subject, []), "dkim")
        elif anomaly.anomalyType == "alignment-failure":
            _explain_alignment_failure(anomaly, recordsByDomain.get(anomaly.subject, []))


def _explain_unknown_sender(
    anomaly: Anomaly,
    records: list[ParsedRecord],
    allowedIps: set[str],
    approvedProviderSet: set[str],
) -> None:
    score = 55
    evidence: list[str] = []

    if not records:
        anomaly.riskLevel = "medium"
        anomaly.confidence = 0.55
        anomaly.whyThisAppeared = "IP address is new and not currently allowlisted"
        anomaly.evidence = ["No parsed records found for deep classification"]
        anomaly.recommendation = "Review manually. If expected, add IP to allowlist."
        return

    sample = records[0]
    provider = sample.senderProvider
    providerLower = provider.lower()
    rdns = sample.reverseDnsHostname

    if anomaly.subject in allowedIps:
        score -= 35
        evidence.append("IP already exists in allowlist")
    else:
        evidence.append("IP is not in allowlist")

    if providerLower in approvedProviderSet:
        score -= 20
        evidence.append(f"Provider '{provider}' is approved")
    elif providerLower != "unknown":
        evidence.append(f"Provider '{provider}' is known but not approved")
    else:
        score += 10
        evidence.append("Provider could not be classified")

    if rdns != "unresolved":
        score -= 10
        evidence.append(f"rDNS resolves to {rdns}")
    else:
        score += 10
        evidence.append("rDNS did not resolve")

    if _all_spf_pass(records):
        score -= 10
        evidence.append("SPF passes for all matching records")
    else:
        score += 15
        evidence.append("SPF has failures in matching records")

    if _all_dkim_pass(records):
        score -= 10
        evidence.append("DKIM passes for all matching records")
    else:
        score += 15
        evidence.append("DKIM has failures in matching records")

    anomaly.whyThisAppeared = "Sender IP is seen for the first time in this watchdog state"
    _finalize_risk(anomaly, score, evidence)

    if anomaly.riskLevel == "low":
        anomaly.recommendation = "Likely legitimate. Monitor and allowlist if this sender is expected."
    elif anomaly.riskLevel == "medium":
        anomaly.recommendation = "Review sender context. Allowlist only after confirming ownership and authentication."
    else:
        anomaly.recommendation = "Investigate now. Verify sender system, SPF/DKIM setup, and provider expectations."


def _explain_unexpected_provider(
    anomaly: Anomaly,
    parsedRecords: list[ParsedRecord],
    approvedProviderSet: set[str],
) -> None:
    score = 70
    evidence: list[str] = []

    providerName = anomaly.subject.split(" (", 1)[0].strip().lower()
    matchingRecords = [record for record in parsedRecords if record.senderProvider.lower() == providerName]

    if providerName in approvedProviderSet:
        score -= 35
        evidence.append("Provider is in approvedProviders but still flagged (check naming consistency)")
    else:
        evidence.append("Provider is not in approvedProviders")

    if matchingRecords and _all_spf_pass(matchingRecords) and _all_dkim_pass(matchingRecords):
        score -= 10
        evidence.append("Authentication mostly passes despite provider mismatch")
    else:
        score += 10
        evidence.append("Authentication failures present with unexpected provider")

    anomaly.whyThisAppeared = "Sender provider classification is outside approved provider list"
    _finalize_risk(anomaly, score, evidence)

    if anomaly.riskLevel == "low":
        anomaly.recommendation = "Likely new legitimate provider. Add to approvedProviders after verification."
    elif anomaly.riskLevel == "medium":
        anomaly.recommendation = "Validate whether this provider should send for your domain."
    else:
        anomaly.recommendation = "Potential abuse or misconfiguration. Investigate provider origin immediately."


def _explain_auth_failure(anomaly: Anomaly, records: list[ParsedRecord], authType: str) -> None:
    score = 60
    evidence: list[str] = []

    if authType == "spf":
        anomaly.whyThisAppeared = "SPF evaluation returned non-pass for one or more records"
        if _all_dkim_pass(records):
            score -= 15
            evidence.append("DKIM still passes, reducing spoofing likelihood")
        else:
            score += 10
            evidence.append("DKIM also has failures")
        anomaly.recommendation = "Check SPF include/redirect chain and sending IP coverage."
    else:
        anomaly.whyThisAppeared = "DKIM evaluation returned non-pass for one or more records"
        if _all_spf_pass(records):
            score -= 15
            evidence.append("SPF still passes, reducing spoofing likelihood")
        else:
            score += 10
            evidence.append("SPF also has failures")
        anomaly.recommendation = "Check DKIM selector keys and signing path for this domain."

    evidence.append(f"Affected domain: {anomaly.subject}")
    _finalize_risk(anomaly, score, evidence)


def _explain_alignment_failure(anomaly: Anomaly, records: list[ParsedRecord]) -> None:
    score = 80
    evidence = [f"Affected domain: {anomaly.subject}"]

    if records:
        evidence.append("Both SPF and DKIM are non-pass for matching records")

    anomaly.whyThisAppeared = "Both SPF and DKIM failed for the same aligned sending context"
    _finalize_risk(anomaly, score, evidence)
    anomaly.recommendation = "High priority: verify DMARC/SPF/DKIM DNS setup and investigate potential spoofing."


def _all_spf_pass(records: list[ParsedRecord]) -> bool:
    if not records:
        return False
    return all(record.spfResult.lower() == "pass" for record in records)


def _all_dkim_pass(records: list[ParsedRecord]) -> bool:
    if not records:
        return False
    return all(record.dkimResult.lower() == "pass" for record in records)


def _finalize_risk(anomaly: Anomaly, rawScore: int, evidence: list[str]) -> None:
    score = max(5, min(95, rawScore))
    anomaly.confidence = score / 100
    anomaly.evidence = evidence

    if score <= 30:
        anomaly.riskLevel = "low"
    elif score <= 65:
        anomaly.riskLevel = "medium"
    else:
        anomaly.riskLevel = "high"
