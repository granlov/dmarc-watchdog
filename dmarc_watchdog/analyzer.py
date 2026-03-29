from collections import defaultdict

from .models import Anomaly, ParsedRecord


def detect_anomalies(
    parsedRecords: list[ParsedRecord],
    allowlist: dict[str, list[str]],
    alertOnUnknownSender: bool,
    alertOnSpfFailure: bool,
    alertOnDkimFailure: bool,
    alertOnAlignmentFailure: bool,
) -> list[Anomaly]:
    anomalies: list[Anomaly] = []

    unknownSenderCounts: dict[str, int] = defaultdict(int)
    spfFailureCounts: dict[str, int] = defaultdict(int)
    dkimFailureCounts: dict[str, int] = defaultdict(int)
    alignmentFailureCounts: dict[str, int] = defaultdict(int)

    allowedIps = set(allowlist.get("sourceIps", []))
    allowedDomains = set(allowlist.get("headerFromDomains", []))

    for record in parsedRecords:
        if alertOnUnknownSender:
            isKnownIp = record.sourceIp in allowedIps
            isKnownDomain = record.headerFromDomain in allowedDomains
            if not isKnownIp and not isKnownDomain:
                unknownSenderCounts[record.sourceIp] += record.messageCount

        if alertOnSpfFailure and record.spfResult.lower() != "pass":
            spfFailureCounts[record.headerFromDomain] += record.messageCount

        if alertOnDkimFailure and record.dkimResult.lower() != "pass":
            dkimFailureCounts[record.headerFromDomain] += record.messageCount

        if alertOnAlignmentFailure:
            spfFailed = record.spfResult.lower() != "pass"
            dkimFailed = record.dkimResult.lower() != "pass"
            if spfFailed and dkimFailed:
                alignmentFailureCounts[record.headerFromDomain] += record.messageCount

    anomalies.extend(_build_anomalies("unknown-sender", "New sender", unknownSenderCounts))
    anomalies.extend(_build_anomalies("spf-failure", "SPF fail", spfFailureCounts))
    anomalies.extend(_build_anomalies("dkim-failure", "DKIM fail", dkimFailureCounts))
    anomalies.extend(_build_anomalies("alignment-failure", "Alignment fail", alignmentFailureCounts))

    return anomalies


def _build_anomalies(
    anomalyType: str,
    label: str,
    countsByKey: dict[str, int],
) -> list[Anomaly]:
    items: list[Anomaly] = []
    for key, count in sorted(countsByKey.items(), key=lambda item: item[1], reverse=True):
        items.append(Anomaly(anomalyType=anomalyType, message=f"{label}: {key} ({count} messages)"))
    return items
