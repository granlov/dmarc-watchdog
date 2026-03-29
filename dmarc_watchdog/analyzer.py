from collections import defaultdict

from .models import Anomaly, ParsedRecord


def detect_anomalies(
    parsedRecords: list[ParsedRecord],
    allowlist: dict[str, list[str]],
    alertOnUnknownSender: bool,
    alertOnUnexpectedProvider: bool,
    approvedProviders: list[str],
    alertOnSpfFailure: bool,
    alertOnDkimFailure: bool,
    alertOnAlignmentFailure: bool,
) -> list[Anomaly]:
    anomalies: list[Anomaly] = []

    unknownSenderCounts: dict[tuple[str, str, str], int] = defaultdict(int)
    unexpectedProviderCounts: dict[str, int] = defaultdict(int)
    spfFailureCounts: dict[str, int] = defaultdict(int)
    dkimFailureCounts: dict[str, int] = defaultdict(int)
    alignmentFailureCounts: dict[str, int] = defaultdict(int)

    allowedIps = set(allowlist.get("sourceIps", []))
    allowedDomains = set(allowlist.get("headerFromDomains", []))
    approvedProviderSet = {provider.lower() for provider in approvedProviders}

    for record in parsedRecords:
        if alertOnUnknownSender:
            isKnownIp = record.sourceIp in allowedIps
            isKnownDomain = record.headerFromDomain in allowedDomains
            if not isKnownIp and not isKnownDomain:
                unknownSenderCounts[
                    (
                        record.sourceIp,
                        record.reverseDnsHostname,
                        record.senderProvider,
                    )
                ] += record.messageCount

        if alertOnUnexpectedProvider:
            if record.senderProvider.lower() not in approvedProviderSet:
                providerLabel = f"{record.senderProvider} ({record.reverseDnsHostname})"
                unexpectedProviderCounts[providerLabel] += record.messageCount

        if alertOnSpfFailure and record.spfResult.lower() != "pass":
            spfFailureCounts[record.headerFromDomain] += record.messageCount

        if alertOnDkimFailure and record.dkimResult.lower() != "pass":
            dkimFailureCounts[record.headerFromDomain] += record.messageCount

        if alertOnAlignmentFailure:
            spfFailed = record.spfResult.lower() != "pass"
            dkimFailed = record.dkimResult.lower() != "pass"
            if spfFailed and dkimFailed:
                alignmentFailureCounts[record.headerFromDomain] += record.messageCount

    anomalies.extend(_build_sender_anomalies(unknownSenderCounts))
    anomalies.extend(
        _build_anomalies(
            "unexpected-provider",
            "Unexpected provider",
            unexpectedProviderCounts,
        )
    )
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
        items.append(
            Anomaly(
                anomalyType=anomalyType,
                message=f"{label}: {key} ({count} messages)",
                subject=key,
                messageCount=count,
            )
        )
    return items


def _build_sender_anomalies(
    senderCounts: dict[tuple[str, str, str], int],
) -> list[Anomaly]:
    items: list[Anomaly] = []
    sortedItems = sorted(senderCounts.items(), key=lambda item: item[1], reverse=True)
    for (sourceIp, reverseDnsHostname, senderProvider), count in sortedItems:
        message = (
            f"New sender: {sourceIp} (provider: {senderProvider}, rdns: {reverseDnsHostname})"
            f" ({count} messages)"
        )
        items.append(
            Anomaly(
                anomalyType="unknown-sender",
                message=message,
                subject=sourceIp,
                messageCount=count,
            )
        )
    return items
