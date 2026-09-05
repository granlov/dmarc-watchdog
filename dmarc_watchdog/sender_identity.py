import socket
import time

from .models import ParsedRecord


REVERSE_DNS_ATTEMPTS = 2
REVERSE_DNS_RETRY_DELAY_SECONDS = 0.5


def enrich_sender_identity(
    parsedRecords: list[ParsedRecord],
    providerHostnamePatterns: dict[str, list[str]],
    enableReverseDns: bool,
) -> None:
    hostnameByIp: dict[str, str] = {}
    providerByIp: dict[str, str] = {}

    for record in parsedRecords:
        if record.sourceIp not in hostnameByIp:
            resolvedHostname = _resolve_reverse_dns(record.sourceIp, enableReverseDns)
            hostnameByIp[record.sourceIp] = resolvedHostname
            providerByIp[record.sourceIp] = _classify_provider(
                resolvedHostname,
                providerHostnamePatterns,
            )

        record.reverseDnsHostname = hostnameByIp[record.sourceIp]
        record.senderProvider = providerByIp[record.sourceIp]


def _resolve_reverse_dns(sourceIp: str, enableReverseDns: bool) -> str:
    if not enableReverseDns:
        return "disabled"

    # A single transient PTR failure would misclassify a known sender as "unknown"
    # and raise a false unexpected-provider alert, so retry once before giving up.
    for attempt in range(REVERSE_DNS_ATTEMPTS):
        try:
            resolvedHostname, _, _ = socket.gethostbyaddr(sourceIp)
            return resolvedHostname.lower()
        except Exception:
            if attempt < REVERSE_DNS_ATTEMPTS - 1:
                time.sleep(REVERSE_DNS_RETRY_DELAY_SECONDS)

    return "unresolved"


def _classify_provider(
    resolvedHostname: str,
    providerHostnamePatterns: dict[str, list[str]],
) -> str:
    if resolvedHostname in {"unresolved", "disabled"}:
        return "unknown"

    hostnameLower = resolvedHostname.lower()
    for providerName, patterns in providerHostnamePatterns.items():
        for pattern in patterns:
            if pattern.lower() in hostnameLower:
                return providerName

    return "unknown"
