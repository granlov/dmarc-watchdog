from dataclasses import dataclass


@dataclass
class ParsedRecord:
    reporterOrganization: str
    reportBeginEpoch: int
    reportEndEpoch: int
    sourceIp: str
    headerFromDomain: str
    messageCount: int
    spfResult: str
    dkimResult: str
    disposition: str
    reverseDnsHostname: str = "unresolved"
    senderProvider: str = "unknown"


@dataclass
class Anomaly:
    anomalyType: str
    message: str
