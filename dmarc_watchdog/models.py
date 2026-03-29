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


@dataclass
class Anomaly:
    anomalyType: str
    message: str
