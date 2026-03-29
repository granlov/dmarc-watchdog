from dataclasses import dataclass, field


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
    subject: str = ""
    messageCount: int = 0
    riskLevel: str = "medium"
    confidence: float = 0.5
    whyThisAppeared: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
