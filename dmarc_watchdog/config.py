import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ImapConfig:
    host: str
    port: int
    username: str
    password: str
    mailbox: str
    filterSubjectContains: list[str]
    filterFromContains: list[str]
    filterToContains: list[str]
    legacySearchCriterion: str


@dataclass
class RuntimeConfig:
    mode: str
    lookbackHours: int


@dataclass
class PathConfig:
    stateFile: str
    allowlistFile: str
    localReportDirectory: str


@dataclass
class RuleConfig:
    alertOnUnknownSender: bool
    alertOnUnexpectedProvider: bool
    alertOnSpfFailure: bool
    alertOnDkimFailure: bool
    alertOnAlignmentFailure: bool


@dataclass
class SenderIdentityConfig:
    enableReverseDns: bool
    approvedProviders: list[str]
    providerHostnamePatterns: dict[str, list[str]]


@dataclass
class AppConfig:
    runtime: RuntimeConfig
    paths: PathConfig
    imap: ImapConfig
    rules: RuleConfig
    senderIdentity: SenderIdentityConfig


class ConfigurationError(Exception):
    pass


def load_app_config(configFilePath: str) -> AppConfig:
    configPath = Path(configFilePath)
    if not configPath.exists():
        raise ConfigurationError(f"Config file not found: {configFilePath}")

    with configPath.open("r", encoding="utf-8") as configFile:
        parsedJson: dict[str, Any] = json.load(configFile)

    runtime = RuntimeConfig(**parsedJson["runtime"])
    paths = PathConfig(**parsedJson["paths"])
    parsedImap = parsedJson["imap"]
    imap = ImapConfig(
        host=parsedImap["host"],
        port=parsedImap["port"],
        username=parsedImap["username"],
        password=parsedImap["password"],
        mailbox=parsedImap["mailbox"],
        filterSubjectContains=parsedImap.get(
            "filterSubjectContains",
            ["dmarc", "aggregate"],
        ),
        filterFromContains=parsedImap.get("filterFromContains", []),
        filterToContains=parsedImap.get("filterToContains", []),
        # Backward compatibility only. Runtime no longer depends on unread state.
        legacySearchCriterion=parsedImap.get("searchCriterion", "UNSEEN"),
    )

    parsedRules = parsedJson.get("rules", {})
    rules = RuleConfig(
        alertOnUnknownSender=parsedRules.get("alertOnUnknownSender", True),
        alertOnUnexpectedProvider=parsedRules.get("alertOnUnexpectedProvider", True),
        alertOnSpfFailure=parsedRules.get("alertOnSpfFailure", True),
        alertOnDkimFailure=parsedRules.get("alertOnDkimFailure", True),
        alertOnAlignmentFailure=parsedRules.get("alertOnAlignmentFailure", True),
    )

    parsedSenderIdentity = parsedJson.get("senderIdentity", {})
    senderIdentity = SenderIdentityConfig(
        enableReverseDns=parsedSenderIdentity.get("enableReverseDns", True),
        approvedProviders=parsedSenderIdentity.get("approvedProviders", ["one.com", "shopify"]),
        providerHostnamePatterns=parsedSenderIdentity.get(
            "providerHostnamePatterns",
            {
                "one.com": ["one.com"],
                "shopify": ["shopify", "sendgrid.net"],
            },
        ),
    )

    return AppConfig(
        runtime=runtime,
        paths=paths,
        imap=imap,
        rules=rules,
        senderIdentity=senderIdentity,
    )


def load_allowlist(allowlistFilePath: str) -> dict[str, list[str]]:
    path = Path(allowlistFilePath)
    if not path.exists():
        return {"sourceIps": [], "headerFromDomains": []}

    with path.open("r", encoding="utf-8") as fileHandle:
        parsed = json.load(fileHandle)

    return {
        "sourceIps": parsed.get("sourceIps", []),
        "headerFromDomains": parsed.get("headerFromDomains", []),
    }
