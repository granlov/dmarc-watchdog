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
    searchCriterion: str


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
    alertOnSpfFailure: bool
    alertOnDkimFailure: bool
    alertOnAlignmentFailure: bool


@dataclass
class AppConfig:
    runtime: RuntimeConfig
    paths: PathConfig
    imap: ImapConfig
    rules: RuleConfig


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
    imap = ImapConfig(**parsedJson["imap"])
    rules = RuleConfig(**parsedJson["rules"])

    return AppConfig(runtime=runtime, paths=paths, imap=imap, rules=rules)


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
