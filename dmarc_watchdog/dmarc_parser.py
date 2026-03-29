from __future__ import annotations

from io import BytesIO
from zipfile import ZipFile
import gzip
from xml.etree import ElementTree

from .models import ParsedRecord


def extract_xml_documents(attachmentName: str, attachmentBytes: bytes) -> list[bytes]:
    lowerName = attachmentName.lower()

    if lowerName.endswith(".xml"):
        return [attachmentBytes]

    if lowerName.endswith(".gz"):
        return [gzip.decompress(attachmentBytes)]

    if lowerName.endswith(".zip"):
        xmlDocuments: list[bytes] = []
        with ZipFile(BytesIO(attachmentBytes)) as zipFile:
            for zipEntry in zipFile.namelist():
                if zipEntry.lower().endswith(".xml"):
                    xmlDocuments.append(zipFile.read(zipEntry))
        return xmlDocuments

    return []


def parse_dmarc_xml(xmlBytes: bytes) -> list[ParsedRecord]:
    root = ElementTree.fromstring(xmlBytes)

    reporterOrganization = _read_text(root, "./report_metadata/org_name", "unknown")
    reportBeginEpoch = int(_read_text(root, "./report_metadata/date_range/begin", "0"))
    reportEndEpoch = int(_read_text(root, "./report_metadata/date_range/end", "0"))

    parsedRecords: list[ParsedRecord] = []
    for recordElement in root.findall("./record"):
        sourceIp = _read_text(recordElement, "./row/source_ip", "unknown")
        messageCount = int(_read_text(recordElement, "./row/count", "0"))

        spfResult = _read_text(recordElement, "./row/policy_evaluated/spf", "unknown")
        dkimResult = _read_text(recordElement, "./row/policy_evaluated/dkim", "unknown")
        disposition = _read_text(recordElement, "./row/policy_evaluated/disposition", "unknown")

        headerFromDomain = _read_text(recordElement, "./identifiers/header_from", "unknown")

        parsedRecords.append(
            ParsedRecord(
                reporterOrganization=reporterOrganization,
                reportBeginEpoch=reportBeginEpoch,
                reportEndEpoch=reportEndEpoch,
                sourceIp=sourceIp,
                headerFromDomain=headerFromDomain,
                messageCount=messageCount,
                spfResult=spfResult,
                dkimResult=dkimResult,
                disposition=disposition,
            )
        )

    return parsedRecords


def _read_text(element, xpath: str, defaultValue: str) -> str:
    found = element.find(xpath)
    if found is None or found.text is None:
        return defaultValue
    return found.text.strip() or defaultValue
