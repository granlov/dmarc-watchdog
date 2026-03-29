from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import email
import imaplib


@dataclass
class AttachmentPayload:
    attachmentName: str
    attachmentBytes: bytes


@dataclass
class MailPayload:
    messageId: str
    attachments: list[AttachmentPayload]


def fetch_mail_payloads_from_local_directory(directoryPath: str) -> list[MailPayload]:
    payloads: list[MailPayload] = []
    directory = Path(directoryPath)
    if not directory.exists():
        return payloads

    for filePath in sorted(directory.glob("*")):
        if not filePath.is_file():
            continue
        payloads.append(
            MailPayload(
                messageId=f"local-file-{filePath.name}",
                attachments=[
                    AttachmentPayload(
                        attachmentName=filePath.name,
                        attachmentBytes=filePath.read_bytes(),
                    )
                ],
            )
        )

    return payloads


def fetch_mail_payloads_from_imap(
    host: str,
    port: int,
    username: str,
    password: str,
    mailbox: str,
    filterSubjectContains: list[str],
    filterFromContains: list[str],
    filterToContains: list[str],
    sinceUtc: datetime | None = None,
) -> list[MailPayload]:
    with imaplib.IMAP4_SSL(host=host, port=port) as mailboxConnection:
        mailboxConnection.login(username, password)
        mailboxConnection.select(mailbox)

        if sinceUtc is not None:
            searchCriterion = f'(SINCE "{sinceUtc.strftime("%d-%b-%Y")}")'
        else:
            searchCriterion = "ALL"

        # Ignore unread/read status. Deduplication is handled by attachment-hash state.
        status, messageIdBlocks = mailboxConnection.search(None, searchCriterion)
        if status != "OK":
            return []

        payloads: list[MailPayload] = []
        for messageSequence in messageIdBlocks[0].split():
            fetchStatus, rawMessageData = mailboxConnection.fetch(messageSequence, "(RFC822)")
            if fetchStatus != "OK" or not rawMessageData:
                continue

            rawMessage = rawMessageData[0][1]
            parsedMessage = email.message_from_bytes(rawMessage)
            if not _mail_matches_header_filters(
                parsedMessage=parsedMessage,
                filterSubjectContains=filterSubjectContains,
                filterFromContains=filterFromContains,
                filterToContains=filterToContains,
            ):
                continue

            messageIdHeader = parsedMessage.get("Message-ID", f"imap-{messageSequence.decode()}")

            attachments: list[AttachmentPayload] = []
            for part in parsedMessage.walk():
                if part.get_content_disposition() != "attachment":
                    continue

                fileName = part.get_filename() or "attachment.bin"
                payload = part.get_payload(decode=True)
                if payload:
                    attachments.append(
                        AttachmentPayload(attachmentName=fileName, attachmentBytes=payload)
                    )

            payloads.append(MailPayload(messageId=messageIdHeader, attachments=attachments))

        return payloads


def _mail_matches_header_filters(
    parsedMessage,
    filterSubjectContains: list[str],
    filterFromContains: list[str],
    filterToContains: list[str],
) -> bool:
    subjectHeader = (parsedMessage.get("Subject") or "").lower()
    fromHeader = (parsedMessage.get("From") or "").lower()
    toHeader = (parsedMessage.get("To") or "").lower()

    subjectMatches = _header_matches_terms(subjectHeader, filterSubjectContains)
    fromMatches = _header_matches_terms(fromHeader, filterFromContains)
    toMatches = _header_matches_terms(toHeader, filterToContains)

    return subjectMatches and fromMatches and toMatches


def _header_matches_terms(headerValue: str, terms: list[str]) -> bool:
    if not terms:
        return True

    normalizedTerms = [term.strip().lower() for term in terms if term.strip()]
    if not normalizedTerms:
        return True

    return any(term in headerValue for term in normalizedTerms)
