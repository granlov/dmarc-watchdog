from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
    searchCriterion: str,
    lookbackHours: int,
) -> list[MailPayload]:
    nowUtc = datetime.now(timezone.utc)
    sinceDate = (nowUtc - timedelta(hours=lookbackHours)).strftime("%d-%b-%Y")

    with imaplib.IMAP4_SSL(host=host, port=port) as mailboxConnection:
        mailboxConnection.login(username, password)
        mailboxConnection.select(mailbox)

        searchQuery = f'({searchCriterion} SINCE "{sinceDate}")'
        status, messageIdBlocks = mailboxConnection.search(None, searchQuery)
        if status != "OK":
            return []

        payloads: list[MailPayload] = []
        for messageSequence in messageIdBlocks[0].split():
            fetchStatus, rawMessageData = mailboxConnection.fetch(messageSequence, "(RFC822)")
            if fetchStatus != "OK" or not rawMessageData:
                continue

            rawMessage = rawMessageData[0][1]
            parsedMessage = email.message_from_bytes(rawMessage)
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
