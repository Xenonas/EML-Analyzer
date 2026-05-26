from collections import defaultdict
from email import policy
from email.parser import BytesParser
import hashlib
from pathlib import PurePath
import re


def get_email_headers(email_file):
    """
    Extract email headers from a binary file-like object.

    Returns a dictionary keyed by lowercase header name, where each value is
    a list of header values. This preserves repeated headers such as Received
    and Authentication-Results and makes lookups case-insensitive.
    """
    msg = BytesParser(policy=policy.default).parse(email_file)

    headers = defaultdict(list)
    for name, value in msg.raw_items():
        headers[name.lower()].append(str(value).strip())

    return dict(headers)


RISKY_ATTACHMENT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".exe",
    ".hta",
    ".iso",
    ".jar",
    ".js",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
    ".wsf",
    ".zip",
}


URL_PATTERN = re.compile(r"https?://[^\s<>'\"()]+", flags=re.IGNORECASE)
HREF_PATTERN = re.compile(r"""href=["']([^"']+)["']""", flags=re.IGNORECASE)


def get_email_headers_body_attachments_and_urls(email_file):
    msg = BytesParser(policy=policy.default).parse(email_file)
    headers = defaultdict(list)
    for name, value in msg.raw_items():
        headers[name.lower()].append(str(value).strip())

    return dict(headers), _extract_body_text(msg), _extract_attachments(msg), _extract_urls(msg)


def get_email_headers_body_and_attachments(email_file):
    headers, body, attachments, _urls = get_email_headers_body_attachments_and_urls(email_file)
    return headers, body, attachments


def get_email_headers_and_body(email_file):
    headers, body, _attachments = get_email_headers_body_and_attachments(email_file)
    return headers, body


def _extract_body_text(message) -> str:
    plain_part = _find_body_part(message, "text/plain")
    if plain_part:
        return _decode_part(plain_part)

    html_part = _find_body_part(message, "text/html")
    if html_part:
        return _html_to_text(_decode_part(html_part))

    payload = message.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload.decode(message.get_content_charset() or "utf-8", errors="replace").strip()

    if isinstance(payload, str):
        return payload.strip()

    return ""


def _find_body_part(message, content_type: str):
    if message.get_content_type() == content_type and not _is_attachment(message):
        return message

    if not message.is_multipart():
        return None

    for part in message.walk():
        if part.get_content_type() == content_type and not _is_attachment(part):
            return part

    return None


def _is_attachment(part) -> bool:
    return part.get_content_disposition() == "attachment"


def _decode_part(part) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = part.get_payload()

    if isinstance(payload, bytes):
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace").strip()

    return str(payload).strip()


def _html_to_text(value: str) -> str:
    without_scripts = re.sub(r"<(script|style).*?</\1>", "", value, flags=re.IGNORECASE | re.DOTALL)
    with_breaks = re.sub(r"</(p|div|br|li|tr|h[1-6])>", "\n", without_scripts, flags=re.IGNORECASE)
    without_tags = re.sub(r"<[^>]+>", "", with_breaks)
    return re.sub(r"\n{3,}", "\n\n", without_tags).strip()


def _extract_attachments(message) -> list[dict]:
    attachments = []
    for index, part in enumerate(message.walk(), start=1):
        filename = part.get_filename()
        if not filename and not _is_attachment(part):
            continue

        payload = part.get_payload(decode=True) or b""
        extension = PurePath(filename or "").suffix.lower()
        risky = extension in RISKY_ATTACHMENT_EXTENSIONS

        attachments.append(
            {
                "index": index,
                "filename": filename or f"attachment-{index}",
                "content_type": part.get_content_type(),
                "content_disposition": part.get_content_disposition() or "",
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "extension": extension,
                "risk": "risky_extension" if risky else "none",
                "risky": risky,
            }
        )

    return attachments


def _extract_urls(message) -> list[str]:
    urls = set()
    for part in message.walk():
        if _is_attachment(part):
            continue
        if not part.get_content_type().startswith("text/"):
            continue

        text = _decode_part(part)
        for match in URL_PATTERN.findall(text):
            urls.add(_clean_url(match))
        if part.get_content_type() == "text/html":
            for href in HREF_PATTERN.findall(text):
                if href.lower().startswith(("http://", "https://")):
                    urls.add(_clean_url(href))

    return sorted(url for url in urls if url)


def _clean_url(value: str) -> str:
    return value.strip().rstrip(".,;:!?]}")
