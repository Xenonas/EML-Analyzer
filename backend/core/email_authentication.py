import ipaddress
import re
from email.utils import parseaddr

import dkim
import dns.exception
import dns.resolver
import spf
from publicsuffix2 import get_sld


def verify_email_authentication(raw_email: bytes, headers: dict) -> dict:
    context = _build_context(headers)
    spf_status = _verify_spf(context)
    dkim_status = _verify_dkim(raw_email, headers)
    dmarc_status = _verify_dmarc(context, spf_status, dkim_status)

    return {
        "spf": spf_status,
        "dkim": dkim_status,
        "dmarc": dmarc_status,
    }


def _build_context(headers: dict) -> dict:
    from_header = _get_first(headers, "from")
    return_path = _get_first(headers, "return-path")
    from_address = parseaddr(from_header)[1].lower()
    return_path_address = parseaddr(return_path)[1].lower()
    from_domain = _domain_from_email(from_address)
    mail_from_domain = _domain_from_email(return_path_address) or from_domain
    sender_ip = _extract_sender_ip(headers.get("received", []))

    return {
        "from_address": from_address,
        "from_domain": from_domain,
        "return_path_address": return_path_address,
        "mail_from_domain": mail_from_domain,
        "sender_ip": sender_ip,
        "helo_domain": _extract_helo_domain(headers.get("received", [])) or mail_from_domain,
    }


def _verify_spf(context: dict) -> dict:
    if not context["sender_ip"] or not context["mail_from_domain"]:
        return _status(
            "SPF",
            "unknown",
            "Independent SPF",
            "Cannot verify SPF without both an SMTP client IP and MAIL FROM/Return-Path domain.",
            {"sender_ip": context["sender_ip"], "mail_from_domain": context["mail_from_domain"]},
        )

    sender = context["return_path_address"] or f"postmaster@{context['mail_from_domain']}"

    try:
        result, explanation = spf.check2(
            i=context["sender_ip"],
            s=sender,
            h=context["helo_domain"] or context["mail_from_domain"],
            timeout=5,
            querytime=5,
        )
    except Exception as exc:
        return _status(
            "SPF",
            "temperror",
            "Independent SPF",
            f"SPF verification failed with an error: {exc}",
            {"sender_ip": context["sender_ip"], "mail_from_domain": context["mail_from_domain"]},
        )

    return _status(
        "SPF",
        result,
        "Independent SPF",
        explanation,
        {
            "sender_ip": context["sender_ip"],
            "mail_from_domain": context["mail_from_domain"],
            "helo_domain": context["helo_domain"],
            "note": "SMTP client IP is inferred from Received headers in uploaded EML files.",
        },
    )


def _verify_dkim(raw_email: bytes, headers: dict) -> dict:
    signatures = headers.get("dkim-signature", [])
    signing_domains = _extract_dkim_domains(signatures)

    if not signatures:
        return _status(
            "DKIM",
            "unknown",
            "Independent DKIM",
            "No DKIM-Signature header found.",
            {"signing_domains": []},
        )

    try:
        passed = bool(dkim.verify(raw_email, timeout=5))
    except Exception as exc:
        return _status(
            "DKIM",
            "temperror",
            "Independent DKIM",
            f"DKIM verification failed with an error: {exc}",
            {"signing_domains": signing_domains},
        )

    return _status(
        "DKIM",
        "pass" if passed else "fail",
        "Independent DKIM",
        "DKIM signature verified." if passed else "DKIM signature did not verify.",
        {"signing_domains": signing_domains},
    )


def _verify_dmarc(context: dict, spf_status: dict, dkim_status: dict) -> dict:
    from_domain = context["from_domain"]
    if not from_domain:
        return _status("DMARC", "unknown", "Independent DMARC", "No From domain found.", {})

    record = _fetch_dmarc_record(from_domain)
    if not record:
        return _status(
            "DMARC",
            "none",
            "Independent DMARC",
            f"No DMARC record found for {from_domain}.",
            {"from_domain": from_domain},
        )

    tags = _parse_dmarc_tags(record)
    spf_aligned = spf_status["result"] == "pass" and _domains_align(
        context["mail_from_domain"],
        from_domain,
        tags.get("aspf", "r"),
    )
    dkim_aligned = dkim_status["result"] == "pass" and any(
        _domains_align(domain, from_domain, tags.get("adkim", "r"))
        for domain in dkim_status.get("metadata", {}).get("signing_domains", [])
    )
    result = "pass" if spf_aligned or dkim_aligned else "fail"

    return _status(
        "DMARC",
        result,
        "Independent DMARC",
        "DMARC passed alignment." if result == "pass" else "DMARC failed alignment.",
        {
            "from_domain": from_domain,
            "record": record,
            "policy": tags.get("p", ""),
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
    )


def _status(name: str, result: str, source: str, details: str, metadata: dict) -> dict:
    return {
        "name": name,
        "result": result,
        "passed": result == "pass",
        "source": source,
        "details": details,
        "metadata": metadata,
    }


def _get_first(headers: dict, *names: str) -> str:
    for name in names:
        for value in headers.get(name.lower(), []):
            cleaned = str(value).strip()
            if cleaned:
                return cleaned
    return ""


def _domain_from_email(value: str) -> str:
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].strip(" .").lower()


def _extract_sender_ip(received_headers: list[str]) -> str:
    for header in reversed(received_headers):
        for candidate in _extract_ip_candidates(header):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            if not (ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local):
                return str(ip)

    return ""


def _extract_ip_candidates(value: str) -> list[str]:
    ipv4 = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)
    ipv6 = re.findall(r"\[([0-9a-fA-F:]{3,})\]", value)
    return ipv4 + ipv6


def _extract_helo_domain(received_headers: list[str]) -> str:
    if not received_headers:
        return ""

    match = re.search(r"\bfrom\s+([^\s(;]+)", received_headers[-1], flags=re.IGNORECASE)
    if match:
        return match.group(1).strip("[]").lower()
    return ""


def _extract_dkim_domains(signatures: list[str]) -> list[str]:
    domains = []
    for signature in signatures:
        match = re.search(r"(?:^|;)\s*d=([^;\s]+)", signature, flags=re.IGNORECASE)
        if match:
            domains.append(match.group(1).strip().lower())
    return domains


def _fetch_dmarc_record(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
        return ""

    for answer in answers:
        record = "".join(part.decode("utf-8", errors="replace") for part in answer.strings)
        if record.lower().startswith("v=dmarc1"):
            return record

    return ""


def _parse_dmarc_tags(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip().lower()
    return tags


def _domains_align(authenticated_domain: str, from_domain: str, mode: str) -> bool:
    if not authenticated_domain or not from_domain:
        return False

    authenticated_domain = authenticated_domain.lower()
    from_domain = from_domain.lower()
    if mode == "s":
        return authenticated_domain == from_domain

    return get_sld(authenticated_domain) == get_sld(from_domain)
