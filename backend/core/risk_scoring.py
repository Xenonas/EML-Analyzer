from email.utils import parseaddr

from publicsuffix2 import get_sld


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def score_risk(
    *,
    authentication: dict,
    attachments: list[dict],
    urls: list[dict],
    sender: str,
    return_path: str,
    received_path: list[str],
) -> dict:
    findings = []

    _score_authentication(authentication or {}, findings)
    _score_attachments(attachments or [], findings)
    _score_urls(urls or [], findings)
    _score_sender_alignment(sender, return_path, findings)
    _score_received_path(received_path or [], findings)

    score = min(sum(finding["points"] for finding in findings), 100)
    severity = _severity_from_score(score)

    return {
        "score": score,
        "severity": severity,
        "findings": sorted(
            findings,
            key=lambda finding: (-SEVERITY_ORDER.get(finding["severity"], 0), -finding["points"], finding["title"]),
        ),
        "signals": {
            "authentication_findings": len([item for item in findings if item["category"] == "authentication"]),
            "attachment_findings": len([item for item in findings if item["category"] == "attachments"]),
            "url_findings": len([item for item in findings if item["category"] == "urls"]),
            "routing_findings": len([item for item in findings if item["category"] in {"sender", "routing"}]),
        },
    }


def _score_authentication(authentication: dict, findings: list[dict]) -> None:
    auth_rules = {
        "dmarc": {
            "fail": (32, "high", "DMARC failed", "DMARC alignment failed for the visible From domain."),
            "none": (12, "medium", "No DMARC policy", "The From domain does not publish a DMARC record."),
            "temperror": (8, "low", "DMARC temporary error", "DMARC verification could not complete cleanly."),
            "permerror": (12, "medium", "DMARC permanent error", "The DMARC record or lookup returned a permanent error."),
        },
        "dkim": {
            "fail": (22, "high", "DKIM failed", "A DKIM signature was present but did not verify."),
            "temperror": (8, "low", "DKIM temporary error", "DKIM verification could not complete cleanly."),
            "permerror": (12, "medium", "DKIM permanent error", "DKIM verification returned a permanent error."),
        },
        "spf": {
            "fail": (18, "medium", "SPF failed", "The sending host was not authorized for the envelope sender."),
            "softfail": (12, "medium", "SPF softfail", "The SPF policy suggests the sender is probably not authorized."),
            "temperror": (6, "low", "SPF temporary error", "SPF verification could not complete cleanly."),
            "permerror": (10, "medium", "SPF permanent error", "The SPF record or lookup returned a permanent error."),
        },
    }

    for mechanism, rules in auth_rules.items():
        status = authentication.get(mechanism) or {}
        result = str(status.get("result") or "unknown").lower()
        if result not in rules:
            continue

        points, severity, title, details = rules[result]
        findings.append(
            _finding(
                f"auth.{mechanism}.{result}",
                "authentication",
                title,
                severity,
                points,
                details,
                {
                    "mechanism": mechanism.upper(),
                    "result": result,
                    "source": status.get("source", ""),
                    "details": status.get("details", ""),
                },
            )
        )


def _score_attachments(attachments: list[dict], findings: list[dict]) -> None:
    risky = [attachment for attachment in attachments if attachment.get("risky")]
    if not risky:
        return

    filenames = [attachment.get("filename") or "unnamed attachment" for attachment in risky[:5]]
    points = min(30 + (len(risky) - 1) * 8, 46)
    findings.append(
        _finding(
            "attachments.risky_extension",
            "attachments",
            "Risky attachment type",
            "high",
            points,
            "One or more attachments use extensions commonly abused for malware delivery.",
            {
                "count": len(risky),
                "filenames": filenames,
            },
        )
    )


def _score_urls(urls: list[dict], findings: list[dict]) -> None:
    suspicious = [url for url in urls if url.get("risk") == "suspicious" or url.get("flags")]
    if not suspicious:
        return

    flag_counts = {}
    for item in suspicious:
        for flag in item.get("flags") or []:
            flag_counts[flag] = flag_counts.get(flag, 0) + 1

    points = min(18 + (len(suspicious) - 1) * 6 + len(flag_counts) * 3, 42)
    findings.append(
        _finding(
            "urls.suspicious",
            "urls",
            "Suspicious URL indicators",
            "medium" if points < 30 else "high",
            points,
            "The message contains URLs with suspicious traits such as shorteners, unsafe schemes, or unresolved domains.",
            {
                "count": len(suspicious),
                "flags": flag_counts,
                "domains": sorted({item.get("domain") for item in suspicious if item.get("domain")})[:8],
            },
        )
    )


def _score_sender_alignment(sender: str, return_path: str, findings: list[dict]) -> None:
    from_domain = _organizational_domain(_domain_from_email(sender))
    return_path_domain = _organizational_domain(_domain_from_email(return_path))

    if not from_domain or not return_path_domain or from_domain == return_path_domain:
        return

    findings.append(
        _finding(
            "sender.return_path_mismatch",
            "sender",
            "Sender and Return-Path differ",
            "medium",
            14,
            "The visible From domain and envelope Return-Path domain do not share the same organizational domain.",
            {
                "from_domain": from_domain,
                "return_path_domain": return_path_domain,
            },
        )
    )


def _score_received_path(received_path: list[str], findings: list[dict]) -> None:
    hop_count = len(received_path)
    if hop_count < 6:
        return

    findings.append(
        _finding(
            "routing.long_received_path",
            "routing",
            "Long received path",
            "low",
            min(5 + (hop_count - 6), 10),
            "The message traversed more mail relays than usual for a simple delivery path.",
            {"hops": hop_count},
        )
    )


def _finding(
    finding_id: str,
    category: str,
    title: str,
    severity: str,
    points: int,
    details: str,
    evidence: dict,
) -> dict:
    return {
        "id": finding_id,
        "category": category,
        "title": title,
        "severity": severity,
        "points": points,
        "details": details,
        "evidence": evidence,
    }


def _severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _domain_from_email(value: str) -> str:
    address = parseaddr(value or "")[1].lower()
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip(" .")


def _organizational_domain(domain: str) -> str:
    if not domain:
        return ""
    return (get_sld(domain) or domain).lower()
