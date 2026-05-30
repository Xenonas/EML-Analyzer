import base64
import ipaddress
import json
import os
import socket
from email.utils import parseaddr
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


VT_API_BASE = "https://www.virustotal.com/api/v3"
HASH_PATTERN_LENGTHS = {32, 40, 64}


def lookup_indicator(value: str) -> dict:
    normalized = _normalize_indicator(value)
    if not normalized:
        return {"error": "No lookup value provided."}

    indicator_type = _indicator_type(normalized)
    domain = normalized if indicator_type == "domain" else ""
    ip_address = normalized if indicator_type == "ip" else ""

    if indicator_type == "email":
        domain = normalized.rsplit("@", 1)[1]
    elif indicator_type == "url":
        domain = urlparse(normalized).hostname or ""

    ip_addresses = [ip_address] if ip_address else _resolve_domain(domain)
    rdap_target = ip_address or domain
    rdap = _fetch_rdap(indicator_type, rdap_target) if rdap_target else {}
    virustotal = _fetch_virustotal(indicator_type, normalized, domain, ip_address)

    return {
        "query": value,
        "normalized": normalized,
        "type": indicator_type,
        "domain": domain,
        "ip_addresses": ip_addresses,
        "rdap": rdap,
        "virustotal": virustotal,
    }


def _normalize_indicator(value: str) -> str:
    cleaned = str(value or "").strip().strip("<>,;")
    if _looks_like_url(cleaned):
        return cleaned

    _, parsed_email = parseaddr(cleaned)
    if "@" in parsed_email:
        return parsed_email.lower()

    return cleaned.lower()


def _indicator_type(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if "@" in value:
        return "email"

    if _looks_like_url(value):
        return "url"

    if len(value) in HASH_PATTERN_LENGTHS and all(char in "0123456789abcdef" for char in value.lower()):
        return "file"

    return "domain"


def _looks_like_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _resolve_domain(domain: str) -> list[str]:
    if not domain:
        return []

    try:
        results = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []

    addresses = {item[4][0] for item in results if item[4]}
    return sorted(addresses)


def _fetch_rdap(indicator_type: str, target: str) -> dict:
    if not target:
        return {}

    rdap_type = "ip" if indicator_type == "ip" else "domain"
    url = f"https://rdap.org/{rdap_type}/{target}"
    request = Request(url, headers={"Accept": "application/rdap+json, application/json"})

    try:
        with urlopen(request, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except (OSError, URLError, json.JSONDecodeError):
        return {"lookup_url": url, "available": False}

    return {
        "lookup_url": url,
        "available": True,
        "handle": payload.get("handle", ""),
        "name": payload.get("name", ""),
        "owner": _extract_owner(payload),
        "country": payload.get("country", ""),
        "registrar": _extract_registrar(payload),
        "entities": _extract_entities(payload),
    }


def _fetch_virustotal(indicator_type: str, normalized: str, domain: str, ip_address: str) -> dict:
    api_key = os.getenv("VT_KEY", "").strip()
    if not api_key:
        return {"available": False, "reason": "VT_KEY is not configured."}

    vt_type, vt_id = _virustotal_target(indicator_type, normalized, domain, ip_address)
    if not vt_type or not vt_id:
        return {"available": False, "reason": "No supported VirusTotal target for this lookup."}

    url = f"{VT_API_BASE}/{vt_type}/{vt_id}"
    request = Request(url, headers={"Accept": "application/json", "x-apikey": api_key})

    try:
        with urlopen(request, timeout=6) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except (OSError, URLError, json.JSONDecodeError) as exc:
        return {"available": False, "lookup_url": url, "error": str(exc)}

    data = payload.get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}

    return {
        "available": True,
        "lookup_url": url,
        "gui_url": _virustotal_gui_url(indicator_type, normalized, domain, ip_address),
        "object_type": data.get("type", ""),
        "id": data.get("id", vt_id),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": stats,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": attributes.get("country", ""),
        "asn": attributes.get("asn", ""),
        "as_owner": attributes.get("as_owner", ""),
        "categories": _extract_vt_categories(attributes),
    }


def _virustotal_target(indicator_type: str, normalized: str, domain: str, ip_address: str) -> tuple[str, str]:
    if indicator_type == "ip":
        return "ip_addresses", ip_address
    if indicator_type == "domain":
        return "domains", domain
    if indicator_type == "email":
        return "domains", domain
    if indicator_type == "url":
        return "urls", _virustotal_url_id(normalized)
    if indicator_type == "file":
        return "files", normalized
    return "", ""


def _virustotal_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _virustotal_gui_url(indicator_type: str, normalized: str, domain: str, ip_address: str) -> str:
    if indicator_type == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{ip_address}"
    if indicator_type in {"domain", "email"}:
        return f"https://www.virustotal.com/gui/domain/{domain}"
    if indicator_type == "url":
        return f"https://www.virustotal.com/gui/url/{_virustotal_url_id(normalized)}"
    if indicator_type == "file":
        return f"https://www.virustotal.com/gui/file/{normalized}"
    return ""


def _extract_vt_categories(attributes: dict) -> list[str]:
    categories = attributes.get("categories") or {}
    if isinstance(categories, dict):
        return sorted({str(value) for value in categories.values() if value})[:8]
    return []


def _extract_registrar(payload: dict) -> str:
    for entity in _iter_entities(payload):
        roles = set(entity.get("roles", []))
        if "registrar" in roles:
            return _entity_name(entity)
    return ""


def _extract_owner(payload: dict) -> str:
    for preferred_role in ("registrant", "administrative", "technical", "abuse"):
        for entity in _iter_entities(payload):
            roles = set(entity.get("roles", []))
            if preferred_role in roles:
                name = _entity_name(entity)
                if name:
                    return name

    for key in ("name", "handle"):
        value = str(payload.get(key) or "").strip()
        if value:
            return value

    for entity in _iter_entities(payload):
        name = _entity_name(entity)
        if name:
            return name

    return ""


def _extract_entities(payload: dict) -> list[dict]:
    entities = []
    seen = set()
    for entity in _iter_entities(payload):
        name = _entity_name(entity)
        roles = entity.get("roles", [])
        key = (name, tuple(roles))
        if key in seen:
            continue

        seen.add(key)
        entities.append(
            {
                "roles": roles,
                "name": name,
            }
        )
        if len(entities) >= 8:
            break
    return entities


def _iter_entities(payload: dict):
    for entity in payload.get("entities", []):
        yield entity
        for nested in entity.get("entities", []):
            yield nested


def _entity_name(entity: dict) -> str:
    vcard = entity.get("vcardArray", [])
    if len(vcard) < 2:
        return entity.get("handle", "")

    for item in vcard[1]:
        if len(item) >= 4 and item[0] in {"fn", "org"}:
            value = _vcard_value(item[3])
            if value:
                return value

    return entity.get("handle", "")


def _vcard_value(value) -> str:
    if isinstance(value, list):
        return " ".join(str(part).strip() for part in value if str(part).strip())
    return str(value or "").strip()
