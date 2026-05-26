import ipaddress
import json
import socket
from email.utils import parseaddr
from urllib.error import URLError
from urllib.request import Request, urlopen


def lookup_indicator(value: str) -> dict:
    normalized = _normalize_indicator(value)
    if not normalized:
        return {"error": "No lookup value provided."}

    indicator_type = _indicator_type(normalized)
    domain = normalized if indicator_type == "domain" else ""
    ip_address = normalized if indicator_type == "ip" else ""

    if indicator_type == "email":
        domain = normalized.rsplit("@", 1)[1]

    ip_addresses = [ip_address] if ip_address else _resolve_domain(domain)
    rdap_target = ip_address or domain
    rdap = _fetch_rdap(indicator_type, rdap_target) if rdap_target else {}

    return {
        "query": value,
        "normalized": normalized,
        "type": indicator_type,
        "domain": domain,
        "ip_addresses": ip_addresses,
        "rdap": rdap,
    }


def _normalize_indicator(value: str) -> str:
    cleaned = str(value or "").strip().strip("<>,;")
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

    return "domain"


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
        "country": payload.get("country", ""),
        "registrar": _extract_registrar(payload),
        "entities": _extract_entities(payload),
    }


def _extract_registrar(payload: dict) -> str:
    for entity in payload.get("entities", []):
        roles = set(entity.get("roles", []))
        if "registrar" in roles:
            return _entity_name(entity)
    return ""


def _extract_entities(payload: dict) -> list[dict]:
    entities = []
    for entity in payload.get("entities", [])[:6]:
        entities.append(
            {
                "roles": entity.get("roles", []),
                "name": _entity_name(entity),
            }
        )
    return entities


def _entity_name(entity: dict) -> str:
    vcard = entity.get("vcardArray", [])
    if len(vcard) < 2:
        return entity.get("handle", "")

    for item in vcard[1]:
        if len(item) >= 4 and item[0] in {"fn", "org"}:
            return str(item[3])

    return entity.get("handle", "")
