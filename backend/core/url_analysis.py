import ipaddress
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "quest", "country", "stream"}


def analyze_urls(urls: list[str]) -> list[dict]:
    return [_analyze_url(url) for url in urls]


def _analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    final_url, redirect_chain, redirect_error = _expand_redirects(url)
    resolved_ips = _resolve_domain(domain)
    flags = _reputation_flags(url, domain, resolved_ips, redirect_chain)

    return {
        "url": url,
        "scheme": parsed.scheme.lower(),
        "domain": domain,
        "path": parsed.path or "/",
        "resolved_ips": resolved_ips,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "redirect_error": redirect_error,
        "flags": flags,
        "risk": "suspicious" if flags else "clean",
    }


def _reputation_flags(url: str, domain: str, resolved_ips: list[str], redirect_chain: list[str]) -> list[str]:
    flags = []
    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        flags.append("non_https")
    if _is_ip_literal(domain):
        flags.append("ip_literal")
    if domain in SHORTENER_DOMAINS:
        flags.append("url_shortener")
    if domain.startswith("xn--") or ".xn--" in domain:
        flags.append("punycode_domain")
    if _tld(domain) in SUSPICIOUS_TLDS:
        flags.append("suspicious_tld")
    if domain.count(".") >= 4:
        flags.append("many_subdomains")
    if domain and not resolved_ips:
        flags.append("unresolved_domain")
    if len(redirect_chain) > 3:
        flags.append("long_redirect_chain")

    return flags


def _expand_redirects(url: str, max_redirects: int = 5) -> tuple[str, list[str], str]:
    opener = build_opener(_NoRedirectHandler)
    current = url
    chain = [url]

    for _ in range(max_redirects):
        request = Request(current, method="HEAD", headers={"User-Agent": "EML-Analyzer/0.1"})
        try:
            opener.open(request, timeout=4)
            return current, chain, ""
        except HTTPError as exc:
            if exc.code not in {301, 302, 303, 307, 308}:
                return current, chain, f"HTTP {exc.code}"

            location = exc.headers.get("Location")
            if not location:
                return current, chain, "Redirect without Location header"

            current = exc.url if location == current else _join_redirect(current, location)
            chain.append(current)
        except (OSError, URLError) as exc:
            return current, chain, str(exc)

    return current, chain, "Maximum redirect depth reached"


def _join_redirect(current: str, location: str) -> str:
    from urllib.parse import urljoin

    return urljoin(current, location)


def _resolve_domain(domain: str) -> list[str]:
    if not domain:
        return []
    if _is_ip_literal(domain):
        return [domain]

    try:
        results = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []

    return sorted({item[4][0] for item in results if item[4]})


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[1] if len(parts) == 2 else ""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
