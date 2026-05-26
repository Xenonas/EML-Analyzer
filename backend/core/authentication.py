import re


AUTH_RESULT_VALUES = {
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
    "policy",
}


def extract_authentication_statuses(auth_results: str, received_spf: str = "") -> dict:
    spf_result, spf_source = _extract_result(auth_results, "spf", received_spf)
    return {
        "spf": _build_status("SPF", spf_result, spf_source, received_spf),
        "dkim": _build_status("DKIM", *_extract_result(auth_results, "dkim"), details=""),
        "dmarc": _build_status("DMARC", *_extract_result(auth_results, "dmarc"), details=""),
    }


def _extract_result(auth_results: str, mechanism: str, fallback_header: str = "") -> tuple[str, str]:
    matches = re.findall(rf"\b{mechanism}=([a-zA-Z]+)", auth_results, flags=re.IGNORECASE)
    for match in matches:
        normalized = match.lower()
        if normalized in AUTH_RESULT_VALUES:
            return normalized, "Authentication-Results"

    fallback_match = re.match(r"\s*([a-zA-Z]+)", fallback_header)
    if fallback_match:
        normalized = fallback_match.group(1).lower()
        if normalized in AUTH_RESULT_VALUES:
            return normalized, "Received-SPF"

    return "unknown", "Not found"


def _build_status(name: str, result: str, source: str, details: str) -> dict:
    return {
        "name": name,
        "result": result,
        "passed": result == "pass",
        "source": source,
        "details": details,
    }
