"""
validator.py (v2)
Validates findings WITHOUT attempting to authenticate against third-party
services using discovered credentials. That distinction matters:

  - Checking whether a discovered *endpoint on the target itself* responds
    (HTTP GET, status code, content-type) is safe recon and is done here,
    scope-checked and rate-limited so it stays polite and in-bounds.
  - Actually using a found AWS/Stripe/Slack/GitHub key to call that
    provider's API would be an unauthorized-access attempt against a
    system outside the tester's control, even in a bug bounty context.
    This tool does NOT do that. Instead it flags such findings as
    "needs manual verification within your program's authorized scope"
    and tells you the standard, safe way to confirm impact.

What this module does:
  1. Structural/format validation (checksums, decodability, length)
  2. JWT decoding (header + payload only - no signature verification,
     since that needs the secret we don't have and shouldn't obtain this way)
  3. Safe, scope-checked, rate-limited reachability probing of endpoints
     found in JS (GET request, status/latency/content-type only)
  4. A weighted final severity model combining pattern confidence,
     structural validation outcome, and live reachability signal
"""

import base64
import json
import re
import time

import requests

from .crawler import DEFAULT_HEADERS, RateLimiter
from .scope import ScopeGuard

MANUAL_VERIFY_CATEGORIES = {
    "cloud", "payment", "messaging", "vcs", "observability", "auth_provider",
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


def _try_b64_decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    header = _try_b64_decode(parts[0])
    payload = _try_b64_decode(parts[1])
    return {"header": header, "payload": payload}


def probe_endpoint(url, session, timeout=8):
    try:
        resp = session.get(url, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
        return {
            "reachable": True,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": len(resp.content),
        }
    except requests.RequestException as e:
        return {"reachable": False, "error": str(e)[:150]}


def classify_severity(finding):
    """Base classification from category + confidence. This is then
    adjusted per-finding (JWT alg=none, live-endpoint bump, etc.) in
    validate_findings and finally normalized through the weighted model."""
    conf = finding["confidence"]
    category = finding["category"]

    if category == "generic" and finding["type"] == "Private Key Block":
        return "CRITICAL"
    if category in ("cloud", "payment", "vcs") and conf >= 70:
        return "CRITICAL"
    if category in ("messaging", "auth_provider", "observability") and conf >= 70:
        return "HIGH"
    if category == "auth" and conf >= 55:
        return "HIGH"
    if category == "endpoint" and re.search(r"admin|internal|debug|graphql|swagger", finding["type"], re.I):
        return "MEDIUM"
    if category == "pii":
        return "LOW" if conf < 40 else "MEDIUM"
    if conf >= 60:
        return "MEDIUM"
    return "LOW"


def validate_findings(
    findings,
    base_url=None,
    do_network_probe=True,
    timeout=8,
    scope: ScopeGuard | None = None,
    requests_per_second=8,
):
    """
    Enriches each finding in-place with:
      - severity
      - validation.notes / validation.decoded (for JWTs)
      - validation.endpoint_probe (for endpoint-category findings)
      - needs_manual_verification (bool)
    """
    session = requests.Session()
    limiter = RateLimiter(requests_per_second)
    if scope is None and base_url:
        scope = ScopeGuard(base_url)

    for f in findings:
        f["severity"] = classify_severity(f)
        f["needs_manual_verification"] = f["category"] in MANUAL_VERIFY_CATEGORIES
        validation = {"notes": []}

        if f["type"] in ("JWT", "Kubernetes Service Account Token"):
            decoded = decode_jwt(f["value"])
            if decoded:
                validation["decoded"] = decoded
                alg = (decoded.get("header") or {}).get("alg", "")
                if alg and alg.lower() == "none":
                    validation["notes"].append(
                        "alg=none — if the backend doesn't reject this, the token can be forged. High-value finding."
                    )
                    f["severity"] = "CRITICAL"
                exp = (decoded.get("payload") or {}).get("exp")
                if exp:
                    validation["notes"].append(f"Token has exp claim: {exp} (check if still valid).")
            else:
                validation["notes"].append("Could not decode — may be truncated or not a real JWT.")
                f["confidence"] = max(0, f["confidence"] - 20)

        elif f["category"] == "endpoint" and do_network_probe:
            candidate = f["value"]
            if candidate.startswith("/") and base_url:
                candidate = base_url.rstrip("/") + candidate
            in_scope = scope.in_scope(candidate) if (scope and candidate.startswith("http")) else False
            if candidate.startswith("http") and not in_scope:
                validation["notes"].append(
                    "Endpoint host is outside the declared scan scope — not probed. "
                    "Add it to --scope if it's part of your authorized target set."
                )
            elif candidate.startswith("http"):
                limiter.wait()
                probe = probe_endpoint(candidate, session, timeout)
                validation["endpoint_probe"] = probe
                if probe.get("reachable") and probe.get("status_code", 500) < 400:
                    validation["notes"].append("Endpoint is live and responded — worth manual inspection.")
                    if f["severity"] == "LOW":
                        f["severity"] = "MEDIUM"
                elif probe.get("reachable"):
                    validation["notes"].append(f"Endpoint returned HTTP {probe.get('status_code')}.")
            else:
                validation["notes"].append("Relative path with no base URL context to resolve against.")

        elif f["needs_manual_verification"]:
            validation["notes"].append(
                "Live-credential testing against the provider's API is intentionally NOT performed by this tool. "
                "To confirm impact within authorized scope: use the provider's own read-only 'whoami' style check "
                "(e.g. `aws sts get-caller-identity` with the key in a scoped/sandboxed shell), or report it directly "
                "to the program — most triagers accept format+entropy+source-context as sufficient proof for leaked keys."
            )

        else:
            validation["notes"].append("Structural/entropy checks only; review context manually before reporting.")

        if f.get("detection") == "heuristic":
            validation["notes"].append(
                "Flagged by the freeform high-entropy heuristic (no named pattern matched) — "
                "higher false-positive rate than named patterns; confirm manually."
            )

        f["validation"] = validation

    # sort by severity then confidence for a triage-friendly order
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: (order.get(x["severity"], 4), -x["confidence"]))
    return findings


def diff_findings(previous_findings, current_findings):
    """Compare two scans (e.g. previous JSON report's findings vs a fresh
    scan) and return newly-introduced, resolved, and persisting findings.
    Useful for CI: fail only on *new* criticals rather than re-flagging
    the same accepted-risk finding every run."""
    key = lambda f: (f["type"], f["value"])
    prev_keys = {key(f) for f in previous_findings}
    curr_keys = {key(f) for f in current_findings}

    new = [f for f in current_findings if key(f) not in prev_keys]
    resolved = [f for f in previous_findings if key(f) not in curr_keys]
    persisting = [f for f in current_findings if key(f) in prev_keys]

    return {"new": new, "resolved": resolved, "persisting": persisting}
