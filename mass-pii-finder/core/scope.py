"""
scope.py
Authorization-scope enforcement.

The tool is only ever supposed to touch infrastructure the user is
authorized to test. This module turns that from a README sentence into
an actual guard rail:

  - Every scan declares an explicit scope: the target's registrable
    domain, plus any additional in-scope domains the user lists
    (common in bug bounty programs with many properties, e.g.
    "api.example.com", "*.example.com", "example-cdn.net").
  - Every URL the crawler or validator would touch (HTML pages, JS
    files, discovered endpoints, subdomains from passive recon) is
    checked against that scope before a request is made.
  - Out-of-scope URLs are recorded (so you can see what was *excluded*
    and double check your scope list) but never fetched.

This does not replace reading your program's actual scope document —
it just stops the tool from silently wandering onto a domain you never
typed in, which matters a lot once crawling/subdomain-discovery depth
increases.
"""

import re
import urllib.parse as urlparse

_WILDCARD_RE_CACHE = {}


def _registrable_suffix_match(host: str, rule: str) -> bool:
    """
    rule may be:
      - an exact host: "api.example.com"
      - a wildcard: "*.example.com" (matches any subdomain, not the bare apex)
      - a bare apex used as a suffix rule: "example.com" (matches example.com
        and any subdomain of it, which is the common bug-bounty convention)
    """
    host = host.lower().rstrip(".")
    rule = rule.lower().strip().rstrip(".")

    if rule.startswith("*."):
        suffix = rule[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    if host == rule:
        return True
    return host.endswith("." + rule)


class ScopeGuard:
    def __init__(self, primary_target_url: str, extra_scope: list | None = None,
                 allow_subdomains: bool = True):
        """
        primary_target_url: the URL the user typed in — always in scope.
        extra_scope: additional domain rules (exact / wildcard / apex-suffix).
        allow_subdomains: if True (default), the primary target's own
          registrable domain is treated as an apex-suffix rule too, so
          discovered subdomains of the SAME site are in-scope. If False,
          only the exact host typed in is in scope.
        """
        parsed = urlparse.urlparse(
            primary_target_url if "://" in primary_target_url else "https://" + primary_target_url
        )
        self.primary_host = parsed.netloc.split("@")[-1].split(":")[0].lower()
        self.rules = list(extra_scope or [])
        if allow_subdomains:
            self.rules.append(self.primary_host)
        else:
            self.rules.append(self.primary_host)  # exact-match still allowed via rule
        self._allow_subdomains = allow_subdomains
        self.excluded = []  # URLs we deliberately did not touch

    def in_scope(self, url: str) -> bool:
        try:
            host = urlparse.urlparse(url).netloc.split("@")[-1].split(":")[0].lower()
        except Exception:
            return False
        if not host:
            return False
        if not self._allow_subdomains and host == self.primary_host:
            return True
        for rule in self.rules:
            if _registrable_suffix_match(host, rule):
                return True
        return False

    def filter(self, urls):
        """Split an iterable of URLs into (in_scope, out_of_scope) lists and
        remember the excluded ones for the final report."""
        keep, drop = [], []
        for u in urls:
            if self.in_scope(u):
                keep.append(u)
            else:
                drop.append(u)
        self.excluded.extend(drop)
        return keep

    def summary(self):
        return {
            "primary_host": self.primary_host,
            "rules": self.rules,
            "subdomains_allowed": self._allow_subdomains,
            "excluded_count": len(set(self.excluded)),
            "excluded_sample": sorted(set(self.excluded))[:20],
        }
