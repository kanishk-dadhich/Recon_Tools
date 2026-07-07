"""
crawler.py (v2)
Given a target base URL, discover every reachable JavaScript file:
  1. Crawl in-scope HTML pages up to max_depth (v1 only pretended to —
     this version actually follows same-scope <a href> links)
  2. Parse <script src> and inline script text for JS references,
     including dynamic import()/require()/fetch() calls and webpack
     chunk-manifest objects (e.g. {123:"a1b2c3.chunk.js"})
  3. Follow JS-to-JS references (import/require/fetch of other .js files)
  4. Check for exposed sourcemaps (*.js.map) which often leak original,
     unminified source (gold for secret hunting)
  5. Probe a larger list of conventional JS/config paths
  6. Optionally enumerate subdomains via passive, public certificate-
     transparency logs (crt.sh) and add any that are still in-scope
     under the ScopeGuard rules — this is what makes discovery "mass"
     rather than single-host, while staying passive (no port scanning,
     no active subdomain brute force)

Everything here is read-only (HTTP GET) and scope-checked. No auth
bypass, no brute force beyond a short static wordlist of conventional
file names, and robots.txt is honored for the HTML-crawl phase.
"""

import time
import urllib.parse as urlparse
import urllib.robotparser as robotparser
from concurrent.futures import ThreadPoolExecutor, as_completed

import re
import requests

from .scope import ScopeGuard

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; MassPIIFinder/2.0; +authorized-recon-tool)"
}

COMMON_JS_GUESSES = [
    "/static/js/main.js", "/js/app.js", "/js/main.js", "/js/bundle.js",
    "/assets/index.js", "/assets/js/app.js", "/dist/main.js", "/dist/bundle.js",
    "/build/static/js/main.js", "/config.js", "/env.js", "/env-config.js",
    "/firebase-config.js", "/manifest.json", "/asset-manifest.json",
    "/_next/static/chunks/main.js", "/static/runtime.js", "/runtime.js",
]

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
ANCHOR_HREF_RE = re.compile(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
JS_REF_RE = re.compile(r'''["\']([^"'<>\s]+\.js(?:\?[^"'<>\s]*)?)["\']''')
DYNAMIC_IMPORT_RE = re.compile(r'''(?:import|require|fetch)\(\s*["\']([^"'<>\s]+\.js[^"'<>\s]*)["\']\s*\)''')
CHUNK_MANIFEST_RE = re.compile(r'''["\']?[a-zA-Z0-9_\-]{1,8}["\']?\s*:\s*["\']([a-zA-Z0-9_.\-\/]+\.js)["\']''')
SOURCEMAP_COMMENT_RE = re.compile(r'//# sourceMappingURL=([^\s]+)')


def _normalize(base_url, path):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urlparse.urljoin(base_url, path)


class RateLimiter:
    """Simple shared token-bucket-ish limiter so we don't hammer the
    target — polite by default, tunable via requests_per_second."""

    def __init__(self, requests_per_second=8):
        self._min_interval = 1.0 / max(0.1, requests_per_second)
        self._last = 0.0
        self._lock = None
        import threading
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self._min_interval:
                time.sleep(self._min_interval - delta)
            self._last = time.monotonic()


def _fetch(session, url, timeout=10, limiter=None, retries=1):
    for attempt in range(retries + 1):
        if limiter:
            limiter.wait()
        try:
            resp = session.get(url, headers=DEFAULT_HEADERS, timeout=timeout, verify=True)
            return resp
        except requests.RequestException:
            if attempt == retries:
                return None
            time.sleep(0.3 * (attempt + 1))
    return None


def _load_robots(session, root, timeout):
    rp = robotparser.RobotFileParser()
    try:
        resp = _fetch(session, root.rstrip("/") + "/robots.txt", timeout=timeout)
        if resp is not None and resp.status_code == 200:
            rp.parse(resp.text.splitlines())
        else:
            rp.allow_all = True
    except Exception:
        rp.allow_all = True
    return rp


def discover_subdomains_passive(root_domain, timeout=10):
    """
    Passive, public-record subdomain discovery via crt.sh certificate
    transparency search. No active probing of the discovered names is
    done here — that happens later, and only for names that pass the
    ScopeGuard. This is the same kind of lookup any browser's CT log
    viewer performs; it does not touch the target's infrastructure.
    """
    subs = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{root_domain}&output=json",
            timeout=timeout,
            headers=DEFAULT_HEADERS,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(root_domain):
                        subs.add(name)
    except Exception:
        pass
    return sorted(subs)


def discover_js_files(
    target_url,
    max_depth=2,
    max_files=150,
    timeout=10,
    scope: ScopeGuard | None = None,
    requests_per_second=8,
    enumerate_subdomains=False,
    respect_robots=True,
):
    """
    Returns a dict:
      {
        "js_files": {url: source_text, ...},
        "sourcemaps": [absolute_url, ...],
        "errors": [str, ...],
        "pages_crawled": [absolute_url, ...],
        "subdomains_found": [hostname, ...],
        "scope_excluded_sample": [url, ...],
      }
    """
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    limiter = RateLimiter(requests_per_second)

    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    if scope is None:
        scope = ScopeGuard(target_url)

    parsed_root = urlparse.urlparse(target_url)
    root = f"{parsed_root.scheme}://{parsed_root.netloc}"

    robots = _load_robots(session, root, timeout) if respect_robots else None

    def robots_allows(u):
        if robots is None:
            return True
        try:
            return robots.can_fetch(DEFAULT_HEADERS["User-Agent"], u)
        except Exception:
            return True

    found_js = set()
    sourcemaps = set()
    errors = []
    visited_html = set()
    pages_crawled = []
    to_visit_html = [target_url]

    # --- Step 1: real multi-hop, in-scope, robots-respecting HTML crawl ---
    depth = 0
    while to_visit_html and depth <= max_depth:
        next_round = []
        batch = scope.filter([u for u in to_visit_html if u not in visited_html])
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {
                pool.submit(_fetch, session, u, timeout, limiter): u
                for u in batch if robots_allows(u)
            }
            for fut in as_completed(futures):
                page_url = futures[fut]
                visited_html.add(page_url)
                resp = fut.result()
                if resp is None or resp.status_code >= 400:
                    errors.append(f"{page_url} -> " + (f"HTTP {resp.status_code}" if resp is not None else "request failed"))
                    continue
                pages_crawled.append(page_url)
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and depth > 0:
                    continue

                for match in SCRIPT_SRC_RE.findall(resp.text):
                    abs_url = _normalize(page_url, match)
                    if abs_url.split("?")[0].endswith(".js"):
                        found_js.add(abs_url.split("#")[0])

                for match in JS_REF_RE.findall(resp.text):
                    abs_url = _normalize(page_url, match)
                    if abs_url.split("?")[0].endswith(".js"):
                        found_js.add(abs_url.split("#")[0])

                for match in DYNAMIC_IMPORT_RE.findall(resp.text):
                    found_js.add(_normalize(page_url, match).split("#")[0])

                if depth < max_depth:
                    for href in ANCHOR_HREF_RE.findall(resp.text):
                        abs_href = _normalize(page_url, href)
                        if abs_href not in visited_html:
                            next_round.append(abs_href)
        to_visit_html = scope.filter(next_round)
        depth += 1

    # --- Step 2: passive subdomain discovery (optional, opt-in) ---
    subdomains_found = []
    if enumerate_subdomains:
        # naive registrable-domain guess: last two labels (fine for most
        # gTLDs; not perfect for multi-part public suffixes, but this is
        # a best-effort recon aid, not a source of truth)
        labels = parsed_root.netloc.split(".")
        root_domain = ".".join(labels[-2:]) if len(labels) >= 2 else parsed_root.netloc
        subdomains_found = discover_subdomains_passive(root_domain, timeout=timeout)
        for sub in subdomains_found:
            for scheme in ("https://",):
                candidate = f"{scheme}{sub}"
                if scope.in_scope(candidate) and candidate not in visited_html:
                    to_visit_html.append(candidate)
        # one shallow pass over newly discovered in-scope hosts for script tags
        if to_visit_html:
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {pool.submit(_fetch, session, u, timeout, limiter): u for u in to_visit_html[:40]}
                for fut in as_completed(futures):
                    page_url = futures[fut]
                    resp = fut.result()
                    if resp is not None and resp.status_code < 400:
                        pages_crawled.append(page_url)
                        for match in SCRIPT_SRC_RE.findall(resp.text):
                            abs_url = _normalize(page_url, match)
                            if abs_url.split("?")[0].endswith(".js"):
                                found_js.add(abs_url.split("#")[0])

    # --- Step 3: probe conventional JS/config paths on the primary root ---
    for guess in COMMON_JS_GUESSES:
        found_js.add(root + guess)

    # --- Step 4: fetch JS, follow one more hop of JS->JS refs, find sourcemaps ---
    def scan_js_for_refs(js_url):
        resp = _fetch(session, js_url, timeout, limiter)
        refs = set()
        sm = None
        if resp is not None and resp.status_code == 200:
            for match in JS_REF_RE.findall(resp.text):
                abs_url = _normalize(js_url, match)
                if abs_url.split("?")[0].endswith(".js"):
                    refs.add(abs_url.split("#")[0])
            for match in DYNAMIC_IMPORT_RE.findall(resp.text):
                refs.add(_normalize(js_url, match).split("#")[0])
            for match in CHUNK_MANIFEST_RE.findall(resp.text):
                refs.add(_normalize(js_url, match).split("#")[0])
            sm_match = SOURCEMAP_COMMENT_RE.search(resp.text)
            if sm_match:
                sm = _normalize(js_url, sm_match.group(1))
        return js_url, resp, refs, sm

    found_js = set(scope.filter(found_js))
    verified = {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(scan_js_for_refs, u): u for u in list(found_js)[:max_files]}
        for fut in as_completed(futures):
            js_url, resp, refs, sm_from_comment = fut.result()
            is_js = resp is not None and resp.status_code == 200 and (
                "javascript" in resp.headers.get("Content-Type", "") or js_url.endswith(".js")
            )
            if is_js:
                verified[js_url] = resp.text
                for r in scope.filter(refs):
                    found_js.add(r)
                if sm_from_comment and scope.in_scope(sm_from_comment):
                    sourcemaps.add(sm_from_comment)
                else:
                    sm_url = js_url + ".map"
                    if scope.in_scope(sm_url):
                        sm_resp = _fetch(session, sm_url, timeout=6, limiter=limiter)
                        if sm_resp is not None and sm_resp.status_code == 200 and sm_resp.text.strip().startswith("{"):
                            sourcemaps.add(sm_url)
            elif resp is not None and resp.status_code >= 400:
                pass  # guessed path simply doesn't exist, that's fine
            else:
                errors.append(f"{js_url} -> unreachable")

    # one more short pass to fetch any newly discovered refs we haven't verified
    remaining = scope.filter([u for u in found_js if u not in verified])[: max(0, max_files - len(verified))]
    if remaining:
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(_fetch, session, u, timeout, limiter): u for u in remaining}
            for fut in as_completed(futures):
                u = futures[fut]
                resp = fut.result()
                if resp is not None and resp.status_code == 200:
                    verified[u] = resp.text

    return {
        "js_files": verified,          # dict: url -> source text
        "sourcemaps": sorted(sourcemaps),
        "errors": errors,
        "pages_crawled": pages_crawled,
        "subdomains_found": subdomains_found,
        "scope_excluded_sample": sorted(set(scope.excluded))[:30],
    }
