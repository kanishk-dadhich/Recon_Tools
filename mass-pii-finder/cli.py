#!/usr/bin/env python3
"""
Mass PII / Secret Finder — CLI (v2)

Pipeline (matches the original whiteboard flow, now with real multi-hop
crawling, scope enforcement, passive subdomain discovery, a much larger
pattern library, and multi-format reporting):

  1. Take user input (target URL) + explicit authorization confirmation
  2. Find every reachable JS file on the target (in-scope only)
  3. From discovered JS, extract API keys / tokens / endpoints / PII
  4. Validate findings (structural checks + safe, scope-checked, rate-
     limited reachability probing)
  5. Emit a triaged report (terminal, JSON/HTML/SARIF/Markdown/CSV)

Usage:
  python cli.py https://target.example.com --confirm-authorized
  python cli.py https://target.example.com --confirm-authorized --json out.json --html out.html
  python cli.py https://target.example.com --confirm-authorized --format sarif -o out.sarif
  python cli.py https://target.example.com --confirm-authorized --no-probe
  python cli.py https://target.example.com --confirm-authorized --min-severity HIGH
  python cli.py https://target.example.com --confirm-authorized --scope api.example.com --scope "*.example-cdn.net"
  python cli.py https://target.example.com --confirm-authorized --enumerate-subdomains
  python cli.py https://target.example.com --confirm-authorized --diff-against previous.json

ONLY run this against targets you are authorized to test. --confirm-authorized
is mandatory and exists to make that an explicit, deliberate step rather than
a README sentence you scroll past.
"""

import argparse
import json
import sys
import time

from core.crawler import discover_js_files
from core.extractor import run_extraction
from core.validator import validate_findings, diff_findings
from core.report import REPORT_BUILDERS
from core.scope import ScopeGuard

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

BANNER = r"""
  __  __                  ____ ___ ___   _____ _           _
 |  \/  | __ _ ___ ___   |  _ \_ _|_ _| |  ___(_)_ __   __| | ___ _ __
 | |\/| |/ _` / __/ __|  | |_) | | | |    |_ | | '_ \ / _` |/ _ \ '__|
 | |  | | (_| \__ \__ \  |  __/| | | |   |_| | | | | | (_| |  __/ |
 |_|  |_|\__,_|___/___/  |_|  |___|___|  |_(_)_|_| |_|\__,_|\___|_|
                                                                v2
 JS recon -> secret/token/PII extraction -> validation & triage
"""


def print_summary(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1
    print("\n" + "-" * 60)
    print(f"  CRITICAL: {counts['CRITICAL']}   HIGH: {counts['HIGH']}   "
          f"MEDIUM: {counts['MEDIUM']}   LOW: {counts['LOW']}")
    print("-" * 60)
    for f in findings:
        print(f"[{f['severity']:8}] {f['type']:38} conf={f['confidence']:3}  "
              f"{f['value'][:60]}")
        for note in f["validation"]["notes"]:
            print(f"           note: {note}")


def main():
    parser = argparse.ArgumentParser(description="Mass PII / Secret Finder (v2)")
    parser.add_argument("target", help="Target URL, e.g. https://example.com")
    parser.add_argument("--confirm-authorized", action="store_true", required=True,
                         help="Required. Confirms you are authorized to test this target (owner, "
                              "in-scope bug bounty program, or client engagement).")
    parser.add_argument("--json", dest="json_out", help="Write JSON report to this path")
    parser.add_argument("--html", dest="html_out", help="Write HTML report to this path")
    parser.add_argument("--format", choices=list(REPORT_BUILDERS.keys()), default=None,
                         help="Additional report format to write via -o/--output")
    parser.add_argument("-o", "--output", dest="output_path",
                         help="Output path for --format (json/html/sarif/markdown/csv)")
    parser.add_argument("--no-probe", action="store_true", help="Skip live endpoint reachability checks")
    parser.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW")
    parser.add_argument("--max-files", type=int, default=150, help="Max JS files to fetch")
    parser.add_argument("--max-depth", type=int, default=2, help="Max HTML crawl depth")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--rate-limit", type=float, default=8.0,
                         help="Max requests/second sent to the target (politeness cap)")
    parser.add_argument("--scope", action="append", default=[],
                         help="Additional in-scope domain (exact, 'sub.example.com', or "
                              "wildcard '*.example.com'). Repeatable.")
    parser.add_argument("--no-subdomains", action="store_true",
                         help="Restrict scope to the exact host typed in (no auto subdomain scope)")
    parser.add_argument("--enumerate-subdomains", action="store_true",
                         help="Passively enumerate subdomains via public CT logs (crt.sh) and "
                              "include any that fall within scope")
    parser.add_argument("--no-robots", action="store_true", help="Do not honor robots.txt during HTML crawl")
    parser.add_argument("--diff-against", dest="diff_against",
                         help="Path to a previous JSON report; only print/exit-nonzero on NEW findings")
    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Target: {args.target}")
    print(f"[*] Scope: primary host + {len(args.scope)} extra rule(s)"
          f"{' (no auto-subdomains)' if args.no_subdomains else ' (subdomains allowed)'}")

    scope = ScopeGuard(args.target, extra_scope=args.scope, allow_subdomains=not args.no_subdomains)

    print("[*] Step 1/4: discovering JS files ...")
    t0 = time.time()
    disc = discover_js_files(
        args.target,
        max_depth=args.max_depth,
        max_files=args.max_files,
        timeout=args.timeout,
        scope=scope,
        requests_per_second=args.rate_limit,
        enumerate_subdomains=args.enumerate_subdomains,
        respect_robots=not args.no_robots,
    )
    print(f"    -> {len(disc['js_files'])} JS files fetched, "
          f"{len(disc['sourcemaps'])} sourcemap(s) found, "
          f"{len(disc['pages_crawled'])} page(s) crawled, "
          f"{len(disc['errors'])} unreachable path(s) ({time.time()-t0:.1f}s)")
    if disc.get("subdomains_found"):
        print(f"    -> {len(disc['subdomains_found'])} subdomain(s) found via CT logs (passive)")
    if disc.get("scope_excluded_sample"):
        print(f"    -> {len(disc['scope_excluded_sample'])} URL(s) excluded as out-of-scope (sample shown in report)")

    if disc["sourcemaps"]:
        print("    [!] Sourcemaps exposed — these often leak full original source:")
        for sm in disc["sourcemaps"][:10]:
            print(f"        {sm}")

    print("[*] Step 2/4: extracting secrets / tokens / endpoints ...")
    findings = run_extraction(disc["js_files"])
    print(f"    -> {len(findings)} unique raw findings before validation")

    print("[*] Step 3/4: validating findings ...")
    findings = validate_findings(
        findings,
        base_url=args.target,
        do_network_probe=not args.no_probe,
        timeout=args.timeout,
        scope=scope,
        requests_per_second=args.rate_limit,
    )

    findings = [f for f in findings if SEVERITY_ORDER[f["severity"]] <= SEVERITY_ORDER[args.min_severity]]

    print("[*] Step 4/4: report")
    print_summary(findings)

    meta = {
        "js_file_count": len(disc["js_files"]),
        "sourcemap_count": len(disc["sourcemaps"]),
        "sourcemaps": disc["sourcemaps"],
        "unreachable_paths": disc["errors"][:20],
        "pages_crawled": len(disc["pages_crawled"]),
        "subdomain_count": len(disc.get("subdomains_found", [])),
        "subdomains_found": disc.get("subdomains_found", []),
        "scope_excluded_sample": disc.get("scope_excluded_sample", []),
    }

    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(REPORT_BUILDERS["json"](args.target, findings, meta))
        print(f"\n[+] JSON report written to {args.json_out}")

    if args.html_out:
        with open(args.html_out, "w") as f:
            f.write(REPORT_BUILDERS["html"](args.target, findings, meta))
        print(f"[+] HTML report written to {args.html_out}")

    if args.format and args.output_path:
        with open(args.output_path, "w") as f:
            f.write(REPORT_BUILDERS[args.format](args.target, findings, meta))
        print(f"[+] {args.format.upper()} report written to {args.output_path}")

    exit_code = 0
    if args.diff_against:
        with open(args.diff_against) as f:
            previous = json.load(f).get("findings", [])
        d = diff_findings(previous, findings)
        print(f"\n[*] Diff vs {args.diff_against}: "
              f"{len(d['new'])} new, {len(d['resolved'])} resolved, {len(d['persisting'])} persisting")
        for f in d["new"]:
            print(f"    [NEW] [{f['severity']:8}] {f['type']} conf={f['confidence']}  {f['value'][:60]}")
        if any(SEVERITY_ORDER[f['severity']] <= SEVERITY_ORDER["HIGH"] for f in d["new"]):
            exit_code = 1

    if not findings:
        print("\n[i] No findings at or above the requested severity threshold.")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
