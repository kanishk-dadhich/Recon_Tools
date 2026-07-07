# Mass PII / Secret Finder — v2

A recon tool that automates the classic bug-bounty JS-mining workflow:

```
target URL (+ explicit authorization confirmation, + scope)
   │
   ▼
discover every reachable, in-scope JS file — real multi-hop HTML crawl,
script tags, dynamic import()/chunk manifests, sourcemaps, conventional
paths, optional passive subdomain discovery via public CT logs
   │
   ▼
mine each file for API keys, tokens, credentials, internal endpoints,
and PII-shaped strings — ~90 named patterns + a freeform high-entropy
heuristic that catches secrets no named pattern covers
   │
   ▼
validate findings — structural/offline checks (Luhn, key-shape, JWT
decode), scope-checked + rate-limited reachability probing — and triage
by a weighted severity model
   │
   ▼
report: live console (GUI) or terminal output, plus JSON / HTML /
SARIF / Markdown / CSV export, with diff-against-previous-scan support
```

## ⚠️ Authorized use only

Run this only against systems you own or are explicitly authorized to test
(a bug bounty program in scope, a client engagement, your own app). Scope
enforcement is no longer just a README sentence:

- **`--confirm-authorized`** is a required CLI flag (and a required,
  checked checkbox in the GUI) — you must explicitly confirm authorization
  before a scan will run.
- Every request the crawler/validator makes is checked against a
  `ScopeGuard`: the primary target's domain plus any `--scope` rules you
  add (exact host, `sub.example.com`, or `*.example.com` wildcard). Anything
  outside that scope is recorded as *excluded*, never fetched.
- `robots.txt` is honored during the HTML-crawl phase by default.
- All target-facing requests are rate-limited (default 8 req/s, tunable
  via `--rate-limit`) so scans stay polite.

It does:
- Read-only HTTP requests to the target (fetching pages/JS it already serves)
- Read-only reachability checks on endpoints *discovered on that same,
  in-scope target*
- Passive, public-record subdomain discovery (CT logs via crt.sh) — no
  active subdomain brute force or port scanning

It deliberately does **not**:
- Attempt to authenticate to third-party providers (AWS, Stripe, Slack,
  GitHub, etc.) using discovered keys. Testing a leaked key against its
  provider is a separate action outside the target's own infrastructure and
  needs its own authorization. The tool flags these for manual, in-scope
  verification instead and tells you the standard safe way to confirm impact.
- Brute-force, fuzz, or guess authentication credentials.
- Exploit any discovered vulnerability.
- Touch anything outside the declared scan scope.

## Setup

```bash
pip install -r requirements.txt
```

## Support / Donate

If this tool helped you during testing, you can support the project here:
https://razorpay.me/@kanishkdadhich



## Usage — GUI (recommended)

```bash
python app.py
```

Open `http://127.0.0.1:7331`. Enter a target URL, confirm authorization,
optionally add extra in-scope domains and tune scan options, click
**Run scan**. You get a live pipeline log, a severity-sorted findings
table, a click-through detail drawer per finding (with decoded JWTs, probe
results, and validation notes), scan history (SQLite-backed), and
one-click JSON / HTML / SARIF / Markdown / CSV export.

## Usage — CLI

```bash
python cli.py https://target.example.com --confirm-authorized
python cli.py https://target.example.com --confirm-authorized --json out.json --html out.html
python cli.py https://target.example.com --confirm-authorized --format sarif -o out.sarif
python cli.py https://target.example.com --confirm-authorized --min-severity HIGH
python cli.py https://target.example.com --confirm-authorized --no-probe    # skip live endpoint checks
python cli.py https://target.example.com --confirm-authorized --scope api.example.com --scope "*.example-cdn.net"
python cli.py https://target.example.com --confirm-authorized --enumerate-subdomains
python cli.py https://target.example.com --confirm-authorized --rate-limit 4
python cli.py https://target.example.com --confirm-authorized --diff-against previous.json
```

## What it detects

~90 named patterns across these categories (up from ~20 in v1), plus a
freeform high-entropy heuristic for un-named/custom secret schemes:

| Category      | Examples |
|---------------|----------|
| Cloud         | AWS (+ session tokens), GCP (API key, OAuth, service-account JSON), Firebase, Azure (Storage/AD), DigitalOcean, Heroku, Alibaba Cloud, Cloudinary |
| Payment       | Stripe (live/restricted/webhook), PayPal Braintree, Square, Shopify, Coinbase |
| Messaging     | Slack, Discord, Twilio, SendGrid, Mailgun, Mailchimp, Telegram, Intercom |
| VCS/CI        | GitHub, GitLab (+CI), NPM, Bitbucket, CircleCI, Docker registry auth, Terraform Cloud, HashiCorp Vault |
| Observability | Sentry, Datadog, New Relic, Mixpanel, Segment, LaunchDarkly, PagerDuty |
| Auth provider | Auth0, Okta, Algolia |
| Auth          | JWTs (decoded), Kubernetes SA tokens, Basic-auth-in-URL, bearer tokens |
| Generic       | Private key blocks, DB connection strings, generic key/password assignments, **freeform high-entropy heuristic** |
| Endpoints     | API paths, GraphQL, admin/internal/debug paths, S3/GCS/Azure Blob buckets, Swagger/OpenAPI, WebSocket, internal/RFC1918 hosts, sourcemap refs |
| PII           | Emails, phones, IPv4/IPv6, SSN-shaped, credit-card-shaped (Luhn-checked), IBAN-shaped, DOB fields |

Every finding gets a multi-signal confidence score (base pattern
confidence + entropy + **offline structural validation** — Luhn checksum,
AWS key-ID shape, JWT segment shape — + noise-hint suppression), a
severity rating (CRITICAL/HIGH/MEDIUM/LOW), and (for endpoints) a
scope-checked, rate-limited live reachability probe.

## Project layout

```
core/
  scope.py       authorization-scope enforcement (ScopeGuard)
  crawler.py     JS discovery: real multi-hop crawl, dynamic imports, chunk
                 manifests, sourcemaps, passive subdomain discovery, robots.txt,
                 rate limiting
  patterns.py    ~90-pattern regex library + offline structural checks + noise-hint list
  extractor.py   pattern matching, entropy scoring, freeform heuristic scanner, dedupe
  validator.py   structural validation, JWT decode, scope-checked safe endpoint
                 probing, weighted severity, scan-to-scan diffing
  report.py      JSON / HTML (searchable) / SARIF / Markdown / CSV report builders
cli.py           terminal entry point
app.py           Flask GUI backend (+ SQLite scan history, diff endpoint)
templates/       GUI HTML
static/          GUI CSS/JS
```

## Extending it

- Add patterns: edit `core/patterns.py` — each entry is `(regex, category, base_confidence)`.
- Add an offline structural check: add a function to `STRUCTURAL_CHECKS` in `core/patterns.py`.
- Add new endpoint shapes: `ENDPOINT_PATTERNS` in the same file.
- Add a new report format: add a builder function to `REPORT_BUILDERS` in `core/report.py`.
- Wire into CI: `cli.py --format sarif -o out.sarif` for GitHub code scanning,
  or `--diff-against previous.json` to fail only on genuinely new findings.

