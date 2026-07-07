"""
patterns.py
Regex library for detecting secrets, tokens, API keys, and interesting
endpoints inside JavaScript source. Patterns are grouped by category and
each carries a 'confidence' hint used later during validation/scoring.

v2: ~90 named secret patterns (up from ~20), plus a `STRUCTURAL_CHECKS`
table of cheap, offline structural validators (no network calls, no
third-party auth) that the extractor uses to sanity-check a match before
trusting it — e.g. does an AWS key ID's prefix/length match the real
format, does a card number pass Luhn, does a JWT have three well-formed
segments. These push obviously-fake or malformed matches down in
confidence without ever contacting the provider the "secret" belongs to.
"""

import re

# Each entry: name -> (compiled_regex, category, base_confidence)
# base_confidence is a starting score 0-100, adjusted later by the validator
# based on structural checks (checksum, entropy, context).

SECRET_PATTERNS = {
    # --- Cloud providers ---
    "AWS Access Key ID": (re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"), "cloud", 90),
    "AWS Secret Access Key": (
        re.compile(r"(?i)aws(.{0,20})?(secret|private)?[_-]?(access)?[_-]?key(.{0,20})?['\"]\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "cloud", 75,
    ),
    "AWS Session Token": (re.compile(r"(?i)aws_session_token['\"]?\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]"), "cloud", 70),
    "GCP API Key": (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "cloud", 85),
    "GCP OAuth Client ID": (re.compile(r"\b[0-9]{6,12}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "cloud", 70),
    "GCP Service Account JSON": (re.compile(r'"type"\s*:\s*"service_account"'), "cloud", 95),
    "Firebase DB URL": (re.compile(r"\b[a-z0-9-]+\.firebaseio\.com\b"), "cloud", 60),
    "Firebase Cloud Messaging Key": (re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}\b"), "cloud", 80),
    "Azure Storage Key": (re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{88}"), "cloud", 85),
    "Azure Connection String": (re.compile(r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}"), "cloud", 90),
    "Azure AD Client Secret": (re.compile(r"(?i)client[_-]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9~_.\-]{34,40}['\"]"), "cloud", 55),
    "DigitalOcean Token": (re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), "cloud", 90),
    "Heroku API Key": (re.compile(r"(?i)heroku[^'\"\n]{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]"), "cloud", 70),
    "Alibaba Cloud AccessKey": (re.compile(r"\bLTAI[A-Za-z0-9]{12,20}\b"), "cloud", 85),
    "Cloudinary URL": (re.compile(r"\bcloudinary://[0-9]{15}:[A-Za-z0-9_-]{20,}@[A-Za-z0-9_-]+\b"), "cloud", 85),

    # --- Payment / commerce ---
    "Stripe Live Secret Key": (re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "payment", 95),
    "Stripe Publishable Key": (re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "payment", 40),
    "Stripe Restricted Key": (re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"), "payment", 90),
    "Stripe Webhook Secret": (re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b"), "payment", 85),
    "PayPal Braintree Token": (re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"), "payment", 90),
    "Square Access Token": (re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"), "payment", 90),
    "Square OAuth Secret": (re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b"), "payment", 90),
    "Shopify Access Token": (re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"), "payment", 90),
    "Shopify Shared Secret": (re.compile(r"\bshpss_[a-fA-F0-9]{32}\b"), "payment", 85),
    "Coinbase API Secret": (re.compile(r"(?i)coinbase[^'\"\n]{0,20}['\"][A-Za-z0-9]{64}['\"]"), "payment", 70),

    # --- Messaging / collaboration ---
    "Slack Token": (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "messaging", 90),
    "Slack Webhook": (re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,}/B[0-9A-Za-z_]{8,}/[0-9A-Za-z_]{24}"), "messaging", 90),
    "Slack Config Access Token": (re.compile(r"\bxoxe\.xox[bp]-\d-[A-Za-z0-9]{146,}\b"), "messaging", 90),
    "Discord Webhook": (re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,}"), "messaging", 90),
    "Discord Bot Token": (re.compile(r"\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b"), "messaging", 85),
    "Twilio API Key": (re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "messaging", 85),
    "Twilio Account SID": (re.compile(r"\bAC[a-zA-Z0-9]{32}\b"), "messaging", 60),
    "Twilio Auth Token": (re.compile(r"(?i)twilio[^'\"\n]{0,20}(auth)?[_-]?token['\"]?\s*[:=]\s*['\"][0-9a-f]{32}['\"]"), "messaging", 75),
    "SendGrid API Key": (re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), "messaging", 90),
    "Mailgun API Key": (re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "messaging", 75),
    "Mailchimp API Key": (re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), "messaging", 80),
    "Telegram Bot Token": (re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"), "messaging", 85),
    "Intercom Access Token": (re.compile(r"(?i)intercom[^'\"\n]{0,20}['\"][A-Za-z0-9=_\-]{40,}['\"]"), "messaging", 55),

    # --- Source control / CI/CD ---
    "GitHub Token (classic/fine-grained)": (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "vcs", 95),
    "GitHub App Installation Token": (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "vcs", 90),
    "GitLab Token": (re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b"), "vcs", 90),
    "GitLab CI Token": (re.compile(r"\bglcbt-[0-9A-Za-z\-_]{20,}\b"), "vcs", 85),
    "NPM Token": (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "vcs", 90),
    "Bitbucket App Password": (re.compile(r"(?i)bitbucket[^'\"\n]{0,20}['\"][A-Za-z0-9]{20,}['\"]"), "vcs", 45),
    "CircleCI Token": (re.compile(r"(?i)circleci[^'\"\n]{0,20}['\"][a-f0-9]{40}['\"]"), "vcs", 70),
    "Docker Hub / Registry Auth": (re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'), "vcs", 55),
    "Terraform Cloud Token": (re.compile(r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b"), "vcs", 85),
    "HashiCorp Vault Token": (re.compile(r"\b[hs]\.vault\.[A-Za-z0-9._-]{20,}\b|\bhvs\.[A-Za-z0-9_-]{24,}\b"), "vcs", 90),

    # --- Analytics / observability ---
    "Sentry DSN": (re.compile(r"https://[a-f0-9]{32}@[a-z0-9.\-]*sentry\.io/[0-9]+"), "observability", 40),
    "Datadog API Key": (re.compile(r"(?i)dd[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), "observability", 75),
    "New Relic License Key": (re.compile(r"(?i)new[_-]?relic[^'\"\n]{0,20}['\"][a-f0-9]{40}['\"]"), "observability", 70),
    "Mixpanel Token": (re.compile(r"(?i)mixpanel[^'\"\n]{0,20}(token)?['\"]?\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), "observability", 30),
    "Segment Write Key": (re.compile(r"(?i)segment[^'\"\n]{0,20}(write)?[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{20,32}['\"]"), "observability", 35),
    "LaunchDarkly SDK Key": (re.compile(r"\bsdk-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "observability", 65),
    "PagerDuty API Key": (re.compile(r"(?i)pagerduty[^'\"\n]{0,20}['\"][A-Za-z0-9+_-]{20}['\"]"), "observability", 65),

    # --- Identity / auth providers ---
    "Auth0 Client Secret": (re.compile(r"(?i)auth0[^'\"\n]{0,20}(client)?[_-]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]{48,64}['\"]"), "auth_provider", 75),
    "Okta API Token": (re.compile(r"\b00[A-Za-z0-9_-]{40}\b"), "auth_provider", 80),
    "Algolia Admin API Key": (re.compile(r"(?i)algolia[^'\"\n]{0,20}(admin)?[_-]?(api)?[_-]?key['\"]?\s*[:=]\s*['\"][a-f0-9]{32}['\"]"), "auth_provider", 60),

    # --- Auth / session material ---
    "JWT": (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "auth", 55),
    "Kubernetes Service Account Token": (re.compile(r"\beyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_-]{20,}\b"), "auth", 70),
    "Basic Auth in URL": (re.compile(r"[a-zA-Z]{3,10}://[^/\s:@]{2,}:[^/\s:@]{2,}@[^\s'\"]+"), "auth", 70),
    "Bearer Token Literal": (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.=]{20,}"), "auth", 45),
    "Generic Authorization Header": (re.compile(r"(?i)['\"]authorization['\"]\s*:\s*['\"][^'\"]{10,}['\"]"), "auth", 35),
    "Session/CSRF Token Assignment": (re.compile(r"(?i)(csrf|xsrf|session)[_-]?token['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_.]{16,}['\"]"), "auth", 25),

    # --- Generic secret-looking assignments (lower confidence, needs review) ---
    "Generic API Key Assignment": (
        re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_./+=]{16,})['\"]"),
        "generic", 40,
    ),
    "Generic Password Assignment": (re.compile(r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"), "generic", 30),
    "Private Key Block": (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "generic", 98),
    "Database Connection String": (
        re.compile(r"(?i)\b(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|couchdb)://[^\s'\"]{6,}"),
        "generic", 80,
    ),

    # --- PII (for the "Mass PII" part of the mission) ---
    "Email Address": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "pii", 20),
    "Phone Number (loose)": (re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"), "pii", 10),
    "IPv4 Address": (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "pii", 10),
    "IPv6 Address": (re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b"), "pii", 10),
    "US Social Security Number (shaped)": (re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "pii", 35),
    "Credit Card Number (shaped)": (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), "pii", 30),
    "IBAN (shaped)": (re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Za-z0-9]{11,30}\b"), "pii", 20),
    "US Passport Number (shaped)": (re.compile(r"(?i)passport['\"]?\s*[:=#]\s*['\"]?\b[0-9A-Z]{6,9}\b"), "pii", 20),
    "Date of Birth Field": (re.compile(r"(?i)(date[_-]?of[_-]?birth|dob)['\"]?\s*[:=]\s*['\"]?\d{1,4}[-/]\d{1,2}[-/]\d{1,4}"), "pii", 20),
}

# Endpoints / paths worth flagging even without a secret attached
ENDPOINT_PATTERNS = {
    "Absolute API Endpoint": re.compile(r"https?://[^\s'\"<>]+?/api/[^\s'\"<>]*", re.IGNORECASE),
    "Relative API Endpoint": re.compile(r"['\"](/[a-zA-Z0-9_\-/]*api[a-zA-Z0-9_\-/]*)['\"]"),
    "GraphQL Endpoint": re.compile(r"['\"]([^'\"]*graphql[^'\"]*)['\"]", re.IGNORECASE),
    "Admin/Internal Path": re.compile(r"['\"](/[a-zA-Z0-9_\-]*(admin|internal|debug|staging|beta|v[0-9]/internal)[a-zA-Z0-9_\-/]*)['\"]", re.IGNORECASE),
    "S3 Bucket URL": re.compile(r"https?://[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com[^\s'\"<>]*", re.IGNORECASE),
    "GCS Bucket URL": re.compile(r"https?://(?:storage\.googleapis\.com/[a-z0-9._\-]+|[a-z0-9._\-]+\.storage\.googleapis\.com)[^\s'\"<>]*", re.IGNORECASE),
    "Azure Blob Container URL": re.compile(r"https?://[a-z0-9]+\.blob\.core\.windows\.net[^\s'\"<>]*", re.IGNORECASE),
    "Swagger/OpenAPI Doc": re.compile(r"['\"]([^'\"]*(swagger|openapi)[^'\"]*\.(json|yaml|yml))['\"]", re.IGNORECASE),
    "Environment/Config File Ref": re.compile(r"['\"](/?(\.env(?:\.[a-z]+)?|config\.json|settings\.json|firebase-config\.json|appsettings\.json))['\"]", re.IGNORECASE),
    "WebSocket Endpoint": re.compile(r"\bwss?://[^\s'\"<>]+", re.IGNORECASE),
    "Internal Hostname (RFC1918-adjacent)": re.compile(r"\bhttps?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?[^\s'\"<>]*"),
    "GraphQL Introspection Hint": re.compile(r"__schema|IntrospectionQuery"),
    "Source Map Reference": re.compile(r"//# sourceMappingURL=([^\s]+\.map)"),
}

# Cheap, fully offline structural validators. Each returns True/False/None
# (None = "not applicable / can't tell"). These NEVER make a network call
# and NEVER contact the credential's own provider — they just check shape,
# checksums, and length against the provider's *published, public* format
# so that malformed/impossible matches (typical of minified-code false
# positives) get down-ranked automatically.
def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _aws_key_id_ok(value: str) -> bool:
    return bool(re.fullmatch(r"(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", value))


def _jwt_shape_ok(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(len(p) > 0 for p in parts)


STRUCTURAL_CHECKS = {
    "Credit Card Number (shaped)": _luhn_ok,
    "AWS Access Key ID": _aws_key_id_ok,
    "JWT": _jwt_shape_ok,
    "Kubernetes Service Account Token": _jwt_shape_ok,
}

# Substrings that, if present near a match, strongly suggest it's a
# placeholder/example rather than a live secret. Used to down-rank noise.
NOISE_HINTS = [
    "example", "placeholder", "your_", "xxxxxxxx", "changeme", "dummy",
    "test_key", "sample", "fake", "0000000000", "1234567890abcdef",
    "insert_key_here", "replace_with", "<key>", "process.env", "lorem",
    "foobar", "abcdef123456", "test-key", "not-a-real", "redacted",
    "-----begin-----", "mock", "stub", "todo", "fixme",
]
