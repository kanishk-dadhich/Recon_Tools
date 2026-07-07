"""
extractor.py (v2)
Runs the pattern library against fetched JS source, dedupes matches,
and applies multi-signal scoring to rank findings by likelihood of
being real:

  1. base_confidence from the matched pattern
  2. Shannon-entropy of the captured value (random-looking vs patterned)
  3. offline structural validation (Luhn, AWS key shape, JWT shape, ...)
     from patterns.STRUCTURAL_CHECKS — never a network call
  4. noise-hint suppression (placeholders/examples/test fixtures)
  5. a freeform high-entropy scanner that flags "key/token/secret = ..."
     assignments even when they don't match any *named* pattern — this
     is what catches custom/internal secret schemes that a fixed regex
     library would otherwise miss entirely

Runs across many JS files in a thread pool since this is CPU-light,
I/O-adjacent text scanning and the file count can be large.
"""

import math
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from .patterns import SECRET_PATTERNS, ENDPOINT_PATTERNS, NOISE_HINTS, STRUCTURAL_CHECKS

FREEFORM_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([a-zA-Z_][a-zA-Z0-9_]{0,30}(?:secret|token|key|credential|passwd|password)[a-zA-Z0-9_]{0,10})"
    r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_/+=]{20,120})['\"]"
)


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def _context_window(text, start, end, pad=40):
    return text[max(0, start - pad): min(len(text), end + pad)]


def _looks_like_noise(context):
    low = context.lower()
    return any(hint in low for hint in NOISE_HINTS)


def _score(name, base_conf, core_value, context):
    confidence = base_conf
    ent = shannon_entropy(core_value)

    # entropy signal: real random secrets skew high, English/placeholder
    # text and short numeric-only patterns skew low
    if ent > 4.2:
        confidence += 15
    elif ent > 3.5:
        confidence += 8
    elif ent < 2.5:
        confidence -= 15

    # offline structural check, if we have one for this pattern name
    checker = STRUCTURAL_CHECKS.get(name)
    if checker is not None:
        try:
            ok = checker(core_value)
        except Exception:
            ok = None
        if ok is True:
            confidence += 12
        elif ok is False:
            confidence -= 30

    if _looks_like_noise(context):
        confidence -= 40

    # length sanity: extremely long "matches" are usually a regex running
    # into adjacent minified code rather than a real bounded secret
    if len(core_value) > 300:
        confidence -= 20

    return max(0, min(100, confidence))


def extract_from_source(js_url, source_text):
    """Returns a list of finding dicts for a single JS file."""
    findings = []
    seen_spans = []  # (start, end) already claimed by a named pattern, to
    # avoid the freeform scanner re-flagging the same literal twice

    for name, (pattern, category, base_conf) in SECRET_PATTERNS.items():
        for m in pattern.finditer(source_text):
            value = m.group(0)
            context = _context_window(source_text, m.start(), m.end())
            core_value = m.group(m.lastindex) if m.lastindex else value
            confidence = _score(name, base_conf, core_value, context)

            findings.append({
                "type": name,
                "category": category,
                "value": value,
                "source_file": js_url,
                "context": context.strip().replace("\n", " ")[:200],
                "confidence": confidence,
                "detection": "pattern",
            })
            # remember the core VALUE's span (not the whole match, which
            # may include surrounding quotes/variable name) so the
            # freeform scanner below can correctly detect overlap
            if m.lastindex:
                seen_spans.append(m.span(m.lastindex))
            else:
                seen_spans.append((m.start(), m.end()))

    # freeform heuristic pass: high-entropy value assigned to a
    # secret/token/key-shaped variable name, not already covered above
    for m in FREEFORM_ASSIGNMENT_RE.finditer(source_text):
        span = m.span(2)  # span of the captured value itself, not the whole assignment
        if any(s <= span[0] < e or s < span[1] <= e for s, e in seen_spans):
            continue
        var_name, value = m.group(1), m.group(2)
        ent = shannon_entropy(value)
        if ent < 3.7:
            continue  # too patterned to be a plausible random secret
        # tight window for the noise check specifically (just the
        # assignment itself) so an unrelated placeholder on the next
        # line doesn't wrongly suppress a real-looking neighbor
        tight_context = _context_window(source_text, m.start(), m.end(), pad=8)
        if _looks_like_noise(tight_context):
            continue
        context = _context_window(source_text, m.start(), m.end())
        confidence = _score("Generic High-Entropy Secret (heuristic)", 30, value, tight_context)
        findings.append({
            "type": f"Unclassified High-Entropy Secret ({var_name})",
            "category": "generic",
            "value": value,
            "source_file": js_url,
            "context": context.strip().replace("\n", " ")[:200],
            "confidence": confidence,
            "detection": "heuristic",
        })

    for name, pattern in ENDPOINT_PATTERNS.items():
        for m in pattern.finditer(source_text):
            value = m.group(1) if m.lastindex else m.group(0)
            context = _context_window(source_text, m.start(), m.end())
            findings.append({
                "type": name,
                "category": "endpoint",
                "value": value,
                "source_file": js_url,
                "context": context.strip().replace("\n", " ")[:200],
                "confidence": 50,
                "detection": "pattern",
            })

    return findings


def dedupe_findings(all_findings):
    """Collapse identical (type, value) pairs across files into one entry
    that lists every file it appeared in."""
    merged = {}
    for f in all_findings:
        key = (f["type"], f["value"])
        if key not in merged:
            merged[key] = dict(f)
            merged[key]["source_files"] = [f["source_file"]]
            merged[key].pop("source_file", None)
        else:
            if f["source_file"] not in merged[key]["source_files"]:
                merged[key]["source_files"].append(f["source_file"])
            merged[key]["confidence"] = max(merged[key]["confidence"], f["confidence"])
    return sorted(merged.values(), key=lambda x: (-x["confidence"], x["type"]))


def run_extraction(js_files: dict, max_workers=8):
    """js_files: dict of url -> source text (from crawler). Scans files
    concurrently — text-regex work is cheap per file but file counts can
    run into the hundreds on large sites/sourcemaps."""
    all_findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(extract_from_source, url, text): url
            for url, text in js_files.items()
        }
        for fut in as_completed(futures):
            all_findings.extend(fut.result())
    return dedupe_findings(all_findings)
