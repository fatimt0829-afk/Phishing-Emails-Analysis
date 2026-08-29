#!/usr/bin/env python3
"""Analyze an RFC 5322 email file for common phishing indicators.

This tool is intentionally defensive. It reads a local .eml file, performs no
network requests, never opens links, and never executes attachments.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
URGENCY_TERMS = {
    "urgent",
    "immediately",
    "today",
    "final notice",
    "suspended",
    "within 24 hours",
    "overdue",
    "action required",
}
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".lnk",
    ".iso",
    ".img",
    ".html",
    ".htm",
    ".zip",
}


def address_domain(value: str | None) -> str:
    """Return the lowercase domain from an email header value."""
    address = parseaddr(value or "")[1]
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower()


def get_body_text(message: Any) -> str:
    """Collect readable body text while excluding attachments."""
    parts: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart() or part.get_filename():
                continue
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            try:
                parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                payload = part.get_payload(decode=True) or b""
                parts.append(payload.decode("utf-8", errors="replace"))
    else:
        try:
            parts.append(message.get_content())
        except (LookupError, UnicodeDecodeError):
            payload = message.get_payload(decode=True) or b""
            parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def extract_urls(text: str) -> list[str]:
    """Extract unique HTTP(S) URLs without visiting them."""
    seen: set[str] = set()
    urls: list[str] = []
    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,);]}")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def defang_url(url: str) -> str:
    """Return a display-safe URL for reports."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").replace(".", "[.]")
    scheme = "hxxps" if parsed.scheme.lower() == "https" else "hxxp"
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def authentication_results(value: str) -> dict[str, str]:
    """Parse SPF, DKIM, and DMARC outcomes from Authentication-Results."""
    lowered = value.lower()
    results: dict[str, str] = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}=([a-z0-9_-]+)", lowered)
        results[mechanism] = match.group(1) if match else "not-found"
    return results


def add_finding(
    findings: list[dict[str, Any]],
    rule_id: str,
    category: str,
    score: int,
    evidence: str,
) -> None:
    findings.append(
        {
            "rule_id": rule_id,
            "category": category,
            "score": score,
            "evidence": evidence,
        }
    )


def analyze_email(path: Path) -> dict[str, Any]:
    """Analyze one local email file and return a structured result."""
    with path.open("rb") as stream:
        message = BytesParser(policy=policy.default).parse(stream)

    from_value = str(message.get("From", ""))
    reply_to_value = str(message.get("Reply-To", ""))
    return_path_value = str(message.get("Return-Path", ""))
    subject = str(message.get("Subject", ""))
    auth_raw = str(message.get("Authentication-Results", ""))

    from_domain = address_domain(from_value)
    reply_to_domain = address_domain(reply_to_value)
    return_path_domain = address_domain(return_path_value)
    auth = authentication_results(auth_raw)
    body = get_body_text(message)
    urls = extract_urls(body)
    url_domains = sorted({urlparse(url).hostname.lower() for url in urls if urlparse(url).hostname})
    attachments = [
        part.get_filename()
        for part in message.walk()
        if part.get_filename()
    ]

    findings: list[dict[str, Any]] = []

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        add_finding(
            findings,
            "HDR-001",
            "Reply-To mismatch",
            20,
            f"From domain {from_domain} differs from Reply-To domain {reply_to_domain}.",
        )

    if return_path_domain and from_domain and return_path_domain != from_domain:
        add_finding(
            findings,
            "HDR-002",
            "Return-Path mismatch",
            15,
            f"From domain {from_domain} differs from Return-Path domain {return_path_domain}.",
        )

    auth_scores = {"spf": 20, "dkim": 15, "dmarc": 25}
    for mechanism, result in auth.items():
        if result in {"fail", "softfail", "temperror", "permerror", "none", "neutral"}:
            add_finding(
                findings,
                f"AUTH-{mechanism.upper()}",
                f"{mechanism.upper()} authentication issue",
                auth_scores[mechanism],
                f"Authentication-Results reported {mechanism}={result}.",
            )

    unrelated_domains = [domain for domain in url_domains if from_domain and domain != from_domain]
    if unrelated_domains:
        add_finding(
            findings,
            "URL-001",
            "Unrelated link domain",
            20,
            "Message links to domain(s) not matching the visible sender: "
            + ", ".join(unrelated_domains)
            + ".",
        )

    body_and_subject = f"{subject}\n{body}".lower()
    matched_urgency = sorted(term for term in URGENCY_TERMS if term in body_and_subject)
    if matched_urgency:
        add_finding(
            findings,
            "TXT-001",
            "Urgent or pressuring language",
            10,
            "Matched term(s): " + ", ".join(matched_urgency) + ".",
        )

    risky_attachments = [
        name
        for name in attachments
        if Path(name).suffix.lower() in SUSPICIOUS_EXTENSIONS
    ]
    if risky_attachments:
        add_finding(
            findings,
            "ATT-001",
            "Potentially risky attachment type",
            20,
            "Attachment filename(s): " + ", ".join(risky_attachments) + ".",
        )

    raw_score = sum(item["score"] for item in findings)
    score = min(raw_score, 100)
    if score >= 70:
        risk = "high"
    elif score >= 40:
        risk = "medium"
    else:
        risk = "low"

    return {
        "source_file": path.name,
        "analysis_time_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "summary": {
            "subject": subject,
            "from": from_value,
            "reply_to": reply_to_value,
            "return_path": return_path_value,
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "authentication": auth,
            "url_domains": url_domains,
            "defanged_urls": [defang_url(url) for url in urls],
            "attachments": attachments,
        },
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "limitations": [
            "No DNS or reputation lookups were performed.",
            "Attachments were identified by filename and were not executed.",
            "The score is a triage aid and requires analyst review.",
        ],
    }


def print_summary(result: dict[str, Any]) -> None:
    print(f"File: {result['source_file']}")
    print(f"Subject: {result['summary']['subject']}")
    print(f"Risk: {result['risk_level'].upper()} ({result['risk_score']}/100)")
    print("Findings:")
    if not result["findings"]:
        print("  - No scored indicators detected.")
    for finding in result["findings"]:
        print(
            f"  - {finding['rule_id']} | {finding['category']} "
            f"(+{finding['score']}): {finding['evidence']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a local .eml file for common phishing indicators."
    )
    parser.add_argument("email_file", type=Path, help="Path to the .eml file")
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional path for the structured JSON result",
    )
    args = parser.parse_args()

    if not args.email_file.is_file():
        parser.error(f"Email file not found: {args.email_file}")

    result = analyze_email(args.email_file)
    print_summary(result)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"JSON result: {args.json_out}")


if __name__ == "__main__":
    main()

