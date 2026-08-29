# Phishing Email Analysis Lab

**Defensive email analysis | Python | SPF, DKIM, DMARC | IOC extraction**

This project documents a defensive phishing-analysis lab built around three simulated email messages: a credential-themed account alert, an invoice lure with a harmless HTML attachment, and a legitimate control message. I reviewed the headers, sender alignment, authentication results, URLs, language, and attachments, then used a small Python tool to apply the same checks consistently.

> **Safety note:** Every message is fictional. All domains use the reserved `.example`, `.test`, or `.invalid` namespaces, so there are no live phishing links, real credentials, or real organizations in this repository. The lab does not send email or collect information.

## Project results

| Sample | Classification | Score | Main indicators |
| --- | --- | ---: | --- |
| Account alert | High risk | 100/100 | SPF, DKIM, and DMARC failures; sender mismatches; unrelated link; urgency |
| Invoice attachment | High risk | 70/100 | Reply-To mismatch; unrelated link; urgent payment language; HTML attachment |
| Security notice control | Low risk | 0/100 | Aligned sender domains, authentication passes, and no suspicious attachment |

## What I analyzed

- `From`, `Reply-To`, and `Return-Path` domain alignment
- SPF, DKIM, and DMARC results in the `Authentication-Results` header
- URL domains compared with the visible sender domain
- Urgent or pressuring language
- Potentially risky attachment extensions
- Indicators of compromise (IOCs) that an analyst could document or block

## Repository structure

```text
phishing-email-analysis/
|-- README.md
|-- findings.md
|-- src/
|   |-- analyze_email.py
|-- samples/
|   |-- 01-account-alert.eml
|   |-- 02-invoice-attachment.eml
|   |-- 03-legitimate-control.eml
|-- analysis/
|   |-- 01-account-alert.md
|   |-- 02-invoice-attachment.md
|   |-- 03-legitimate-control.md
|-- results/
|   |-- 01-account-alert.json
|   |-- 02-invoice-attachment.json
|   |-- 03-legitimate-control.json
|-- indicators/
|   |-- iocs.csv
|-- docs/
|   |-- analyst-checklist.md
|   |-- phishing-analysis-report.pdf
|-- tests/
|   |-- test_analyze_email.py
|-- tools/
|   |-- generate_report.py
|-- requirements-report.txt
```

## Run the lab

The analyzer uses only Python's standard library.

```bash
python src/analyze_email.py samples/01-account-alert.eml
```

Save a structured JSON result:

```bash
python src/analyze_email.py samples/01-account-alert.eml \
  --json-out results/01-account-alert.json
```

Analyze all three samples:

```bash
python src/analyze_email.py samples/01-account-alert.eml --json-out results/01-account-alert.json
python src/analyze_email.py samples/02-invoice-attachment.eml --json-out results/02-invoice-attachment.json
python src/analyze_email.py samples/03-legitimate-control.eml --json-out results/03-legitimate-control.json
```

Run the automated tests:

```bash
python -m unittest discover -s tests -v
```

The risk score is a triage aid, not a final verdict. A real security analyst would combine these signals with mail-gateway data, DNS records, reputation sources, organizational context, and safe attachment analysis.

## Findings

### 1. Account alert - High

The account-alert sample had the strongest combination of suspicious evidence. The apparent sender, reply address, and return path used different domains; SPF, DKIM, and DMARC failed; and the message linked to a domain unrelated to the visible sender. The language also created time pressure.

**Recommended response:** quarantine the message, block the listed indicators where appropriate, search the environment for similar messages, and notify affected users through an approved channel.

### 2. Invoice attachment - High

The invoice sample passed the simulated authentication checks, showing that authentication alone cannot prove that a message is safe. The different Reply-To domain, unrelated payment link, urgent language, and HTML attachment still justified escalation.

**Recommended response:** do not open the attachment in a normal user environment. Validate the invoice through a known contact method and inspect the attachment only with approved security tooling.

### 3. Legitimate control - Low

The control message used aligned sender domains, passed the simulated authentication checks, linked back to the sender's domain, and did not include a suspicious attachment or pressure language. It provides a baseline for comparison.

Detailed reasoning is available in [findings.md](findings.md) and the [PDF analysis report](docs/phishing-analysis-report.pdf).

## Skills demonstrated

- Email-header analysis
- SPF, DKIM, and DMARC interpretation
- Sender-domain and Reply-To comparison
- URL and attachment triage
- IOC extraction and defanging
- Python automation and unit testing
- Risk communication and incident-response recommendations

## Limitations

- The messages are simulated and contain no real infrastructure.
- The tool reads existing authentication results; it does not perform DNS validation.
- The score is intentionally simple and should not replace a secure email gateway or analyst judgment.
- Attachments are identified by filename only and are never executed.
- No external links are opened and no network requests are made.

## References

- [CISA: Recognize and Report Phishing](https://www.cisa.gov/secure-our-world/recognize-and-report-phishing)
- [IETF RFC 7208: Sender Policy Framework](https://datatracker.ietf.org/doc/html/rfc7208)
- [IETF RFC 6376: DKIM Signatures](https://datatracker.ietf.org/doc/html/rfc6376)
- [IETF RFC 9989: DMARC](https://datatracker.ietf.org/doc/html/rfc9989)
- [IETF RFC 8601: Authentication-Results Header](https://datatracker.ietf.org/doc/html/rfc8601)
