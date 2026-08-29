# Findings Summary

## Scope

Three fictional `.eml` files were analyzed in an offline lab. The assessment compared sender headers, authentication results, URLs, message language, and attachment filenames. No external network requests were made, and no attachment was executed.

## Results

| Sample | Risk | Score | Findings |
| --- | --- | ---: | ---: |
| `01-account-alert.eml` | High | 100 | 7 |
| `02-invoice-attachment.eml` | High | 70 | 4 |
| `03-legitimate-control.eml` | Low | 0 | 0 |

## Finding F-01: Sender-domain mismatch

**Observed in:** Samples 01 and 02  
**Risk:** High when combined with other indicators

The visible From domain differed from the Reply-To domain. In Sample 01, the Return-Path also used a different domain. These differences can redirect replies away from the organization the recipient believes sent the message.

**Recommendation:** Compare From, Reply-To, Return-Path, and authenticated domains. Investigate unexplained differences and confirm requests using known contact information.

## Finding F-02: Email authentication failure

**Observed in:** Sample 01  
**Risk:** High

The Authentication-Results header reported SPF, DKIM, and DMARC failures. These results indicate that the claimed sender identity was not successfully authenticated by the simulated receiving system.

**Recommendation:** Quarantine the message, review gateway telemetry, and investigate related messages and domains. Authentication results should be combined with content and context rather than used alone.

## Finding F-03: Unrelated link domain

**Observed in:** Samples 01 and 02  
**Risk:** Medium to High

Both suspicious messages linked to domains that did not match the visible sender. An unrelated domain can be legitimate, but it should be explained by known vendor infrastructure or organizational context.

**Recommendation:** Do not open suspicious links. Defang and document them, check reputation using approved tooling, and confirm the request through a trusted channel.

## Finding F-04: Pressure language

**Observed in:** Samples 01 and 02  
**Risk:** Medium

The messages used terms such as “urgent,” “suspended,” “action required,” “overdue,” and “today.” Pressure language is a social-engineering indicator because it can encourage a recipient to act before checking the request.

**Recommendation:** Train users to pause and verify urgent account or payment requests. Analysts should combine language signals with technical evidence.

## Finding F-05: HTML attachment

**Observed in:** Sample 02  
**Risk:** Medium

The invoice message contained an HTML attachment. The included lab attachment is harmless, but real HTML attachments can present misleading pages or active content.

**Recommendation:** Do not open unexpected attachments on a normal workstation. Use approved sandboxing and file-analysis procedures, and verify the sender through an independent method.

## Key lesson

Authentication passes do not automatically make a message safe. Sample 02 passed SPF, DKIM, and DMARC but still contained multiple reasons for escalation. Strong phishing analysis combines authentication, header alignment, URLs, attachments, language, and business context.
