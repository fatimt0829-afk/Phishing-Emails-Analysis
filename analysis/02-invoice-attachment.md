# Sample 02 Analysis: Invoice Attachment

## Verdict

**High risk - quarantine or escalate for validation**

## Evidence

| Check | Observation | Why it matters |
| --- | --- | --- |
| From | `billing@northwind.example` | The visible sender looks business-related. |
| Reply-To | `accounts@northwind-payments.invalid` | Replies would go to a different domain. |
| Authentication | SPF, DKIM, and DMARC pass | Authentication supports domain use, but does not prove the business request is legitimate. |
| Link | `northwind-payments.invalid` | The payment link does not match the visible sender domain. |
| Language | “Action required,” “overdue,” and “today” | Payment pressure can reduce careful verification. |
| Attachment | `Invoice_8841.html` | HTML attachments deserve careful handling because they can contain active or deceptive content. This training file is harmless. |

## Analyst conclusion

The authentication passes reduce the likelihood of simple domain spoofing, but they do not remove the other risks. A compromised legitimate account, abused mail service, or misleading business request could still pass authentication. The different Reply-To domain, payment link, urgency, and HTML attachment justify escalation.

## Recommended response

1. Do not open the attachment in a normal user environment.
2. Confirm the invoice through a known phone number or established vendor portal.
3. Inspect the attachment only with approved security tooling.
4. Search for related messages and domains.
5. Escalate confirmed fraud attempts to the incident-response team.
