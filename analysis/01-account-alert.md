# Sample 01 Analysis: Account Alert

## Verdict

**High risk - quarantine and investigate**

## Evidence

| Check | Observation | Why it matters |
| --- | --- | --- |
| From | `security@clouddesk.example` | This is the identity visible to the recipient. |
| Reply-To | `help@clouddesk-support.test` | The reply domain does not match the visible sender. |
| Return-Path | `bounce@mailer.invalid` | The envelope sender uses a third, unrelated domain. |
| Authentication | SPF, DKIM, and DMARC fail | The simulated receiving system could not authenticate the claimed sender. |
| Link | `clouddesk-support.test` | The link domain does not match `clouddesk.example`. |
| Language | “URGENT,” “suspended,” “today,” and “immediately” | The message pressures the recipient to act before verifying it. |

## Analyst conclusion

No single indicator should be treated as absolute proof, but the indicators reinforce one another. The failed authentication results, sender-domain mismatches, unrelated link, and pressure language justify a High classification.

## Recommended response

1. Quarantine the message.
2. Search mail logs for the sender, Reply-To domain, return-path domain, subject, and linked domain.
3. Block confirmed malicious indicators using approved controls.
4. Notify recipients through a trusted internal channel.
5. If a user interacted with the message, follow the organization's account-security and incident-response process.

