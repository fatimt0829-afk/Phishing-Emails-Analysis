# Sample 03 Analysis: Legitimate Control

## Verdict

**Low risk - no scored indicators detected**

## Evidence

| Check | Observation |
| --- | --- |
| Sender alignment | From, Reply-To, and Return-Path all use `clouddesk.example`. |
| Authentication | SPF, DKIM, and DMARC pass. |
| Link alignment | The link uses the same domain as the visible sender. |
| Language | The message does not create urgency and explicitly says no action is required. |
| Attachments | None. |

## Analyst conclusion

The message provides a useful baseline for comparison with the suspicious samples. A Low score does not guarantee that any real-world email is safe, but the tested indicators do not justify escalation by themselves.

