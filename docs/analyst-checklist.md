# Phishing Email Analyst Checklist

Use this checklist for authorized defensive analysis. Do not open suspicious links or attachments on a normal workstation.

## Preserve and scope

- Save the original message in an approved location.
- Record the date, reporter, mailbox, and message identifier.
- Confirm that you are authorized to inspect the message and related logs.

## Review the headers

- Compare the display name with the actual From address.
- Compare From, Reply-To, and Return-Path domains.
- Review Received headers from bottom to top when available.
- Review SPF, DKIM, and DMARC results.
- Note that a pass supports authentication but does not prove the request is trustworthy.

## Review the content

- Look for urgent account, payment, payroll, or document-sharing requests.
- Compare link domains with the organization the message claims to represent.
- Defang suspicious URLs before documenting or sharing them.
- Record unexpected attachments and their extensions.
- Verify unusual requests using a known phone number, portal, or separate message thread.

## Respond

- Quarantine confirmed or strongly suspected phishing messages.
- Search for related senders, subjects, domains, URLs, hashes, and message IDs.
- Block indicators only after validation and according to policy.
- Notify recipients using an approved internal channel.
- Escalate user interaction, credential entry, or attachment execution through the incident-response process.
- Document the evidence, decision, actions, and limitations.

