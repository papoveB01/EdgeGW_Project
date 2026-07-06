# Security Policy

Edge Gateway sits inside financial institutions and handles fraud signals
derived from customer PII. We take security reports seriously and appreciate
responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue or pull request for a security problem.**

Instead, report privately through one of:

- GitHub's **[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)**
  (Security tab → "Report a vulnerability"), or
- Email **security@intelfraud.com** with the details below. If possible,
  encrypt sensitive reports (PGP key on request).

Please include:

- A description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected version(s) / commit, and configuration if relevant.
- Any suggested remediation.

**Never include real PII, production secrets, live salts/peppers, API keys, or
real bank identifiers** in a report. Use redacted or synthetic values.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity triage within 10 business days.
- Coordinated disclosure: we'll agree on a timeline with you, aim to ship a
  fix before public disclosure, and credit you in the advisory unless you
  prefer to remain anonymous.

## Scope

In scope: the gateway code in this repository (anonymization, validation,
inbound auth, Hub forwarding, the spool, configuration handling).

Out of scope for this repo: the IntelFraud Hub service and its APIs (report
those to the same contact, but note they are a separate system), and issues
requiring a compromised host or physical access.

## Handling of secrets and PII

The gateway is designed so that raw PII never leaves the bank and never lands
in logs or on the wire. Reports of any path that violates that — PII in logs,
PII forwarded to the Hub, reversible or unsalted identifiers, secrets written
to disk — are considered high severity.
