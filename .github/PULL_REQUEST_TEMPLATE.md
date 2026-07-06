<!-- Thanks for contributing to Edge Gateway! -->

## What does this PR do?

<!-- Brief description of the change and the problem it solves. Link the issue. -->

Fixes #

## Checklist

- [ ] My commits are **signed off** (`git commit -s`) per the [DCO](../DCO) — see [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] `make test` passes (`go test -race ./...`)
- [ ] `make lint` passes (`go vet ./...`)
- [ ] I added or updated tests for behavior changes
- [ ] No PII, secrets, real salts/peppers, API keys, or real bank identifiers in code, tests, or fixtures
- [ ] I did not weaken a privacy/security guarantee (PII in logs, PII on the wire, unsalted hashes, dropped validation) without prior discussion
- [ ] If I changed the Hub wire format, I updated `docs/signal-schema-v2.md`

## Notes for reviewers

<!-- Anything that helps review: trade-offs, alternatives considered, follow-ups. -->
