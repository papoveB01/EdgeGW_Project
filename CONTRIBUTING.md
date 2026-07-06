# Contributing to Edge Gateway

Thanks for your interest in improving Edge Gateway. This project is developed
in the open and we welcome bug reports, fixes, tests, docs, and feature
proposals from the community.

## Ground rules

- **Be respectful.** All participation is governed by our
  [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security issues are different.** Do **not** open a public issue or PR for a
  vulnerability. Follow the process in [SECURITY.md](SECURITY.md).
- **This is privacy- and compliance-sensitive software** handling financial
  fraud signals. Never include real PII, production secrets, real bank
  identifiers, salts, peppers, or API keys in issues, tests, or fixtures.

## License and the DCO sign-off

Edge Gateway is licensed under the [Apache License 2.0](LICENSE). Contributions
are accepted **inbound under the same license** — by contributing, you agree
your contribution is licensed to the project and its users under Apache 2.0.
You retain copyright to your contribution.

We use the **Developer Certificate of Origin (DCO)** instead of a CLA. The DCO
is a lightweight statement (see the [DCO](DCO) file) that you have the right to
submit the code you are contributing. You certify it by adding a `Signed-off-by`
line to **every commit**:

```
Signed-off-by: Jane Developer <jane@example.com>
```

The name and email must be your real identity and match the commit author. The
easiest way is to let git add it automatically:

```bash
git commit -s -m "Fix geohash rounding at the pole"
```

To sign off a commit you already made, or a whole branch:

```bash
git commit --amend -s --no-edit        # last commit
git rebase --signoff main              # every commit on your branch
```

PRs whose commits are not signed off cannot be merged. (Maintainers: enable the
[DCO GitHub App](https://github.com/apps/dco) on the repo to enforce this
automatically — it requires no workflow file and no special token scope.)

## Development workflow

```bash
# Fork and clone, then:
make test        # go test -race ./...
make lint        # go vet ./...
make build       # produces ./edge-gateway
```

Before opening a PR:

1. **Open an issue first** for anything beyond a small fix, so we can agree on
   the approach before you invest time.
2. `make test` and `make lint` must pass. Add tests for behavior changes —
   the anonymization, validation, and forwarding paths especially.
3. Keep changes focused; one logical change per PR.
4. Never weaken a privacy or security guarantee (PII in logs, PII on the wire,
   unsalted hashes, dropped validation) without explicit discussion in the issue.
5. If you change the Hub wire format, update `docs/signal-schema-v2.md` — that
   contract is coordinated with the Hub team.

## Reporting bugs and requesting features

Use GitHub Issues. For bugs, include the gateway version, Go version, config
(with secrets redacted), and a minimal reproduction. For features, describe the
fraud-detection or operational problem you're solving, not just the mechanism.

## What we're likely to accept

Correctness fixes, tests, docs, performance work, portability, and
observability improvements are all welcome. Larger architectural changes and
anything touching the anonymization scheme or the Hub contract should start as
an issue or design discussion first.
