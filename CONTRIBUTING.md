# Contributing

Keep the change narrow. One problem, one pull request, and the smallest test
that proves the behavior.

## Local setup

Use Go 1.26.5. Keep the runtime dependency set fixed unless the product
contract is being deliberately revised.

The usual pre-push check is:

```sh
make check
```

The individual targets are available when you need a tighter loop:

```sh
make fmt
make vet
make test
make test-race
make fuzz-smoke
make build
make check
```

`make check` verifies formatting, runs `go vet`, tests, and builds. Before a
release—or after changing parsing, normalization, policy evaluation, or
rendering—also run `make test-race` and `make fuzz-smoke`.

## Code and tests

Tests use Go's standard `testing` package. Behavior changes need the smallest
runnable regression check that would fail if the behavior returned.

Do not add stubs, disabled tests, placeholder implementations, telemetry,
network calls, hidden commands, or implicit apply behavior. The experimental
Nginx watcher must remain dry-run by default; only an explicit `--apply` may
enter its documented privilege path. Avoid speculative interfaces and utility
packages too; split code only when a second responsibility is already real.

## Fixture privacy

Fixtures must be synthetic. Use RFC 5737/3849 documentation addresses,
`.example` domains, and explicit synthetic canaries.

Never commit client or production logs, keys, cookies, email addresses,
credentials, database dumps, or customer workspaces. Minimize fuzz crashers
and inspect them for sensitive input before committing.

Security findings do not belong in a public issue or pull request. Follow
[SECURITY.md](SECURITY.md).

## Contract changes

Changes to policy, config, report, simulation, sanitized, workspace, or render
formats must update all of these together:

- Go DTO validation;
- JSON Schema;
- synthetic valid and invalid fixtures;
- compatibility notes.

SQLite changes require a new transactional migration and an updated
`PRAGMA user_version`. Never edit a published migration.

Protection changes must also keep the Go validators and three `protect-v1`
schemas aligned, preserve canonical state/apply JSON and active-map bytes, and
test both dry-run and Linux mutation boundaries. Run the protection fuzz
targets and the pinned real-Nginx fixture after changing parsing, matching,
rendering, locks, rollback, rate/burst behavior, or Nginx includes. Never add a
second privileged command to the sudoers example; `setup` runs manually as
root and `clear` runs as the service account through the existing locked
`apply` child.

## Catalog updates

1. Pin an immutable upstream commit.
2. Rebuild the embedded catalog deterministically.
3. Review case-insensitive name and token uniqueness, plus boundary matching.
4. Recheck curated categories and protected defaults.
5. Update `internal/catalog/data/NOTICE.md`, root `NOTICE`, the version string,
   tests, and generated evidence.

## Review boundaries

There is no automatic line-count gate. Review files longer than 400 lines for
mixed responsibilities, but do not split a cohesive file merely to satisfy a
number.

No DCO or CLA is imposed. Adding either requires an explicit owner decision
and a documentation change.
