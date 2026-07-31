# CrawlLedger

**See what crawlers cost your origin before you decide what to block.**

[![CI][badge-ci]][ci]
[![Go][badge-go]][go-module]
[![Builds][badge-builds]][ci]
[![Checks][badge-checks]][ci]
[![Offline runtime][badge-offline]][ci]
[![Security policy][badge-security]][security]
[![License: MIT][badge-license]][license]

Access logs show footprints. They rarely show the bill.

CrawlLedger reads the Nginx or Caddy logs you already have and turns them into
something you can reason about: which claimed crawlers arrived, where they
wandered, how much origin work followed, whether they fell into a crawl trap,
and what a deny or rate-limit policy would have changed.

Everything stays local. The main workflow produces a self-contained HTML
report, machine-readable JSON and—only after a separate simulation—reviewable
server-configuration fragments. An experimental, explicitly enabled Nginx
watcher can also install static probe blocks and temporary emergency rate
limits. It is off by default; dry-run is the default even when invoked.

CI checks formatting, runs `go vet`, and tests on Go 1.26.5 across Ubuntu,
macOS and Windows. It also runs the race detector, twelve fuzz smoke targets,
validates generated Nginx and Caddy fragments, exercises analysis without a
network namespace, cross-builds six pure-Go binaries, and checks schemas, docs
and module integrity.

![CrawlLedger HTML report generated from a synthetic Nginx log](docs/demo-report.png)

<sub>This is the actual HTML report from the synthetic fixture included in the repository. No production traffic is shown.</sub>

## What you get

- Claimed search, AI/LLM, monitoring and other crawler traffic, broken down
  without pretending a User-Agent is proof of identity.
- Origin load by normalized route: response bytes, duration, upstream time and
  cache state whenever the source log actually contains those fields.
- Deterministic findings for crawl traps, expensive 404s, query-space
  explosion, cache busting, security probes and `robots.txt` violations.
- Historical policy simulation with ordered, first-match rules.
- Nginx or Caddy configuration drafts. Drafts—not auto-applied changes.
- Optional Nginx-only emergency protection: deterministic probe `403`s and a
  temporary route-level `429` circuit breaker for very high-confidence floods.
- Privacy-conscious storage; raw log lines are never written to the workspace.

There is one hard boundary. A request labelled `Googlebot`, `GPTBot`, or
anything else has merely claimed that name through its `User-Agent` header.
CrawlLedger does not DNS-verify it. The label may be spoofed.

## Quick start

One prerequisite: Go 1.26.5.

```sh
make build

./bin/crawlledger analyze \
  --input testdata/logs/nginx-combined/valid.log \
  --format nginx-combined \
  --output ./demo-audit
```

Open `demo-audit/report.html` in a browser. The fixture is tiny—three synthetic
requests—but it still demonstrates crawler classification, route
normalization, missing-metric disclosure and a security-probe finding.

Output paths must be new. Deliberately. CrawlLedger refuses to replace an
existing workspace, simulation, evidence bundle, or rendered configuration.

There is no public v1 tag yet, so build from this checkout for now. Tagged
releases will carry binaries and checksums on
[GitHub Releases](https://github.com/balyakin/crawlledger/releases).

## Analyze your logs

Nginx combined log? Point CrawlLedger at it:

```sh
crawlledger analyze \
  --input /var/log/nginx/access.log \
  --format nginx-combined \
  --output ./crawl-audit
```

Caddy JSON is just as direct:

```sh
crawlledger analyze \
  --input /var/log/caddy/access.log \
  --format caddy-json \
  --output ./crawl-audit
```

Repeat `--input` to process several files in order. Plain text and gzip are
detected from their contents, not from a hopeful filename suffix. Use
`--input -` once to read standard input.

One run, one explicit format. CrawlLedger does not guess; a firm parse error
is safer than a polished report built from the wrong grammar.

### Input formats

| Format | Use it for | Metric coverage |
| --- | --- | --- |
| `nginx-combined` | The standard Nginx combined format | Requests, status, bytes, referer and User-Agent |
| `nginx-json` | The CrawlLedger Nginx JSON format below | Adds request time, upstream time and cache state |
| `caddy-json` | Standard Caddy JSON access logs | Adds request duration; upstream and cache metrics are unavailable |
| `crawlledger-json` | A bundle created by `crawlledger sanitize` | Preserves the metrics present in the source bundle |

<details>
<summary>Recommended Nginx JSON log format</summary>

Add this inside the Nginx `http` block:

```nginx
log_format crawlledger escape=json
  '{"timestamp":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"method":"$request_method",'
  '"uri":"$request_uri",'
  '"nginx_uri":"$uri",'
  '"status":"$status",'
  '"limit_req_status":"$limit_req_status",'
  '"bytes_sent":"$body_bytes_sent",'
  '"request_time":"$request_time",'
  '"upstream_response_time":"$upstream_response_time",'
  '"upstream_cache_status":"$upstream_cache_status",'
  '"user_agent":"$http_user_agent",'
  '"referer":"$http_referer"}';

access_log /var/log/nginx/access.crawlledger.json crawlledger;
```

Then analyze it:

```sh
crawlledger analyze \
  --input /var/log/nginx/access.crawlledger.json \
  --format nginx-json \
  --output ./crawl-audit
```

</details>

The complete field set above is required by `protect run`. The two
protection-specific fields are harmless in ordinary offline analysis: `$uri`
binds decisions to the path Nginx will actually enforce, and
`$limit_req_status` distinguishes an application `429` from CrawlLedger's
limiter.

### Inside the workspace

| File | Purpose |
| --- | --- |
| `report.html` | Local, self-contained report for a browser or print-to-PDF |
| `report.json` | Versioned report for scripts and further analysis |
| `analysis.sqlite` | Normalized aggregates and bounded parse diagnostics |
| `manifest.json` | Completion marker, artifact sizes and SHA-256 hashes |

No `manifest.json`? Treat the workspace as incomplete.

## Test a policy before writing configuration

Analysis tells you what happened. Simulation asks the more dangerous question:
what would a policy have done?

Policies are strict, versioned JSON. Rules run from top to bottom; the first
match wins. Small examples live in
[`testdata/policies`](testdata/policies).

```sh
crawlledger policy simulate \
  --workspace ./crawl-audit \
  --policy ./testdata/policies/safe.json \
  --output ./simulation.json
```

Read the totals. Then the rule impacts, coverage and assumptions. Most of all,
read every item in `risks`.

Some risks demand an explicit acknowledgement before rendering:

```sh
crawlledger policy render \
  --workspace ./crawl-audit \
  --policy ./testdata/policies/safe.json \
  --simulation ./simulation.json \
  --target nginx \
  --output ./rendered-nginx \
  --ack claimed-allow-bypass:allow-googlebot
```

That acknowledgement belongs to the bundled example. Use the exact IDs from
your own `simulation.json`; unknown IDs and non-acknowledgeable blockers are
rejected.

Nginx drafts support `allow`, `deny` and fixed rate profiles. Caddy drafts
support `allow` and `deny`. Cache rules are analytical upper bounds, so a
policy containing one remains simulation-only and cannot be rendered.

### Install a draft carefully

Draft means draft. The `analyze`, `sanitize`, `policy simulate`, and
`policy render` workflows never run Nginx, Caddy, Docker, systemd, SSH, or a
shell. Only the separate, experimental `protect` command family described
below has a privileged apply path.

For Nginx, include `crawlledger-http.conf` inside `http {}` and
`crawlledger-server.conf` inside the audited `server {}`, before the content
handler. Back up the current configuration. Then validate:

```sh
nginx -t
```

For Caddy, import `Caddyfile.crawlledger` before `reverse_proxy`, then run:

```sh
caddy adapt --config Caddyfile --adapter caddyfile --validate
caddy validate --config Caddyfile
```

Reload manually and watch responses as well as access logs. If validation or
traffic turns strange, restore the backup and reload.

## Experimental emergency protection for Nginx

This is a narrow origin circuit breaker, not a WAF or a DDoS service. It has
two actions:

- configured, deterministic malicious probe signatures return `403`;
- an extreme route surge or a distributed, expensive request shape can create
  one temporary global route limiter. Requests within its configured rate
  pass; excess requests receive `429`.

The dynamic rule is keyed by HTTP method and safe path prefix—not IP or
User-Agent—so a flood spread across thousands of addresses still shares one
Nginx bucket. That is also the main trade-off: legitimate requests above the
emergency rate receive `429` while the rule is active. Default rule lifetime
is a sliding ten minutes, and detection takes roughly a minute at default
thresholds. Use upstream/CDN protection for network saturation or subsecond
response.

Requirements:

- Linux for `setup`, `clear`, `run --apply`, and the privileged `apply` child;
  dry-run works on Linux, macOS, and Windows;
- Nginx only;
- a dedicated JSON access log with the two fields shown above;
- an integrity-verified, completed `nginx-json` workspace containing at least
  1,440 complete minutes with no route overflow. Seven representative days is
  better;
- a dedicated non-root service account and a root-owned CrawlLedger binary,
  config, Nginx binary, and managed directory.

Start from [the complete example config](docs/examples/crawlledger-protect.json).
Install a root-owned copy; a user-owned `go install` binary is deliberately
rejected by live mode because sudoers authorizes the exact executable:

```sh
sudo install -o root -g root -m 0755 ./bin/crawlledger /usr/local/sbin/crawlledger
sudo install -d -o root -g root -m 0755 /etc/crawlledger
sudo install -o root -g root -m 0644 \
  docs/examples/crawlledger-protect.json /etc/crawlledger/example-protect.json
sudo install -d -o crawlledger -g crawlledger -m 0700 /var/lib/crawlledger/example
```

Run setup as root. It creates locked managed files, runs `nginx -T`,
`nginx -t`, and reloads with rollback. It does not edit `nginx.conf`, sudoers,
or systemd:

```sh
sudo /usr/local/sbin/crawlledger protect setup \
  --config /etc/crawlledger/example-protect.json
```

Manually include the reported HTTP fragment once inside `http {}` and the
server fragment once inside the intended `server {}`. Run setup again so its
expanded-config check sees each marker exactly once. Inspect every nested
`location`: a location-level `limit_req` directive replaces inherited
server-level limiters under native Nginx rules. The synthetic
[Nginx fixture](testdata/protect/nginx/README.md) demonstrates that shadowing.

Observe before enforcing:

```sh
sudo -u crawlledger /usr/local/sbin/crawlledger protect run \
  --config /etc/crawlledger/example-protect.json
```

Dry-run reads neither persistent protection state nor locks and never invokes
Nginx or sudo. Review the structured `protect_candidate` events and tune the
explicit floors, historical multiplier, exclusions, rate, burst, and TTL.

To enable live temporary `429`s, install an exact sudoers grant based on
[the example](docs/examples/crawlledger-protect.sudoers), then add `--apply`.
The long-running process remains unprivileged. It persists a tiny desired-state
file first and sends only method/path pairs to the root child. That child
revalidates the root-owned config and state, checks both locks, runs
`nginx -T` and `nginx -t`, reloads, and restores the exact previous map if a
step fails. It never receives client addresses or detector evidence.

The optional [systemd template](docs/examples/crawlledger-protect@.service)
shows the same boundary. Stop sends `SIGTERM`; the watcher attempts a bounded
graceful clear. After a crash or failed stop, clear explicitly as the service
account:

```sh
sudo -u crawlledger /usr/local/sbin/crawlledger protect clear \
  --config /etc/crawlledger/example-protect.json
```

Static `403` signatures remain installed after the watcher stops. The default
set covers `.env`, `.git`, raw or once-encoded traversal segments, and raw
Log4Shell `${jndi:` probes. Optional WordPress, phpMyAdmin, and shell-path
signatures stay disabled unless you name them in the config because those
paths may be legitimate.

## Share a sanitized evidence bundle

A raw access log is useful evidence wrapped around sensitive data. Do not pass
it around casually. Create a pseudonymized bundle instead:

```sh
crawlledger sanitize \
  --input /var/log/nginx/access.log \
  --format nginx-combined \
  --output ./crawl-evidence \
  --key-file /secure/crawlledger.key
```

If the key file does not exist, CrawlLedger creates a private-permission,
32-byte key. Keep it outside both bundle and workspace. Reusing the key makes
pseudonyms comparable across runs; omitting `--key-file` creates an ephemeral
key that is not retained.

Before any record reaches disk, CrawlLedger:

- replaces client IPs and User-Agent values with domain-separated HMAC
  pseudonyms;
- removes query values while keeping safe query-key names;
- normalizes token-like path segments;
- cuts referers down to hostnames;
- discards cookies and raw log lines.

Safer is not anonymous. The bundle still holds timestamps, normalized routes,
crawler claims, referer hosts and stable pseudonyms; those can be correlated
or re-identified. Treat bundles, workspaces, simulations, keys and generated
configuration as sensitive files.

## Honest limits

- Claimed crawler identity is spoofable. CrawlLedger audits traffic; it does
  not authenticate bots.
- Offline analysis remains batch-based. Experimental live protection is
  Nginx-only, opt-in, and intentionally limited to very high-confidence route
  floods and explicit static signatures.
- The emergency limiter does not protect bandwidth, TLS, connection tables,
  attacks that stop log delivery, arbitrary low-rate path fragmentation, or
  application routes hidden behind path-changing rewrites.
- Combined Nginx and standard Caddy logs cannot expose every origin or cache
  metric. Reports show the holes instead of filling them with guesses.
- Cost figures are proportional allocations driven by your configuration,
  neither invoices nor promised savings.
- Cache simulation cannot see application semantics such as `Authorization`,
  `Set-Cookie`, `Cache-Control`, or `Vary`.
- History is not prophecy: a simulation cannot know how a crawler will react
  after the policy changes.

## License

CrawlLedger is released under the [MIT License](LICENSE). Third-party
attributions live in [NOTICE](NOTICE).

## Development

The everyday local gate is short:

```sh
make check
```

That checks formatting, runs `go vet`, tests the code and builds the project.
Before a release—or after changing parsing, normalization, policy evaluation,
or rendering—go further:

```sh
make test-race
make fuzz-smoke
```

Fixtures use synthetic documentation addresses and `.example` domains. Keep
production logs, customer workspaces, credentials and real HMAC keys out of
the repository.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before touching schemas, migrations, or
the embedded crawler catalog. Security reports take a different route: follow
[SECURITY.md](SECURITY.md), and never place sensitive details in a public
issue.

This project was developed with AI assistance and is maintained by the author.

[badge-ci]: https://github.com/balyakin/crawlledger/actions/workflows/ci.yml/badge.svg
[badge-go]: https://img.shields.io/badge/go-1.26.5-00ADD8?logo=go&logoColor=white
[badge-builds]: https://img.shields.io/badge/build-linux%20%7C%20macOS%20%7C%20Windows-brightgreen
[badge-checks]: https://img.shields.io/badge/checks-vet%20%7C%20race%20%7C%20fuzz-brightgreen
[badge-offline]: https://img.shields.io/badge/runtime-offline-blueviolet
[badge-security]: https://img.shields.io/badge/security-policy-blue
[badge-license]: https://img.shields.io/badge/license-MIT-green.svg
[ci]: https://github.com/balyakin/crawlledger/actions/workflows/ci.yml
[go-module]: go.mod
[security]: SECURITY.md
[license]: LICENSE
