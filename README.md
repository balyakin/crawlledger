# CrawlLedger

**See what crawlers cost your origin before you decide what to block.**

[![CI][badge-ci]][ci]
[![Go][badge-go]][go-module]
[![Builds][badge-builds]][ci]
[![Checks][badge-checks]][ci]
[![Offline runtime][badge-offline]][ci]
[![Security policy][badge-security]][security]
[![License: MIT][badge-license]][license]

Access logs leave footprints. The invoice stays buried.

CrawlLedger digs through the Nginx or Caddy logs you already keep and surfaces what actually matters: which claimed crawlers showed up, which corners of the site they scraped, how hard the origin worked for them, whether any of them wandered into a trap, and what a deny or rate-limit rule would have changed if it had been live.

Nothing leaves the machine. The ordinary path ends with a self-contained HTML report, machine-readable JSON, and—only after you run a separate simulation—configuration fragments you can read before anyone touches the server. There is also an experimental Nginx watcher. Explicitly enabled. Capable of dropping static probe blocks and short-lived emergency rate limits. Off unless you turn it on; dry-run even then.

CI is picky on purpose. Formatting, `go vet`, tests on Go 1.26.5 across Ubuntu, macOS and Windows. Race detector. Twelve fuzz smoke targets. Validation of the generated Nginx and Caddy scraps. Analysis exercised with no network namespace in sight. Six pure-Go binaries cross-built. Schemas, docs, module integrity—checked.

![CrawlLedger HTML report generated from a synthetic Nginx log](docs/demo-report.png)

<sub>This is the actual HTML report from the synthetic fixture included in the repository. No production traffic is shown.</sub>

## What you get

- Claimed search, AI/LLM, monitoring and other crawler traffic, sliced apart without treating a User-Agent string as gospel.
- Origin load by normalized route: response bytes, duration, upstream time and cache state—when the source log bothers to carry those fields.
- Deterministic findings for crawl traps, expensive 404s, query-space blow-ups, cache busting, security probes and `robots.txt` violations.
- Historical policy simulation. Ordered rules. First match wins.
- Nginx or Caddy configuration drafts. Drafts. Not silent rewrites of your live config.
- Optional Nginx-only emergency protection: hard probe `403`s plus a temporary route-level `429` breaker aimed at very high-confidence floods.
- Storage that keeps raw log lines out of the workspace on purpose.

One hard line. A request labelled `Googlebot`, `GPTBot`, or anything else has only claimed that name in a header. CrawlLedger does not chase reverse DNS. Spoofing works. Treat the label as a claim.

## Quick start

One prerequisite: Go 1.26.5.

```sh
make build

./bin/crawlledger analyze \
  --input testdata/logs/nginx-combined/valid.log \
  --format nginx-combined \
  --output ./demo-audit
```

Open `demo-audit/report.html`. The fixture is deliberately tiny—three synthetic requests—and still shows crawler classification, route normalization, missing-metric disclosure and a security-probe finding.

Output paths have to be fresh. CrawlLedger will not overwrite an existing workspace, simulation, evidence bundle or rendered configuration. That refusal is intentional.

No public v1 tag yet. Build from this checkout. Tagged releases will ship binaries and checksums on
[GitHub Releases](https://github.com/balyakin/crawlledger/releases).

## Analyze your logs

Got an Nginx combined log? Feed it in:

```sh
crawlledger analyze \
  --input /var/log/nginx/access.log \
  --format nginx-combined \
  --output ./crawl-audit
```

Caddy JSON is the same shape of command:

```sh
crawlledger analyze \
  --input /var/log/caddy/access.log \
  --format caddy-json \
  --output ./crawl-audit
```

Repeat `--input` for several files; they are processed in the order you give them. Plain text versus gzip is sniffed from content, not from a hopeful suffix. `--input -` once reads standard input.

One run, one explicit format. CrawlLedger refuses to guess. A blunt parse error beats a glossy report built on the wrong grammar.

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

`protect run` wants the full field set above. The two protection-specific fields do not hurt ordinary offline analysis: `$uri` ties decisions to the path Nginx will actually enforce, and `$limit_req_status` keeps an application `429` distinct from CrawlLedger's own limiter.

### Inside the workspace

| File | Purpose |
| --- | --- |
| `report.html` | Local, self-contained report for a browser or print-to-PDF |
| `report.json` | Versioned report for scripts and further analysis |
| `analysis.sqlite` | Normalized aggregates and bounded parse diagnostics |
| `manifest.json` | Completion marker, artifact sizes and SHA-256 hashes |

Missing `manifest.json`? Call the workspace unfinished.

## Test a policy before writing configuration

Analysis recounts the past. Simulation asks the nastier question: what would this policy have done?

Policies are strict, versioned JSON. Rules walk top to bottom; first match wins. Small samples sit in
[`testdata/policies`](testdata/policies).

```sh
crawlledger policy simulate \
  --workspace ./crawl-audit \
  --policy ./testdata/policies/safe.json \
  --output ./simulation.json
```

Read the totals. Then rule impacts, coverage, assumptions. And every single entry in `risks`.

Some risks refuse to render until you acknowledge them by name:

```sh
crawlledger policy render \
  --workspace ./crawl-audit \
  --policy ./testdata/policies/safe.json \
  --simulation ./simulation.json \
  --target nginx \
  --output ./rendered-nginx \
  --ack claimed-allow-bypass:allow-googlebot
```

That acknowledgement is for the bundled example. Pull the exact IDs from your own `simulation.json`. Unknown IDs and non-acknowledgeable blockers are rejected cold.

Nginx drafts cover `allow`, `deny` and fixed rate profiles. Caddy drafts cover `allow` and `deny`. Cache rules stay analytical upper bounds—simulation-only, never rendered.

### Install a draft carefully

Draft means draft. `analyze`, `sanitize`, `policy simulate` and `policy render` never touch Nginx, Caddy, Docker, systemd, SSH or a shell. The only privileged apply path lives in the separate, experimental `protect` family below.

For Nginx, drop `crawlledger-http.conf` inside `http {}` and `crawlledger-server.conf` inside the audited `server {}`, ahead of the content handler. Back up first. Then:

```sh
nginx -t
```

For Caddy, import `Caddyfile.crawlledger` before `reverse_proxy`, then:

```sh
caddy adapt --config Caddyfile --adapter caddyfile --validate
caddy validate --config Caddyfile
```

Reload by hand. Watch responses and access logs together. Validation looks wrong, or traffic starts acting odd—restore the backup and reload again.

## Experimental emergency protection for Nginx

Narrow origin circuit breaker. Not a WAF. Not a DDoS product. Two moves only:

- configured, deterministic malicious probe signatures answer with `403`;
- an extreme route surge, or a distributed expensive request shape, can spin up one temporary global route limiter. Traffic inside the configured rate passes; the rest gets `429`.

The dynamic rule keys on HTTP method and a safe path prefix—not IP, not User-Agent—so a flood spread across thousands of addresses still lands in one Nginx bucket. That is the trade-off in plain sight: legitimate requests above the emergency rate also eat `429` while the rule lives. Default lifetime is a sliding ten minutes. Detection needs roughly a minute at stock thresholds. Network saturation and subsecond reaction still belong to upstream or CDN gear.

Requirements:

- Linux for `setup`, `clear`, `run --apply`, and the privileged `apply` child; dry-run works on Linux, macOS, and Windows;
- Nginx only;
- a dedicated JSON access log carrying the two fields shown above;
- an integrity-verified, completed `nginx-json` workspace with at least 1,440 complete minutes and no route overflow—seven representative days is better;
- a dedicated non-root service account plus a root-owned CrawlLedger binary, config, Nginx binary, and managed directory.

Start from [the complete example config](docs/examples/crawlledger-protect.json).
Install a root-owned copy. A user-owned `go install` binary is rejected in live mode on purpose—sudoers pins the exact executable:

```sh
sudo install -o root -g root -m 0755 ./bin/crawlledger /usr/local/sbin/crawlledger
sudo install -d -o root -g root -m 0755 /etc/crawlledger
sudo install -o root -g root -m 0644 \
  docs/examples/crawlledger-protect.json /etc/crawlledger/example-protect.json
sudo install -d -o crawlledger -g crawlledger -m 0700 /var/lib/crawlledger/example
```

Run setup as root. It locks managed files into place, runs `nginx -T`, `nginx -t`, and reloads with rollback. It does not rewrite `nginx.conf`, sudoers, or systemd:

```sh
sudo /usr/local/sbin/crawlledger protect setup \
  --config /etc/crawlledger/example-protect.json
```

Include the reported HTTP fragment once inside `http {}` and the server fragment once inside the intended `server {}`. Run setup again so the expanded-config check sees each marker exactly once. Then stare at every nested `location`: a location-level `limit_req` replaces inherited server-level limiters under ordinary Nginx rules. The synthetic
[Nginx fixture](testdata/protect/nginx/README.md) shows that shadowing in action.

Watch before you enforce:

```sh
sudo -u crawlledger /usr/local/sbin/crawlledger protect run \
  --config /etc/crawlledger/example-protect.json
```

Dry-run touches neither persistent protection state nor locks, and never calls Nginx or sudo. Read the structured `protect_candidate` events. Tune floors, historical multiplier, exclusions, rate, burst, TTL.

Live temporary `429`s need an exact sudoers grant based on
[the example](docs/examples/crawlledger-protect.sudoers), then `--apply`.
The long-running process stays unprivileged. It writes a tiny desired-state file first and hands the root child only method/path pairs. That child rechecks the root-owned config and state, verifies both locks, runs `nginx -T` and `nginx -t`, reloads, and restores the previous map if any step fails. Client addresses and detector evidence never cross that boundary.

The optional [systemd template](docs/examples/crawlledger-protect@.service)
keeps the same split. Stop sends `SIGTERM`; the watcher tries a bounded graceful clear. After a crash or a failed stop, clear explicitly as the service account:

```sh
sudo -u crawlledger /usr/local/sbin/crawlledger protect clear \
  --config /etc/crawlledger/example-protect.json
```

Static `403` signatures stay installed after the watcher exits. Defaults cover `.env`, `.git`, raw or once-encoded traversal segments, and raw Log4Shell `${jndi:` probes. WordPress, phpMyAdmin and shell-path signatures stay off unless you name them in the config—those paths can be legitimate.

## Share a sanitized evidence bundle

A raw access log is useful evidence wrapped in things you should not email. Build a pseudonymized bundle instead:

```sh
crawlledger sanitize \
  --input /var/log/nginx/access.log \
  --format nginx-combined \
  --output ./crawl-evidence \
  --key-file /secure/crawlledger.key
```

Missing key file? CrawlLedger writes a 32-byte key with private permissions. Keep it outside both bundle and workspace. Reuse the same key if you want pseudonyms comparable across runs; skip `--key-file` and you get an ephemeral key that is not retained.

Before anything hits disk, CrawlLedger:

- swaps client IPs and User-Agent values for domain-separated HMAC pseudonyms;
- strips query values while keeping safe query-key names;
- normalizes token-like path segments;
- cuts referers down to hostnames;
- drops cookies and raw log lines.

Safer is not anonymous. Timestamps, normalized routes, crawler claims, referer hosts and stable pseudonyms still sit in the bundle; correlation and re-identification remain possible. Treat bundles, workspaces, simulations, keys and generated configuration as sensitive.

## Honest limits

- Claimed crawler identity is spoofable. CrawlLedger audits traffic. It does not authenticate bots.
- Offline analysis is batch work. Experimental live protection is Nginx-only, opt-in, and deliberately limited to very high-confidence route floods plus explicit static signatures.
- The emergency limiter does not cover bandwidth, TLS, connection tables, attacks that stop log delivery, arbitrary low-rate path fragmentation, or application routes hidden behind path-changing rewrites.
- Combined Nginx and standard Caddy logs cannot expose every origin or cache metric. Reports show the gaps instead of inventing numbers.
- Cost figures are proportional allocations from your configuration—not invoices, not guaranteed savings.
- Cache simulation cannot see application semantics such as `Authorization`, `Set-Cookie`, `Cache-Control`, or `Vary`.
- History is not prophecy. A simulation cannot know how a crawler will behave after the policy changes.

## License

CrawlLedger ships under the [MIT License](LICENSE). Third-party attributions live in [NOTICE](NOTICE).

## Development

Day-to-day gate is short:

```sh
make check
```

Formatting, `go vet`, tests, build. Before a release—or after you touch parsing, normalization, policy evaluation, or rendering—go further:

```sh
make test-race
make fuzz-smoke
```

Fixtures stick to synthetic documentation addresses and `.example` domains. Keep production logs, customer workspaces, credentials and real HMAC keys out of the repository.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing schemas, migrations, or the embedded crawler catalog. Security reports take another door: follow
[SECURITY.md](SECURITY.md), and never drop sensitive detail into a public issue.

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
