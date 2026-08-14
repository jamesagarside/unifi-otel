# unifi-otel

An OpenTelemetry Collector configuration that receives UniFi syslog and
CEF — and, optionally, polls the console over SNMP — parses it with OTTL
into ECS-shaped records, and exports them over OTLP to whatever you point
it at. It is YAML and nothing else: no plugin, no fork, no custom image,
just `--config` files for the stock
`otel/opentelemetry-collector-contrib` build.

The parsing is the value. There is no backend-specific index, data stream
or routing configuration anywhere in `collector/`, because where a record
lands is a property of your gateway, not of the parsing.

## Start here

[`docs/quickstart.md`](docs/quickstart.md) is the fastest path from
nothing to a parsed record: Docker Compose, three commands, **no
credentials of any kind**, prints to stdout and exports nowhere. Prove
the parsing works there first, even if you are heading for Kubernetes.

## What is covered, and what is not

| Area | Status |
| --- | --- |
| UniFi Network events via the **SIEM Server** feed (CEF) | **Parsed.** Per-code taxonomy for the codes observed live (201, 202, 203, 401–405, 544, 546, firewall policy events); an unseen code still lands in `unifi.network` rather than falling out of the schema. |
| **Gateway/console device syslog** (RFC3164 over UDP) | **Parsed** into five datasets — `coredns`, `dnsmasq-dhcp`, `sudo`, `linkcheck`, and everything else. |
| **AP and switch syslog** | **Unverified.** The parsers exist and are believed correct, but **no real AP or switch frame has ever been seen by this project** ([#20](https://github.com/jamesagarside/unifi-otel/issues/20)). The shape is exercised by synthetic replay only. Not a support claim. |
| **Non-CEF RFC5424 over TCP** | **Under-tested** ([#25](https://github.com/jamesagarside/unifi-otel/issues/25)). The receiver shares the operators and processor chain with the UDP path, but whether UniFi emits non-CEF device syslog over 5424 at all is an open question, and no real frame exists to check against. |
| **UniFi Protect, Access and Talk** | **No path in at all** ([#21](https://github.com/jamesagarside/unifi-otel/issues/21)). The SIEM feed is Network-only — its CEF header is always `Ubiquiti\|UniFi Network`. The only other route is the Alarm Manager webhook, which is deliberately absent: for Network events it duplicated syslog exactly, and syslog is the superset. |
| **SNMP metrics** | **Opt-in, off by default** ([`docs/snmp.md`](docs/snmp.md)). Three extra `--config` flags and SNMPv3 credentials. It reaches the **console only**, and CI cannot cover it. |
| **Per-port / per-device counters** from adopted APs and switches | **Not available.** Those devices serve no SNMP agent. A UniFi limitation, not a gap here. |
| `linkcheck` **multi-line JSON** | **Parsed** ([#9](https://github.com/jamesagarside/unifi-otel/issues/9)). A `recombine` operator reassembles the datagrams of one pretty-printed frame into a single record, and the payload becomes `unifi.speedtest`. Verified against **one real captured frame, from one gateway** — the operator is scoped to that shape and nothing else is reassembled. The residual log noise and the multi-gateway caveat are in [`docs/known-issues.md`](docs/known-issues.md). |
| **Backend routing** (index, data stream, sourcetype) | **Not shipped, by design.** Records carry `event.dataset`; a backend that routes on a different field — Elasticsearch routes on `data_stream.dataset` — needs that mapping in your own gateway. See [`docs/destinations.md`](docs/destinations.md). |

## Datasets

Every record leaves with exactly one `event.dataset`. Five come from the
CEF feed, five from device syslog.

| `event.dataset` | Source | Carries |
| --- | --- | --- |
| `unifi.firewall` | CEF, any event with `UNIFIpolicyType: Firewall` | 5-tuple, allowed/denied, `rule.name` and `rule.ruleset`, source/destination zones, byte and packet counts |
| `unifi.security` | CEF, category `Security` other than policy enforcement | IDS/IPS detections and honeypot triggers. `event.kind: alert`, on a deny-list — code 203 and firewall enforcement are excluded, everything else in the category alerts |
| `unifi.client` | CEF, category `Client Devices` | connect / disconnect / roam, SSID, band, channel, RSSI, the AP or switch the client is on and the one it came from, session duration and usage |
| `unifi.audit` | CEF, category `Audit` | admin sign-in and configuration change, `user.name`, access method, settings section/entry/changes |
| `unifi.network` | CEF, default | any CEF event the four above do not claim — the reason an unseen event code stays inside the schema |
| `unifi.dns` | device syslog, `coredns` | DNS **block** decisions only — `dns.question.name`, `rule.category`, client IP/MAC. It is not a record of every lookup |
| `unifi.dhcp` | device syslog, `dnsmasq-dhcp` | DISCOVER / OFFER / REQUEST / ACK: MAC → IP → hostname → bridge interface, which is the join key for the other datasets |
| `unifi.sudo` | device syslog, `sudo` | privileged execution: user, effective user, working directory, command line, and `event.outcome` including the failure lines |
| `unifi.speedtest` | device syslog, `linkcheck` | WAN speedtest results, reassembled from a pretty-printed multi-line JSON frame: the measured rate in `unifi.speedtest.speed_mbps`, the test endpoint in `url.full` and `destination.ip`/`destination.port`, and the test server's ISP and geo under `destination.as.*` and `destination.geo.*`. The only dataset here that describes the far end rather than your own network |
| `unifi.system` | device syslog, everything else | `systemd`, `mcad`, `ubios-udapi-server`, `ulogd`, `earlyoom` and similar. Syslog envelope, process name and pid, severity from the PRI; per-daemon internal formats are not parsed yet |

`unifi.syslog` is a transient value the non-CEF branch assigns before
refinement. No record leaves carrying it, and the test suite asserts
that.

Records that fail a parsing stage are tagged `unifi.parse_failure` with
the stage that failed, routed to their own pipeline, printed in full by a
`debug` exporter, and still exported — so a frame the parser cannot
handle announces itself instead of passing through as plausible output.

## Schema

**OTel semantic conventions wherever the ECS ↔ OTel alignment table
records a match or equivalent relationship AND the mapping permits it;
ECS retained for the security event taxonomy, which semconv does not
cover, and for two fields whose ECS names collide with OTel namespaces.**

This project is **not** semconv-compliant and does not claim to be. ECS
was donated to OpenTelemetry with the intent to converge, but that
convergence is directional and explicitly incomplete, so the label would
be inaccurate.

Three consequences worth knowing before you query the data:

- **`source.ip` and `source.address` are both emitted** (likewise
  `destination.*`). The alignment table marks them equivalent, there is
  no alias mechanism in a log record, and consumers exist for both
  spellings — ECS security rules want `.ip`, semconv consumers want
  `.address`.
- **`process.executable` and `network.protocol` keep their ECS
  spellings.** The table marks them equivalent to
  `process.executable.path` and `network.protocol.name`, but there the
  ECS name *is* the OTel namespace, and a document store cannot map one
  field as both a leaf and an object.
- **`event.*`, `observer.*`, `related.*`, `rule.*` stay ECS.** Semconv
  has no successor for the security event taxonomy, which is the whole
  reason ECS is still here.

Vendor detail ECS has no home for keeps a `unifi.*` prefix rather than
being dropped. The field-by-field reasoning lives in the comments of
[`collector/20-processors-logs.yaml`](collector/20-processors-logs.yaml).

## How this is tested

A corpus of **352 frames in 20 files** is replayed through the **real,
pinned collector image** and diffed against committed golden files. It
runs on every pull request and every push to `main`, as the `corpus
replay + privacy gate` job in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). Five bars, each
reported separately:

1. zero OTTL errors from any processor or exporter (receiver-level noise
   is pinned by count in a telemetry golden, not waved through);
2. every record carries exactly one `event.dataset` and none is stranded
   on the `unifi.syslog` fallback;
3. no working attribute survives — the check lifts the strip regex
   verbatim from the config;
4. the CEF path is byte-identical with and without the device-syslog
   transform, and **fails** rather than passing vacuously if it finds no
   CEF frames;
5. 26 matched pairs — 21 hostname shapes, 5 transport — agree on
   dataset, populated key set, severity and parse-failure status, with
   `event.original` byte-equal to the frame sent.

Bar 5 exists because of
[#24](https://github.com/jamesagarside/unifi-otel/issues/24), where
device-log parsing silently degraded on any device that did not double
its hostname: bars 1–4 all pass with that bug present. Only bar 5 and the
goldens catch it.

CI also runs `otelcol validate` over three config permutations —
including a negative control asserting SNMP still refuses to start
without credentials — validates every destination snippet in the docs
against the pinned image, and lints, renders and `kubeconform`s the Helm
chart, then diffs the rendered config against `collector/*.yaml` to catch
drift.

**What this does not prove**, stated plainly:

- **The corpus is hybrid, and every real frame came from one gateway.**
  285 of the 352 frames were captured from a live UDM and scrubbed; the
  other 67 are synthetic. A synthetic frame was written by someone who
  had already read the parser, so it can only encode properties already
  known — read a green run on that portion as "the parsers still do what
  they did when the goldens were written", not as "the parsers are
  correct". The real frames do not carry that circularity, but they are
  one model of gateway on one site: no AP or switch has ever sent a
  frame here ([#20](https://github.com/jamesagarside/unifi-otel/issues/20)),
  and the capture contained no RFC5424 at all
  ([#25](https://github.com/jamesagarside/unifi-otel/issues/25)), so
  those shapes remain synthetic-only.
- **CI proves the log path only.** SNMP polls *outward* to a live device
  on a schedule — there is no frame to replay, so CI can only prove the
  SNMP config parses and builds, never that the OIDs still return what
  the comments say.
- **No destination beyond OTLP is proven.** The gateway snippets in the
  docs are validated as config, which shows the components exist and the
  keys parse; it does not show that data arrives.

[`tests/README.md`](tests/README.md) carries the full per-property
observation-versus-invention table, the harness gotchas, and the known
limitations of the goldens.

## Destinations

The collector has exactly one exporter, `otlp_grpc/gateway`. Point
`OTLP_GATEWAY_ENDPOINT` at anything that speaks OTLP/gRPC.
[`docs/destinations.md`](docs/destinations.md) carries six
gateway-collector recipes, equally weighted and alphabetical, each
validated in CI against the pinned image, each with an honest note on
whether anyone has actually run it. Destinations are documentation, not
shipped config: baking one vendor's routing into the shared pipeline
would make everyone else's install a fork.

## Known issues

[`docs/known-issues.md`](docs/known-issues.md). An entry earns a place
there if a working deployment produces visible evidence of it — records
in the parse-failure stream, errors in the container log, or a field
conspicuously absent. One entry today: `linkcheck`'s continuation lines
still make the receiver log an error each, even though the frame they
belong to is now reassembled and no failure record is produced.

## Contributing

The most useful contribution to this project is **a real, scrubbed
frame** from hardware the maintainer does not own. In rough order of
value:

- an AP or switch frame ([#20](https://github.com/jamesagarside/unifi-otel/issues/20));
- a non-CEF RFC5424 device frame, if such a thing exists
  ([#25](https://github.com/jamesagarside/unifi-otel/issues/25));
- Protect or Access alarms, from someone who runs that hardware
  ([#21](https://github.com/jamesagarside/unifi-otel/issues/21));
- a `linkcheck` frame from a **second** gateway, with every continuation
  line intact ([#9](https://github.com/jamesagarside/unifi-otel/issues/9)).
  Reassembly is verified, but against exactly one frame from one box, so
  the payload key set and the frame boundary are one observation each.

**Never paste a raw frame into an issue or a pull request.** Read
[`docs/contributing-samples.md`](docs/contributing-samples.md) first —
its privacy rules are not optional — and scrub with
[`scripts/scrub.py`](scripts/scrub.py) before the frame leaves your
machine ([usage and exit codes](scripts/README.md)). Corrections to the
unverified destination entries are welcome on the same terms.

## Documentation

| File | What it is |
| --- | --- |
| [`docs/quickstart.md`](docs/quickstart.md) | Docker Compose quickstart, zero credentials. The primary entry point |
| [`docs/destinations.md`](docs/destinations.md) | Six backends, equally weighted, with verification status |
| [`docs/snmp.md`](docs/snmp.md) | The opt-in SNMP module: what it adds, what it does not, how to enable it |
| [`docs/helm.md`](docs/helm.md) | Kubernetes deployment via the wrapper chart |
| [`docs/known-issues.md`](docs/known-issues.md) | Known issues, with symptoms and what a fix would need |
| [`docs/contributing-samples.md`](docs/contributing-samples.md) | How to contribute test fixtures without publishing your network |
| [`docs/versions.md`](docs/versions.md) | Collector version pinning, the minimum supported version, version-sensitive behaviour |
| [`chart/README.md`](chart/README.md) | Chart values, files, and the chart/collector drift check |
| [`scripts/README.md`](scripts/README.md) | `scrub.py`, the capture scrubber and privacy gate |
| [`tests/README.md`](tests/README.md) | The replay corpus and harness, and what it does and does not prove |

The configuration itself is heavily commented and is the authority on
every decision in it:
[`10-receivers-logs.yaml`](collector/10-receivers-logs.yaml),
[`20-processors-logs.yaml`](collector/20-processors-logs.yaml),
[`40-exporters.yaml`](collector/40-exporters.yaml),
[`90-service.yaml`](collector/90-service.yaml), and the optional
[`collector/optional/snmp/`](collector/optional/snmp).

## Versions

| | |
| --- | --- |
| Collector image | `otel/opentelemetry-collector-contrib:0.157.0`, pinned |
| Minimum supported | `0.157.0` |
| Upstream Helm chart | `opentelemetry-collector` 0.168.0 |

The pin is not caution for its own sake: this configuration leans on
OTTL, on the syslog receiver's timestamp handling and on confmap's
deep-merge semantics, all of which have changed between releases. CI
asserts the three places the version is written agree with each other,
and separately exercises the minimum and upstream `:latest`. See
[`docs/versions.md`](docs/versions.md).

## Licence

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This project is not affiliated with, endorsed by, or supported by
Ubiquiti Inc., nor by the vendors of any observability backend named in
this repository. Product names are used only to describe the formats this
configuration parses and the places telemetry can be sent.
