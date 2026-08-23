# `tests/` — golden-file replay corpus and harness

This replays a corpus of syslog frames through the **real, pinned
collector image** and compares the parsed records against committed
golden files. It is the thing that makes a claim like "the DHCP parser
handles `DHCPDISCOVER`" checkable by somebody who does not have a UniFi
gateway.

```
tests/
  corpus/     the frames, one per line (or one per `#[frame]` block for
              a multi-line frame), grouped by dataset and shape
  golden/     the expected record for every frame, plus the expected
              collector telemetry
  run.py      the harness
```

---

## Read this first: the corpus is hybrid

**359 frames — 286 real, 73 synthetic.**

A frame is not always a line. 359 frames go out as **381 wire units**
(datagrams, or newline-delimited records on TCP), because four frames
are several datagrams that the receiver recombines into a single record
each: the two `linkcheck` frames are eleven apiece and the two
`wan-failover-monitor-icmp` frames are two apiece. See
[Multi-line frames](#multi-line-frames).

Files named `real-*.txt` came off a live UDM gateway and were passed
through [`scripts/scrub.py`](../scripts/scrub.py). Everything else was
written by hand against the shapes documented in this repository.

The split matters, and issue
[#3](https://github.com/jamesagarside/unifi-otel/issues/3) says why
better than this file can:

> the format's important properties were *discovered*, not predicted. The
> doubled hostname is the clearest example — nobody hand-writing fixtures
> invents it, and it is the single thing most likely to break a naive
> parser.

That argument proved itself the first time real frames arrived. Scrubbing
them exposed two leaks no synthetic fixture could have contained: a
`linkcheck` speedtest payload carrying a real ISP, its domain, the city,
coordinates to fifteen decimal places and the reporting device's
timezone — and, underneath that, the fact that **no domain inside any URL
had ever been scrubbed anywhere**. Nobody hand-writes a fixture
containing their own ISP, so nobody would have found it.

**What the real frames are, and are not.** They come from one household's
gateway over seven days. They are real UniFi output, which is what makes
them worth having. They are not a representative sample of UniFi
deployments — one site, one hardware generation, one configuration.

**The synthetic frames are still load-bearing** and are not going away.
They cover edge cases a capture is unlikely to contain on any given week:
a truncated CEF envelope, an unmapped event code, a 1400-byte frame, a
line with no tag at all. Real traffic supplies the ordinary; synthetic
supplies the deliberately awkward.

Still not covered by either: see
[Known limitations](#known-limitations). Do not read a green
run as "the parsers are correct" — read it as "the parsers still do what
they did when these goldens were written", now with a much better idea of
what they actually did.

### What rests on observation, and what is invention

| Property in the corpus | Basis |
| --- | --- |
| The gateway **doubles its hostname** (`host host tag[pid]: …`) | Observed. Documented in `collector/20-processors-logs.yaml` and `scripts/README.md`. |
| CEF frames carry a **single** hostname, and `appname` becomes the literal string `CEF` | Observed, and re-confirmed against 0.157.0 while building this corpus. |
| CEF has no quoting; the extension string splits on ` key=`; values contain spaces | Observed. It is the reason `transform/cef_extensions` exists. |
| Event codes 201, 202, 203, 401, 402, 403, 404, 405, 544, 546 and firewall policy events are live | Observed. Named in `collector/20-processors-logs.yaml`. |
| Code 203 arrives carrying **no** `UNIFIpolicyType` | Observed. It is why the alert branch excludes 203 by code. |
| `coredns` logs only **block** decisions, split `dnsAdBlock` / `contentFilteringBlock` | Observed. |
| The five `dnsmasq-dhcp` shapes, incl. `DHCPDISCOVER` putting a MAC where its siblings put an IP, and `Updating leases` not matching | Observed. |
| The four `sudo` shapes, incl. vendor service accounts and `pam_unix` | Observed. |
| `unifi-mq-broker` logs its tag as a **full path** | Observed. |
| A gateway may re-emit a **full header on every datagram** of a multi-line message | **Observed** for `ubios-udapi-server` on UniFi Network 10.5.67 (`real-wan-failover.txt`). **Not** observed for `linkcheck`: `linkcheck-headed.txt` applies the same framing to the real `linkcheck` payload, and its framing is invented. Both receiver operators handle both shapes. |
| `linkcheck` pretty-prints its JSON and sends **one datagram per line**, only the first carrying a syslog header | **Observed of one frame, not of the daemon.** `real-linkcheck.txt` is one complete captured frame: a header line ending `speedtest.ui_speedtest_log_results(): {`, then one pretty-printed JSON line per datagram, then a closing `}`. This is what #9 was blocked on. The receiver now recombines them into one record; the corpus still sends eleven datagrams, because that is what the gateway does. |
| `ubios-udapi-server` splits an unterminated single-quoted payload across two datagrams, and the second carries a **complete** header — PRI, timestamp, doubled hostname, tag and sub-tag — in front of a lone `'` | **Observed, and the frame is real.** `real-wan-failover.txt` is one complete captured frame from `wan-failover-monitor-icmp`. It is the counter-example to the assumption `linkcheck` taught: a continuation line does **not** always arrive header-less. This is [#32](https://github.com/jamesagarside/unifi-otel/issues/32). |
| The same producer on a gateway that does **not** double its hostname | **Invented.** `wan-failover-single-host.txt` is the real frame with the doubling removed from both datagrams, and it exists because the recombine predicate has to find the tag by regex on one shape and by `appname` on the other — the [#24](https://github.com/jamesagarside/unifi-otel/issues/24) axis. No real single-hostname frame of any kind has ever reached this project. |
| Other `ubios-udapi-server` sub-tags emitting the same quoting | **Not observed either way.** The receiver's predicate is deliberately written against the *quoting*, not against `wan-failover-monitor-icmp`, so a sibling sub-tag that does this is covered without a config change — but no capture proves any sibling does. |
| `linkcheck` is the **only** recurring parse failure | Observed *at the time of that capture*, and only of the unheaded shape — a re-headed continuation parses cleanly and raises nothing, so it never reaches the failure stream at all. It fans out into one record per line instead, which no parse-failure count would show. Observed. Every parse-failure record in a 14-day window came from `linkcheck`; nothing else appeared. |
| SIEM Server *offers* RFC5424 over TCP | **Vendor option, not an observation.** It is a setting in the UniFi UI. **No RFC5424 frame of any kind has ever reached this project** — the seven-day capture contains zero, because the source gateway's SIEM Server is set to UDP. An earlier version of this table said "everything seen on it has been CEF", which was true only in the sense that nothing had been seen on it at all. |
| A CEF frame over RFC5424 carries `APP-NAME` = `CEF` | **Invented**, and it is the single assumption the transport axis leans on hardest. Measured against 0.157.0: with `APP-NAME` set to `CEF` or to NILVALUE the record matches its UDP twin, but with a real app name the RFC5424 record gains `process.name` and `process.pid` that the UDP twin never has — and the matched pair would fail, correctly. Green here means somebody chose that field's value, not that anybody measured it ([#25](https://github.com/jamesagarside/unifi-otel/issues/25)). |
| **Every value** — hostname, IP, MAC, domain, SSID, username, policy name, site | **Invented.** They are scrubber-shaped pseudonyms, not scrubbed real data. |
| The exact **CEF key set per event code** | **Modelled** on the keys `transform/unifi_ecs` reads, not taken from a capture. A real 403 may carry keys this corpus omits. |
| Code 801 with `act=allowed` | **Assumed.** The allowed side of a firewall policy has not been seen under 801. |
| AP and switch frames (`kernel`, `hostapd`), and a **doubled** hostname on either | **Invented on top of an invention.** No real AP or switch frame has ever reached this project ([#20](https://github.com/jamesagarside/unifi-otel/issues/20)). |
| Non-CEF RFC5424 frames | **Invented.** Whether UniFi emits non-CEF device syslog over 5424 at all is open ([#25](https://github.com/jamesagarside/unifi-otel/issues/25)). |
| The `linkcheck` payload: line count, which lines carry a PRI, where the frame ends | **No longer invented.** Those three unknowns were the entire reason [#9](https://github.com/jamesagarside/unifi-otel/issues/9) was documented rather than fixed; `real-linkcheck.txt` answers all three from a capture, and the synthetic `linkcheck-multiline.txt` that guessed at them was removed. **One** real frame answers them, though — whether every `linkcheck` result has this key set is still unknown. |
| Event code 999 | **Invented**, deliberately, to exercise the taxonomy default. |

---

## Running it

```sh
python3 tests/run.py            # verify. Exits 0 on success, 1 on any failure.
python3 tests/run.py -v         # print every diff in full rather than the first 40 lines
python3 tests/run.py --keep     # leave both containers up for inspection
python3 tests/run.py --update   # regenerate the goldens. Read the warning below.
```

Requirements: Python 3 (standard library only — the same hard requirement
`scripts/scrub.py` carries) and a working `docker`. A full run takes
around a minute and starts two containers, on ports 45514/46601/44133 and
45515/46602/44134, bound to loopback only. They are removed in a
`finally` block, so an interrupted or failing run does not leave them
behind.

The image tag is **read from `docker-compose.yml`**, so the harness
cannot drift away from the tag the project actually ships (issue
[#12](https://github.com/jamesagarside/unifi-otel/issues/12)). Override
with `--image` only to answer "does this break on the next release?".

### Two gotchas the harness encodes so you do not have to remember them

- **`service::telemetry::logs::level` must be `info`.** At `warn` the
  debug exporter prints nothing at all, which looks exactly like zero
  records arriving. `collector/90-service.yaml` already sets `info`; the
  harness pins it again in its own overlay so a change there cannot
  silently blind the tests.
- **Never generate traffic with `nc`.** macOS `nc` truncates UDP
  datagrams at around 1024 bytes, and a truncated CEF frame looks exactly
  like a parse failure. `run.py` uses a socket loop, and
  `tests/corpus/edge-cases.txt` carries a deliberately oversized 1400+
  byte frame so that swapping the socket loop back for `nc` fails loudly
  instead of quietly.

Nothing under `collector/` knows this harness exists. The debug exporter
and pipeline rewiring are applied as `--config=yaml:` overlays on the
command line, the same technique `docker-compose.yml` already uses for
its `collector-debug` profile.

---

## The checks

Each is reported separately, as `[PASS]` or `[FAIL]` with a count, and
any one failing exits non-zero.

| Check | What it asserts |
| --- | --- |
| corpus structure | Frames are unique; matched-pair files hold an even number of frames and each pair really differs only in the way it claims to. The RFC3164 member of a **transport** pair must carry a *single* hostname — RFC5424 has no doubled-hostname shape, so a doubled frame would vary two axes at once. A malformed `#[frame]` block — unterminated, nested, stray close, empty — exits 2 during loading, before this check runs at all. |
| both syslog receivers exercised | At least one RFC3164/UDP frame, at least one RFC5424/TCP frame, at least one transport pair. Same reasoning as bar 4's refusal to pass on zero CEF frames: deleting both members of a transport pair keeps the pair count even and every other bar green, while leaving `syslog/unifi_tcp` entirely untested. Every real frame this project holds arrived over UDP, so the RFC5424 ones are exactly the ones somebody might reasonably prune. |
| privacy gate | `python3 scripts/scrub.py --check tests/corpus/*.txt` exits 0. This is the command issue [#11](https://github.com/jamesagarside/unifi-otel/issues/11) will gate on, run here so a PR fails locally first. |
| every frame produced exactly one record | No frame silently dropped, no frame fanned out, no record the harness cannot attribute to a frame. One record per **frame**, not per datagram: a multi-line frame that came back as one record per line shows up here as one missing frame and N orphan records. |
| **bar 1** — zero OTTL errors | No `error` or `warn` line from any processor or exporter. Receiver-level errors are counted separately and pinned by `golden/_telemetry.golden` rather than waved through. |
| **bar 2** — exactly one dataset, none on the fallback | Every record carries exactly one `event.dataset`, and none is left on `unifi.syslog`, which is the transient value the non-CEF branch assigns before refinement. |
| **bar 3** — no working attributes survive | No attribute key matches `transform/strip_working_fields`' own regex — `cef_`, `dev_`, `dns_kv`, `dhcp_`, `sudo_`, and the syslog parser's raw fields. The regex is lifted verbatim from the config so this asserts what the config claims, not a paraphrase of it. |
| **bar 4** — CEF path byte-identical without the device transform | A second collector is started with `transform/device_syslog` removed from the pipeline, the CEF frames are replayed into it, and the normalised records must be identical. Scope is derived from run A — every frame whose record carries `event.provider: unifi-network`, i.e. every frame that actually went through the CEF branch — so it cannot silently shrink to zero frames. If it finds none, it **fails**. |
| **bar 5** — matched pairs agree | Beyond the issue's four. Every declared pair must agree on dataset, populated key set, severity and parse-failure status; both members must carry an `event.original` byte-equal to the frame sent; every shared attribute must hold the **same value**, not merely be present; and neither member may still have the whole raw frame sitting in `body`. `event.original` byte-equality is [#24](https://github.com/jamesagarside/unifi-otel/issues/24)'s added criterion — the one field whose absence looks like nothing is wrong. Value equality and the `body` clause are [#25](https://github.com/jamesagarside/unifi-otel/issues/25)'s: key-set equality alone passes a regression that fills a field from the wrong capture group, and "raw frame still in `body`" is precisely what #24 looked like. **Transport** pairs additionally require equal `body`. Hostname pairs do not, and cannot — see [One thing the corpus turned up](#one-thing-the-corpus-turned-up). Timestamps are never compared: an RFC3164 frame is stamped in `UNIFI_SYSLOG_TIMEZONE` while its RFC5424 twin carries an explicit offset, so the two legitimately differ by the zone, and the goldens pin both. |
| goldens match | The normalised records equal the committed goldens, file by file. |

Bars 2–5 are the point. Bar 1 alone would pass a regression that silently
stops setting `event.category` — and, demonstrably, bars 1, 2 and 3 all
pass while the [#24](https://github.com/jamesagarside/unifi-otel/issues/24)
bug is present. Only bar 5 and the goldens catch it.

---

## The corpus

One frame per line. Blank lines and lines starting with `#` are comments
and are not replayed.

### Multi-line frames

Syslog has no continuation line, so a daemon whose message contains one
sends one **datagram per line**. Two producers here do, and they do it
differently — which is the point:

- `linkcheck` pretty-prints JSON across eleven datagrams, and only the
  first carries a PRI and an RFC3164 header.
- `wan-failover-monitor-icmp` splits a quoted blob across two, and the
  second is a **complete frame** — header, tag and sub-tag re-emitted in
  front of a lone `'`. Nothing about it looks like a continuation.

The two shapes are **not** a property of the daemon; they are a property
of the gateway, and one gateway can send both. `linkcheck-headed.txt`
carries the `linkcheck` payload in the re-headed shape for exactly that
reason. A predicate that handles one shape and not the other is the bug
in both issues, and it is silent: the records still arrive, still carry
a dataset, and still pass every bar except the goldens.

The receiver recombines each into one record, and the corpus has to be
able to say "these lines are one frame" without the harness guessing.

A line that is exactly `#[frame]` opens a block; a line that is exactly
`#[/frame]` closes it:

```
#[frame]
<14>Aug 13 05:08:28 host-43e7 host-43e7 linkcheck[1253]: speedtest…(): {
  "speedMbps": 1000
}
#[/frame]
```

**Inside a block every line is a wire unit, verbatim.** No `#` comment
stripping, no blank-line skipping, and leading whitespace is preserved
exactly — the indentation is bytes the gateway sent, not formatting. Put
your explanatory comments *above* the block, never inside it.

Each line is sent as its own datagram, in order, so the block exercises
reassembly rather than assuming it. The whole block is **one** frame: it
must produce **one** record, its identity for correlation and for the
goldens is its lines joined with newlines, and the transport is decided
from its first line.

The harness refuses the file outright — before any container starts — on
an unterminated block, a nested `#[frame]`, a stray `#[/frame]`, or an
empty block.

> The markers carry **no dotted token** for the same reason comments must
> not: `scrub.py --check` reads the whole file and cannot tell a dotted
> word from a domain.

> **Comments must not contain a dotted token.** `scrub.py --check` runs
> over the whole file, and a schema field name like `event.dataset` is
> indistinguishable from a domain to it. Write `event dataset` in prose.
> This is also why `tests/golden/` is **not** covered by the privacy
> gate: goldens are full of ECS field names.

| File | Contents |
| --- | --- |
| `cef-firewall.txt` | Code 801, blocked and allowed. |
| `cef-security.txt` | Codes 201 (IDS/IPS), 202 (honeypot), 203 (no policy type). |
| `cef-client.txt` | Codes 401, 402, 403, 404, 405. |
| `cef-audit.txt` | Codes 544 (admin sign-in), 546 (config modified). |
| `device-coredns.txt` | `dnsAdBlock`, `contentFilteringBlock`, and `coredns` emitting non-JSON. |
| `device-dhcp.txt` | All five DHCP shapes, plus `DHCPACK` with and without the optional hostname. |
| `device-sudo.txt` | All four `sudo` shapes, including `pam_unix`. |
| `device-system.txt` | Full-path tag, tag with no `[pid]`, no tag at all, `systemd`, a colon inside the message, switch-shaped `kernel`, AP-shaped `hostapd`, and a frame with no PRI header. |
| `edge-cases.txt` | Truncated CEF envelope, an unmapped event code, an oversized frame. |
| `linkcheck-headed.txt` | The `real-linkcheck.txt` payload with a full RFC3164 header, doubled hostname and tag on **every** datagram. Synthetic framing over a real payload; the regression case for [#34](https://github.com/jamesagarside/unifi-otel/issues/34), where a gateway that re-heads continuation lines shredded a whole speedtest payload and glued successive runs together. |
| `wan-failover-single-host.txt` | The [#32](https://github.com/jamesagarside/unifi-otel/issues/32) frame with its hostname doubling removed from both datagrams — the [#24](https://github.com/jamesagarside/unifi-otel/issues/24) axis for a re-headered reassembly. It cannot live in a `device-*.txt` pair: the harness collapses the doubled hostname on the **first line only**, and here every line has one. |
| `transport-rfc5424.txt` | The [#25](https://github.com/jamesagarside/unifi-otel/issues/25) axis: the same payload over RFC3164/UDP and RFC5424/TCP. Seven pairs — `coredns`, `dnsmasq-dhcp`, `sudo`, `systemd` with RFC5424 `STRUCTURED-DATA` and a `MSGID`, CEF, a full-path `APP-NAME`, and a NILVALUE `APP-NAME` with the tag left inside the message. Wholly invented; see the honesty note at the top of the file. |

**Real frames**, captured from a live gateway and scrubbed. One file per
dataset, named for it:

| File | Frames |
| --- | --- |
| `real-firewall.txt` | 40 |
| `real-client.txt` | 40 |
| `real-dns.txt` | 40 |
| `real-dhcp.txt` | 40 |
| `real-sudo.txt` | 40 |
| `real-system.txt` | 40 |
| `real-audit.txt` | 30 |
| `real-network.txt` | 8 |
| `real-security.txt` | 6 |
| `real-linkcheck.txt` | One complete multi-line frame — the real shape behind [#9](https://github.com/jamesagarside/unifi-otel/issues/9). |
| `real-wan-failover.txt` | One complete multi-line frame — the real shape behind [#32](https://github.com/jamesagarside/unifi-otel/issues/32), whose continuation carries a full header. |

The counts are uneven because they are real: `unifi.security` and
`unifi.network` are genuinely low-volume on the capture site, and padding
them would mean inventing frames, which is the thing these files exist to
avoid.

`real-linkcheck.txt` deliberately holds **one** frame. A real capture
repeats lines across speedtest results — a closing brace is a closing
brace — and the harness correlates records to frames by content, so
repeated lines cannot be paired. It supersedes the synthetic
`linkcheck-multiline.txt`, which was removed: an invented shape has no
value once the real one exists.

`linkcheck-headed.txt` is the same payload as `real-linkcheck.txt` in
the other framing, at a different minute so the two frames — and their
goldens — cannot be confused. Its record is field-for-field identical to
the unheaded one apart from `event.original` and the timestamp, which is
the assertion worth having: the framing must not reach the schema.

`real-wan-failover.txt` holds one frame for the same reason, and rather
more sharply: **every** frame this producer emits ends in the identical
`… wan-failover-monitor-icmp: '` datagram, so two of them in the corpus
would be two frames sharing a wire unit. Its single-hostname twin lives
in `wan-failover-single-host.txt`, where the hostname makes the lines
distinct.

A multi-line frame whose continuation carries its own header does
round-trip byte-for-byte, unlike the `linkcheck` one: there is no
leading whitespace for the input operator to strip, so the record's
`event.original` equals the corpus text exactly. The framing the daemon
re-emitted is removed from `message` and `body` and **not** from
`event.original` — see section 0 of `transform/device_syslog`.

### Conventions the harness enforces

- **`device-*.txt` are hostname matched-pair files.** Frames come in
  adjacent pairs: the doubled-hostname frame first, then the
  byte-identical payload with a single hostname. Same PRI, same
  timestamp, same payload — only the doubling differs. The harness
  verifies this structurally: collapsing the repeated hostname in the
  first member must yield the second member exactly. If it does not, the
  file is not a pair file and the run fails before any container starts.

- **`transport-*.txt` are transport matched-pair files.** RFC3164 first,
  RFC5424 second, and the RFC3164 member must carry a **single**
  hostname. RFC5424 has no doubled-hostname shape, so pairing a doubled
  frame against one would vary the hostname axis and the transport axis
  together, and a pair that varies two things proves neither. It is also
  what makes `body` comparable across a transport pair at all: the two
  hostname shapes are known to disagree on `body`, the two wire formats
  are not.

- **Transport is chosen by the frame's own syntax.** A frame matching
  `<PRI>1 ` is RFC5424 and goes to the TCP receiver on 6601; everything
  else goes to the UDP receiver on 5514. There is no per-file transport
  setting to keep in sync. For a multi-line frame the **first** line
  decides, since it is the only one with a header.

- **Frames must be unique.** Records are correlated back to frames by
  content, not by order: the export and failure pipelines batch
  independently, so a failure record can be printed before an earlier
  export record. The key is `event.original` where it is set, and `body`
  otherwise.

  A reassembled multi-line frame does **not** come back byte-identical
  to the corpus: the receiver strips the leading whitespace off every
  header-less line before recombine joins them, so the record carries
  the JSON de-indented while the corpus keeps the gateway's two-space
  indentation. The harness indexes each frame under both forms, and that
  de-indented one is the key that actually hits.

  What it deliberately does **not** index is the individual lines of a
  multi-line frame. If reassembly ever stops working, each line comes
  back as its own record and every one is reported as an orphan — which
  is the honest signal. Indexing them would let that regression
  correlate cleanly and pass.

---

## The goldens

One `.golden` per corpus file, plus `_telemetry.golden`. Each frame gets
a block:

```
--- frame
in     <30>Aug 13 09:17:04 host-0a3 host-0a3 dnsmasq-dhcp[2211]: DHCPACK(br3) …
wire   udp
route  export
sev    Info(9) / info
time   parsed 08-13 09:17:04 +0000 UTC
fail   -
body   Str(DHCPACK(br3) 198.51.100.31 00:00:5E:00:53:21 host-77e5)
attr   dns.question.name = Str(…)
…
```

- `route` is which pipeline the `routing/parse_failures` connector sent
  the record to — `export` or `failures`. It is read from the exporter
  that printed the record, so it is a real assertion about routing.
- `attr` lines are **sorted by key**, because attribute map iteration
  order is not stable between runs.
- Values are asserted, not just key presence. A regression that keeps
  `event.category` populated but changes it to the wrong value shows up
  here.
- **One logical value per physical line.** A reassembled multi-line frame
  puts real newlines in `in`, in `body` and in `event.original`; the
  goldens write a newline as `\n` and a literal backslash as `\\` so a
  value cannot silently spill into extra rows and read as several fields.
  Nothing else is escaped. A `body` line in a golden is therefore always
  exactly one `body`, however many datagrams produced it.

### What is normalised away, and the blind spot that creates

`ObservedTimestamp` is dropped entirely. `Timestamp` becomes one of
`observed` (equal to the observed time, i.e. `transform/timestamp_guard`
filled it in), `zero`, or `parsed <timestamp with the year removed>`.

The year has to go: the RFC3164 parser **infers** it from the current
date, so a header-derived timestamp changes year every 1 January while a
payload-derived one does not.

**The blind spot:** a regression that shifts a record by exactly one year
is invisible to these goldens. Nothing else about the timestamp is —
`parsed 08-13 08:16:01.123` versus `parsed 08-13 09:16:01` is exactly the
difference between "took the payload's millisecond-precise UTC" and
"took the syslog header", and that distinction is asserted on every DNS
and CEF record.

The harness also fixes `UNIFI_SYSLOG_TIMEZONE=Etc/UTC`. Changing it moves
every non-CEF timestamp and every golden with it.

### `_telemetry.golden`

Every `error` and `warn` line the collector logged, grouped by component,
operator and message, with counts. Bar 1 only asserts that none of them
came from a processor; this file pins the receiver-level noise too.

"First impressions of a parser are made in its failure stream"
([#9](https://github.com/jamesagarside/unifi-otel/issues/9)) — so a new
source of stack traces in the container log is a finding, not background.
Every entry in this file must be explainable from a fixture.

**Reassembly did not silence the receiver-level noise, and could not
have.** A receiver's user operators — `recombine` among them — run
*after* its own syslog parser, so the ten header-less `linkcheck` lines
are still parsed individually and still raise before anything recombines
them. What changed is downstream: they no longer reach the failure
pipeline as ten records. Today the file holds:

- `syslog_parser` and `udp_input`, one pair per header-less `linkcheck`
  line — the parser raises `expecting a sequence number`, then the UDP
  input logs the write failure;
- `regex_parser` and `udp_input`, one pair from the truncated CEF
  envelope in `edge-cases.txt`;
- one `recombine` **warn** per BATCHED entry: *entry does not contain
  the source_identifier, so it may be pooled with other sources*. Read
  the operator source rather than the count here — the warn is raised
  once for every entry the `if` accepts, header or not, because the
  default identifier is a file attribute no UDP path ever sets. An
  earlier version of this file said "per header-less line", which fits
  the count but not the code; measured against 0.157.0, the
  `wan-failover-monitor-icmp` frames raise one each too, and every entry
  in them carries a full syslog parse. Harmless with a single sender;
  something to revisit if a second device ever emits multi-line frames
  into the same receiver.

Two counts here are **lower** than the number of raising entries, and
both are the collector's own log sampling rather than a lost datagram.
The sampler caps identical messages at ten per tick and then keeps only
every hundredth, and the tick is longer than the whole replay.

- the `syslog_parser` / `udp_input` pairs come out one short of the
  eleven raising `linkcheck` lines: `10 + 1 = 11` are raised, ten
  survive;
- the `recombine` warns stay at ten however many multi-line frames the
  corpus holds. The `linkcheck` frame raises eleven and exhausts the
  budget, so the four raised by the two `wan-failover` frames are
  dropped. Verified by sending one of those frames into an otherwise
  idle collector: two warns, one per entry.

Do not "fix" either count by reconciling it with the fixtures by hand —
regenerate and read what comes out.

---

## Adding a frame

1. **Scrub it first**, if it is real. `docs/contributing-samples.md` is
   the authority and its rules are not optional. Never commit a raw
   capture.
2. Put it in the file that matches its **shape**, not its capture
   session. If it is a new shape, a new file is fine — name it after the
   device class and shape (`usw-lite-8-kernel.txt`), never after a date.
3. If you are adding to a `device-*.txt` file, add **both** hostname
   shapes, doubled first. If you only have one shape, put it in a
   non-pair file rather than half-filling a pair — the harness will
   reject an odd count, and it should.
4. If the frame arrived as **several datagrams**, wrap it in a
   `#[frame]` … `#[/frame]` block and paste the lines verbatim,
   indentation and all. Do not collapse it to one line: that would test
   a shape the gateway never sends.
5. Add a `#` comment above it saying what the frame is for, with no
   dotted tokens. Above the block, not inside it.
6. `python3 scripts/scrub.py --check tests/corpus/*.txt` — must exit 0.
7. `python3 tests/run.py` — it will fail, because there is no golden for
   your frame yet. **Read the block it prints for your frame.** That is
   the parser's actual behaviour, and it is the whole reason to add the
   frame.
8. If the behaviour is right, `python3 tests/run.py --update`, then
   `diff` the golden and commit both. If the behaviour is wrong, commit
   the frame and the golden anyway and **say so in the PR** — a fixture
   that documents a bug is more valuable than one that documents a
   success, and a reviewer needs to know not to "correct" it.

### When a real frame arrives

Add it alongside the synthetic ones rather than replacing them, and say
in its comment that it is real. Then delete whichever synthetic frame it
supersedes **only if** it covers the same shape — and update the
observation/invention table above, which is the honest claim this
directory makes about itself.

---

## Regenerating the goldens

`--update` overwrites every golden with whatever this run produced. It
does not ask.

**Legitimate:**

- you added or edited a frame, and the new block is behaviour you have
  read and agree with;
- you changed the config on purpose, you have read the diff line by line,
  and every changed line is a change you intended;
- you bumped the collector image and the diff is explained by a
  documented upstream change.

**Papering over a regression:**

- the goldens failed, you did not read the diff, and `--update` made the
  red go away;
- the diff contains a field disappearing and you cannot say which change
  removed it;
- the diff touches files you did not think you were changing. A config
  edit aimed at the DHCP parser that also moves `cef-client.golden` is
  telling you something.

The tell is almost always **a key disappearing from an `attr` list**.
Fields going missing is the failure mode this whole directory exists to
catch — it is what [#24](https://github.com/jamesagarside/unifi-otel/issues/24)
looked like, and it raised no error and moved no dataset histogram.
Always read `git diff tests/golden/` before committing a regeneration,
and if it is more than a few lines, say in the PR why each group of lines
moved.

---

## Known limitations

- **The real frames are one site, one week.** 286 of 359 frames came off
  a single household's UDM gateway over seven days — real UniFi output,
  but not a representative sample of UniFi deployments, hardware
  generations or configurations. Frames from other estates remain the
  most valuable contribution available.
- **Only the gateway has ever reported.** Every real frame here is from
  the console. No AP or switch frame has ever been seen
  ([#20](https://github.com/jamesagarside/unifi-otel/issues/20)), so the
  single-hostname device shapes are still exercised synthetically only —
  which is exactly the path
  [#24](https://github.com/jamesagarside/unifi-otel/issues/24) showed had
  been silently broken.
- **Every real frame arrived over UDP/RFC3164, and no RFC5424 frame has
  ever been seen at all.** The seven RFC5424/TCP pairs are wholly
  synthetic ([#25](https://github.com/jamesagarside/unifi-otel/issues/25)).
  What they can honestly prove is bounded: that a *well-formed* RFC5424
  frame carrying a known payload comes out of this pipeline as the same
  record its RFC3164 twin does. They cannot prove UniFi ever sends one,
  and they cannot prove it looks like this if it does. The `APP-NAME` on
  the CEF pair is the assumption most likely to be wrong — see the
  observation-versus-invention table above, and the capture recipe in
  [`docs/contributing-samples.md`](../docs/contributing-samples.md).
- **Bar 3 cannot tell "stripped" from "never produced" for the
  RFC5424-only working fields.** `version`, `msg_id` and
  `structured_data` are named in `transform/strip_working_fields` and
  only RFC5424 populates them. Bar 3 asserts they do not survive to
  export, which stays green whether they were removed or were never set
  in the first place. Measured directly against 0.157.0 with the strip
  processor lifted out of the pipeline: `version` is set on **every**
  RFC5424 record, and `msg_id` and `structured_data` on the `systemd`
  pair, so the clauses are not vacuous today — but nothing in the
  harness would notice if that changed. Proving it continuously would
  need a third container run, which has not been judged worth its
  minute.
- **No fixture trips `transform/cef_extensions`.** A CEF frame whose
  extension string contains no `=` at all would raise inside
  `ParseKeyValue`, and `error_mode: ignore` logs every raise — which
  would collide head-on with bar 1. Covering the `cef_extensions` failure
  tag needs a separate harness mode with its own expected-error list.
  Until then that branch of `transform/tag_parse_failures` is untested.
- **`tests/golden/` cannot be run through `scrub.py --check`.** ECS field
  names contain dots and read as domains. The privacy gate covers
  `tests/corpus/` only, which is where frames actually live.
- **One year of timestamp drift is invisible.** See above.
- **Resource attributes are not in the goldens.** `service.name` and
  `observed.source` are constants set by `resource/unifi`; they carry no
  per-frame information.
- **A lost datagram fails the run rather than retrying.** That is
  deliberate — a retry loop would hide a receiver that genuinely drops
  frames — but on a loaded machine it can show up as a spurious "frame
  produced no record". Re-run before believing it.
- **Two multi-line shapes are exercised, and only two.** The corpus has
  four `#[frame]` blocks, covering both shapes on both producers: the
  header-less `linkcheck` frame, the same payload re-headed, the real
  re-headed `ubios-udapi-server` frame and its single-hostname twin.
  Both recombine operators are scoped to those. Nothing here tests what happens when two
  multi-line frames **interleave** on the wire, or when a payload never
  sends its terminator — both are plausible on a busy gateway and
  neither has been captured. The interleaving gap is sharper for #32
  than for #9: the `wan-failover` continuation is a fully-formed frame,
  so it carries a hostname and could in principle be demultiplexed on
  one, but `recombine` has no way to express "close the batch this
  hostname opened" and nothing here would notice if two gateways
  crossed.
- **Nothing asserts the 5s flush path.** A `ubios-udapi-server` line
  that ends `key: 'value` with no continuation to come opens a batch and
  waits out `force_flush_period` before being emitted alone. Measured by
  hand against 0.157.0: the record turned up 5.75s after the datagram,
  and it is complete and correctly parsed. No fixture exercises it,
  because a frame that only differs after a six-second wait would add
  six seconds to every run for one assertion.
- **A header-less multi-line frame does not round-trip byte-for-byte.**
  The receiver
  strips the leading whitespace off every header-less line, so the
  reassembled `body` and `event.original` carry the JSON de-indented.
  The goldens record what actually comes out, not what was sent; the
  `in` line above them is the sent bytes, so the difference is visible in
  the block rather than hidden by it.
- **The harness parses a newline inside a body or attribute value by
  reading to the next known section key** (`Attributes:`, `Trace ID:`,
  `Span ID:`, `Flags:`). A value that itself contained one of those at
  the start of a line would be truncated there. No fixture does, and a
  syslog frame realistically cannot, but it is an assumption about the
  debug exporter's output format rather than a guarantee.

## One thing the corpus turned up

The two members of the first `sudo` pair produce **different `body`
values**, and the goldens record it:

| Frame | `body` |
| --- | --- |
| doubled hostname | `uid : PWD=/ ; USER=root ; COMMAND=…` |
| single hostname | `␣␣␣␣␣uid : PWD=/ ; USER=root ; COMMAND=…` |

`sudo` space-pads the username. On the doubled frame the tag is recovered
by `transform/device_syslog`, whose pattern ends `:\s+`, so the padding is
consumed. On the single frame the RFC3164 parser strips the tag and
leaves the padding in `message`. Every extracted field is identical and
every bar passes — the leading whitespace is the only difference — but it
means `body` is *not* byte-identical across the two hostname shapes, and
anything downstream doing an exact-match on body text would see them as
different strings.
