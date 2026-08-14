# Known issues

Things this project gets wrong, or does not do, that you will notice
while running it — written down here so that finding one in your own
output is a confirmation rather than a surprise.

An entry earns its place here if a working deployment produces visible
evidence of it: records in the parse-failure stream, errors in the
container log, or a field that is conspicuously absent. Gaps with no
visible symptom belong in
[`contributing-samples.md`](contributing-samples.md) under the wanted
list; design decisions belong in the comments of the config file that
implements them.

| Issue | Symptom | Status |
| --- | --- | --- |
| [`linkcheck` continuation lines still log a receiver error each](#linkcheck-continuation-lines-still-log-a-receiver-error-each--9) | `error`-level lines with a Go stack trace in the collector's own log, a handful a day. No parse-failure record any more | Understood, and not addressable from inside this configuration |

One entry, and it is the residue of a fixed one. The `linkcheck`
multi-line JSON failure that used to live here **is fixed** — the frame
is reassembled and parsed into `unifi.speedtest`. What survives is
collector telemetry that this configuration has no way to reach. The
history is kept below because the log lines have not changed, so
somebody who greps for them still needs to land somewhere that explains
them.

---

## `linkcheck` continuation lines still log a receiver error each — [#9](https://github.com/jamesagarside/unifi-otel/issues/9)

### What `linkcheck` is

The gateway's WAN link and speedtest checker. It runs on a schedule and
reports the state of the internet connection. Unlike every other daemon
on the box it emits **pretty-printed, multi-line JSON** over syslog — one
logical record spread across many lines.

Syslog has no concept of a continuation line. Each line arrives as its
own datagram, and only the first carries a PRI and an RFC3164 header;
every line after it is bare text as far as the receiver is concerned.

### What used to happen, and what happens now

A `recombine` operator on both syslog receivers
(`collector/10-receivers-logs.yaml`) reassembles the datagrams of one
frame into a single record, and the JSON payload is parsed into
`event.dataset: unifi.speedtest`.

| | Before | Now |
| --- | --- | --- |
| Records per frame | One per datagram | **One** |
| Continuation lines | Tagged `unifi.parse_failure = "syslog_header"`, diverted to `logs/unifi_parse_failures` | Appended to the open batch; no record of their own |
| `event.dataset` | `unifi.system` on every one of them | `unifi.speedtest` on the single record |
| Payload | Discarded — the header line's `body` was the opening `{` and nothing else | Parsed: rate, test-server URL, ISP and geo |
| Timestamp | Header line from the syslog header; continuations stamped with collector arrival time | From the syslog header of the first datagram |
| Severity | Header line from the PRI; continuations unspecified | From the PRI |

Observed against 0.157.0 with the one real captured frame in
`tests/corpus/real-linkcheck.txt`: **11 datagrams in, 1 record out**, the
header entry's attributes, timestamp and severity carried through.

Reassembly is bounded by the closing `}` rather than by a line count, so
a frame of a different length still works. A frame that never sends its
closing brace is **not lost and not held for ever**: `recombine`'s
default `force_flush_period` of 5s emits what it has. A well-formed
frame is emitted the instant the brace arrives, with no added latency.

### What you still see

Each continuation line still produces one `error`-level line **with a Go
stack trace** in the collector's own log, from the receiver:

```
Failed to write entry  {... "otelcol.component.id": "syslog/unifi_udp",
 "error": "expecting a sequence number (from 1 to max 255 digits) [col 3]"}
```

**This is the one visible symptom that the fix does not remove.** The
receiver's internal chain is `udp_input → syslog_parser → operators`, so
the RFC3164 parser has already rejected the bare line and logged it
before the `recombine` operator — or any processor in this config — gets
to see the entry. Nothing downstream of the receiver can suppress it.

So the rate of these log lines is unchanged. What changed is that they
no longer correspond to anything: there is no `syslog_header` record in
your backend to go with them, because the entry they refer to was folded
into a `unifi.speedtest` record instead of being emitted on its own.

The count is exactly what the parse-failure count used to be — one log
line per continuation line, which is what one failure record used to be
too. **Roughly five a day** in the single deployment where it was
measured, scaling with however often your gateway runs a link check.
Read that as an order of magnitude, not a specification. Hundreds a day,
or a burst, is something other than `linkcheck` and is worth an issue.

### Residual limitations

Three, all of them consequences of the fact that a continuation line
carries no identifying information whatsoever.

**Two gateways sending to one collector could interleave.** The
continuation lines have no hostname — nothing distinguishes one
gateway's `"city": …` line from another's. If two gateways ran a link
check at the same instant and both reported to the same collector, their
lines could land in the same batch and produce one nonsense record.
There is no way to demultiplex them inside `recombine`, because there is
nothing to key on. **Single-gateway deployments are unaffected**, which
is every deployment this has been run in; the multi-gateway case is
reasoned, not observed, and nobody has a two-gateway setup to test it
against. If you run one and see a merged record, that is worth an issue.

**A stray brace-leading line waits 5s.** The reassembly predicate is
scoped to `linkcheck`-shaped traffic, but its second clause has to
accept header-less lines that begin with `{`, `}` or `"` — that is what
a continuation line looks like, and there is nothing else to match on.
If such a line arrives while no frame is open, it opens one, and it is
emitted alone when the flush period expires. Bounded latency on an
already-malformed record, not a loss.

**Unrelated frames are not swallowed.** This is the failure mode the
`if` predicate exists to prevent, and it was tested rather than assumed:
an unrelated syslog frame injected into the middle of a `linkcheck`
frame passes straight through untouched. It may be emitted slightly
ahead of the `linkcheck` record, since that one is still waiting for its
closing brace, which is harmless. Listed here so that a reader who finds
the operator does not have to wonder.

### How far the verification goes

**One real frame, from one gateway.** The predicate matches on the
`linkcheck[pid]:` tag and a trailing `{`, and it was verified against
**both** gateway hostname shapes — the doubled hostname a UDM emits, and
the single-hostname shape that
[#24](https://github.com/jamesagarside/unifi-otel/issues/24) broke.

What that does *not* establish is that every gateway's `linkcheck`
emits the same payload keys, the same line count, or the same trailing
`{` on its header line. The captured frame carries `speedMbps` and no
direction — which is why the field is `unifi.speedtest.speed_mbps` and
not `download_mbps`, and why this project does not claim upload,
download or latency are captured. One observation is one observation. A
`linkcheck` frame from a second gateway is on the wanted list in
[`contributing-samples.md`](contributing-samples.md) for exactly this
reason.

### Confirming this is what you are seeing

Two halves: the record that should now exist, and the log noise that
should now be unaccompanied.

In the container log, with the debug profile from
[`quickstart.md`](quickstart.md):

```bash
docker compose logs collector-debug | grep -c 'event.dataset: Str(unifi.speedtest)'
docker compose logs collector-debug | grep -c 'unifi.parse_failure: Str(syslog_header)'
```

The first should be non-zero after a link check has run; the second
should be zero, or should at least not be growing in step with your
`linkcheck` schedule. A `unifi.speedtest` record carries
`process.name: linkcheck`, a one-line summary body reading
`WAN speedtest: … Mbps via …`, the payload fields under `destination.*`
and `unifi.speedtest.*`, and the whole reassembled multi-line frame in
`event.original` — which is the thing to look at if the parsed fields
are not what you expected.

If you are still seeing `syslog_header` failures arriving in tight
bursts of ten or so, with bodies that are JSON fragments — a bare `{`, a
`"key": value,` line, a lone `}` — then reassembly is **not** matching
your gateway's frames. That is a different frame shape from the one
verified here, and a scrubbed capture of it is worth an issue.

`syslog_header` failures that arrive singly, from some other daemon, are
a different problem again and this entry is not your answer.

### The geo and ISP fields describe the far end

`destination.geo.city_name`, `destination.geo.country_name`,
`destination.as.organization.name` and the rest hang off `destination.*`
because they describe the **speedtest server**, not your household. That
is the honest mapping, and it is also why they are not as anonymous as
`destination.*` makes them sound: a speedtest picks a *nearby* server,
so the set of cities you see is a coarse location fix on whoever is
running it. `scripts/scrub.py` scrubs them for that reason, and the
reason is written down in the allowlist block of the script itself.

### Making the log noise quiet

There is **no configuration flag for this** and this project will not
invent one. There is also nothing to invent: the lines are produced
inside the receiver, so no processor, connector or exporter in this
configuration is downstream of them.

What you can do is filter the collector's own logs wherever you collect
them, on the component id and the error string. There is no
collector-side setting that reaches these lines without also silencing
every other receiver-level error, which is the class of error you most
want to hear about. Records are unaffected either way — nothing is
routed anywhere on account of these lines.
