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
| [`linkcheck` multi-line JSON](#linkcheck-multi-line-json-is-not-reassembled--9) | Recurring `syslog_header` parse failures, a few a day | Documented, not fixed — needs a real frame |

---

## `linkcheck` multi-line JSON is not reassembled — [#9](https://github.com/jamesagarside/unifi-otel/issues/9)

### What `linkcheck` is

The gateway's WAN link and speedtest checker. It runs on a schedule and
reports the state of the internet connection. Unlike every other daemon
on the box it emits **pretty-printed, multi-line JSON** over syslog — one
logical record spread across many lines.

### What happens

Syslog has no concept of a continuation line, and neither does the
receiver: **each datagram is parsed on its own**. A frame spread over ten
lines therefore becomes ten independent records, and only the first one
carries a PRI and an RFC3164 header.

Traced through the config, in order:

1. `syslog/unifi_udp` (`collector/10-receivers-logs.yaml`) parses the
   first line normally. The continuation lines have no PRI and no
   header, so the RFC3164 parser rejects them. Because
   `allow_skip_pri_header: true` is set, they are **not dropped** — the
   receiver logs the failure and emits the record anyway, with the raw
   line in `body` and no `message` attribute.
2. `transform/tag_parse_failures`
   (`collector/20-processors-logs.yaml`) sets
   `unifi.parse_failure = "syslog_header"` on anything where
   `attributes["message"] == nil`. That is exactly the condition the
   continuation lines meet — "the syslog parser produced no message
   attribute".
3. The `routing/parse_failures` connector
   (`collector/40-exporters.yaml`) matches
   `log.attributes["unifi.parse_failure"] != nil` and diverts those
   records into the `logs/unifi_parse_failures` pipeline instead of the
   default `logs/unifi_syslog_export`.
4. That pipeline exports to the same OTLP endpoint as everything else
   **and** to `debug/parse_failures`, which prints the whole record at
   `detailed` verbosity into the collector's own log.

Observed against 0.157.0, sending a multi-line JSON payload as separate
UDP datagrams — one record out per datagram in, and the two kinds of
record look nothing alike:

| | First line (has the header) | Every continuation line |
| --- | --- | --- |
| `body` | Whatever followed the tag — the opening `{` on its own | The raw line, leading whitespace stripped |
| `unifi.parse_failure` | *unset* | `syslog_header` |
| Pipeline | `logs/unifi_syslog_export` (normal path) | `logs/unifi_parse_failures` |
| `process.name` | `linkcheck` | *unset* |
| `observer.name` | set | *unset* |
| `event.original` | set | *unset* |
| `event.dataset` | `unifi.system` | `unifi.system` |
| Timestamp | Parsed from the syslog header | Zero, then filled in by `transform/timestamp_guard` with the time the collector saw it |
| Severity | From the PRI | Unspecified |

Each continuation line also produces one `error`-level line **with a Go
stack trace** in the collector's own log, from the receiver:

```
Failed to write entry  {... "otelcol.component.id": "syslog/unifi_udp",
 "error": "expecting a sequence number (from 1 to max 255 digits) [col 3]"}
```

That is collector telemetry, not a record. It is emitted inside the
receiver, before any processor in this config can see it, so nothing
downstream of the receiver suppresses it.

> The mechanism above is what was demonstrated. The **shape** of a real
> `linkcheck` frame was not: how many lines it is, whether anything
> other than the first carries a PRI, and where the frame ends are all
> unknown here. That is not incidental — it is the entire reason this is
> documented rather than fixed. See [below](#what-would-fix-it).

### Expected rate

**Roughly five records a day.** That figure is from the single
deployment where this was observed and should be read as an order of
magnitude, not a specification. It scales with however often your
gateway decides to run a link check, and one frame accounts for several
records, so a site that checks more often will see proportionally more.

If you are seeing hundreds a day, or a burst, something other than
`linkcheck` is involved and it is worth a look — and worth an issue.

### Why it is benign

- **It is caught, by design.** The failure gate that tags these records
  exists precisely so that a frame the parser cannot handle announces
  itself instead of passing through as plausible-looking output. This is
  that gate working.
- **It is isolated.** Tagged records leave the normal export path at the
  connector. They cannot contaminate a dataset, skew a count of
  `unifi.dns` or `unifi.dhcp`, or land anywhere a parsed record lands.
- **Nothing silently mis-parses.** Every field set on every one of these
  records is correct. The continuation lines assert nothing beyond the
  raw text in `body` and the module-level attributes every syslog record
  gets. The header line's record is likewise correct in everything it
  claims — it is just missing a payload, and its one-character `body`
  makes that obvious rather than subtle.
- **Nothing is lost that other datasets carry.** No `dns.question.name`,
  no `source.ip`, no `user.name` goes missing here, because a
  `linkcheck` frame never had any of those to give up.

Which is to say: the failure output is telling you the truth, and
leaving these records visible costs you nothing except the need to know
what they are. Hence this page.

### What *is* lost

**The payload.** A `linkcheck` frame carries WAN speedtest results —
throughput, the ISP, and geo information about the test endpoint. That
is data **nothing else in this pipeline reports**: it does not arrive
over CEF from the SIEM feed, it is not derivable from any other syslog
dataset, and the SNMP module does not poll it either.

So this is a missing feature, not merely noise. The records in the
failure stream are the visible half; the invisible half is that your
gateway measures its own WAN performance and none of that reaches your
backend.

### Confirming this is what you are seeing

In the container log, with the debug profile from
[`quickstart.md`](quickstart.md):

```bash
docker compose logs collector-debug | grep -c 'unifi.parse_failure: Str(syslog_header)'
```

In your backend, filter on `unifi.parse_failure: "syslog_header"`.

Then identify them, which takes one extra step, because **the failure
records do not name `linkcheck`**. They have no `process.name` — the tag
was on the header line, and these are not that line. What you look for
instead:

- **Bodies that are JSON fragments**: a bare `{`, a `"key": value,`
  line, a lone `}`. A fragment is not valid JSON on its own, which is
  the tell.
- **The record immediately before them**, on the normal export path,
  with `process.name: linkcheck`, `event.dataset: unifi.system` and a
  body of just `{`. That one is the header line, and it is what ties the
  group to `linkcheck`.
- **Arrival in a tight burst** — one frame's worth of lines lands within
  milliseconds — and then nothing for hours.

If your `syslog_header` failures do *not* look like that, they are a
different problem and this entry is not your answer. A capture of them
is worth an issue.

### Making it quiet, if you do not care

There is **no configuration flag for this** and this project will not
invent one; suppressing a failure signal by default is how a parser ends
up shipping broken and confident.

What you can do is filter downstream. Every one of these records carries
`unifi.parse_failure = "syslog_header"`, and that attribute survives
export — it is a schema field, not a working attribute, so
`transform/strip_working_fields` leaves it alone. Drop or route on it in
your gateway, your ingest pipeline, or your backend's own rules,
whichever sits between this collector and storage —
[`destinations.md`](destinations.md) describes what is on the wire and
says the same thing about this attribute.

Filter on the attribute rather than on the body text. The bodies vary
with the payload; the tag does not.

### What would fix it

Reassembly needs a `recombine` operator on the receiver, and a
`recombine` operator needs an exact answer to three questions:

1. How many lines is a frame, and is it fixed?
2. Does every line carry a PRI, or only the first?
3. **Where does the frame end** — what marks the last line, and what
   distinguishes it from an unrelated record that arrived next?

Guessing at any of those produces a parser that works on the frame
somebody imagined and silently mangles the one that actually arrives.
This project has a standing rule against shipping parsers verified only
against synthetic data — it is why AP and switch support is a documented
gap rather than a claim
([#20](https://github.com/jamesagarside/unifi-otel/issues/20)), and
[#24](https://github.com/jamesagarside/unifi-otel/issues/24) is what
happens when a path is assumed to work rather than tested. Hand-writing
a fixture here and calling the result verified would repeat exactly that
mistake, in the one place where the failure would be silent.

**No real `linkcheck` frame is available to this repository.** That is
the only thing blocking the fix.

#### What to send

A scrubbed real `linkcheck` frame **including every continuation line,
exactly as it arrived on the wire** — same lines, same order, same
whitespace, same boundaries. The boundary is the whole difficulty, so a
frame with the lines joined, trimmed, re-indented or truncated answers
none of the three questions above and is not usable.

Read [`contributing-samples.md`](contributing-samples.md) first — the
privacy rules there are not optional, and a `linkcheck` payload carries
your ISP and your approximate location.

Two things specific to this frame:

- **Capture off the wire, with the socket recipe** in
  `contributing-samples.md`. The "export `event.original` from your
  backend" route does **not** work here: as the table above shows, the
  continuation records have no `event.original` at all. Taking `body`
  off each failure record in order is a fallback, but a wire capture is
  better because it preserves the datagram boundaries, which is the
  thing being asked about.
- **`scripts/scrub.py` is line-oriented.** It reads and writes one line
  at a time and will not disturb your line structure — but it also
  cannot restore it, so preserve it yourself. Do not join the lines
  before scrubbing, and do not let an editor reflow or strip trailing
  whitespace on the way past. Check with `diff -u` that only values
  changed and the line count did not.

Attach it to
[#9](https://github.com/jamesagarside/unifi-otel/issues/9) as a
scrubbed file, never as pasted text in a comment.
