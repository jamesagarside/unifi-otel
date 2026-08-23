# Contributing test samples

The parsers in this project were written against traffic from **one**
gateway on **one** site. Every shape they handle correctly is a shape
somebody happened to observe. Everything else is a guess.

That is the gap contributed samples close. A frame from hardware the
maintainer does not own is worth more than any amount of code review,
because it is the only thing that can turn "the regex looks right" into
"the regex is right".

## Read this part first

**Never paste a raw frame into an issue, a pull request description, or a
comment.** Public git history and GitHub comments are permanent, indexed
and mirrored; an edit does not remove them. Scrub first, always, before
the frame leaves your machine — and if you are unsure whether something
is scrubbed, treat it as raw.

Fixtures here are real network traffic, which makes them the most
sensitive artifact in the repository:

- DNS queries are browsing history.
- DHCP frames carry the names people gave their phones and laptops.
- `sudo` frames carry usernames and home directory paths.
- Every frame carries MAC addresses and the shape of an internal network.
- CEF frames carry the site name, SSIDs, client aliases, admin email
  addresses, firewall policy names and the ISP.

The tooling below exists so you can contribute without publishing any of
that. Use it.

---

## 1. Capture

You need the **raw frame**, as it arrived, byte for byte — not a
screenshot, not a parsed record, not a tidied-up version.

### If you are already shipping to a backend

The raw frame is retained on every record as `event.original`. Query for
the records you want and export that one attribute, one frame per line.
Nothing else in the record is needed.

One caveat, and it is the reason [#24](https://github.com/jamesagarside/unifi-otel/issues/24)
exists: `event.original` is only set on frames that reach the
device-syslog transform's body-splitting stage. On a device that does
**not** double its hostname the whole raw frame is still sitting in
`body` instead. If `event.original` is missing on the records you care
about, take `body` — and mention it in the PR, because that absence is
itself a finding.

### If you are not shipping anywhere yet

Run the debug profile from [`quickstart.md`](quickstart.md), which parses
and prints and exports nowhere:

```bash
cp .env.example .env
$EDITOR .env                          # set UNIFI_SYSLOG_TIMEZONE
docker compose up -d collector-debug
docker compose logs -f collector-debug
```

Confirm frames are arriving, then read `event.original` off the printed
records.

### Capturing off the wire instead

If you want the exact bytes with no collector in the path, listen on a
spare port and point the UniFi device at it:

```python
# save as listen.py, then:  python3 listen.py 5514 > capture.txt
import socket, sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 5514))
try:
    while True:
        data, _ = s.recvfrom(65535)
        sys.stdout.buffer.write(data.rstrip(b"\r\n") + b"\n")
        sys.stdout.flush()
except KeyboardInterrupt:
    pass
```

Use a socket, not `nc`. macOS `nc` truncates UDP datagrams at around 1024
bytes, and a truncated CEF frame looks exactly like a parse failure —
you would be contributing a fixture for a bug that does not exist.

Whatever route you take, the result should be a plain text file, **one
frame per line**.

---

## 2. Scrub

`scripts/scrub.py` rewrites every value that identifies you and leaves
the frames identical in shape. Python 3, standard library only, no
install step.

```bash
python3 scripts/scrub.py capture.txt -o scrubbed.txt
```

Pass the whole capture in **one invocation** if it spans several files.
The mapping table is shared across all inputs in a run, so a MAC seen in
a DHCP frame and again in a CEF frame still correlates afterwards:

```bash
python3 scripts/scrub.py capture-a.txt capture-b.txt -o scrubbed.txt
```

Mappings come from a keyed BLAKE2b digest, not from `random`, so the same
input value maps to the same output value within a run and across runs.
That correlation is load-bearing — DHCP is the join key (MAC → IP →
hostname → bridge) for every other dataset, and breaking it makes
`related.ip`, `related.hosts` and `related.user` untestable.

The default salt is a public constant, which means anyone holding the
script can confirm a *guess* at a short hostname by re-hashing it. If
that matters to you, supply your own and keep it:

```bash
python3 scripts/scrub.py --salt "$(openssl rand -hex 16)" capture.txt -o scrubbed.txt
```

`--check` does not depend on the salt, so a custom salt costs you
nothing downstream.

### The rule: scrub values, never structure

A fixture exists because of the **shape** of the frame, not because of
what is in it. A contributor who "tidies" a malformed frame has destroyed
the only reason to keep it.

The script never re-wraps, re-orders, re-cases or normalises anything. It
finds value-shaped substrings, replaces them with deterministic
look-alikes of the same token shape, and puts every delimiter and
whitespace byte back where it found it. Do the same by hand if you touch
the file at all. In particular, all of the following must survive
untouched:

| Property | Why |
| --- | --- |
| The doubled hostname (`Gateway Gateway coredns[4155]: …`) | Breaks RFC3164 appname parsing; the whole `transform/device_syslog` prefix regex exists for it. |
| The doubling *inverting* on CEF frames | `appname` becomes the literal string `CEF`, which `transform/unifi_ecs` has to exclude from `process.name`. |
| A tag with no `[pid]` | The optional `(?:\[(?P<dev_pid>[0-9]+)\])?` branch. |
| A line with no tag at all | Must fall through to `unifi.system` without crashing the tag regex. |
| `coredns` emitting non-JSON | Must **not** become `unifi.dns`. |
| `DHCPDISCOVER` putting a MAC where its siblings put an IP | The optional-IP branch of the DHCP pattern. |
| All four `sudo` shapes, including `pam_unix` auth failures | `user=` instead of `COMMAND=`; a different `event.outcome` path. |
| A frame with no PRI header | `allow_skip_pri_header: true`. |
| A `linkcheck` frame's line breaks, in the right places | Each line is a separate datagram. The `recombine` operator keys off the header line's trailing `{` and the closing `}` on its own line; joining, re-indenting or truncating the lines destroys the only property the fixture tests. |
| Values containing spaces (site names, SSIDs, `Internet 1`, a whole `msg=` sentence) | CEF has no quoting; `transform/cef_extensions` splits on ` key=` and exists precisely for these. |

`scripts/README.md` documents what gets rewritten, what is deliberately
left alone (vendor service accounts, device models, `br0`/`eth4`,
`127.0.0.1`, UniFi's own event vocabulary) and how to extend the
allowlist when the scrubber eats something it should not have.

### Read the diff. The automation cannot do this part for you.

```bash
diff -u capture.txt scrubbed.txt | less
```

The script learns names from **structured positions** — the syslog
hostname field, CEF keys it recognises, the DHCP hostname slot, the
`sudo` username slots — and then redacts those learned strings everywhere
else in the input, including inside `msg=` sentences.

**A name that appears only in free prose and never in a structured
position is never learned, so it is neither rewritten nor caught by
`--check`.** Demonstrated:

```
$ python3 scripts/scrub.py prose.txt
<30>Aug 13 09:20:00 host-0a3 host-0a3 ubios-udapi-server[1234]: failed to apply profile for Priyas Study Desk, retrying

$ python3 scripts/scrub.py --check prose.txt; echo $?
scrub.py: OK -- 1 file(s) contain nothing that looks unscrubbed
0
```

The frame is unchanged, the gate is green, and a person's name is in it.
This is the one place the tooling cannot save you. Skim the diff, and pay
particular attention to `msg=` values and any free-text field.

### Verify before you open a PR

```bash
python3 scripts/scrub.py --check scrubbed.txt
```

| Exit | Meaning |
| --- | --- |
| `0` | Nothing in the file looks unscrubbed. |
| `1` | At least one value would still be rewritten. Do not commit it. |
| `2` | Usage or I/O error. |

Clean:

```
scrub.py: OK -- 1 file(s) contain nothing that looks unscrubbed
```

Not clean — findings go to **stdout**, one per line, and the summary to
**stderr**:

```
scrub.py: FAIL -- 40 unscrubbed value(s) across 1 file(s). Run `python3 scripts/scrub.py <file> -o <file>` before committing.
capture.txt:1: host: Ro<redacted 5 chars>
capture.txt:3: domain: ad<redacted 19 chars>
capture.txt:11: ssid: Ga<redacted 13 chars>
capture.txt:11: name-in-text: ja<redacted 13 chars>
```

Values are **redacted by default, deliberately**: a privacy gate that
echoes the leaked value into a public CI log has defeated its own
purpose. Add `--show-values` when you need to see what tripped it, and
only locally.

This same command is the CI corpus privacy gate
([#11](https://github.com/jamesagarside/unifi-otel/issues/11)), so
running it yourself is not busywork — it is exactly what the PR will be
judged on, minus the part where a failure is visible to everyone.

`--check` passes if and only if scrubbing the input changes nothing.
Every output form is recognisable as already-scrubbed, so re-scrubbing a
scrubbed file is a no-op and the gate is exact. Note the limit of what
that proves: it answers "does anything here still look like a real
identifier?", which is the right question for CI and the wrong question
for "is this definitely safe to publish?". That second question is yours.

Finally: **never commit the raw capture**, and do not leave it in the
working tree where a `git add -A` can find it.

---

## 3. Add and check locally

Scrubbed fixtures live under `tests/corpus/`, as plain text, one frame
per line. Group by device class and frame shape rather than by capture
session — a file called `usw-lite-8-kernel.txt` is useful to a reviewer
and `capture-2026-08-13.txt` is not.

Run the replay harness. It is the same thing CI runs, so a green run
locally means a green run on your PR:

```bash
python3 tests/run.py
```

It replays every frame under `tests/corpus/` through the real collector
image and diffs the result against the golden files in `tests/golden/`.
Adding a frame therefore fails the first time by design — there is no
golden for it yet. Generate one:

```bash
python3 tests/run.py --update
```

**Then read the diff before committing it.** That diff is the entire
value of the golden files: it is a plain statement of how your frame was
parsed. If a field is missing, or the dataset is not what you expected,
you have found something — which is a useful contribution, not a
problem.

`--update` is also how a genuine regression gets laundered into a
"passing" test suite, so the rule is: regenerate when you have ADDED a
frame, and be suspicious when regenerating changes goldens for frames
you did not touch. `tests/README.md` covers this in more detail.

You do not need to fix what you find — **a fixture that fails is a valid
and welcome contribution.** Say so in the PR so a reviewer knows the
frame is deliberate and does not "correct" it.

Two harness details that will otherwise look like bugs:

- Corpus files may carry `#` comment lines, but those lines **must not
  contain dotted tokens** — the privacy gate cannot tell `event.dataset`
  from a domain name, so a comment mentioning one will fail the check.
- The gate runs over `tests/corpus/` only, never `tests/golden/`, for
  exactly that reason.

---

## What makes a good sample

**Structural diversity, not volume.** Ten frames of ten different shapes
are worth more than ten thousand of one shape. The corpus is a set of
test cases, not a data set.

**Edge cases beat clean records.** A frame that parses correctly already
passes; adding it proves nothing that is not already proven. The
valuable submissions are the awkward ones:

- a frame that lands in the parse-failure pipeline — **the single most
  valuable thing you can send**, because it is a bug with a reproducer
  attached
- a daemon nobody here has seen, in a format nobody here has parsed
- a device that formats its hostname, tag or timestamp differently
- truncation, embedded newlines, an unexpected character set, a missing
  PRI header — anything that looks broken

**Matched pairs of hostname shapes are disproportionately useful.** The
same payload from a device that doubles its hostname and one that does
not is exactly the pairing that catches the class of bug in
[#24](https://github.com/jamesagarside/unifi-otel/issues/24), where
parsing silently degrades on single-hostname devices without raising a
single error. Reproduced against 0.157.0 with identical payloads
differing only in the hostname:

| Frame | Doubled hostname | Single hostname |
| --- | --- | --- |
| `DHCPACK(br3) …` | `unifi.dhcp`, fields populated | `unifi.system`, nothing extracted |
| `coredns[…]: {json}` | `unifi.dns`, `dns.question.name` set | `unifi.system`, no `dns.question.name` |
| `sudo[…]: uid : PWD=… COMMAND=…` | `unifi.sudo`, `user.name` + `process.command_line` set | `unifi.sudo`, zero fields extracted |

Nothing about that is visible in an error log or a dataset histogram. It
took a matched pair to find it, and it will take matched pairs in the
corpus to stop it coming back.

The same trap was avoided deliberately for `linkcheck` reassembly: the
`recombine` predicate tests for the `linkcheck[pid]:` tag in *both*
positions the two hostname shapes put it in — `message` when the
hostname is doubled, `appname` when it is not — and both were exercised
before it shipped. That covers the reassembly step only. Whether the
rest of the device-syslog chain degrades on a single-hostname
`linkcheck` frame in the way the matrix above shows for its siblings has
not been tested, because the one real frame available is a doubled one.

**Non-gateway devices, always.** See the wanted list below.

## What not to bother sending

- **Thousands of near-identical records.** Send one of each shape. If you
  believe the volume itself is the finding — a burst, a rate change, a
  flood — describe it in the PR and send a representative handful.
- **Shapes already in `tests/corpus/`.** Skim it first.
- **Anything you had to hand-edit into cleanliness.** If it no longer
  matches the bytes on the wire it is not a fixture, it is a guess.
- **Parsed records, screenshots, or reconstructions from memory.** Only
  raw frames are usable.

---

## Wanted right now

These are the gaps where a contribution changes what this project can
honestly claim.

### AP and switch syslog frames — [#20](https://github.com/jamesagarside/unifi-otel/issues/20)

**No real AP or switch frame has ever been seen by this project.** Device
syslog was enabled on both in the source environment and nothing ever
arrived; the cause is unknown. The parsers exist and are believed
correct, but they are verified against *synthetic* single-hostname
`hostapd` and `kernel` frames only — so any claim of AP or switch support
currently rests on data somebody made up.

If you have a UniFi AP or switch that emits syslog, a handful of scrubbed
frames from it is **the single highest-value contribution available to
this project**. It converts an unverified claim into a verified one, and
in combination with #24 it is likely to expose real bugs rather than
confirm correctness.

### Any RFC5424 frame at all — [#25](https://github.com/jamesagarside/unifi-otel/issues/25)

**No RFC5424 frame of any kind has ever reached this project.** The
seven-day capture behind `tests/corpus/real-*.txt` contains zero of them,
because the gateway it came from has its SIEM Server set to UDP. So
`syslog/unifi_tcp` — the whole RFC5424 receiver — is exercised by
invented frames only.

Two separate questions are open, and they are worth different amounts:

1. **What does a real CEF frame look like over RFC5424?** Specifically
   its `APP-NAME`. The synthetic fixture sets it to the literal `CEF`,
   because that is what the RFC3164 parser derives from a CEF frame's
   `CEF:` tag, and that choice is what makes the matched pair agree.
   Measured against 0.157.0, the whole CEF path over 5424 turns on that
   one field:

   | `APP-NAME` | Result |
   | --- | --- |
   | `CEF` | no `process.name`, no `process.pid` — matches the UDP twin |
   | `-` (NILVALUE) | no `process.name`, no `process.pid` — matches the UDP twin |
   | a real process name | `process.name` **and** `process.pid` are set, which the UDP twin never has |

   That third row is not a bug — a real app name is real information —
   but it means the fixture is green because of a value somebody chose.
   **This one is answerable and worth answering.**

2. **Does UniFi emit *non-CEF* device syslog over 5424 at all?** Probably
   not, and the reason is structural rather than mysterious: the two
   feeds are configured separately, and only one of them offers a
   transport choice. Per [`quickstart.md`](quickstart.md), device syslog
   comes from *Remote syslog*, which is RFC3164/UDP with no TCP option,
   while the RFC5424/TCP option belongs to *SIEM Server*, which carries
   only CEF. If that holds when somebody actually looks at the UI, the
   answer to #25 is "there is nothing to capture", the receiver keeps its
   synthetic regression fixtures, and the ticket closes as documentation.
   **Confirming that from the UI is itself the contribution.**

#### The capture recipe

You need a UniFi console with the SIEM Server feed enabled. Roughly a
day of wall-clock time, almost all of it waiting.

**1. Flip the SIEM Server to TCP.**

*Settings → CyberSecure → SIEM Server* (UniFi moves these between
releases; if it is not there, type "SIEM" into the Settings search box).
Change the transport from UDP to TCP and point it at port **601** on the
host running this collector — the container listens on 6601 and the
Compose/Helm mapping publishes 601 onto it, so the port you type into
UniFi is 601. Leave *Remote syslog* exactly as it is.

**While you are in there, record what the UI offers.** Screenshot or
describe, in words, whether *Remote syslog* has any transport or format
selector at all. That is the answer to question 2 and it costs nothing.

**2. Leave it for 24 hours.**

Not an hour. The low-volume datasets are the interesting ones —
`unifi.audit` fires when an admin signs in, `unifi.security` when
something is detected — and a short window catches only firewall and
client chatter. A day also spans at least one of whatever runs on a
timer.

Check partway through that anything is arriving at all. If the TCP
listener is getting nothing, that is a finding too: say so and stop,
rather than waiting out the day.

**3. Pull the raw frames back out.**

Every parsed record carries the frame it came from in
`event.original`, so a backend query is the easiest capture route. What
follows is Elasticsearch, because that is the destination this project's
maintainer runs; adapt the index names to whatever your gateway routes
to.

On Elastic Cloud the Elasticsearch endpoint is your Kibana URL with
`.kb.` replaced by `.es.` — same deployment, different service:

```bash
export ES_URL="https://<deployment>.es.<region>.<provider>.elastic-cloud.com"
export ES_KEY="<an API key with read on the unifi indices>"
```

Successfully parsed records. Pull the window wholesale and pick the
RFC5424 frames out **client-side** — they are the ones whose
`event.original` starts `<PRI>1 `. Doing the filter in Python rather than
in the query is deliberate: whether a `prefix` query on
`event.original` works depends on how your mapping analysed the field,
and a query that silently matches nothing looks exactly like a gateway
that sent nothing.

```bash
curl -sS -H "Authorization: ApiKey $ES_KEY" -H 'Content-Type: application/json' \
  "$ES_URL/logs.otel.unifi*/_search?size=1000" -d '{
  "_source": ["attributes.event.original", "body.text"],
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}}
}' | python3 -c '
import json, re, sys

def original(src):
    """event.original, however this mapping happens to spell it."""
    flat = src.get("attributes.event.original")
    if flat:
        return flat
    attrs = src.get("attributes") or {}
    ev = attrs.get("event")
    if isinstance(ev, dict):
        return ev.get("original")
    return attrs.get("event.original")

doc = json.load(sys.stdin)
hits = doc.get("hits", {}).get("hits", [])
print(f"{len(hits)} record(s) in the window", file=sys.stderr)
seen = set()
for h in hits:
    v = original(h["_source"])
    if v and re.match(r"^<\d+>1 ", v) and v not in seen:
        seen.add(v)
        print(v)
print(f"{len(seen)} distinct RFC5424 frame(s)", file=sys.stderr)
' > capture-5424.txt
```

The two counts on stderr are the point of the exercise. "1000 records in
the window, 0 distinct RFC5424 frames" is a complete and publishable
answer to question 1 — it says the SIEM feed moved to TCP and device
syslog did not follow. Report it as a finding rather than as a failed
capture.

**Parse failures matter more than successes here**, and they live
somewhere else — this project routes them to their own stream:

```bash
curl -sS -H "Authorization: ApiKey $ES_KEY" -H 'Content-Type: application/json' \
  "$ES_URL/logs-unifi.parsefail*/_search?size=1000" -d '{
  "_source": ["attributes.event.original", "body.text"],
  "query": {"range": {"@timestamp": {"gte": "now-24h"}}}
}' | python3 -c '
import json,sys
seen=set()
for h in json.load(sys.stdin)["hits"]["hits"]:
    s=h["_source"]
    a=s.get("attributes",{}).get("event",{})
    v=a.get("original") if isinstance(a,dict) else None
    # A continuation line never reached the transform that sets
    # event.original, so the raw text is still sitting in the body.
    if not v:
        b=s.get("body")
        v=b.get("text") if isinstance(b,dict) else b
    if v and v not in seen:
        seen.add(v); print(v)
' >> capture-5424.txt
```

That `body.text` fallback is not optional. A multi-line payload arrives
as several wire units and only the first carries a header; the rest have
no `event.original` at all, and dropping them silently would turn a
multi-line frame into a one-line one — a fixture for a shape that never
existed.

**4. Scrub, check, read the diff.**

```bash
python3 scripts/scrub.py capture-5424.txt -o tests/corpus/transport-rfc5424-real.txt
python3 scripts/scrub.py --check tests/corpus/transport-rfc5424-real.txt
diff -u capture-5424.txt tests/corpus/transport-rfc5424-real.txt | less
```

Then `python3 tests/run.py`, read the block it prints for each new
frame, and `--update` only once you agree with it. Section 3 above
covers the rest.

**5. Say what the `APP-NAME` was.**

In the PR, in words. It is the single fact the whole synthetic axis is
resting on, and it is visible in the fourth field of the frame.

Do **not** delete the synthetic pairs when real frames arrive. They are
structural fixtures — a NILVALUE `APP-NAME`, a full-path one — and a real
capture is unlikely to contain either. Add alongside, and update the
observation-versus-invention table in `tests/README.md`, which is the
honest claim that directory makes about itself.

### UniFi Protect and Access alarms — [#21](https://github.com/jamesagarside/unifi-otel/issues/21)

These have **no path into the pipeline at all** today, and cannot have
one via syslog: the SIEM Server feed is UniFi Network only, and its CEF
header is always `Ubiquiti|UniFi Network`. The only route is the Alarm
Manager webhook.

Reinstating that blind would ship a receiver that has never seen a real
frame — the same implied-coverage problem as #20. It needs someone who
actually runs Protect or Access. If that is you, scrubbed frames are the
prerequisite for the work, not a nice-to-have alongside it.

### Devices that do not double their hostname — [#24](https://github.com/jamesagarside/unifi-otel/issues/24)

Any device whose frames carry a single hostname, whatever it is. See the
matrix above for why. Matched pairs are ideal; a single-hostname capture
on its own is still valuable.

### A second gateway's `linkcheck` frame — [#9](https://github.com/jamesagarside/unifi-otel/issues/9)

**This one is mostly satisfied.** A real multi-line `linkcheck` frame was
contributed, the `recombine` operator that reassembles it shipped on the
back of it, and the payload is parsed into `unifi.speedtest`. It is on
this list only because the whole of that rests on **one frame from one
gateway**: one observation of the payload key set, one of the line count,
one of the trailing `{` the predicate matches on.

A `linkcheck` frame from a different gateway or a different firmware
would turn that into a pattern. Worth sending even if it looks
identical — "identical" is the finding.

A re-headed frame **has now been contributed**: `real-linkcheck-headed.txt`
is a capture from UniFi Network 10.5.67, where the gateway re-emits the
full RFC3164 header, hostname and tag on *every* datagram
([#34](https://github.com/jamesagarside/unifi-otel/issues/34)). It
settled the question the old fixture was guessing at — the head line now
reads `[info ] {` — and it exposed that the payload is no longer one
brace-delimited object at all.

What is still wanted here is **a third gateway or firmware**, to say
whether either shape is general. And specifically: a run in which the
server-entry list is terminated, or one where the
`Completed: Downlink … Uplink …` summary is absent or worded
differently. Both are load-bearing guesses right now.

The capture rules for this frame are stricter than for a single-line one:

- **Capture off the wire**, with the socket recipe above. Each line is
  its own datagram, and the datagram boundaries are the thing being
  tested.
- **Do not join, re-indent or truncate the lines.** `scripts/scrub.py`
  is line-oriented and will not disturb your line structure, but it
  cannot restore it either. Check with `diff -u` that only values
  changed and the line count did not.
- **A `linkcheck` payload is the most sensitive frame in this project.**
  It carries your ISP, the domain of its website, a city, your public
  WAN address, and — in the client-info block — `lat`/`lon` **to your
  own location**, not the test server's. Verified against a real
  capture: `scrub.py` catches all of them, reporting the coordinates as
  kind `coordinate` and zeroing them, and it catches `lat`/`lon` as well
  as `latitude`/`longitude`. Read the diff anyway;
  [#31](https://github.com/jamesagarside/unifi-otel/pull/31) exists
  because an ISP field reached a golden once already. Never paste one of
  these frames into an issue or a PR description.

### Another `ubios-udapi-server` sub-tag that splits a quoted payload — [#32](https://github.com/jamesagarside/unifi-otel/issues/32)

`wan-failover-monitor-icmp` logs a single-quoted blob whose closing
quote lands on its own line, and the second datagram arrives as a
**complete** frame with the header, the `ubios-udapi-server[pid]:` tag
and the sub-tag all re-emitted in front of a lone `'`. The receiver now
folds the pair back into one record.

The predicate deliberately matches the **quoting**, not that sub-tag:
any `ubios-udapi-server` message whose last `'` opens a value and never
closes it is treated as the head of a split payload. That generalisation
is currently supported by exactly one observed sub-tag, so what is
wanted is either half of the question:

- **a sibling sub-tag doing the same thing** — `linkstate`, `process`,
  another `wan-failover-*`, anything. It would turn the generalisation
  into an observation.
- **a `ubios-udapi-server` line that ends on an open quote and is
  genuinely complete**, with no continuation to come. That is the one
  shape the predicate gets wrong: it holds the record for about five
  seconds and then emits it alone. A real example is the only thing that
  would justify narrowing the predicate back to named sub-tags.

Capture rules are the `linkcheck` ones above, with one addition: **send
both datagrams**. A capture of the head alone is indistinguishable from
the bug this fixed, and a capture of the continuation alone is a lone
quote mark.

---

## Licensing and attribution

Contributed fixtures land in a **public** repository under the
[Apache License 2.0](../LICENSE), the same licence as the rest of the
project. They are published, mirrored and permanent.

By opening a pull request that adds a fixture you are confirming that:

- the traffic came from a network you operate or are authorised to
  capture from, and you have the right to publish it;
- you have scrubbed it with `scripts/scrub.py`, `--check` exits 0, and
  you have read the diff; and
- you are contributing it under the project's licence.

If any of those is not true, do not open the PR — open an issue
describing the shape of the frame **in words**, with no raw content, and
it can be worked out from there.
