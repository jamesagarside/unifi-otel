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

The golden-file replay harness is
[#3](https://github.com/jamesagarside/unifi-otel/issues/3) and has not
landed yet, so there is currently no `make test` to run. Until it does,
check your fixture by replaying it into the debug profile and looking at
what comes out:

```bash
docker compose up -d collector-debug
python3 - tests/corpus/your-fixture.txt <<'EOF'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for line in open(sys.argv[1], 'rb'):
    line = line.rstrip(b'\r\n')
    if line:
        s.sendto(line, ('127.0.0.1', 514))
        time.sleep(0.05)
EOF
docker compose logs collector-debug | grep -o 'event.dataset: Str([^)]*)' | sort | uniq -c
```

Report that count in the PR, plus anything carrying `unifi.parse_failure`.
You do not need to fix what you find — a fixture that fails is a valid
and welcome contribution. Say so in the PR so a reviewer knows the frame
is deliberate and does not "correct" it.

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

### `linkcheck` multi-line JSON — [#9](https://github.com/jamesagarside/unifi-otel/issues/9)

`linkcheck` emits pretty-printed multi-line JSON, which the RFC3164
parser cannot handle, so those records land in the parse-failure stream —
roughly five a day in the source environment. A capture of the **complete
multi-line frame**, with the line breaks intact and in the right places,
is what is needed to either fix it or document it accurately. This is one
place where preserving structure means preserving the newlines: do not
join the lines.

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
