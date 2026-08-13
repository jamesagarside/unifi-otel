# `scripts/`

## `scrub.py` — capture scrubber

Test fixtures for this project are **real network traffic**, which makes them
the most sensitive artifact in the repository:

- DNS queries are browsing history.
- DHCP frames carry the names people gave their phones and laptops.
- `sudo` frames carry usernames and home directory paths.
- Every frame carries MAC addresses and the shape of an internal network.
- CEF frames carry the site name, SSIDs, client aliases, admin email
  addresses, firewall policy names and the ISP.

None of that can land in a public diff. `scrub.py` rewrites all of it while
leaving the frames byte-for-byte identical in shape.

The script is committed, not just its output. That is the point: a
contributor scrubs their own capture *before* opening a PR, so raw traffic
never reaches the repository in the first place, and a reviewer can read the
rules that were applied instead of taking a stranger's word for it.

---

## Running it

```sh
# file in, stdout out
python3 scripts/scrub.py capture.txt > scrubbed.txt

# file in, file out
python3 scripts/scrub.py capture.txt -o scrubbed.txt

# stdin
tail -f /var/log/unifi.log | python3 scripts/scrub.py

# several files at once, so that values correlate across all of them
python3 scripts/scrub.py capture-a.txt capture-b.txt > corpus.txt

# dry run: does anything in here still look unscrubbed?
python3 scripts/scrub.py --check tests/corpus/*.txt
```

Python 3, standard library only, no install step. That is a hard requirement
so CI can run it as-is.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Success. With `--check`: nothing looks unscrubbed. |
| `1`  | `--check` only: at least one value would be rewritten. |
| `2`  | Usage or I/O error. |

`--check` writes one finding per line to **stdout**, in the form
`<path>:<line>: <kind>: <redacted>`, and a human summary to **stderr**. This
is the contract the CI corpus privacy gate (issue #11) consumes.

Values are **redacted by default** — a privacy gate that echoes the leaked
value into a public CI log has defeated its own purpose. Pass
`--show-values` locally when you need to see what tripped it.

---

## The rule that matters: scrub values, never structure

A fixture exists because of the *shape* of the frame, not because of what is
in it. Every one of the following has to survive:

| Case | Why it matters |
| ---- | -------------- |
| The doubled hostname (`Gateway Gateway coredns[4155]: …`) | Breaks RFC3164 appname parsing; it is the reason `transform/device_syslog` needs a lazy `(?:\S+\s+)*?` prefix. |
| The doubling *inverting* on CEF frames | `appname` becomes the literal string `CEF`, which is why `transform/unifi_ecs` has to exclude it from `process.name`. |
| A tag with no `[pid]` | The `(?:\[(?P<dev_pid>[0-9]+)\])?` branch. |
| A line with no tag at all | Must fall through to `unifi.system`, not crash the tag regex. |
| `coredns` emitting non-JSON | Must **not** become `unifi.dns`. |
| `DHCPDISCOVER` putting a MAC where its siblings put an IP | The optional-IP branch of the DHCP pattern. |
| All four `sudo` shapes, including `pam_unix` auth failures | `user=` instead of `COMMAND=`; different `event.outcome` path. |
| A frame with no PRI header | `allow_skip_pri_header: true`. |

**A scrub that "tidies" a malformed frame destroys the only reason that
fixture exists.** So the script never re-wraps, re-orders, re-cases or
normalises anything. It finds value-shaped substrings, replaces them with
deterministic look-alikes of the same token shape, and puts every delimiter
and whitespace byte back exactly where it found it.

Specifically, it parses the CEF extension string on **the same boundary the
collector uses** (one whitespace byte followed by `key=`), so a value
containing spaces — a site name, an SSID, `Internet 1`, a whole `msg=`
sentence — comes out still containing spaces in the same places. Collapsing
a spaced SSID to one word would silently delete the test case that
`transform/cef_extensions` exists to satisfy.

### What gets rewritten

| Input | Output | Reference |
| ----- | ------ | --------- |
| IPv4 | `198.51.100.0/24` (private scope), `203.0.113.0/24` (routable), `192.0.2.0/24` (overflow) | RFC 5737 |
| IPv6 | `2001:db8::/32` | RFC 3849 |
| MAC | `00:00:5E:00:53:xx`, overflowing to `02:00:5E:xx:xx:xx` | RFC 7042 §2.1.2 |
| Domains | `…example.com` / `.net` / `.org` | RFC 2606 |
| Hostnames, site names, SSIDs, aliases | `host-…`, `site-…`, `ssid-…`, `alias-…` | — |
| Usernames, admin emails | `user-…`, `user-…@example.org` | — |
| ISP names, cities | `isp-…`, `geo-…` | — |
| Country codes | `ZZ` | ISO 3166-1 user-assigned |
| ASNs | 64496–64511 | RFC 5398 |

### Determinism, and why it is not optional

Every mapping comes from a keyed BLAKE2b digest, never from `random`, so the
same input value maps to the same output value **within a run and across
runs**.

That is load-bearing, not cosmetic. A MAC that appears in a DHCP frame and
again in a CEF frame has to still correlate after scrubbing, because the DHCP
dataset is the **join key** for every other dataset — MAC → IP → hostname →
bridge. Break the correlation and `related.ip`, `related.hosts` and
`related.user` become untestable and the corpus is worthless.

The same table is shared across all input files in one invocation, so pass
the whole corpus in one command if you want values to correlate between
files.

There is also **one** name table shared by every name-like field. If a site
calls a network and a zone the same thing, both come out as the same
pseudonym — two different pseudonyms for one string is indistinguishable
from a scrubber bug when you are reading a diff.

### Salt

The default salt is a public constant so that a clone of this repo reproduces
the reference corpus byte-for-byte. That also means anyone holding this
script can confirm a *guess* at a short hostname by re-hashing it.

If you are scrubbing your own capture for publication and that bothers you:

```sh
python3 scripts/scrub.py --salt "$(openssl rand -hex 16)" capture.txt -o scrubbed.txt
# or: export UNIFI_SCRUB_SALT=…
```

…and keep the salt to yourself. `--check` does not depend on the salt.

### Length preservation

Preserved where it is cheap and safe, skipped where preserving it would cost
correctness:

- **MAC addresses** — preserved. Always 17 bytes; free. The `dhcp_mac`
  pattern in `transform/device_syslog` counts them.
- **Name-like tokens** — preserved. The pseudonym is padded or truncated to
  the original length, with a floor of `prefix + 3` characters so the marker
  survives on very short names. Interior whitespace is kept at word
  granularity.
- **Domain names** — label *count* preserved, and each label to the left of
  the registrable domain keeps its own length. The last two labels become
  `example.<tld>`, which changes the total length. Deliberate: RFC 2606 is the
  only way to guarantee the output can never resolve to somebody's real host,
  and `example` is seven bytes whether we like it or not. Labels are hashed
  individually, so two names sharing a parent domain still share it
  afterwards.
- **IPv4 and IPv6** — **not** preserved, and it cannot be. An address that is
  simultaneously valid, inside RFC 5737, and the same byte length as an
  arbitrary input does not exist: every RFC 5737 range has a three-digit first
  octet, so `10.0.0.1` (8 bytes) cannot come back shorter than 12. Validity
  and documentation-range membership win, because the `dhcp_ip` pattern and
  every `ip`-typed field downstream care about those and none of them care
  about length.

### Idempotence

Every output form is recognisable as already-scrubbed (RFC 5737/3849 ranges,
the `00:00:5E:00:53` MAC block, an `example.com` suffix, a `<marker>-<hex>`
pseudonym). Scrubbing an already-scrubbed file is therefore a no-op, which
makes the dry-run gate exact:

> `--check` passes if and only if scrubbing the input changes nothing.

Anything the rewriter would have touched is, by definition, something that
still looks unscrubbed.

---

## The allowlist

At the top of `scrub.py` there is a clearly-marked block of constants —
`ALLOWLIST_VALUES`, `PRESERVE_IP_NETWORKS`, `PRESERVE_MACS`,
`NON_DOMAIN_SUFFIXES`, `PRESERVE_CEF_KEYS`. **Edit that block, and only that
block, when the scrubber eats something it should have left alone.**

Deliberately *not* scrubbed:

- **Vendor service account names** in `sudo` records — `uid`, `ucs-update`,
  `unifi-user-assets`, `unifi-access`, `root`. These are UniFi's own agents
  firing on a timer, not people.
- **UniFi device model names** — `UDMPRO`, `USW-Lite-8`, `U6-Pro`, …
- **Default interface and bridge names** — `br0`, `br3`, `eth4`, `switch0`.
  `dhcp_iface` reads these straight through into
  `observer.ingress.interface.name`.
- **Default zone and network names** — `Internet 1`, `Default`, …
- **UniFi's own event, category and policy vocabulary** — `Scanning
  Activity`, `Security`, `Audit`, `Client Devices`, `Firewall`, `IDS/IPS`.
  These are the exact values the taxonomy in `transform/unifi_ecs` switches
  on.
- **`127.0.0.1` and `0.0.0.0`** — `127.0.0.1:1053` is the UDM's *own*
  resolver. It is load-bearing in a comment in `transform/device_syslog` and
  in the DNS destination mapping; rewriting it would make that comment a lie.
  Broadcast and multicast are preserved for the same reason.
- **systemd unit names and file extensions** — `ubios-udapi-server.service`
  is not a domain, and turning it into `…example.com` would be vandalism.
- **Version strings** — `UNIFIdeviceVersion=4.3.10.1` is in
  `PRESERVE_CEF_KEYS` precisely because a four-part version is
  indistinguishable from an IPv4 literal to any regex.

These are stock on every UniFi install. They carry no site information, they
are load-bearing for the parsers, and they are worth keeping in a public
corpus as documentation of what the vendor actually emits. Scrubbing them
would break the fixtures **and** make them less useful.

One value gets a conditional rule. `UNIFIpolicyName` is two different things
wearing one key: on an IDS/IPS record it is a signature name (`Scanning
Activity` — vendor vocabulary, worth keeping), and on a Firewall record it is
a rule the operator named, which routinely embeds a site, a person or a
device. The script keeps it when the sibling `UNIFIpolicyType` says
`IDS/IPS`, and scrubs it otherwise.

---

## Contributor workflow

If you are contributing fixtures:

1. **Capture** your own UniFi syslog to a file.
2. **Scrub it** before it touches `git`:
   ```sh
   python3 scripts/scrub.py my-capture.txt -o tests/corpus/my-capture.txt
   ```
3. **Read the diff.** Not the whole file — but skim `msg=` values and any
   free-text field. See the limitations below for what the script cannot
   catch on its own.
4. **Verify:**
   ```sh
   python3 scripts/scrub.py --check tests/corpus/my-capture.txt   # must exit 0
   ```
5. Commit the scrubbed file. **Never** commit the raw capture, and do not
   leave it in the working tree where a `git add -A` can find it.

If you added a fixture for a frame shape the parsers do not handle yet, say
so in the PR — a deliberately malformed frame is a feature, and a reviewer
needs to know not to "fix" it.

---

## Limitations a reviewer should know about

- **A name that appears *only* in free prose is not caught.** The script
  learns names from structured positions (the syslog hostname field, CEF keys
  it recognises, the DHCP hostname slot, `sudo` username slots) and then
  redacts those learned strings everywhere else in the input, including inside
  `msg=` sentences. A person's name that never appears in a structured field
  is invisible to it — and `--check` cannot see it either. **Skim the diff.**
- **A four-part version number is indistinguishable from an IPv4 address.**
  Known CEF keys carrying versions are allowlisted; one appearing in free-text
  device syslog will be rewritten into the documentation range. Cosmetic, but
  it is a rewrite.
- **IPv4 collisions are possible.** RFC 5737 gives 254 usable addresses per
  scope before overflow. The mapping is hash-seeded with linear probing, so a
  capture with more than ~500 distinct addresses of one scope aborts loudly
  rather than colliding silently. In the rare collision case, adding new
  frames to an input can shift one address between runs; the mapping stays
  internally consistent either way.
- **Subnets collapse.** `UNIFInetworkSubnet` maps every private subnet onto
  the same documentation network with the original prefix length preserved.
  RFC 5737 does not give us enough space to keep them distinct, and subnet
  identity is not a join key for any dataset in this collector.
- **Country codes all become `ZZ`.** The field stays populated and the key set
  is unchanged, but you lose geographic variety across the corpus.
- **`--check` tests shape, not secrecy.** It answers "does anything here still
  look like a real identifier?", which is the right question for a CI gate and
  the wrong question for "is this definitely safe to publish?".

---

## How this was verified

Both the raw and the scrubbed samples were replayed through the real
collector — `otel/opentelemetry-collector-contrib:0.157.0` running
`10-receivers-logs.yaml` + `20-processors-logs.yaml` — over UDP for RFC3164
and TCP for RFC5424, and the parsed records were compared frame by frame.

The bar, met for every frame: the scrubbed version produces the **same
`event.dataset`**, the **same set of populated attribute keys**, the **same
`unifi.parse_failure` status** and the same severity as the original.

If you change the scrubbing rules, re-run that comparison. A rule that looks
harmless in a diff can quietly move a frame from `unifi.dhcp` to
`unifi.system`.
