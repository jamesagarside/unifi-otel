# Elastic detection rules

What Elastic Security's prebuilt detection rules do, and mostly do not
do, with the records this collector produces.

The short version: **three rules**. Everything else in a 2,069-rule
prebuilt catalogue is blocked by an index pattern that does not name your
data, a field the UniFi feeds never emit, or both. That is not a failure
of the parsing — it is what a network-appliance syslog feed looks like
next to a rule catalogue written mostly for endpoint, cloud audit and
Windows telemetry. The value of this page is the *specific* missing
field for each rule somebody will reasonably expect to work, so nobody
has to repeat the investigation.

## How this was established

One Elastic Security serverless project on **9.6.0**, with 2,069
prebuilt rules installed, fed by one UDM over the paths in the
[README](../README.md) scope table. Every rule was tested against four
bars, in order, and a rule had to clear all four:

1. its index pattern resolves to the UniFi data at all;
2. every field its query and its `required_fields` reference resolves
   under `_field_caps` over that pattern;
3. the rule's own query matches **real documents** in the last 30 days —
   run it, count the hits, and reject on zero;
4. for machine-learning rules, the anomaly detection job can actually
   start: its detector fields *and its influencers* have mappings.

Bar 4 exists because a missing influencer is not a silent no-op. The
datafeed refuses to extract and the job dies with `cannot retrieve field
[…] because it has no mappings`, and the rule sitting on top of it
reports a failure on every execution from then on. Two of the DNS rules
below fail exactly this way.

Volumes quoted are from a 30-day window ending 2026-08-23, of which the
data covers about 13 days, on a network that was in a temporary location
behind a 5G WAN with most devices offline. Read them as evidence that a
query matches *something*, not as a rate.

## Prerequisite: `logs-*` has to resolve to your data

Every prebuilt rule that can see this data at all matches on `logs-*`.
Whether that works depends on the shape your gateway writes into.

**Classic data streams** — `logs-<dataset>-<namespace>`, which is what
the Elasticsearch exporter produces when it routes on
`data_stream.dataset` — are matched by `logs-*` with nothing further to
do.

**Wired streams** are not. Their names are dotted (`logs.otel.unifi`),
and `logs-*` cannot match a dotted name. The failure mode is the bad
one: the rule reports `succeeded` on every execution and finds nothing,
because nothing was ever in scope. Give the stream a second, hyphenated
name:

```bash
curl -X POST "$ES/_aliases" -H "Content-Type: application/json" -d '{
  "actions": [
    { "add": { "index": "logs.otel.unifi", "alias": "logs-unifi.udm-otel" } }
  ]
}'
```

Two things to get right:

- **Name every child stream, not just the parent.** If you partition by
  `event.dataset` — and `unifi.system` is around 90% of all records, so
  you probably should — the parent keeps almost nothing. An alias on the
  parent alone leaves every partitioned record invisible, which is the
  same silent zero it was created to fix.
- **Prefer the alias to editing the rule's index list.** Editing a
  prebuilt rule marks it customised, which changes how it takes upstream
  updates, and on serverless the revert API may not be available to
  clear that flag. An alias leaves every stock rule untouched and
  extends coverage to all of them at once.

Confirm before you trust it:

```bash
curl -s "$ES/_resolve/index/logs-*"
curl -s "$ES/logs-*/_search?size=0" -H "Content-Type: application/json" \
  -d '{"query":{"term":{"event.dataset":"unifi.firewall"}}}'
```

## The rules that work

| Rule | Type | Fed by | Evidence over 30 days |
| --- | --- | --- | --- |
| **External Alerts** | query, `logs-*` | `unifi.security` | 22 records matched `event.kind:alert and not event.module:(endgame or endpoint or cloud_defend)`; 20 alerts raised — IDS/IPS blocks and one honeypot trigger |
| **Spike in Firewall Denies** | ML, `high_count_network_denies` | `unifi.firewall`, `unifi.dns`, `unifi.security` | datafeed matched 5,166 records (3,093 / 2,053 / 20); job open, 7 anomaly records, top score 66 |
| **Spike in Network Traffic** | ML, `high_count_network_events` | everything with `event.category: network` | datafeed matched ~136,000 records; job open, 138 anomaly records, top score 95 |

**External Alerts is the one that earns its place.** It is the bridge
between UniFi's IDS/IPS and Elastic's alert workflow: it promotes
anything carrying `event.kind: alert` into a security alert, and
`unifi.security` is the only dataset here that sets that. Its
`rule_name_override` means the alert is titled with UniFi's own
description of the detection rather than the rule name, which is what
you want.

**Spike in Firewall Denies is a genuine fit.** Its datafeed asks for
`event.category: network` plus `event.outcome: deny` or `event.type:
denied`, and both `unifi.firewall` (policy blocks) and `unifi.dns`
(CoreDNS block decisions) satisfy that without any mapping work.

**Spike in Network Traffic is not measuring what its name suggests.**
Its datafeed asks only for `event.category: network`, and this collector
assigns that category to every record from the gateway — including
`unifi.system`, the systemd/mcad/ulogd device chatter, which is around
90% of all records. So the job is a spike detector on *gateway syslog
volume*, not on traffic. That is still a useful signal — a device
melting down produces a spike — but do not read an anomaly as "somebody
moved a lot of data". If you want the narrow reading, clone the job with
`event.dataset: unifi.firewall` added to the datafeed query.

Enable them with the bulk action API rather than one at a time:

```bash
curl -X POST "$KIBANA_URL/api/detection_engine/rules/_bulk_action" \
  -H "kbn-xsrf: true" -H "Content-Type: application/json" \
  -d '{"action":"enable","ids":["<rule id>", "..."]}'
```

The two ML rules need their jobs opened and datafeeds started as well;
the rule reports `partial failure` with *"ML jobs are not started"*
until you do.

## The rules that do not work, and why

Named individually where somebody would reasonably expect otherwise.
Everything here was rejected against a specific, checkable fact — not on
a judgement that it "probably would not fire".

| Rule | Blocked by |
| --- | --- |
| **DNS Tunneling** (ML `dns_tunneling_ea`) | `dns.question.type` has no mapping anywhere in `logs-*`. It is an influencer, so the datafeed cannot extract and the job stops with `cannot retrieve field [dns.question.type] because it has no mappings`. Also wants a scripted eTLD field this data has no basis for |
| **Unusual DNS Activity** (ML `rare_dns_question_ea`) | Same class. The detector field `dns.question.name` *is* present (2,053 records), but the influencers `dns.question.type`, `dns.question.registered_domain` and `host.id` are all unmapped |
| **Network Traffic to Rare Destination Country**, **Spike in Network Traffic To a Country** (ML) | Both need `destination.geo.country_name`, and both datafeeds additionally filter on `exists: destination.geo.country_name`. The CEF feed enriches with `destination.geo.country_iso_code` (3,002 records) and never the name. Zero documents; the jobs would start and analyse nothing |
| **Threat Intel IP Address Indicator Match** | The source side is fine — 9,893 records carry `source.ip` or `destination.ip`. The indicator side is not: with no threat-intel integration installed there are no `logs-ti_*` or `filebeat-*` indices, and the rule reports `Unable to find matching threat indicator indices` on every run. **This one becomes viable the moment you run any TI integration**, and it is the single highest-value rule to revisit |
| **Threat Intel URL Indicator Match** | `url.full` is mapped but was never populated. It is set only on `unifi.speedtest`, where it describes the test server |
| **Threat Intel Hash / Email / Windows Registry Indicator Match**, **Rapid7 Threat Command CVEs Correlation** | `file.hash.*`, `process.hash.*`, `email.*.address`, `registry.path` and `vulnerability.id` have no mapping in `logs-*` at all. Nothing in a network syslog feed produces them |
| **Command Line Obfuscation via Whitespace Padding** (ES\|QL, `logs-*`) | Fails verification outright: `Unknown column [host.id]`, `Unknown column [process.parent.executable]`. The prefilter would have matched — 11,153 `unifi.sudo` records carry `event.category: process`, `event.type: start` and `process.command_line` — but relaxing the threshold from 100 consecutive spaces to 10 still returns zero |
| **Elastic Defend and Network Security Alerts Correlation** (ES\|QL, `logs-*`) | Requires `endpoint.alerts` on one side of the join |
| **My First Rule** | Elastic's own onboarding practice rule, and it groups by `host.name`, which is mapped but never populated here |
| **The other 100 ML rules** | Their anomaly detection jobs are not installed, and none of them is a network-appliance job. An ML rule whose job is missing does not warn, it **fails** every execution |
| **The remaining 1,953 rules** | Index patterns naming a specific integration — `logs-endpoint.events.*`, `logs-system.security*`, `logs-aws.cloudtrail-*`, `winlogbeat-*`, `endgame-*` and so on. No alias makes these correct to match |

### The near miss worth knowing about

One family is field-compatible and blocked purely by naming. The
port-activity rules — *RDP from the Internet*, *SMB Activity from the
Internet*, *RPC to the Internet*, *VNC*, *IPSEC NAT Traversal*,
*Accepted Default Telnet Port Connection* — accept
`event.category:(network or network_traffic)` as an alternative to a
dataset check, and they need only `source.ip`, `destination.ip`,
`destination.port` and `network.transport`, all of which the CEF
firewall records carry. They are invisible solely because their index
patterns name `logs-pfsense.log-*`, `logs-network_traffic.*` and
similar.

It is therefore tempting to name your alias after one of those
integrations. Do not bother, on this evidence: over 30 days the only
destination ports present in the whole dataset were 123, 443, 80, 1053,
22, 5222 and 5223. None of 135, 139, 445, 3389, 4500 or 5800–5810
appears, so the rules would match zero documents even with the data in
scope — and the deny-only caveat below would suppress most of them
regardless. This was checked against the underlying data, not by
actually renaming an alias and running the rules.

## Caveats that shape all of the above

**The SIEM export is deny-oriented.** UniFi logs a firewall policy only
when you tick logging on that policy, and the sensible thing to tick is
your block rules. In the reference deployment 100% of `unifi.firewall`
records over 30 days were denies, from a single policy. Every Elastic
rule phrased as "allowed traffic to a suspicious port" —
`event.type:(connection and not (denied or end))` and its variants —
will stay silent, and that silence means "not exported", not "did not
happen". Do not treat it as coverage.

**There is no host identity.** `host.id` has no mapping, and `host.name`
is mapped but never populated: the gateway identifies itself in
`observer.name`, and clients appear as `source.ip` / `source.mac`. This
is the second-biggest blocker after index patterns, because a large
share of Elastic's rules and nearly all of its ML jobs group, influence
or dedupe by host. If you want to change that, set it in your gateway
rather than here — a copy of `observer.name` into `host.name` is honest
for device-syslog datasets, and `unifi.dhcp` is the join key that maps a
MAC to a hostname if you want per-client identity, but neither is
something the collector can decide for you.

**`event.category: network` is on everything from the gateway**,
including plain systemd noise in `unifi.system`. Anything that counts
network events counts that too.

**Geo is ISO code only.** The CEF feed gives
`destination.geo.country_iso_code`. `destination.geo.country_name`,
`destination.as.organization.name` and the rest of the geo block are set
only on `unifi.speedtest`, and there they describe the speedtest server
rather than your traffic — see the note in
[`destinations.md`](destinations.md).

**Enabling a rule that cannot work is not harmless.** It does not sit
quiet: it reports `failed` or `partial failure` on every execution
interval, forever, and buries the rules that do work in a monitoring
page full of red. Check before you enable, and disable anything that
comes back with an unmapped-field warning.

## Checking this for yourself

The catalogue changes with every Elastic release, and your feeds are not
these feeds. Re-run the four bars rather than trusting the table:

```bash
# 1. which prebuilt rules can see the data at all
curl -s "$KIBANA_URL/api/detection_engine/rules/_find?per_page=100&page=1" \
  -H "kbn-xsrf: true" | jq -r '.data[] | select(.index // [] | any(. == "logs-*")) | .name'

# 2. do the fields resolve
curl -s "$ES/logs-*/_field_caps?fields=host.id,dns.question.type,destination.geo.country_name"

# 3. does the query match anything (30 days)
curl -s "$ES/logs-*/_search?size=0" -H "Content-Type: application/json" -d '{
  "query": {"bool": {"filter": [
    {"term": {"event.kind": "alert"}},
    {"range": {"@timestamp": {"gte": "now-30d"}}}
  ]}}}'

# 4. after enabling, read the execution summary back
curl -s "$KIBANA_URL/api/detection_engine/rules/_find?filter=alert.attributes.enabled:true" \
  -H "kbn-xsrf: true" \
  | jq -r '.data[] | "\(.name)\t\(.execution_summary.last_execution.status)"'
```

Bar 3 is the one people skip. A rule whose fields all resolve can still
match nothing for a structural reason — deny-only export, a port that
never appears, an enrichment the vendor does not do — and there is no
way to find that out except to run the query.

## What this does not prove

- **One project, one gateway, 13 days of data.** A rule listed as
  matching zero documents is a statement about this deployment, not a
  proof that it can never fire. The rejections grounded in a *missing
  mapping* are structural and will hold anywhere; the ones grounded in a
  *zero match count* may not.
- **No AP or switch frame has ever been seen by this project**
  ([#20](https://github.com/jamesagarside/unifi-otel/issues/20)), so
  none of this is informed by wireless-side data beyond what the CEF
  `unifi.client` dataset carries.
- **Prebuilt rules only.** Custom rules written directly against
  `unifi.*` fields are a different and much better-supported question —
  the schema is documented, and nothing here suggests the data is thin.
  It is the *catalogue* that does not fit, not the data.
- **The alias trick was verified for `logs-*` rules specifically.**
  Whether it is enough for every Kibana feature that consumes detection
  data — entity analytics, the alerts data view, prebuilt dashboards —
  was not tested.
