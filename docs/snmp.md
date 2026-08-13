# SNMP polling (optional, off by default)

This project ships SNMP polling as an **opt-in module**. The default
config set is logs only: it starts with no SNMP receiver, no metrics
pipeline, and needs no credentials of any kind.

Turning SNMP on is purely additive — you append three `--config` flags to
the ones you already pass. Nothing in the default set changes.

## What it adds

Polled from the UniFi console over SNMPv3, shaped to the OpenTelemetry
system-metrics semantic conventions:

| Metric | Source | Poll |
| --- | --- | --- |
| `system.network.io` | IF-MIB 64-bit octet counters, per interface, `network.io.direction` receive/transmit | 60s |
| `unifi.interface.operational.status` | IF-MIB `ifOperStatus` (1 up, 2 down, 3 testing) | 60s |
| `system.cpu.time` | UCD raw tick counters, `cpu.mode` user/system/idle/iowait, converted to seconds and to delta temporality | 60s |
| `system.cpu.load_average.{1m,5m,15m}` | UCD `laLoadInt`, descaled | 60s |
| `system.memory.limit`, `system.memory.usage` | UCD `memTotalReal` / `memAvailReal`, KiB converted to bytes | 60s |
| `system.memory.utilization` | derived (see the caveat in `collector/optional/snmp/30-processors-metrics.yaml` — UCD has no `memAvailable`, so page cache counts as used) | 60s |
| `system.uptime` | `sysUpTime`, TimeTicks converted to seconds | 60s |
| `system.network.errors`, `system.network.packet.dropped` | IF-MIB error and discard counters | 300s |

`snmpreceiver` has no MIB support, so every OID is hand-mapped in
`collector/optional/snmp/15-receivers-snmp.yaml`. The comments in that
file record what was verified against a real device and why each choice
was made; read them before changing anything.

## What it does not add

**SNMP reaches the console and nothing else.** Adopted access points and
switches serve no SNMP agent of their own, so there are no per-AP or
per-port counters for them — no matter how the collector is configured.
In an estate of a gateway plus a dozen adopted devices, this covers
exactly one device. That is a UniFi limitation, not a gap in this config.

If you want per-device visibility across the estate, this module is not
the mechanism.

## Opt in

Append these three flags to whatever `--config` flags you already pass:

```
--config=/conf/optional/snmp/15-receivers-snmp.yaml
--config=/conf/optional/snmp/30-processors-metrics.yaml
--config=/conf/optional/snmp/91-service-metrics.yaml
```

Order matters only in that `91-service-metrics.yaml` must come after
`90-service.yaml`. The full set then reads:

```
--config=/conf/10-receivers-logs.yaml
--config=/conf/20-processors-logs.yaml
--config=/conf/40-exporters.yaml
--config=/conf/90-service.yaml
--config=/conf/optional/snmp/15-receivers-snmp.yaml
--config=/conf/optional/snmp/30-processors-metrics.yaml
--config=/conf/optional/snmp/91-service-metrics.yaml
```

The collector deep-merges repeated `--config` files, including the same
top-level key split across files, so `91-service-metrics.yaml` adds a
`metrics/unifi_snmp` pipeline to the `service.pipelines` block defined in
`90-service.yaml` without restating any log pipeline.

The module reuses `memory_limiter`, `resource/unifi` and `batch` from the
default set's `20-processors-logs.yaml`. It is an addition to the default
flags, never a replacement for them.

> The collector has **no glob or directory mode** — `--config='/conf/*.yaml'`
> fails outright, and a file you simply do not list is silently ignored
> rather than an error. The list of `--config` flags is therefore the
> entire configuration surface. If SNMP metrics do not appear, the first
> thing to check is that all three flags are actually present on the
> command line.

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `UNIFI_HOST` | recommended | `192.0.2.1` | Console address; polled as `udp://$UNIFI_HOST:161` |
| `UNIFI_SNMP_USER` | yes | — | SNMPv3 username |
| `UNIFI_SNMP_PASSWORD` | yes | — | SNMPv3 password, used for **both** auth and privacy (see below) |

`UNIFI_SNMP_USER` and `UNIFI_SNMP_PASSWORD` have no defaults on purpose:
with the SNMP flags passed and those variables unset, the collector fails
config validation rather than starting up and quietly polling nothing.

The `UNIFI_HOST` default is `192.0.2.1` (TEST-NET-1, guaranteed
unroutable). If you opt in without setting it, polling goes nowhere.

## UniFi-side setup

SNMP is disabled on the console by default. Enable it at:

**UniFi Network → Settings → CyberSecure → Traffic Logging → SNMP**

Create an **SNMPv3** user there. The module is configured for
`security_level: auth_priv` with `SHA` authentication and `AES` privacy,
which is what the UniFi form produces.

### The single-password quirk

UniFi's SNMPv3 form offers **one** password field, not two. SNMPv3 itself
has two secrets — the authentication key and the privacy (encryption)
key — and UniFi derives both from that single field.

This is why the receiver config reads the same environment variable
twice:

```yaml
auth_password: ${env:UNIFI_SNMP_PASSWORD}
privacy_password: ${env:UNIFI_SNMP_PASSWORD}
```

That is not a copy-paste mistake, and splitting it into two variables
would break against a UniFi console. If you point this at some other
SNMPv3 agent that does have distinct keys, change those two lines.

## Verifying

Config-level check (exit 0 means every referenced component exists and
parses):

```bash
docker run --rm \
  -e UNIFI_SNMP_USER=x -e UNIFI_SNMP_PASSWORD=y \
  -v "$PWD/collector":/conf:ro \
  otel/opentelemetry-collector-contrib:0.157.0 validate \
  --config=/conf/10-receivers-logs.yaml \
  --config=/conf/20-processors-logs.yaml \
  --config=/conf/40-exporters.yaml \
  --config=/conf/90-service.yaml \
  --config=/conf/optional/snmp/15-receivers-snmp.yaml \
  --config=/conf/optional/snmp/30-processors-metrics.yaml \
  --config=/conf/optional/snmp/91-service-metrics.yaml
```

Device-level check, before blaming the collector — confirm the console
answers at all:

```bash
snmpwalk -v3 -l authPriv -a SHA -x AES \
  -u "$UNIFI_SNMP_USER" -A "$UNIFI_SNMP_PASSWORD" -X "$UNIFI_SNMP_PASSWORD" \
  "$UNIFI_HOST" 1.3.6.1.2.1.1.5.0
```

Note `-A` and `-X` taking the same value, for the same reason as above.

## SNMP is not covered by CI

The test approach for this project is replaying captured frames into a
container and asserting on what comes out. That works for syslog, which
is push-based, and it cannot work for SNMP: the collector polls
**outward** to a live device on a schedule, so there is no frame to
replay and nothing to assert against without a real UDM on the network.

So CI proves the SNMP config *parses and builds* — it never proves the
OIDs still return what the comments say they return. Treat the metric
table above as verified-at-the-time (against a UDM-SE, UniFi OS 5.x)
rather than continuously verified. This is one of the reasons the module
is off by default: the quickstart's most likely failure mode should not
be the one thing CI cannot check.
