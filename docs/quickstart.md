# Quickstart (Docker Compose)

Fastest path from nothing to a parsed UniFi record. **No credentials of
any kind** — you do not create an API key, an SNMP user or a service
account. You enable syslog forwarding on the UniFi side and start a
container.

Kubernetes is not required. If you do want the Helm chart, this is still
the right place to start: prove the parsing works here first.

## Prerequisites

- Docker with Compose v2 (`docker compose version`)
- A UniFi gateway/console that can reach this host over the network
- This repository cloned locally (the collector config is bind-mounted
  from `./collector`, so you need the working tree, not just the image)

Binding the default host ports 514/601 needs a Docker daemon running as
root, which is the normal install. On **rootless Docker** you cannot bind
below 1024 — set `UNIFI_SYSLOG_UDP_PORT` / `UNIFI_SYSLOG_TCP_PORT` in
`.env` to something higher and use that port on the UniFi side.

## The three commands

```bash
cp .env.example .env
$EDITOR .env                          # set UNIFI_SYSLOG_TIMEZONE
docker compose up -d collector-debug  # parse, print to stdout, export nowhere
```

Then watch:

```bash
docker compose logs -f collector-debug
```

`collector-debug` is in a Compose profile. Naming it on the command line
enables that profile automatically, so you do not need `--profile debug`
— and you should not use `--profile debug`, because that starts *both*
services and they collide on the syslog ports.

`.env` is shipped with `UNIFI_SYSLOG_TIMEZONE` **empty on purpose**.
Compose refuses to start until you set it:

```
error while interpolating services.collector.environment.UNIFI_SYSLOG_TIMEZONE:
required variable UNIFI_SYSLOG_TIMEZONE is missing a value: set
UNIFI_SYSLOG_TIMEZONE in .env to the IANA timezone of your UniFi gateway...
```

That is the guard rail, not a bug. See [the timezone
trap](#the-timezone-trap) below for why it is worth a hard stop.

You do **not** need `OTLP_GATEWAY_ENDPOINT` for the debug profile. Leave
it empty until you have a backend.

## Point UniFi at it

Send syslog to **the Docker host's LAN address, UDP port 514**.

There are two separate feeds, and they are configured in two different
places:

| Feed | Gives you | Transport |
| --- | --- | --- |
| Remote syslog / syslog server | `unifi.dns`, `unifi.dhcp`, `unifi.sudo`, `unifi.system` — the gateway's own Linux logs | RFC3164 over UDP 514 |
| SIEM Server | `unifi.firewall`, `unifi.security`, `unifi.client`, `unifi.audit` — CEF events from UniFi Network itself | UDP 514, or RFC5424 over TCP 601 |

**On the menu paths: UniFi moves these between releases and I have not
verified them against every version, so treat the following as a
starting point rather than gospel.** Remote syslog has historically lived
under *UniFi Network → Settings → System*, in an *Advanced* or *Remote
Logging* section. The SIEM Server option is newer and sits under
*Settings → CyberSecure* (which is also where SNMP is, per
[`snmp.md`](snmp.md)). If neither is where this says, type "syslog" or
"SIEM" into the Settings search box — that is faster than following a
stale menu path, including this one.

Enabling only remote syslog is fine. You will get the four device
datasets and no CEF, which is still a working install.

## How to tell it is working

Records appear on stdout within a second or two of the gateway logging
something. A parsed record looks like this (real output, trimmed):

```
Timestamp: 2026-08-13 17:29:15 +0000 UTC
Body: Str(DHCPACK(br3) 192.168.30.44 aa:bb:cc:dd:ee:ff iot-plug)
Attributes:
     -> event.dataset: Str(unifi.dhcp)
     -> event.action: Str(dhcp_ack)
     -> source.mac: Str(aa:bb:cc:dd:ee:ff)
     -> source.ip: Str(192.168.30.44)
     -> source.domain: Str(iot-plug)
     -> observer.ingress.interface.name: Str(br3)
```

The single field to check is **`event.dataset`**. If it is present and
specific (`unifi.dhcp`, `unifi.dns`, `unifi.firewall`, …) the parser did
its job. Count what you are getting:

```bash
docker compose logs collector-debug | grep -o 'event.dataset: Str([^)]*)' | sort | uniq -c
```

Two things mean something is wrong:

- **`unifi.parse_failure` in the attributes** — the frame reached the
  collector but a parsing stage failed. The attribute names the stage,
  and `event.original` holds the raw frame.
- **Everything is `unifi.system`** — records are arriving but not
  matching any specific rule. Worth opening an issue with a redacted
  `event.original`.

Nothing at all on stdout means the frames are not arriving. Check the
health endpoint first (`curl -sf http://127.0.0.1:13133` → `{"status":
"Server available", ...}`), then the host firewall, then that UniFi is
pointed at the right address and port.

To rule out the network entirely, replay a frame locally with Python:

```python
import socket
f = b'<134>Aug 13 09:14:02 Gateway Gateway dnsmasq-dhcp[2185]: ' \
    b'DHCPACK(br3) 192.168.30.44 aa:bb:cc:dd:ee:ff iot-plug'
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(f, ('127.0.0.1', 514))
```

Use Python, not `nc`. macOS `nc` truncates UDP datagrams at around 1024
bytes, and a truncated CEF frame looks exactly like a parse failure.

Note the **doubled hostname** (`Gateway Gateway`) in that frame — the UDM
really does emit it, and the parser is built around it. If you hand-write
test frames without it you are not testing the real path.

## The timezone trap

**This is the one that will get you.** It fails silently and everything
else about the record looks perfect.

The gateway stamps RFC3164 syslog in **local time with no offset**. The
receiver cannot infer the offset, so it is told, via
`UNIFI_SYSLOG_TIMEZONE`. If that is empty the receiver falls back to UTC
without logging anything at all.

CEF records are immune — they are re-stamped from the CEF `UNIFIutcTime`
field, which is genuine UTC. `unifi.dns` is immune too, for the same
reason (the coredns payload carries epoch milliseconds). So the damage is
confined to `unifi.dhcp`, `unifi.sudo` and `unifi.system`, which is
precisely why it goes unnoticed: your firewall dashboard is fine.

### Detection recipe

Two ways, easiest first.

**1. Compare datasets against each other.** Send or wait for a mixed
batch and line up the timestamps. With a BST (UTC+1) gateway and the
timezone set wrong, real output looked like:

```
unifi.firewall   Timestamp: 2026-08-13 17:30:16.09 +0000 UTC   <- CEF, correct
unifi.security   Timestamp: 2026-08-13 17:30:16.09 +0000 UTC   <- CEF, correct
unifi.dns        Timestamp: 2026-08-13 17:30:16.09 +0000 UTC   <- epoch ms, correct
unifi.dhcp       Timestamp: 2026-08-13 18:30:16    +0000 UTC   <- one hour out
unifi.sudo       Timestamp: 2026-08-13 18:30:16    +0000 UTC   <- one hour out
unifi.system     Timestamp: 2026-08-13 18:30:16    +0000 UTC   <- one hour out
```

A whole-hour gap between the CEF datasets and the device datasets in the
same batch means the timezone is wrong. With it set correctly, all six
agree.

**2. Compare against the wall clock.** Take a `unifi.dhcp` or
`unifi.system` record and compare its timestamp to the gateway's own
clock at the moment it was logged. A whole number of hours out — often
into the *future*, as above — means the timezone is wrong. Minutes or
seconds out is just clock skew and is not this.

Fix by setting `UNIFI_SYSLOG_TIMEZONE` to the gateway's IANA zone
(`Europe/London`, `America/New_York`, …), then
`docker compose up -d --force-recreate collector-debug`. Match the
**gateway's** timezone, not the Docker host's, if the two differ. Records
already ingested are not corrected retroactively.

## Moving to a real backend

The debug profile prints and exports nowhere. When you have somewhere to
send records:

```bash
docker compose down                     # free the syslog ports
$EDITOR .env                            # set OTLP_GATEWAY_ENDPOINT
docker compose up -d                    # the export path
```

`OTLP_GATEWAY_ENDPOINT` is `host:port` of anything speaking OTLP/gRPC.
See [`destinations.md`](destinations.md) for what to put at the far end.

If you leave it empty, the collector refuses to start rather than
pretending to work:

```
info  Configuration references empty environment variable  {"name": "OTLP_GATEWAY_ENDPOINT"}
Error: invalid configuration: exporters::otlp_grpc/gateway: requires a non-empty "endpoint"
```

That is deliberate. The config's built-in default is a Kubernetes
in-cluster DNS name (`otel-gateway.observability.svc.cluster.local`)
which cannot resolve under Compose, and a container that looks healthy
while dropping everything is a much worse outcome than one that will not
start. Because `restart: unless-stopped` is set, a missing endpoint shows
up as a container in `restarting` — read the logs, do not chase the
restart loop.

The export path does not print records. To confirm it is alive: the
health endpoint returns 200, and the container log stays quiet — the OTLP
exporter is loud about failures, so no news is good news. If you want to
see records *and* export them, run the debug profile alongside a backend
of your own rather than trying to run both services at once.

## SNMP is opt-in

There is no SNMP in this quickstart and none in `docker-compose.yml`. It
is a separate module that polls the console over SNMPv3, needs
credentials, and covers the console only — not adopted APs or switches.

If you want it, read [`snmp.md`](snmp.md); it means appending three more
`--config` flags to the `command:` list in `docker-compose.yml` and
adding two variables to `.env`.

## Reference

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `UNIFI_SYSLOG_TIMEZONE` | **yes, both services** | none — Compose stops | IANA timezone of the gateway |
| `OTLP_GATEWAY_ENDPOINT` | export path only | none — collector stops | `host:port` of your OTLP/gRPC receiver |
| `UNIFI_SYSLOG_UDP_PORT` | no | `514` | Host port published onto container `5514/udp` |
| `UNIFI_SYSLOG_TCP_PORT` | no | `601` | Host port published onto container `6601/tcp` |
| `UNIFI_HEALTH_PORT` | no | `13133` | Health endpoint, bound to `127.0.0.1` only |

The receivers bind unprivileged ports (5514, 6601) inside the container
so it can run as non-root; the standard 514/601 are put back on by the
Compose port publish. That mapping is the only reason the numbers differ.

The collector has **no glob or directory mode**. The `--config` flags in
`docker-compose.yml` are the entire configuration surface — a file under
`collector/` that is not listed there is silently ignored, not an error.
