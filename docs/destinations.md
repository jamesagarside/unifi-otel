# Destinations

This collector has exactly one exporter:

```yaml
otlp_grpc/gateway:
  endpoint: ${env:OTLP_GATEWAY_ENDPOINT:-otel-gateway.observability.svc.cluster.local:4317}
  tls:
    insecure: true
```

Every pipeline ends there — the parsed syslog export, the parse-failure
branch (which additionally prints to a `debug` exporter), and the SNMP
metrics pipeline. `otlp_grpc` rather than the bare `otlp` alias, which is
deprecated as of collector 0.157.0 and warns on every start. TLS is
disabled by default because the common deployment is a gateway on the same
private network; set your own `tls` block if that is not true for you.

There is deliberately no backend-specific index, data stream or routing
configuration anywhere in `collector/`. Where a record lands is a property
of your gateway or backend, not of the parsing, and baking one vendor's
routing into the shared config would make everyone else's install a
fork. So destinations are **documentation, not shipped config**: your job
is to point `OTLP_GATEWAY_ENDPOINT` at something that speaks OTLP.

## What the snippets below configure

**Not this collector.** Each snippet configures a *gateway collector* you
run yourself — the thing at the far end of `OTLP_GATEWAY_ENDPOINT` — or,
where the backend terminates OTLP itself, it shows the endpoint you point
at directly and no gateway is involved. Nothing in this repository changes
per destination.

Each snippet is a complete, self-contained gateway config: an `otlp`
receiver on 4317, one exporter, one logs pipeline. Add a `batch` processor,
retries, queueing and your own TLS to taste — those are gateway concerns
and are left out so the destination-specific part is visible.

## What is on the wire

Records arrive as OTLP log records with ECS-shaped attribute names:
`event.dataset`, `event.kind`, `event.category`, `event.action`,
`source.ip`, `destination.ip`, `rule.name`, `observer.*`, `related.*`, plus
vendor fields under `unifi.*`. Both `source.ip` and `source.address` are
emitted: the ECS ↔ OTel alignment table marks them equivalent, there is no
alias mechanism in a log record, and consumers exist for both spellings.

`event.dataset` is one of `unifi.firewall`, `unifi.security`,
`unifi.client`, `unifi.audit`, `unifi.network`, `unifi.dns`, `unifi.dhcp`,
`unifi.sudo`, `unifi.speedtest`, `unifi.system`. Records that failed a
parsing stage carry `unifi.parse_failure` naming the stage; route or filter
on that attribute downstream if you want them separated. Resource
attributes are `service.name: unifi-udm` and
`observed.source: unifi-otel`.

**One attribute is not a scalar.** Every attribute this collector emits is
a string, a number or a slice of strings, with a single exception:
`destination.geo.location`, set only on `unifi.speedtest` records, is a map
of `lat` and `lon`. It is emitted that way because that is the shape
Elasticsearch reads as a `geo_point`. What another backend makes of a
nested map attribute has not been tested against any of the destinations
below — the likely outcome is that it flattens to
`destination.geo.location.lat` and `.lon`, which loses the geo type but no
data. If your backend rejects the record outright rather than flattening
it, that is worth an issue; dropping the attribute in your gateway is the
workaround in the meantime.

Those geo fields, and `destination.as.organization.name` alongside them,
describe the **speedtest server** rather than your own network. That is why
they sit under `destination.*`. It is also not as anonymous as it sounds —
speedtests pick nearby servers — so treat a `unifi.speedtest` record as
carrying a coarse location fix when you decide where it may be stored.

## Verification status

One person runs one of these in production. Everything else below is
written from the exporters' own documentation and validated as config, not
observed working end to end.

| Destination           | Status                                      |
| --------------------- | ------------------------------------------- |
| ClickHouse            | Unverified — no production mileage          |
| Datadog               | Unverified — no production mileage          |
| Elasticsearch         | Verified — maintainer runs this in anger    |
| Generic OTLP backend  | Unverified — no production mileage          |
| Grafana Loki          | Unverified — no production mileage          |
| Splunk                | Unverified — no production mileage          |

"Unverified" is not a warning about quality, it is a statement about
evidence. If you run one, a correction or a confirmation is the single most
useful contribution you can make to this file.

## The destinations

Listed alphabetically. The ordering carries no recommendation, and no
destination gets more prose than any other — that symmetry is deliberate
and is checked before release.

### ClickHouse

*Unverified — no production mileage.*

ClickHouse speaks no OTLP, so a gateway collector with the `clickhouse`
exporter is required. It creates its own schema on first run and writes log
records into an `otel_logs` table, batching inside the exporter rather than
through a `batch` processor.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  clickhouse:
    endpoint: tcp://clickhouse.example.net:9000?dial_timeout=10s
    database: otel
    logs_table_name: otel_logs
    ttl: 720h
    sending_queue:
      batch:
        min_size: 5000
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [clickhouse]
```

Schema: agnostic. Attributes become keys in a map column, so the ECS
spellings survive verbatim and are queried as `LogAttributes['event.dataset']`.

### Datadog

*Unverified — no production mileage.*

Datadog accepts OTLP through the Datadog Agent's own OTLP ingest, in which
case point `OTLP_GATEWAY_ENDPOINT` at the Agent and stop reading. Otherwise
run a gateway collector with the `datadog` exporter, which posts to the
intake API for your site.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  datadog:
    api:
      key: ${env:DD_API_KEY}
      site: datadoghq.eu
    sending_queue:
      batch:
        min_size: 10
        max_size: 100
        flush_timeout: 10s
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [datadog]
```

Schema: opinionated. Datadog's standard attributes (`network.client.ip`,
`usr.name`) are not ECS names, so remap in a Datadog log pipeline.

### Elasticsearch

*Verified — this is the destination the maintainer runs in production.*

Elasticsearch speaks no OTLP, so a gateway collector with the
`elasticsearch` exporter is required — either the contrib exporter as
below, or a distribution that bundles it. The gateway holds the
credentials; this collector never sees the cluster.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  elasticsearch:
    endpoints: [https://elasticsearch.example.net:9200]
    api_key: ${env:ES_API_KEY}
    mapping:
      mode: otel
    sending_queue:
      batch:
        flush_timeout: 10s
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [elasticsearch]
```

Schema: ECS-aware, but in `otel` mapping mode attributes are stored under
`attributes.*` and routing keys off `data_stream.dataset`, not `event.dataset`.

If you are running Elastic Security rather than plain Elasticsearch,
[`elastic-detection-rules.md`](elastic-detection-rules.md) covers which
prebuilt detection rules this data populates, which ones cannot fire and
what each is missing, and the index naming that has to be right before
any of them see the records at all.

### Generic OTLP backend

*Unverified — no production mileage.*

Anything that terminates OTLP — an OTLP-native SaaS, another collector, a
self-hosted receiver — needs no gateway at all if it accepts gRPC: set
`OTLP_GATEWAY_ENDPOINT` to it and add TLS. The snippet below is the gateway
case, where the backend wants HTTP or a header.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  otlphttp/backend:
    endpoint: https://otlp.example.net
    compression: gzip
    headers:
      authorization: ${env:OTLP_API_TOKEN}
    sending_queue:
      batch:
        flush_timeout: 5s
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlphttp/backend]
```

Schema: whatever the backend makes of dotted attribute names is its own
business — nothing in this path rewrites, drops or flattens them.

### Grafana Loki

*Unverified — no production mileage.*

Loki 3.x ingests OTLP natively on `/otlp` of its HTTP port, and Grafana
Cloud exposes the same path. A gateway is still needed in practice because
that endpoint is OTLP/HTTP while this collector exports gRPC; the
standalone `loki` exporter was deprecated and removed, so use `otlphttp`.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  otlphttp/loki:
    endpoint: http://loki.example.net:3100/otlp
    compression: gzip
    headers:
      X-Scope-OrgID: unifi
    sending_queue:
      batch:
        flush_timeout: 5s
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlphttp/loki]
```

Schema: agnostic but split. Resource attributes become index labels and log
attributes become structured metadata — queryable, not indexed.

### Splunk

*Unverified — no production mileage.*

Splunk Enterprise and Splunk Cloud take HEC rather than OTLP, so a gateway
collector with the `splunk_hec` exporter is required. Splunk Observability
Cloud is the exception and terminates OTLP directly, in which case point
`OTLP_GATEWAY_ENDPOINT` at its ingest endpoint instead.

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  splunk_hec:
    token: ${env:SPLUNK_HEC_TOKEN}
    endpoint: https://splunk.example.net:8088/services/collector
    index: netops
    source: unifi
    sourcetype: unifi:otel
    max_content_length_logs: 2097152
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [splunk_hec]
```

Schema: CIM, not ECS. Fields arrive under their ECS names and need aliases;
per-record sourcetype comes from `com.splunk.sourcetype`, not `event.dataset`.

## Snippet provenance and version drift

Every snippet above was checked with `otelcol validate` against
`otel/opentelemetry-collector-contrib:0.158.0` and reported no error. That
proves the keys exist and parse at that version; it does not prove data
arrives, which is what the verification table is about.

Exporter configuration drifts, sometimes faster than documentation. Three
current examples, none of which affect the snippets above but all of which
will bite anyone copying older recipes:

- The core OTLP gRPC exporter is `otlp_grpc`; the `otlp` alias is deprecated.
- The `loki` exporter was deprecated and removed from collector-contrib in
  favour of `otlphttp` against Loki's own OTLP endpoint.
- On the Elasticsearch exporter, `logs_dynamic_index::enabled` is now a
  no-op (documents route dynamically unless `logs_index` is set), and
  `mapping::mode` is deprecated on `main` in favour of the
  `elastic.mapping.mode` scope attribute — it still works at 0.158.0.

If you are pinned to a different collector version, check the exporter's
README for that tag rather than trusting this page.

## A future `destinations/` directory

This page is documentation and will stay small. The plan is a
`destinations/` directory of contributor-owned snippets, one file per
backend, on the same terms as the test fixtures in #13:

- Every file carries an attribution line naming who contributed it and what
  they actually ran it against, including backend version.
- Every file is marked verified or unverified, honestly. Unverified is an
  acceptable state for a merged file; a false claim of verification is not.
- Every file must pass `otelcol validate` in CI (#10). A snippet that does
  not parse is not documentation, it is a bug report.
- No file gets special prominence for being the maintainer's backend, and
  the equal-weighting rule in this page applies there too.

Corrections to the unverified entries above are welcome as issues or pull
requests, and are more valuable than new destinations nobody has run.
