# unifi-otel Helm chart

A thin wrapper over the upstream
[`open-telemetry/opentelemetry-collector`](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-collector)
chart. It declares that chart as a dependency and supplies this project's
complete syslog/CEF pipeline through its `alternateConfig` value.

It ships **values, not manifests**. The only template in this chart is
`NOTES.txt`; the Deployment, Service, ConfigMap, ServiceAccount, probes,
`securityContext` and the config-hash annotation that rolls the pod when
the pipeline changes all come from upstream. Every value upstream exposes
stays reachable, so nobody has to adopt this project's deployment
opinions to use its parsing.

Full installation and configuration guide: **[`../docs/helm.md`](../docs/helm.md)**.

## Quick reference

```bash
helm dependency build chart/
helm install unifi-otel ./chart -n unifi-otel --create-namespace -f my-values.yaml
```

| | |
| --- | --- |
| Upstream chart | `opentelemetry-collector` 0.168.0 |
| Collector image | `otel/opentelemetry-collector-contrib:0.158.0` (pinned) |
| Mode | `deployment`, 1 replica |
| Listeners | udp/514 → containerPort 5514 (RFC3164), tcp/601 → containerPort 6601 (RFC5424) |
| Service | one Service, `ClusterIP` by default, both protocols on it |
| Exporter | `otlp_grpc/gateway`, endpoint from `OTLP_GATEWAY_ENDPOINT` |
| SNMP | off; enable with `-f chart/values-snmp.yaml` |

## Files

| File | Purpose |
| --- | --- |
| `values.yaml` | Chart defaults plus the default (logs-only) pipeline under `alternateConfig` |
| `values-snmp.yaml` | Optional overlay adding the SNMP receivers, metric processors and metrics pipeline |
| `templates/NOTES.txt` | Post-install summary; warns about unset `UNIFI_SYSLOG_TIMEZONE` and missing SNMP credentials |

## Relationship to `collector/`

`collector/*.yaml` is the annotated source of truth. On a host the
collector is started with one `--config` flag per file and merges them
itself; it has no glob or directory mode, so that flag list is the entire
configuration surface. The upstream chart mounts a single file, so the
same files are deep-merged into one `alternateConfig` map here.

The two are kept semantically identical. To check that yourself:

```bash
yq eval-all '. as $i ireduce ({}; . * $i)' \
  collector/10-receivers-logs.yaml \
  collector/20-processors-logs.yaml \
  collector/40-exporters.yaml \
  collector/90-service.yaml \
  | yq -o=json 'sort_keys(..)' > /tmp/from-collector.json

helm template chart/ \
  | yq 'select(.kind=="ConfigMap") | .data.relay' \
  | yq -o=json 'sort_keys(..)' > /tmp/from-chart.json

diff /tmp/from-collector.json /tmp/from-chart.json
```

Change `collector/*.yaml` first, then mirror it here.
