# Deploying on Kubernetes with Helm

The chart in `chart/` is a **thin wrapper** over the upstream
[`opentelemetry-collector`](https://github.com/open-telemetry/opentelemetry-helm-charts/tree/main/charts/opentelemetry-collector)
chart. It declares that chart as a dependency and supplies this project's
complete pipeline through its `alternateConfig` value.

It ships **values, not manifests**. The Deployment, Service, ConfigMap,
ServiceAccount, probes, `securityContext` and the config-hash annotation
that rolls the pod when the pipeline changes all come from upstream.
Reimplementing those would force you to adopt this project's deployment
opinions in order to use its parsing; instead every knob upstream exposes
stays reachable from your own values file.

| | |
| --- | --- |
| Upstream chart | `opentelemetry-collector` 0.168.0 |
| Collector image | `otel/opentelemetry-collector-contrib:0.158.0` (pinned) |
| Mode | `deployment`, 1 replica |
| Listeners | udp/514 → containerPort 5514 (RFC3164), tcp/601 → containerPort 6601 (RFC5424) |
| Exporter | `otlp_grpc/gateway` → `OTLP_GATEWAY_ENDPOINT` |
| SNMP | off by default |

## Install

The chart is not published to a chart repository yet, so install from a
checkout:

```bash
git clone https://github.com/jamesagarside/unifi-otel
cd unifi-otel

# pulls the upstream collector chart named in chart/Chart.lock
helm dependency build chart/

helm install unifi-otel ./chart \
  --namespace unifi-otel --create-namespace \
  -f my-values.yaml
```

`helm dependency build` reads the committed `Chart.lock` and pulls exactly
the version pinned there. `helm dependency update` re-resolves the version
range and rewrites the lock; use `build` unless you mean to bump.

Upgrades are ordinary:

```bash
helm upgrade unifi-otel ./chart -n unifi-otel -f my-values.yaml
```

The upstream chart puts a checksum of the rendered config in the pod
template annotations, so any change to the pipeline rolls the Deployment
on its own — no manual restart, and no risk of a ConfigMap change sitting
unapplied in a running pod.

## What you must set

Everything goes under the `opentelemetry-collector` key, because that is
the name of the dependency:

```yaml
opentelemetry-collector:
  extraEnvs:
    - name: OTLP_GATEWAY_ENDPOINT
      value: "otel-gateway.observability.svc.cluster.local:4317"
    - name: UNIFI_SYSLOG_TIMEZONE
      value: "Europe/London"
```

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `OTLP_GATEWAY_ENDPOINT` | yes in practice | `otel-gateway.observability.svc.cluster.local:4317` | Where records are exported, over OTLP/gRPC |
| `UNIFI_SYSLOG_TIMEZONE` | yes in practice | `Etc/UTC` | Timezone of the UniFi console |

Both have defaults inside the pipeline, so neither will stop the collector
starting — which is exactly why they need attention:

- **`OTLP_GATEWAY_ENDPOINT`** defaults to a name that almost certainly
  does not resolve in your cluster. That failure is at least loud: the
  exporter logs connection errors.
- **`UNIFI_SYSLOG_TIMEZONE`** fails **silently**. The console stamps
  RFC3164 syslog in local time with no offset, so if this does not match
  the console's timezone every non-CEF record lands a whole number of
  hours out, with no error anywhere. CEF records are re-stamped from
  `UNIFIutcTime` and are unaffected, which makes the discrepancy easy to
  miss. To check: compare a `unifi.system` record's timestamp against the
  wall clock on the console.

`extraEnvs` is a **list**, so whatever you supply replaces the chart
default wholesale rather than merging into it. Restate both entries in
your own file. `NOTES.txt` warns after install if `UNIFI_SYSLOG_TIMEZONE`
is missing from the list.

## Reaching the collector from the console

By default the Service is `ClusterIP`, which nothing outside the cluster
can reach. A UniFi console sends syslog to a fixed address you type into
its UI, so in practice this wants a `LoadBalancer` with a pinned address:

```yaml
opentelemetry-collector:
  service:
    type: LoadBalancer
    loadBalancerIP: 198.51.100.10
    annotations:
      # whatever your load balancer expects, if anything
      example.io/address-pool: unifi
```

**The chart names no load balancer, ingress controller or cloud
provider.** `service.annotations` is a free-form map and `loadBalancerIP`
and `type` are plain values, so an address pool annotation, a
provider-specific IP-allocation key, an `externalTrafficPolicy`, a
`NodePort` instead — all of it is yours to supply and none of it is baked
in. Anything the upstream chart's `service` block accepts works here.

`externalTrafficPolicy: Local` is worth considering if you want the
console's own address preserved as the syslog peer; it is an upstream
value, set it alongside the others.

### One Service, not two

Both listeners are ports on a **single** Service, and it is worth knowing
why before you split them.

The upstream chart renders one Service and sets `protocol` per port — its
own defaults already mix UDP (`jaeger-compact`) and TCP in one object, so
this is not something the wrapper had to work around. This chart disables
all of upstream's default ports and adds two:

| Service port | Container port | Protocol | Receiver |
| --- | --- | --- | --- |
| 514 | 5514 | UDP | `syslog/unifi_udp`, RFC3164 |
| 601 | 6601 | TCP | `syslog/unifi_tcp`, RFC5424 |

Splitting those across two Services so each could have its own address is
a trap on any cluster where the load balancer claims addresses by **L2
announcement**. Announcement is leased per Service, and two leases for
what the sender treats as one syslog target can be granted to different
nodes; each node then answers ARP for its own address. UDP tolerates the
resulting churn — a lost datagram is a lost record and the next one goes
somewhere that works. A long-lived syslog TCP connection does not: it is
pinned to whichever node answered when it was established, and it breaks
when that changes. One Service, one lease, one node answering.

### Privileged ports

`containerPort` and `servicePort` are separate values upstream, so the
receivers bind unprivileged **5514** and **6601** inside the container and
the Service maps the standard 514 and 601 onto them. The pod needs no
`NET_BIND_SERVICE` capability, no `sysctl` and no init container, and can
run as a non-root user.

The chart leaves `podSecurityContext` and `securityContext` at the
upstream defaults deliberately — harden them from your own values file to
whatever your cluster's policy requires rather than inheriting this
project's opinion.

## Resources

The pipeline's `memory_limiter` is configured with `limit_percentage`, so
it measures itself against the container's memory **limit**. The chart
therefore sets one:

```yaml
opentelemetry-collector:
  resources:
    limits:
      memory: 512Mi
```

If you remove that limit, `memory_limiter` measures against total host
memory instead and protects nothing. Raise or lower it, but do not delete
it. The upstream chart derives `GOMEMLIMIT` from the same value.

## Enabling SNMP

SNMP polling is off by default, exactly as it is off in the `--config`
flag list. Read [`snmp.md`](snmp.md) first — it reaches the console only,
not adopted APs or switches, and it is not covered by CI.

Turn it on with the overlay values file:

```bash
helm install unifi-otel ./chart \
  --namespace unifi-otel --create-namespace \
  -f chart/values-snmp.yaml \
  -f my-values.yaml
```

Pass it **before** your own file. Helm merges `-f` files left to right
with later files winning, and lists replace rather than merge, so your
`extraEnvs` must come last.

The overlay only adds map keys under `alternateConfig` — new entries in
`receivers`, `processors` and `service.pipelines`. Nothing already there
is touched, which is the same additive relationship the three extra
`--config` flags have to the default four on a host.

### SNMP credentials

`UNIFI_SNMP_USER` and `UNIFI_SNMP_PASSWORD` have **no defaults**, on
purpose: with SNMP enabled and those variables unset the collector fails
config validation and crash-loops rather than starting up and quietly
polling nothing. `NOTES.txt` warns about this at install time.

Supply them from a Secret you already manage, not as plaintext Helm
values. The upstream chart's `extraEnvsFrom` takes `envFrom` sources, and
it is a **separate list** from `extraEnvs`, so using it does not disturb
the two log variables:

```bash
kubectl -n unifi-otel create secret generic unifi-snmp \
  --from-literal=UNIFI_SNMP_USER='otel' \
  --from-literal=UNIFI_SNMP_PASSWORD='...'
```

```yaml
opentelemetry-collector:
  extraEnvs:
    - name: OTLP_GATEWAY_ENDPOINT
      value: "otel-gateway.observability.svc.cluster.local:4317"
    - name: UNIFI_SYSLOG_TIMEZONE
      value: "Europe/London"
    - name: UNIFI_HOST
      value: "198.51.100.1"   # the console to poll; not a secret
  extraEnvsFrom:
    - secretRef:
        name: unifi-snmp
```

The Secret's **keys must be named** `UNIFI_SNMP_USER` and
`UNIFI_SNMP_PASSWORD`, because `envFrom` uses the key as the variable
name. If you are stuck with a Secret whose keys are named otherwise —
one synced by an external secrets operator, say — use `extraEnvs` with
`valueFrom` instead and remap them there:

```yaml
opentelemetry-collector:
  extraEnvs:
    - name: OTLP_GATEWAY_ENDPOINT
      value: "otel-gateway.observability.svc.cluster.local:4317"
    - name: UNIFI_SYSLOG_TIMEZONE
      value: "Europe/London"
    - name: UNIFI_HOST
      value: "198.51.100.1"
    - name: UNIFI_SNMP_USER
      valueFrom:
        secretKeyRef:
          name: unifi-snmp
          key: username
    - name: UNIFI_SNMP_PASSWORD
      valueFrom:
        secretKeyRef:
          name: unifi-snmp
          key: password
```

UniFi's SNMPv3 form has a single password field and derives both the
authentication and the privacy key from it, which is why the pipeline
reads `UNIFI_SNMP_PASSWORD` twice. That is not a copy-paste mistake — see
[`snmp.md`](snmp.md).

`UNIFI_HOST` defaults to `192.0.2.1` (TEST-NET-1, guaranteed unroutable),
so polling goes nowhere until you set it.

## YAML anchors

`collector/optional/snmp/15-receivers-snmp.yaml` leans on YAML anchors
heavily — the slow receiver aliases nine values from the fast one. Anchors
do **not** cross `--config` files, which is why every anchor in this
project is defined and consumed inside a single file.

That constraint carries over to the chart, in one direction only. Merging
the files into a single `alternateConfig` map is safe, because an anchor
whose definition and use were already in the same file still resolves.
The reverse is not: **do not add an alias in `chart/values-snmp.yaml` to
an anchor defined in `chart/values.yaml`.** A values file is one YAML
document, resolved before Helm merges anything, so an alias across files
fails to resolve here — and even if it did, it would break the host
deployment where the same content is split across `--config` flags.

Helm resolves anchors when it parses the values files and emits the
expansion, so the rendered ConfigMap contains the expanded content rather
than anchors and aliases. That is the same document the collector would
have built from the individual files.

## Verifying a render

`helm lint` and `helm template` prove the chart produces valid Kubernetes
YAML. They prove nothing about whether the collector config *inside* the
ConfigMap is valid — a chart that renders a perfectly well-formed
ConfigMap containing a broken pipeline is the failure worth catching. Run
the config through the collector binary:

```bash
helm template chart/ \
  | yq 'select(.kind=="ConfigMap") | .data.relay' > /tmp/conf/relay.yaml

docker run --rm -v /tmp/conf:/conf:ro \
  otel/opentelemetry-collector-contrib:0.158.0 validate --config=/conf/relay.yaml
```

Exit 0 means every referenced component exists, every pipeline resolves
and every component's own config unmarshals. With SNMP enabled the same
command needs credentials in the environment, or it will (correctly) fail:

```bash
helm template chart/ -f chart/values-snmp.yaml \
  | yq 'select(.kind=="ConfigMap") | .data.relay' > /tmp/conf/relay-snmp.yaml

docker run --rm \
  -e UNIFI_SNMP_USER=x -e UNIFI_SNMP_PASSWORD=y \
  -v /tmp/conf:/conf:ro \
  otel/opentelemetry-collector-contrib:0.158.0 validate --config=/conf/relay-snmp.yaml
```

To confirm the chart has not drifted from `collector/*.yaml`, diff the
rendered config against the merge of the source files — see
[`../chart/README.md`](../chart/README.md).

## Keeping the chart and `collector/` in step

`collector/*.yaml` is the annotated source of truth: every design
decision, every "verified by replay" note and every warning about what
breaks if you change a line lives there. `chart/values.yaml` is the same
configuration with the essays stripped, so the rationale exists in one
place and cannot drift between two copies.

The configuration itself does have to be mirrored. Change
`collector/*.yaml` first, mirror it into `chart/values.yaml` (or
`chart/values-snmp.yaml`), then run the diff above. This is the one
maintenance cost of the wrapper approach, and it is the price of the
upstream chart mounting a single config file where the host deployment
passes several.

## Troubleshooting

**Nothing arrives.** Check the Service actually has an external address
and that the console is pointed at it. `kubectl -n unifi-otel get svc`.
Note UDP: a syslog sender gets no feedback whatsoever when datagrams go
nowhere, so the console showing no error means nothing.

**Records arrive but timestamps are hours out.** `UNIFI_SYSLOG_TIMEZONE`.
See above.

**Records arrive tagged `unifi.parse_failure`.** They are exported anyway
and also printed in full by the `debug/parse_failures` exporter, so
`kubectl logs` shows the raw frame and its attributes without a round trip
to your backend. The attribute value names the stage that failed:
`syslog_header`, `cef_envelope`, `cef_extensions` or `ecs_mapping`.

**Pod crash-loops immediately with SNMP enabled.** Almost certainly
missing credentials; `kubectl logs` will say
`receivers::snmp/unifi: user must be specified when version is v3`.

**Config change does not seem to apply.** It should — upstream annotates
the pod template with a config checksum. If the Deployment did not roll,
check you actually changed something under `alternateConfig` and not, say,
a comment.
