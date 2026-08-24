# Collector versions

This project pins one collector release and tests two.

| | |
| --- | --- |
| **Pinned** (what you get if you follow the quickstart or install the chart) | `0.158.0` |
| **Minimum supported** | `0.157.0` |
| Upstream `:latest` when this page was last checked (2026-08-24) | `0.159.0` |

The pin is not caution for its own sake. This configuration leans on
OTTL, on the syslog receiver's timestamp handling and on confmap's
deep-merge semantics, and all three have changed between releases
before. Floating to `:latest` means a parser that can change under a
`docker compose pull` with no diff to review.

## Where the version is written

| File | Key | Bumped by |
| --- | --- | --- |
| `docker-compose.yml` | `x-collector.image` | Dependabot |
| `chart/values.yaml` | `opentelemetry-collector.image.tag` | you |
| `chart/Chart.yaml` | `appVersion` | you |
| `.github/collector-versions.env` | `COLLECTOR_MIN_SUPPORTED` | you, rarely — see below |
| `chart/README.md`, `docs/helm.md`, `docs/snmp.md`, `docs/destinations.md` | prose and tables | you |

The first three are compared against each other by the `pins` job in
`.github/workflows/ci.yml`, which fails the pull request and names the
files that still disagree. The documentation tables are not
machine-checked; they are on the checklist below instead.

`docker-compose.yml` is the canonical pin — it is the one Dependabot
edits, and it is the one CI reads to decide which version to run every
other check against.

## Minimum supported version

`0.157.0`, declared in `.github/collector-versions.env`.

It is the version every design decision in `collector/*.yaml` was
verified against, and the oldest release this project claims to work
on. It is not a claim that older releases fail — nobody has tried.

**Raise it only when the configuration actually requires something a
newer release introduced.** A new component, a bug fix the config now
depends on, a syntax that only parses on the newer build: those are
reasons. "A newer version exists" is not. Raising the minimum forces an
upgrade on everyone running an older collector for their own reasons,
and buys nothing unless something here needs it.

When you do raise it, say in the commit message which release
introduced the thing that made it necessary, and update the table at
the top of this page.

The pinned version may sit ahead of the minimum; that is the normal
state after a bump. CI checks that it never sits behind.

## Version-sensitive behaviour

Every item below was verified against one specific build and should not
be assumed stable across releases. When you bump the pin, re-test these
specifically — `otelcol validate` will not catch most of them, because
they are behaviours rather than schema errors.

### The deprecated bare `otlp` exporter alias

The exporter is spelled `otlp_grpc`. The bare `otlp` alias is
deprecated as of 0.157.0 and warns on every start. A future release is
expected to remove it.

**Re-test:** start the collector and read the first few lines of its
own log. A new deprecation warning naming a component this project uses
is the earliest signal that a future release will break it. `validate`
does not surface these — it only reports errors.

### The syslog receiver's empty-environment timezone fallback

`UNIFI_SYSLOG_TIMEZONE` set to the empty string is not an error. It
silently means UTC, which puts every non-CEF record a whole number of
hours out with no message anywhere. Compose refuses to start without
the variable for exactly this reason.

**Re-test:** send an RFC3164 frame with `UNIFI_SYSLOG_TIMEZONE` set to
a non-UTC zone and confirm the emitted timestamp is shifted by that
zone's offset. Then confirm the Compose guard still fires when the
variable is unset. If a release starts *rejecting* an empty value the
guard is redundant but harmless; if a release changes the fallback from
UTC to the host zone, every deployment's timestamps move.

### Backreference syntax in OTTL `replace_pattern`

Replacement backreferences in `replace_pattern` are Go `regexp`
syntax, and the accepted spelling has changed in OTTL before.

**Re-test:** anything under `collector/20-processors-logs.yaml` using
`replace_pattern` with a capture group in the replacement. A change
here fails loudly at validate time if the syntax is rejected, and
silently — producing a literal `$1` in an attribute value — if it is
merely reinterpreted. The silent case is the one to look for.

### Deep-merge semantics for repeated `--config`

The whole layout of `collector/` depends on confmap merging repeated
`--config` files: maps merge, **lists replace**, and the same top-level
key split across files combines rather than the later file winning
outright. `collector/optional/snmp/91-service-metrics.yaml` adds a
pipeline to the `service.pipelines` block defined in
`90-service.yaml` on that basis, and the Compose debug profile relies
on list-replacement to unwire the OTLP exporter.

**Re-test:** the three validate permutations cover the additive case.
For list-replacement, bring up `collector-debug` and confirm records
print to stdout rather than being dialled at `OTLP_GATEWAY_ENDPOINT`.

### SNMPv3 credential validation

`snmpreceiver` currently rejects a `v3` receiver with no `user`,
`auth_password` or `privacy_password`. The SNMP module has no defaults
for those variables precisely so that opting in without credentials is
a startup failure rather than a collector that polls nothing.

**Re-test:** CI does this on every run — permutation 3 below. It
asserts both a non-zero exit *and* that the error names
`receivers::snmp/unifi`, so a config error somewhere else cannot make
the control pass by accident.

### What is not covered at all

- **SNMP actually working.** The collector polls outward to a live
  device, so there is no frame to replay. CI proves the SNMP config
  parses and builds, never that the OIDs still return what
  `collector/optional/snmp/15-receivers-snmp.yaml` says they return.
  See `snmp.md`.
- **Any destination beyond OTLP.** The snippets in `destinations.md`
  are verified by whoever contributed them, at whatever version they
  ran.
- **Parsing output on frames the corpus does not carry.** The
  golden-file replay landed in #3 and pins 362 frames across 23 files,
  so a green run does now mean "the configuration still parses *those*
  frames the same way". It says nothing about a UniFi log shape nobody
  has contributed a sample of — see `contributing-samples.md`.

## How the matrix works

Two cells, as argued in #12: the minimum supported version and
`:latest`. Testing every recent minor spends CI proving compatibility
with versions nobody has reported using.

They are split across two workflows, because the two cells deserve
different treatment.

### `ci.yml` — the pull request gate

Runs on every pull request and every push to `main`, against the
version pinned in `docker-compose.yml`. Hard failure. Nothing in it
reaches for a floating tag, so it can only go red because of a change
in the pull request being reviewed.

Jobs:

| Job | What it does |
| --- | --- |
| `pins` | reads the three machine-readable pins and compares them |
| `pin-consistency` | fails if they disagree |
| `validate` | calls `collector-checks.yml` against the pinned version |

`pins` and `pin-consistency` are separate jobs on purpose. If they were
one job, a disagreement would skip `validate`, and a version-bump pull
request would tell you "you have files left to edit" while withholding
the thing you actually opened it to learn — whether the new release
works.

### `upstream-collector.yml` — release tracking

Runs weekly on a schedule, and on demand. Two cells:

| Cell | Version | On failure |
| --- | --- | --- |
| `minimum` | `COLLECTOR_MIN_SUPPORTED` | hard failure |
| `latest` | resolved from `:latest`, skipped if it equals the minimum | soft failure, reported as an issue |

**Why `:latest` is not on pull requests, and why it is soft.** The
`:latest` cell exists in order to break; that is its entire purpose.
But when it breaks, the cause is an upstream release, not the pull
request in front of you. A red X that the author cannot act on is how a
project teaches people to stop reading CI, and once they have stopped,
the red X that *is* their fault gets ignored too. So:

- it runs on a schedule, never on a pull request, so it never appears
  as a check on anyone's work;
- the cell is soft-failed, so the scheduled run itself stays green and
  the finding is filed as an issue instead.

An issue can be triaged, assigned, commented on and closed. A failed
run from three weeks ago can only be scrolled past. The
`minimum` cell is *not* soft-failed: a break there means this project
is making a compatibility claim that is not true, which is a defect
here rather than news about upstream.

The `:latest` tag is resolved to a concrete version before the checks
run, from the image's `org.opencontainers.image.version` label, so the
issue title names a fixed release and a re-run months later still means
something.

### `collector-checks.yml` — the checks themselves

Reusable, called by both workflows with a version and a soft-fail flag.
Everything that can run today lives here, so anything added to it is
automatically both a pull request gate and part of the upstream matrix.

**`otelcol validate`, three permutations.** The collector has no glob
or directory mode, so the `--config` flag list *is* the configuration
surface and a file that is simply not listed is a silent no-op rather
than an error.

| # | Permutation | Expected |
| - | ----------- | -------- |
| 1 | the default four files, SNMP environment unset | exit 0 |
| 2 | all seven files, `UNIFI_SNMP_USER` and `UNIFI_SNMP_PASSWORD` set | exit 0 |
| 3 | all seven files, credentials unset | non-zero, naming `receivers::snmp/unifi` |

Permutation 3 is the one that earns its place. Without a negative
control, "SNMP is off by default" is indistinguishable from "SNMP is on
by default but happens to be inert", and the two fail very differently
for an operator.

**Chart.** `helm lint`, `helm template` and `kubeconform` for both the
default and the SNMP permutation; then the rendered ConfigMap's
contents run through `otelcol validate` for the cell's collector
version. That last step closes the gap `kubeconform` leaves: a chart
that renders a perfectly valid ConfigMap containing a broken pipeline
passes `kubeconform` without complaint, because the pipeline is a
string as far as it is concerned.

**Chart/collector drift.** `chart/values.yaml` mirrors
`collector/*.yaml` because Helm cannot read files outside the chart
directory. Nothing but this check notices when the mirror goes stale,
and a stale mirror ships a silently older parser — the worst failure
this project has available to it. The procedure is the `yq`/`diff` one
documented in `../chart/README.md`, run for both permutations.

**Corpus.** The `corpus` job runs the privacy gate
(`scrub.py --check`) and then the golden-file replay
(`tests/run.py --image`), both against the cell's collector version.
A bump that changes parsing output fails here, and the golden diff in
the pull request *is* the behaviour change. Landed in #3 and #11.

## Dependabot

`.github/dependabot.yml` watches two things: the collector image tag in
`docker-compose.yml`, weekly; and the actions used by these workflows,
monthly and grouped into one pull request.

**Auto-PR, never auto-merge.** Nothing in the configuration enables
auto-merge and nothing should. Green CI on a bump now proves the log
path still builds *and* that parsing output is byte-identical across
the corpus. It still cannot prove SNMP works, and it cannot prove any
destination beyond OTLP works. Those gaps are narrower than they were,
but a bump still moves the binary every user runs on evidence that
stops short of their own deployment, so it stays a human decision.

**Dependabot bumps `docker-compose.yml` and nothing else.** It does not
know about `chart/values.yaml`, `chart/Chart.yaml` or the documentation
tables. That is what `pin-consistency` is for: a bump pull request
arrives with that check red and a message naming the files still to
edit, and it cannot merge until they are done. That red X is
*actionable and caused by the pull request*, which is the distinction
this page keeps drawing.

The upstream Helm chart dependency in `chart/Chart.yaml` is
deliberately not watched. Bumping it without regenerating
`chart/Chart.lock` breaks `helm dependency build`, so every such pull
request would arrive red and need a local `helm dependency update`
anyway.

A `cooldown` setting, which delays pull requests for a configurable
number of days after a release, is worth considering if bumps start
arriving faster than they can be reviewed. It is not configured today.

## Bumping the pin: checklist

Most of this arrives as a Dependabot pull request; the rest is manual.

1. Read the upstream release notes, specifically for `syslogreceiver`,
   `snmpreceiver`, `transformprocessor`/OTTL, `confmap` and the OTLP
   exporters.
2. `docker-compose.yml` — `x-collector.image` (Dependabot does this).
3. `chart/values.yaml` — `opentelemetry-collector.image.tag`.
4. `chart/Chart.yaml` — `appVersion`. Bump the chart `version` too:
   the chart now deploys a different binary, so it is a different
   chart.
5. Version tables in `chart/README.md`, `docs/helm.md`, `docs/snmp.md`
   and the provenance note in `docs/destinations.md`.
6. The table at the top of this page.
7. Work through the version-sensitive behaviours above. CI covers the
   validate permutations, the chart and the corpus replay; it does not
   cover the deprecation warnings, the timezone fallback or
   list-replacement in the debug profile. Those three are manual.
8. Leave `COLLECTOR_MIN_SUPPORTED` alone unless the configuration now
   genuinely requires the newer release.

## Running the checks locally

```bash
# permutation 1 — expect exit 0
docker run --rm -v "$PWD/collector":/conf:ro \
  otel/opentelemetry-collector-contrib:0.158.0 validate \
  --config=/conf/10-receivers-logs.yaml \
  --config=/conf/20-processors-logs.yaml \
  --config=/conf/40-exporters.yaml \
  --config=/conf/90-service.yaml

# permutation 2 — expect exit 0
docker run --rm -e UNIFI_SNMP_USER=x -e UNIFI_SNMP_PASSWORD=y \
  -v "$PWD/collector":/conf:ro \
  otel/opentelemetry-collector-contrib:0.158.0 validate \
  --config=/conf/10-receivers-logs.yaml \
  --config=/conf/20-processors-logs.yaml \
  --config=/conf/40-exporters.yaml \
  --config=/conf/90-service.yaml \
  --config=/conf/optional/snmp/15-receivers-snmp.yaml \
  --config=/conf/optional/snmp/30-processors-metrics.yaml \
  --config=/conf/optional/snmp/91-service-metrics.yaml

# permutation 3 — expect NON-ZERO, naming receivers::snmp/unifi.
# Same command as permutation 2 with the two -e flags removed.
```

The chart checks need `helm repo add open-telemetry
https://open-telemetry.github.io/opentelemetry-helm-charts` followed by
`helm dependency build chart/` first — `dependency build` reads the
committed `Chart.lock` but will not fetch from a repository URL helm has
never been told about. Use `build`, not `update`: `update` re-resolves
the version range and rewrites the lock.

The drift command is in [`../chart/README.md`](../chart/README.md); the
rendered-config validate is in [`helm.md`](helm.md).
