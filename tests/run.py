#!/usr/bin/env python3
"""Golden-file replay harness for the unifi-otel corpus (issue #3).

Replays tests/corpus/*.txt through the REAL pinned collector image and
compares the parsed records against tests/golden/*.golden.

Python 3, standard library only, no install step -- the same hard
requirement scripts/scrub.py carries, so CI can run it as-is. The only
external dependency is a working `docker`.

Usage
-----
    python3 tests/run.py                 # verify; exits non-zero on any failure
    python3 tests/run.py --update        # regenerate the goldens
    python3 tests/run.py -v              # print every diff in full
    python3 tests/run.py --keep          # leave the containers running

Read tests/README.md before using --update.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

# ── Layout ───────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS_DIR = os.path.join(HERE, "corpus")
GOLDEN_DIR = os.path.join(HERE, "golden")
COLLECTOR_DIR = os.path.join(ROOT, "collector")
SCRUB = os.path.join(ROOT, "scripts", "scrub.py")
SERVICE_YAML = os.path.join(COLLECTOR_DIR, "90-service.yaml")
COMPOSE_YAML = os.path.join(ROOT, "docker-compose.yml")

# Deliberately unusual so concurrent work on this repo cannot collide.
CONTAINER_A = "unifi-otel-corpus-replay-a"
CONTAINER_B = "unifi-otel-corpus-replay-b"
# (udp, tcp, health). Run B gets its own set so --keep can leave both
# containers up for inspection without a bind collision.
PORTS_A = (45514, 46601, 44133)
PORTS_B = (45515, 46602, 44134)

# Only used if docker-compose.yml stops naming a pinned tag.
FALLBACK_IMAGE = "otel/opentelemetry-collector-contrib:0.157.0"

# The timezone the goldens were generated under. NOT a suggestion: the
# RFC3164 receiver stamps non-CEF records in this zone, so changing it
# moves every non-CEF timestamp and the goldens with it.
CORPUS_TIMEZONE = "Etc/UTC"

CONFIG_FILES = [
    "10-receivers-logs.yaml",
    "20-processors-logs.yaml",
    "40-exporters.yaml",
    "90-service.yaml",
]

# transform/strip_working_fields' own regex, lifted verbatim so bar 3
# asserts exactly what the config claims to remove rather than a
# paraphrase of it.
WORKING_KEY_RE = re.compile(
    r"^(cef_|dev_|dns_kv$|dhcp_|sudo_|hostname$|appname$|facility$"
    r"|facility_text$|priority$|message$|version$|proc_id$|msg_id$"
    r"|structured_data$)"
)

# The subset the issue names explicitly, reported separately because it
# is the headline claim.
WORKING_PREFIXES = ("cef_", "dev_", "dns_kv", "dhcp_", "sudo_")

FALLBACK_DATASET = "unifi.syslog"

# Frames whose parsed record carries this provider went through the CEF
# branch, i.e. cef_kv was populated. That is the scope of bar 4.
CEF_PROVIDER = "unifi-network"


# ── Corpus ───────────────────────────────────────────────────────────
# A multi-line frame is one logical frame delivered as SEVERAL wire
# units: linkcheck pretty-prints its JSON and each LINE leaves the
# gateway as its own datagram. The receiver stitches them back together
# with a recombine operator, so the corpus has to be able to say "these
# N lines are one frame" without the harness guessing.
#
# The markers deliberately carry no dotted token: scrub.py --check reads
# the whole file and cannot tell a dotted word from a domain.
FRAME_OPEN = "#[frame]"
FRAME_CLOSE = "#[/frame]"


class Frame:
    """One logical frame, made of one or more wire units.

    `lines` is what goes on the wire, in order, one send per element.
    `text` is the frame's IDENTITY: the wire units joined with newlines.
    Records are correlated back to frames by content, and goldens are
    keyed on it, so it must be unique across the corpus.
    """

    __slots__ = ("path", "name", "lineno", "lines", "text", "transport")

    def __init__(self, path, name, lineno, lines):
        self.path = path
        self.name = name
        self.lineno = lineno
        self.lines = list(lines)
        self.text = "\n".join(self.lines)
        # Routed by the frame's own syntax: "<PRI>1 " is RFC5424, which
        # only the TCP receiver speaks. Everything else is RFC3164/UDP.
        # Only the FIRST wire unit carries a header, so only it can say.
        self.transport = "tcp" if re.match(r"^<\d+>1 ", self.lines[0]) else "udp"

    @property
    def multiline(self):
        return len(self.lines) > 1

    def __repr__(self):
        return f"<Frame {self.name}:{self.lineno}>"


def load_corpus():
    """Read tests/corpus/*.txt into frames.

    Outside a block: one non-blank, non-'#' line is one single-line
    frame. Blank lines and '#' lines are comments.

    Inside a `#[frame]` … `#[/frame]` block: EVERY line is a wire unit
    verbatim -- no comment stripping, no blank-line skipping, leading
    whitespace preserved exactly, because the indentation is part of the
    bytes the gateway actually sent.
    """
    frames = []
    paths = sorted(
        os.path.join(CORPUS_DIR, f)
        for f in os.listdir(CORPUS_DIR)
        if f.endswith(".txt")
    )
    if not paths:
        die(f"no corpus files found in {CORPUS_DIR}")
    for path in paths:
        name = os.path.basename(path)
        block = None          # accumulated wire units, or None when closed
        block_open_at = 0     # line number of the opening marker
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n").rstrip("\r")

                if block is not None:
                    if line == FRAME_CLOSE:
                        if not block:
                            die(f"{path}:{block_open_at}: empty {FRAME_OPEN} "
                                f"block -- a block must hold at least one "
                                f"wire unit")
                        frames.append(
                            Frame(path, name, block_open_at + 1, block))
                        block = None
                        continue
                    if line == FRAME_OPEN:
                        die(f"{path}:{lineno}: nested {FRAME_OPEN} -- the "
                            f"block opened at line {block_open_at} is still "
                            f"open. Blocks do not nest.")
                    block.append(line)
                    continue

                if line == FRAME_OPEN:
                    block = []
                    block_open_at = lineno
                    continue
                if line == FRAME_CLOSE:
                    die(f"{path}:{lineno}: stray {FRAME_CLOSE} with no "
                        f"matching {FRAME_OPEN}")
                if not line.strip() or line.startswith("#"):
                    continue
                frames.append(Frame(path, name, lineno, [line]))

        if block is not None:
            die(f"{path}:{block_open_at}: unterminated {FRAME_OPEN} block -- "
                f"end of file reached with no {FRAME_CLOSE}")
    return frames


def expected_records(frames):
    """How many records the collector should print for these frames.

    One per FRAME, not one per wire unit: a single-line frame is one
    datagram and one record, and a multi-line frame is several datagrams
    that the receiver's recombine operator stitches back into one record
    before any user operator sees it. So this is len(frames) today -- it
    exists as a function because that identity is a claim about the
    receiver config, not an arithmetic truism, and this is where it would
    change if a frame ever fanned out.
    """
    return sum(1 for _ in frames)


def wire_units(frames):
    return sum(len(f.lines) for f in frames)


DOUBLED_RE = re.compile(
    r"^((?:<\d+>)?(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d )?)(\S+) \2 "
)


def collapse_doubled_hostname(text):
    """'<30>Aug 13 09:00:00 h h tag: msg' -> '<30>Aug 13 09:00:00 h tag: msg'."""
    return DOUBLED_RE.sub(r"\1\2 ", text, count=1)


def pair_kind(name):
    if name.startswith("device-"):
        return "hostname"
    if name.startswith("transport-"):
        return "transport"
    return None


def validate_corpus(frames):
    """Structural invariants the harness depends on. Returns a list of errors."""
    errors = []

    seen = {}
    for f in frames:
        if f.text in seen:
            prev = seen[f.text]
            errors.append(
                f"duplicate frame: {f.name}:{f.lineno} repeats "
                f"{prev.name}:{prev.lineno}. Frames are correlated to records "
                f"by content, so every frame must be unique."
            )
        seen[f.text] = f

    by_file = {}
    for f in frames:
        by_file.setdefault(f.name, []).append(f)

    for name, group in sorted(by_file.items()):
        kind = pair_kind(name)
        if kind is None:
            continue
        if len(group) % 2:
            errors.append(
                f"{name}: {len(group)} frames. A matched-pair file must hold "
                f"an even number: members are adjacent."
            )
            continue
        for a, b in zip(group[0::2], group[1::2]):
            if kind == "hostname":
                if collapse_doubled_hostname(a.text) != b.text:
                    errors.append(
                        f"{name}:{a.lineno}/{b.lineno}: not a hostname pair. "
                        f"Collapsing the doubled hostname in the first member "
                        f"must yield the second member exactly, so that the "
                        f"only difference between them is the doubling."
                    )
            elif kind == "transport":
                if a.transport != "udp" or b.transport != "tcp":
                    errors.append(
                        f"{name}:{a.lineno}/{b.lineno}: not a transport pair. "
                        f"Expected RFC3164/UDP first and RFC5424/TCP second, "
                        f"got {a.transport}/{b.transport}."
                    )
    return errors


def matched_pairs(frames):
    """[(kind, frame_a, frame_b)] for every declared pair."""
    by_file = {}
    for f in frames:
        by_file.setdefault(f.name, []).append(f)
    pairs = []
    for name, group in sorted(by_file.items()):
        kind = pair_kind(name)
        if kind is None or len(group) % 2:
            continue
        for a, b in zip(group[0::2], group[1::2]):
            pairs.append((kind, a, b))
    return pairs


# ── Collector image and pipeline, read from the repo ─────────────────
def pinned_image():
    """The tag docker-compose.yml pins, so the harness cannot drift from it."""
    try:
        with open(COMPOSE_YAML, "r", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(
                    r"\s*image:\s*(otel/opentelemetry-collector-contrib:\S+)\s*$",
                    line,
                )
                if m:
                    return m.group(1)
    except OSError:
        pass
    return FALLBACK_IMAGE


def syslog_pipeline_processors():
    """The processor list of logs/unifi_syslog, read from 90-service.yaml.

    Read rather than hardcoded so that bar 4 cannot quietly become
    vacuous if the pipeline is reordered or renamed.
    """
    with open(SERVICE_YAML, "r", encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    out = []
    in_pipeline = False
    in_processors = False
    for line in lines:
        if re.match(r"\s*logs/unifi_syslog:\s*$", line):
            in_pipeline = True
            continue
        if in_pipeline:
            if re.match(r"\s*processors:\s*$", line):
                in_processors = True
                continue
            if in_processors:
                m = re.match(r"\s*-\s*(\S+)\s*$", line)
                if m:
                    out.append(m.group(1))
                    continue
                break
            if re.match(r"\s*\S+:\s*$", line) and not line.strip().startswith("#"):
                # another pipeline started before processors: was found
                break
    return out


# ── Docker ───────────────────────────────────────────────────────────
def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def docker_rm(name):
    run(["docker", "rm", "-f", name])


def start_collector(name, image, ports, processors, verbose=False):
    """Start the collector with a debug exporter wired to both pipelines.

    The overlay technique is the one docker-compose.yml already uses for
    its debug profile: `--config=yaml:` fragments are deep-merged like
    any other --config, so nothing under collector/ has to know the test
    harness exists.
    """
    udp_port, tcp_port, health_port = ports
    docker_rm(name)
    cmd = [
        "docker", "run", "-d", "--name", name,
        "-v", f"{COLLECTOR_DIR}:/conf:ro",
        "-p", f"127.0.0.1:{udp_port}:5514/udp",
        "-p", f"127.0.0.1:{tcp_port}:6601/tcp",
        "-p", f"127.0.0.1:{health_port}:13133/tcp",
        "-e", f"UNIFI_SYSLOG_TIMEZONE={CORPUS_TIMEZONE}",
        image,
    ]
    cmd += [f"--config=/conf/{f}" for f in CONFIG_FILES]
    cmd += [
        # A debug exporter that prints EVERY record in full. Sampling
        # defaults drop records once the rate picks up, which looks
        # exactly like a parser that stopped working.
        "--config=yaml:exporters::debug/stdout::verbosity: detailed",
        "--config=yaml:exporters::debug/stdout::sampling_initial: 100000",
        "--config=yaml:exporters::debug/stdout::sampling_thereafter: 1",
        "--config=yaml:exporters::debug/parse_failures::sampling_initial: 100000",
        "--config=yaml:exporters::debug/parse_failures::sampling_thereafter: 1",
        # Repoint both terminal pipelines. Lists are replaced on merge,
        # not appended, so otlp_grpc/gateway is dropped: no backend
        # needed, and no records leave the container.
        "--config=yaml:service::pipelines::logs/unifi_syslog_export::exporters: [debug/stdout]",
        "--config=yaml:service::pipelines::logs/unifi_parse_failures::exporters: [debug/parse_failures]",
        # The gotcha this harness exists to encode: at `warn` the debug
        # exporter prints nothing and it looks like zero records
        # arrived. 90-service.yaml already sets info; pin it here so a
        # change there cannot silently blind the harness.
        "--config=yaml:service::telemetry::logs::level: info",
        # The shipped batch timeout is 5s. Shortening it only changes how
        # long the harness waits, never what the records contain.
        "--config=yaml:processors::batch::timeout: 1s",
    ]
    if processors is not None:
        cmd.append(
            "--config=yaml:service::pipelines::logs/unifi_syslog::processors: ["
            + ", ".join(processors)
            + "]"
        )
    if verbose:
        print("  $ " + " ".join(cmd))
    res = run(cmd)
    if res.returncode != 0:
        die(f"docker run failed for {name}:\n{res.stderr.strip()}")
    return name


def wait_ready(name, health_port, timeout=60):
    """Poll the health_check extension from the host.

    The image is FROM scratch -- no shell, no curl -- so probing from
    outside is the only option.
    """
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{health_port}/"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        if run(["docker", "inspect", "-f", "{{.State.Running}}", name]).stdout.strip() != "true":
            logs = container_logs(name)
            die(f"collector {name} exited during startup:\n{logs[-4000:]}")
        time.sleep(0.5)
    die(f"collector {name} did not become ready within {timeout}s")


def container_logs(name):
    res = run(["docker", "logs", name])
    return (res.stdout or "") + (res.stderr or "")


# ── Replay ───────────────────────────────────────────────────────────
def replay(frames, ports, verbose=False):
    """Send every WIRE UNIT of every frame. A socket loop, never `nc`.

    macOS `nc` truncates UDP datagrams at around 1024 bytes, and a
    truncated CEF frame looks exactly like a parse failure -- you would
    spend an afternoon debugging a parser that is fine.

    A multi-line frame is sent one datagram PER LINE, in order, which is
    how the gateway sends it. Reassembly is the receiver's job, not the
    harness's -- sending the frame as a single datagram would test a
    shape that never occurs on the wire.
    """
    udp_port, tcp_port, _ = ports
    udp = [f for f in frames if f.transport == "udp"]
    tcp = [f for f in frames if f.transport == "tcp"]

    if udp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Datagrams larger than the default send buffer are the whole
        # point of the oversized fixture; make room for them.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
        except OSError:
            pass
        try:
            for f in udp:
                for line in f.lines:
                    payload = line.encode("utf-8")
                    sent = sock.sendto(payload, ("127.0.0.1", udp_port))
                    if sent != len(payload):
                        die(
                            f"short UDP send for {f.name}:{f.lineno} "
                            f"({sent} of {len(payload)} bytes)"
                        )
                    time.sleep(0.02)
        finally:
            sock.close()

    if tcp:
        sock = socket.create_connection(("127.0.0.1", tcp_port), timeout=10)
        try:
            for f in tcp:
                for line in f.lines:
                    sock.sendall(line.encode("utf-8") + b"\n")
                    time.sleep(0.02)
            # The stanza tcp input splits on newlines; give it a moment
            # before the FIN so the last frame is not racing the close.
            time.sleep(1.0)
        finally:
            sock.close()

    if verbose:
        print(f"  replayed {len(udp)} UDP frame(s) ({wire_units(udp)} unit(s)), "
              f"{len(tcp)} TCP frame(s) ({wire_units(tcp)} unit(s))")


# ── Debug-exporter output parsing ────────────────────────────────────
ZAP_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T\S+\t(debug|info|warn|error)\t")
ZAP_FIELDS = re.compile(r'^\t?\{"resource":.*\}\s*$')
COMPONENT_ID = re.compile(r'"otelcol\.component\.id":\s*"([^"]+)"')
ATTR_RE = re.compile(r"^\s+-> ([^:]+): (.*)$")


class Record:
    __slots__ = ("observed", "timestamp", "severity_text", "severity_number",
                 "body", "attrs", "exporter")

    def __init__(self):
        self.observed = ""
        self.timestamp = ""
        self.severity_text = ""
        self.severity_number = ""
        self.body = ""
        self.attrs = []
        self.exporter = ""


# The keys the debug exporter prints AFTER Body:, in a fixed order. A
# multi-line body or attribute value ends at the first of these -- which
# is the only reliable way to know where such a value stops, since its
# own continuation lines can look like anything the gateway sent.
VALUE_TERMINATORS = ("Attributes:", "Trace ID:", "Span ID:", "Flags:")


def parse_debug_output(text):
    """Return (records, log_lines).

    log_lines is [(level, component_id, message)] for every zap entry, so
    bar 1 can be asserted against the collector's own telemetry.

    Bodies and attribute values may span several physical lines: a
    recombined multi-line frame puts real newlines in body, and
    event.original carries the same bytes. Such a value is accumulated
    until one of VALUE_TERMINATORS (or a structural line) is reached.
    """
    records = []
    log_lines = []
    lines = text.split("\n")

    dump = None          # records accumulated in the current dump
    rec = None
    section = None
    unparsed = []

    # An open multi-line value: (record, "body"|"attr", key, [parts]).
    pending = None

    def flush():
        nonlocal pending
        if pending is None:
            return
        target, kind, key, parts = pending
        pending = None
        value = "\n".join(parts)
        if kind == "body":
            target.body = value
        else:
            target.attrs.append((key, value))

    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1

        m = ZAP_PREFIX.match(line)
        if m:
            flush()
            level = m.group(1)
            rest = line[m.end():]
            comp = COMPONENT_ID.search(line)
            log_lines.append((level, comp.group(1) if comp else "", rest))
            if rest.startswith("ResourceLog #"):
                dump = []
                rec = None
                section = None
            elif dump is not None:
                # a new zap entry interrupts the dump
                records.extend(dump)
                dump = None
                rec = None
            continue

        if dump is None:
            continue

        if ZAP_FIELDS.match(line):
            flush()
            comp = COMPONENT_ID.search(line)
            for r in dump:
                r.exporter = comp.group(1) if comp else ""
            records.extend(dump)
            dump = None
            rec = None
            section = None
            continue

        if line.startswith("ResourceLog #") or line.startswith("ScopeLogs #"):
            flush()
            rec = None
            section = None
            continue
        if line.startswith("LogRecord #"):
            flush()
            rec = Record()
            dump.append(rec)
            section = None
            continue
        if rec is None:
            continue

        # Terminators come first: they close whatever value is open, and
        # nothing inside a value may be mistaken for them.
        if line == "Attributes:":
            flush()
            section = "attrs"
            continue
        if line.startswith(VALUE_TERMINATORS):
            flush()
            section = None
            continue

        if section == "attrs":
            m = ATTR_RE.match(line)
            if m:
                flush()
                pending = (rec, "attr", m.group(1), [m.group(2)])
            elif pending is not None:
                # continuation of the attribute value opened above
                pending[3].append(line)
            else:
                unparsed.append(line)
            continue

        if pending is not None:
            # continuation of a multi-line Body
            pending[3].append(line)
            continue

        if line.startswith("Body: "):
            pending = (rec, "body", None, [line[len("Body: "):]])
        elif line.startswith("ObservedTimestamp: "):
            rec.observed = line[len("ObservedTimestamp: "):]
        elif line.startswith("Timestamp: "):
            rec.timestamp = line[len("Timestamp: "):]
        elif line.startswith("SeverityText: "):
            rec.severity_text = line[len("SeverityText: "):]
        elif line == "SeverityText:":
            rec.severity_text = ""
        elif line.startswith("SeverityNumber: "):
            rec.severity_number = line[len("SeverityNumber: "):]
        elif line.startswith("Resource ") or line.startswith("InstrumentationScope") \
                or line.startswith("     -> "):
            continue

    flush()
    if dump:
        records.extend(dump)
    if unparsed:
        die(
            "could not parse the debug exporter output -- an attribute "
            "block held a line that is neither an attribute nor the "
            "continuation of one:\n  " + "\n  ".join(unparsed[:5])
        )
    return records, log_lines


def attr(rec, key):
    for k, v in rec.attrs:
        if k == key:
            return v
    return None


def unwrap(value):
    """'Str(x)' -> 'x'. Leaves other pdata renderings alone."""
    if value is None:
        return None
    if value.startswith("Str(") and value.endswith(")"):
        return value[4:-1]
    return value


# ── Normalisation ────────────────────────────────────────────────────
YEAR_RE = re.compile(r"^\d{4}-")


def norm_time(rec):
    """Collapse wall-clock variation out of the timestamp.

    - equal to ObservedTimestamp  -> "observed" (transform/timestamp_guard
      filled it in, or the receiver did)
    - epoch / zero value          -> "zero"
    - otherwise                   -> the timestamp with the YEAR removed

    The year has to go: the RFC3164 parser infers it from the current
    date, so a header-derived timestamp changes year every 1 January
    while a payload-derived one does not. The cost is that a regression
    which shifts a record by exactly one year is invisible here; see
    tests/README.md.
    """
    ts = rec.timestamp
    if not ts:
        return "absent"
    if ts == rec.observed:
        return "observed"
    if ts.startswith("1970-01-01") or ts.startswith("0001-01-01"):
        return "zero"
    return "parsed " + YEAR_RE.sub("", ts)


def norm_exporter(exporter):
    if exporter == "debug/stdout":
        return "export"
    if exporter == "debug/parse_failures":
        return "failures"
    return exporter or "?"


def escape(value):
    """Keep one logical value on one physical golden line.

    A recombined multi-line frame puts real newlines in body, in
    event.original and in the frame text itself. Goldens are read line by
    line and diffed line by line, so an unescaped newline would silently
    turn one value into several rows. Backslash first, then newline, so
    the escaping round-trips.
    """
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def render_block(frame, rec):
    """One frame's normalised record. Stable, diffable, no wall clock."""
    out = ["--- frame"]
    out.append("in     " + escape(frame.text))
    out.append("wire   " + frame.transport)
    if rec is None:
        out.append("route  MISSING -- no record was produced for this frame")
        return "\n".join(out) + "\n"
    out.append("route  " + norm_exporter(rec.exporter))
    out.append("sev    " + (rec.severity_number or "-") +
               " / " + (rec.severity_text or "-"))
    out.append("time   " + norm_time(rec))
    out.append("fail   " + escape(unwrap(attr(rec, "unifi.parse_failure")) or "-"))
    out.append("body   " + escape(rec.body))
    for k, v in sorted(rec.attrs):
        out.append(f"attr   {k} = {escape(v)}")
    return "\n".join(out) + "\n"


def render_golden(name, frames, mapping):
    header = [
        "# GENERATED by tests/run.py -- do not hand-edit.",
        f"# corpus: {name}",
        "# Timestamps are normalised (see norm_time in tests/run.py);",
        "# attributes are sorted by key. One logical value per line: a",
        "# newline inside a value is written \\n and a backslash \\\\, so a",
        "# reassembled multi-line frame stays on one row. Regenerate with:",
        "#     python3 tests/run.py --update",
        "",
    ]
    body = [render_block(f, mapping.get(f.text)) for f in frames]
    return "\n".join(header) + "\n".join(body)


OPERATOR_RE = re.compile(r'"operator_type": "([^"]+)"')
ERROR_RE = re.compile(r'"error": "([^"]*)"')


def render_telemetry_golden(telemetry):
    """Pin the collector's own error/warn output.

    "First impressions of a parser are made in its failure stream"
    (issue #9). Bar 1 only asserts that no PROCESSOR errors, so a new
    source of receiver noise would slip past it silently. This golden
    makes the noise a number somebody has to look at.
    """
    counts = {}
    for level, comp, rest in telemetry:
        if level not in ("error", "warn"):
            continue
        op = OPERATOR_RE.search(rest)
        err = ERROR_RE.search(rest)
        key = (level, comp, op.group(1) if op else "-", err.group(1) if err else "-")
        counts[key] = counts.get(key, 0) + 1
    out = [
        "# GENERATED by tests/run.py -- do not hand-edit.",
        "# Every error/warn line the collector logged while replaying the",
        "# whole corpus, grouped and counted. Each entry here must be",
        "# explainable from a fixture; an unexplained one is a finding.",
        "#     python3 tests/run.py --update",
        "",
        "count  level  component  operator  error",
    ]
    for (level, comp, op, err), n in sorted(counts.items()):
        out.append(f"{n:5d}  {level}  {comp or '-'}  {op}  {err}")
    if len(out) == 7:
        out.append("(none)")
    return "\n".join(out) + "\n"


# ── Correlation ──────────────────────────────────────────────────────
def frame_keys(frame):
    """Every content key a record for this frame might correlate under.

    A recombined multi-line frame does NOT come back byte-identical to
    the corpus text: the syslog receiver strips the leading whitespace
    off every header-less continuation line before recombine joins them,
    so the record's body carries the JSON DE-INDENTED while the corpus
    preserves the two-space indentation the gateway actually sent. That
    de-indented form is the key that will hit in practice; the others
    are kept so a change on either side still correlates.
    """
    dedented = "\n".join(line.lstrip() for line in frame.lines)
    keys = [frame.text, frame.text.strip(), dedented, dedented.strip()]
    out = []
    for k in keys:
        if k not in out:
            out.append(k)
    return out


def correlate(frames, records):
    """Map records back to the frame that produced them, by content.

    Order would be simpler but is not safe: the export and failure
    pipelines batch independently, so a failure record can be printed
    before an earlier export record. Content works because
    transform/device_syslog and transform/unifi_ecs both put the raw
    frame in event.original -- and where they do not (a header-less
    line), the raw text survives in body.

    Note what is deliberately NOT indexed: the individual wire units of a
    multi-line frame. If the receiver stops recombining them, each line
    comes back as its own record and every one of them is reported as an
    orphan, which is the honest signal. Indexing them would let a
    regression that undoes reassembly correlate cleanly.
    """
    index = {}
    for f in frames:
        for key in frame_keys(f):
            index.setdefault(key, f)

    mapping = {}
    duplicates = []
    orphans = []
    for rec in records:
        key = unwrap(attr(rec, "event.original"))
        if key is None:
            key = unwrap(rec.body)
        frame = index.get(key)
        if frame is None and key is not None:
            frame = index.get(key.strip())
        if frame is None:
            orphans.append(rec)
            continue
        if frame.text in mapping:
            duplicates.append(frame)
            continue
        mapping[frame.text] = rec
    return mapping, duplicates, orphans


# ── Reporting ────────────────────────────────────────────────────────
class Report:
    def __init__(self):
        self.checks = []

    def add(self, name, ok, detail=""):
        self.checks.append((name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail else ""))
        return ok

    @property
    def ok(self):
        return all(ok for _, ok, _ in self.checks)


def die(msg):
    print(f"\ntests/run.py: {msg}", file=sys.stderr)
    sys.exit(2)


# ── Main ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true",
                    help="rewrite the goldens from this run (read tests/README.md first)")
    ap.add_argument("--image", default=None,
                    help="collector image; defaults to the tag docker-compose.yml pins")
    ap.add_argument("--keep", action="store_true",
                    help="leave the containers running for inspection")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--timeout", type=int, default=90,
                    help="seconds to wait for all records to arrive")
    ap.add_argument("--collector-dir", default=None,
                    help="alternate config directory. For deliberately breaking "
                         "the config to prove the harness fails -- point it at a "
                         "COPY, never at collector/ itself.")
    args = ap.parse_args()

    global COLLECTOR_DIR, SERVICE_YAML
    if args.collector_dir:
        COLLECTOR_DIR = os.path.abspath(args.collector_dir)
        SERVICE_YAML = os.path.join(COLLECTOR_DIR, "90-service.yaml")
        print(f"!! using an alternate config directory: {COLLECTOR_DIR}")

    if shutil.which("docker") is None:
        die("docker not found on PATH")

    image = args.image or pinned_image()
    frames = load_corpus()
    by_file = {}
    for f in frames:
        by_file.setdefault(f.name, []).append(f)

    print(f"unifi-otel corpus replay")
    print(f"  image      {image}")
    print(f"  timezone   {CORPUS_TIMEZONE}")
    multiline = [f for f in frames if f.multiline]
    print(f"  corpus     {len(frames)} frame(s) in {len(by_file)} file(s), "
          f"{wire_units(frames)} wire unit(s)"
          + (f", {len(multiline)} multi-line frame(s)" if multiline else ""))
    print()

    report = Report()

    # ---- precheck: corpus structure ---------------------------------
    print("precheck")
    errs = validate_corpus(frames)
    report.add("corpus structure", not errs,
               "" if not errs else f"{len(errs)} problem(s)")
    if errs:
        for e in errs:
            print(f"         {e}")

    # ---- precheck: privacy gate -------------------------------------
    # The same command issue #11 will gate on. Findings are redacted by
    # scrub.py itself, so it is safe to print them in CI.
    corpus_files = sorted(
        os.path.join(CORPUS_DIR, f)
        for f in os.listdir(CORPUS_DIR) if f.endswith(".txt")
    )
    res = run([sys.executable, SCRUB, "--check"] + corpus_files)
    report.add("privacy gate (scrub.py --check)", res.returncode == 0,
               res.stderr.strip().splitlines()[-1] if res.stderr.strip() else "")
    if res.returncode != 0:
        print(res.stdout)

    # ---- pipeline, read from the repo -------------------------------
    processors = syslog_pipeline_processors()
    if "transform/device_syslog" not in processors:
        die(
            "transform/device_syslog is not in the logs/unifi_syslog pipeline "
            f"read from {SERVICE_YAML} (got {processors}). Bar 4 compares the "
            "CEF path with and without it, so it cannot run."
        )
    processors_no_dev = [p for p in processors if p != "transform/device_syslog"]

    containers = []
    try:
        # ---- run A: the shipped pipeline ----------------------------
        print("\nrun A -- shipped pipeline")
        containers.append(
            start_collector(CONTAINER_A, image, PORTS_A, None, args.verbose))
        wait_ready(CONTAINER_A, PORTS_A[2])
        replay(frames, PORTS_A, args.verbose)
        log_a = drain(CONTAINER_A, expected_records(frames),
                      args.timeout, args.verbose)
        records_a, telemetry_a = parse_debug_output(log_a)
        print(f"  {len(records_a)} record(s) from {len(frames)} frame(s) "
              f"({wire_units(frames)} wire unit(s)), "
              f"{expected_records(frames)} expected")

        mapping_a, dups, orphans = correlate(frames, records_a)

        # ---- bar 0: one record per frame ----------------------------
        missing = [f for f in frames if f.text not in mapping_a]
        ok = not missing and not dups and not orphans
        detail = ""
        if not ok:
            detail = (f"{len(missing)} frame(s) with no record, "
                      f"{len(dups)} duplicate(s), {len(orphans)} orphan record(s)")
        report.add("every frame produced exactly one record", ok, detail)
        for f in missing[:10]:
            print(f"         no record for {f.name}:{f.lineno}: "
                  f"{escape(f.text)[:90]}")
        for r in orphans[:10]:
            print(f"         orphan record body={escape(r.body)[:90]}")

        # ---- bar 1: zero OTTL errors --------------------------------
        bad = [(lvl, comp, msg) for lvl, comp, msg in telemetry_a
               if lvl in ("error", "warn")
               and not comp.startswith("syslog/unifi_")]
        receiver_errs = [t for t in telemetry_a
                         if t[0] == "error" and t[1].startswith("syslog/unifi_")]
        report.add(
            "bar 1: zero OTTL errors",
            not bad,
            f"{len(bad)} error/warn line(s) from processors or exporters; "
            f"{len(receiver_errs)} receiver-level error(s), which are pinned "
            f"by golden/_telemetry.golden rather than assumed benign",
        )
        for lvl, comp, msg in bad[:10]:
            print(f"         {lvl} {comp}: {msg[:160]}")

        # ---- bar 2: exactly one dataset, never the fallback ---------
        no_dataset, on_fallback = [], []
        for f in frames:
            rec = mapping_a.get(f.text)
            if rec is None:
                continue
            hits = [v for k, v in rec.attrs if k == "event.dataset"]
            if len(hits) != 1:
                no_dataset.append((f, len(hits)))
            elif unwrap(hits[0]) == FALLBACK_DATASET:
                on_fallback.append(f)
        ok = not no_dataset and not on_fallback
        report.add(
            "bar 2: exactly one event dataset, none on the fallback",
            ok,
            f"{len(no_dataset)} without a single dataset, "
            f"{len(on_fallback)} stranded on {FALLBACK_DATASET}",
        )
        for f, n in no_dataset[:10]:
            print(f"         {f.name}:{f.lineno} has {n} event.dataset value(s)")
        for f in on_fallback[:10]:
            print(f"         {f.name}:{f.lineno} stranded on {FALLBACK_DATASET}")

        # ---- bar 3: no working attributes survive -------------------
        leaks = []
        for f in frames:
            rec = mapping_a.get(f.text)
            if rec is None:
                continue
            for k, _ in rec.attrs:
                if WORKING_KEY_RE.match(k):
                    leaks.append((f, k))
        named = sorted({k for _, k in leaks
                        if k.startswith(WORKING_PREFIXES)})
        report.add(
            "bar 3: no working attributes survive",
            not leaks,
            "" if not leaks else f"{len(leaks)} leak(s), keys: {named or sorted({k for _, k in leaks})}",
        )
        for f, k in leaks[:10]:
            print(f"         {f.name}:{f.lineno} still carries {k}")

        # ---- bar 5 (beyond the issue): matched pairs ----------------
        pair_problems = []
        pairs = matched_pairs(frames)
        for kind, a, b in pairs:
            ra, rb = mapping_a.get(a.text), mapping_a.get(b.text)
            if ra is None or rb is None:
                pair_problems.append((kind, a, b, "one member produced no record"))
                continue
            da, db = unwrap(attr(ra, "event.dataset")), unwrap(attr(rb, "event.dataset"))
            if da != db:
                pair_problems.append((kind, a, b, f"dataset {da} != {db}"))
                continue
            ka = sorted(k for k, _ in ra.attrs)
            kb = sorted(k for k, _ in rb.attrs)
            if ka != kb:
                only_a = sorted(set(ka) - set(kb))
                only_b = sorted(set(kb) - set(ka))
                pair_problems.append(
                    (kind, a, b, f"key set differs: only first {only_a}, only second {only_b}")
                )
                continue
            if ra.severity_number != rb.severity_number:
                pair_problems.append(
                    (kind, a, b, f"severity {ra.severity_number} != {rb.severity_number}"))
                continue
            fa = unwrap(attr(ra, "unifi.parse_failure"))
            fb = unwrap(attr(rb, "unifi.parse_failure"))
            if fa != fb:
                pair_problems.append((kind, a, b, f"parse failure {fa} != {fb}"))
                continue
            # Issue #24's added acceptance criterion: event.original
            # populated identically across both shapes -- the one field
            # whose absence looks like nothing is wrong.
            oa = unwrap(attr(ra, "event.original"))
            ob = unwrap(attr(rb, "event.original"))
            if oa != a.text or ob != b.text:
                pair_problems.append(
                    (kind, a, b, "event.original missing or not byte-equal to the frame sent"))
        report.add(
            f"bar 5: {len(pairs)} matched pair(s) agree",
            not pair_problems,
            "" if not pair_problems else f"{len(pair_problems)} divergence(s)",
        )
        for kind, a, b, why in pair_problems[:10]:
            print(f"         {kind} pair {a.name}:{a.lineno}/{b.lineno}: {why}")

        # ---- bar 4: CEF byte-identical without device_syslog --------
        cef_frames = [
            f for f in frames
            if mapping_a.get(f.text) is not None
            and unwrap(attr(mapping_a[f.text], "event.provider")) == CEF_PROVIDER
        ]
        print(f"\nrun B -- pipeline without transform/device_syslog "
              f"({len(cef_frames)} CEF frame(s))")
        if not cef_frames:
            report.add("bar 4: CEF path byte-identical without the device transform",
                       False, "no CEF frames were identified in run A")
        else:
            containers.append(
                start_collector(CONTAINER_B, image, PORTS_B,
                                processors_no_dev, args.verbose))
            wait_ready(CONTAINER_B, PORTS_B[2])
            replay(cef_frames, PORTS_B, args.verbose)
            log_b = drain(CONTAINER_B, expected_records(cef_frames),
                          args.timeout, args.verbose)
            records_b, telemetry_b = parse_debug_output(log_b)
            mapping_b, _, _ = correlate(cef_frames, records_b)
            print(f"  {len(records_b)} record(s) from {len(cef_frames)} frame(s)")

            diffs = []
            for f in cef_frames:
                a_block = render_block(f, mapping_a.get(f.text))
                b_block = render_block(f, mapping_b.get(f.text))
                if a_block != b_block:
                    diffs.append((f, a_block, b_block))
            report.add(
                "bar 4: CEF path byte-identical without the device transform",
                not diffs,
                f"{len(cef_frames)} frame(s) compared, {len(diffs)} differ",
            )
            for f, a_block, b_block in diffs[:5]:
                print(f"         {f.name}:{f.lineno}")
                for line in difflib.unified_diff(
                        a_block.split("\n"), b_block.split("\n"),
                        "with device_syslog", "without device_syslog", lineterm=""):
                    print("           " + line)

        # ---- goldens ------------------------------------------------
        print("\ngolden files")
        os.makedirs(GOLDEN_DIR, exist_ok=True)
        golden_failures = []
        wanted = [
            (name.replace(".txt", ".golden"), render_golden(name, by_file[name], mapping_a))
            for name in sorted(by_file)
        ]
        wanted.append(("_telemetry.golden", render_telemetry_golden(telemetry_a)))
        for name, want in wanted:
            path = os.path.join(GOLDEN_DIR, name)
            if args.update:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(want)
                print(f"  wrote {os.path.relpath(path, ROOT)}")
                continue
            if not os.path.exists(path):
                golden_failures.append((name, f"no golden at {os.path.relpath(path, ROOT)}"))
                continue
            with open(path, "r", encoding="utf-8") as fh:
                have = fh.read()
            if have != want:
                d = list(difflib.unified_diff(
                    have.split("\n"), want.split("\n"),
                    f"golden/{name}", "this run", lineterm=""))
                shown = d if args.verbose else d[:40]
                golden_failures.append((name, "\n".join(shown)))

        if args.update:
            report.add("goldens", True, "regenerated")
        else:
            report.add("goldens match", not golden_failures,
                       f"{len(wanted) - len(golden_failures)}/{len(wanted)} file(s) match")
            for name, detail in golden_failures:
                print(f"\n  --- {name}")
                print("  " + detail.replace("\n", "\n  "))

    finally:
        if args.keep:
            print(f"\n(--keep) containers left running: {', '.join(containers)}")
        else:
            for name in containers:
                docker_rm(name)

    print()
    if report.ok:
        print("tests/run.py: OK -- all checks passed")
        return 0
    failed = [n for n, ok, _ in report.checks if not ok]
    print(f"tests/run.py: FAIL -- {len(failed)} check(s) failed: {', '.join(failed)}")
    return 1


def drain(name, expected, timeout, verbose=False):
    """Wait until every expected record has been printed, then settle.

    Polls rather than sleeping a fixed interval so a slow machine does
    not produce a spurious 'records missing' failure.
    """
    deadline = time.time() + timeout
    last = -1
    stable = 0
    while time.time() < deadline:
        text = container_logs(name)
        count = text.count("\nLogRecord #") + text.count("\tLogRecord #")
        if count >= expected and count == last:
            stable += 1
            if stable >= 2:
                return text
        else:
            stable = 0
        last = count
        time.sleep(1.0)
    text = container_logs(name)
    if verbose:
        print(f"  drain timed out with {last} record(s) of {expected} expected")
    return text


if __name__ == "__main__":
    sys.exit(main())
