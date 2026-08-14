#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scrub a UniFi syslog capture: rewrite the values, preserve the structure.

Test fixtures for this project are real network traffic, and real network
traffic is the most sensitive artifact in the repository. DNS queries are
browsing history. DHCP frames carry the names people gave their phones.
`sudo` frames carry usernames. Every frame carries MAC addresses and the
shape of an internal network. None of that can land in a public diff.

THE RULE THAT MATTERS: scrub values, never structure.

A fixture exists because of the shape of the frame, not because of what is
in it. Every one of these has to survive byte-for-byte in shape:

  * the doubled hostname the gateway emits, which breaks RFC3164 appname
    parsing ("Gateway Gateway coredns[4155]: ...") and inverts on CEF
    frames so that appname becomes the literal string "CEF"
  * a tag with no [pid]
  * a line with no tag at all
  * coredns emitting something that is not JSON
  * DHCPDISCOVER placing a MAC where its sibling messages place an IP
  * all four sudo shapes, including pam_unix auth failures

A scrub that "tidies" a malformed frame destroys the only reason that
fixture exists. So this script never re-wraps, re-orders, re-cases or
normalises anything. It finds value-shaped substrings, replaces them with
deterministic look-alikes of the same token shape, and puts back every
delimiter and whitespace byte exactly as it found them.

WHAT IT REWRITES
  IPv4        -> RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24,
                 203.0.113/24)
  IPv6        -> RFC 3849 documentation prefix (2001:db8::/32)
  MAC         -> RFC 7042 documentation range 00:00:5E:00:53:xx, spilling
                 into locally-administered 02:00:5E:xx:xx:xx when exhausted
  domains     -> RFC 2606 example.com / example.net / example.org
  hostnames   -> host-<hex>, and friends (site-, ssid-, alias-, user-, ...)
  usernames   -> user-<hex>, except the vendor service accounts (allowlist)
  ISP / geo   -> isp-<hex>, geo-<hex>, ZZ, RFC 5398 documentation ASNs

DETERMINISM
  Every mapping comes from a keyed BLAKE2b digest, never from `random`, so
  the same input value maps to the same output value within a run AND
  across runs. That is not a nicety: a MAC seen in a DHCP frame and again
  in a CEF frame has to still correlate after scrubbing, because the DHCP
  dataset is the join key for every other dataset (see the dnsmasq-dhcp
  note in collector/20-processors-logs.yaml). Break the correlation and
  `related.mac` / `related.ip` / `related.hosts` become untestable and the
  corpus is worthless.

  The default salt is a public constant so that a clone of this repo
  reproduces the reference corpus byte-for-byte. That also means anyone
  holding this script can confirm a *guess* at a short hostname by
  re-hashing it. If you are scrubbing your own capture for publication and
  that bothers you, pass --salt (or set UNIFI_SCRUB_SALT) and keep the
  value to yourself. --check does not depend on the salt.

LENGTH PRESERVATION
  Preserved where it is cheap and safe, and skipped where preserving it
  would cost correctness. Explicitly:

  * MAC addresses      length preserved (always 17 bytes, free).
  * Name-like tokens   length preserved (hostnames, SSIDs, site names,
                       usernames, aliases, ISP names). The pseudonym is
                       padded or truncated to the original length, with a
                       floor of prefix+3 characters so the marker survives
                       on very short names. Interior whitespace is kept at
                       word granularity: a site name of "My Home Site"
                       comes out as three space-separated tokens, because
                       CEF has no quoting and a value containing spaces is
                       exactly what transform/cef_extensions exists to
                       handle -- collapsing it to one word would delete the
                       test case.
  * Domain names       label COUNT preserved, and every label to the left
                       of the registrable domain keeps its length. The last
                       two labels become example.<tld>, which changes the
                       overall length. Chosen deliberately: RFC 2606 is the
                       only way to guarantee the output can never resolve
                       to somebody's real host, and "example" is 7 bytes
                       whether you like it or not.
  * IPv4               NOT length preserved, and it cannot be. An address
                       that is simultaneously (a) syntactically valid,
                       (b) inside RFC 5737, and (c) the same byte length as
                       an arbitrary input does not exist: every RFC 5737
                       range has a 3-digit first octet, so "10.0.0.1" (8
                       bytes) cannot come back shorter than 12. Validity
                       and documentation-range membership win, because both
                       the OTTL dhcp_ip pattern and any downstream ip-typed
                       field care about those and neither cares about
                       length.
  * IPv6               NOT length preserved, same reasoning.

IDEMPOTENCE, AND WHY --check IS ONE LINE OF LOGIC
  Every output form is recognisable as already-scrubbed: RFC 5737 / 3849
  ranges, the 00:00:5E:00:53 MAC block, an example.com suffix, a
  <marker>-<hex> pseudonym. Scrubbing an already-scrubbed file is
  therefore a no-op, which makes the dry-run gate trivial and exact:

      --check passes if and only if scrubbing the input changes nothing.

  Anything the rewriter would have touched is, by definition, something
  that still looks unscrubbed.

EXIT CODES (this is the contract for the CI corpus privacy gate, issue #11)
  0  clean: nothing in the input looks unscrubbed
  1  findings: at least one value would be rewritten. Every finding is
     printed to stdout as "<path>:<line>: <kind>: <redacted>", one per
     line, greppable, with a human summary on stderr. Values are REDACTED
     by default -- a privacy gate that echoes the leaked value into a
     public CI log has defeated itself. Pass --show-values locally when
     you need to see what tripped it.
  2  usage or I/O error.

USAGE
  python3 scripts/scrub.py capture.txt > scrubbed.txt
  python3 scripts/scrub.py capture.txt -o scrubbed.txt
  cat capture.txt | python3 scripts/scrub.py > scrubbed.txt
  python3 scripts/scrub.py --check tests/corpus/*.txt

Python 3 standard library only, on purpose: CI has to be able to run this
with no install step.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import sys

# ═════════════════════════════════════════════════════════════════════
#  ALLOWLIST -- things that are deliberately NOT scrubbed.
#
#  Edit this block, and only this block, when the scrubber eats something
#  it should have left alone.
#
#  Everything here is stock on every UniFi install. It carries no site
#  information, it is load-bearing for the OTTL in
#  collector/20-processors-logs.yaml, and it is worth keeping in a public
#  corpus as documentation of what the vendor actually emits. Scrubbing it
#  would break the fixtures AND make them less useful.
# ═════════════════════════════════════════════════════════════════════

ALLOWLIST_VALUES = frozenset(
    v.casefold()
    for v in (
        # -- vendor service accounts seen in sudo records. These are UniFi's
        #    own agents firing on a timer, not people. transform/device_syslog
        #    section 5 names them in a comment; keeping them makes the sudo
        #    fixtures readable.
        "uid",
        "ucs-update",
        "unifi-user-assets",
        "unifi-access",
        "root",
        # -- UniFi hardware model names. Vendor SKUs, not site data.
        "UDMPRO",
        "UDM-Pro",
        "UDMPROMAX",
        "UDR",
        "UDW",
        "USW-Lite-8",
        "USW-Lite-8-PoE",
        "USW-Flex-Mini",
        "USW-Pro-24-PoE",
        "U6-Pro",
        "U6-Lite",
        "U6-Mesh",
        "U7-Pro",
        "UAP-AC-Pro",
        # -- default interface / bridge names. Kernel and UniFi defaults.
        #    dhcp_iface in the DHCP pattern reads these straight through.
        "br0",
        "br1",
        "br2",
        "br3",
        "br4",
        "eth0",
        "eth1",
        "eth2",
        "eth3",
        "eth4",
        "eth5",
        "eth6",
        "eth7",
        "eth8",
        "eth9",
        "switch0",
        "lo",
        "wan",
        "lan",
        # -- default zone / network names.
        "Internet 1",
        "Internet 2",
        "Internal",
        "External",
        "Default",
        "Gateway Cluster",
        "VPN",
        "Hotspot",
        # -- UniFi's own event / category / policy vocabulary. These are the
        #    values the taxonomy in transform/unifi_ecs switches on, plus the
        #    IDS/IPS signature names that arrive in UNIFIpolicyName.
        "Scanning Activity",
        "Security",
        "Audit",
        "Client Devices",
        "Firewall",
        "IDS/IPS",
        "Network",
        "System",
        "Threat Management",
        "Honeypot",
        "Blocked by Firewall",
        "Allowed by Firewall",
        # -- CEF envelope literals.
        "CEF",
        "Ubiquiti",
        "UniFi Network",
        "UniFi OS",
    )
)

# Addresses that must survive untouched. 127.0.0.1 in particular is the
# UDM's OWN resolver (127.0.0.1:1053) -- it is load-bearing in a comment in
# transform/device_syslog section 3 and in the DNS destination mapping, and
# rewriting it would make that comment a lie.
#
# Public resolvers (8.8.8.8, 1.1.1.1, ...) are deliberately NOT here: they
# are usually a deliberate site configuration choice, so they get scrubbed
# by default. Add them if your corpus needs them readable.
PRESERVE_IP_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/32",  # the unspecified address
        "127.0.0.0/8",  # loopback, incl. the UDM's own resolver
        "255.255.255.255/32",  # broadcast; DHCP frames are full of it
        "224.0.0.0/4",  # IPv4 multicast (mDNS, IGMP)
        "::/128",
        "::1/128",
        "ff00::/8",  # IPv6 multicast
    )
)

# fe80::/10 is deliberately absent from the list above: an IPv6 link-local
# address usually embeds the interface MAC (EUI-64), so it is an identifier
# and gets scrubbed like any other address.

PRESERVE_MACS = frozenset(
    (
        "ff:ff:ff:ff:ff:ff",  # broadcast
        "00:00:00:00:00:00",  # unspecified
    )
)

# Dotted tokens whose final label is NOT a TLD. Gateway syslog is full of
# systemd unit names and file paths, and turning "ubios-udapi-server.service"
# into "xxxxxxxxxxxxxxxxxx.example.com" would be vandalism, not scrubbing.
NON_DOMAIN_SUFFIXES = frozenset(
    (
        # systemd units
        "service",
        "socket",
        "timer",
        "mount",
        "automount",
        "target",
        "slice",
        "scope",
        "device",
        "swap",
        "path",
        "netdev",
        "network",
        "link",
        # file extensions that show up in gateway log lines
        "so",
        "sh",
        "py",
        "conf",
        "cfg",
        "ini",
        "json",
        "yaml",
        "yml",
        "log",
        "pid",
        "sock",
        "key",
        "crt",
        "pem",
        "gz",
        "xz",
        "tar",
        "txt",
        "md",
        "db",
        "lock",
        "tmp",
        "bak",
        "old",
        "new",
        "bin",
        "img",
        "cfg",
    )
)

# CEF extension keys whose values are never touched. Vendor vocabulary,
# model numbers, version strings, timestamps and counters. UNIFIdeviceVersion
# in particular MUST be here: a four-part version like "4.3.10.1" is
# indistinguishable from an IPv4 literal to any regex.
PRESERVE_CEF_KEYS = frozenset(
    (
        "UNIFIcategory",
        "UNIFIpolicyType",
        "UNIFIdirection",
        "UNIFIrisk",
        "UNIFIutcTime",
        "UNIFIdeviceModel",
        "UNIFIsrcClientModel",
        "UNIFIconnectedToDeviceModel",
        "UNIFIlastConnectedToDeviceModel",
        "UNIFIdeviceVersion",
        "UNIFIconnectedToDeviceVersion",
        "UNIFIlastConnectedToDeviceVersion",
        "UNIFIlinkSpeed",
        "UNIFIduration",
        "UNIFIusageUp",
        "UNIFIusageDown",
        "UNIFItotalBytes",
        "UNIFItotalPackets",
        "UNIFIflowId",
        "UNIFIflowCount",
        "UNIFInetworkVlan",
        "UNIFIwifiBand",
        "UNIFIwifiChannel",
        "UNIFIwifiChannelWidth",
        "UNIFIWiFiRssi",
        "UNIFIwifiAirtimeUtilization",
        "UNIFIwifiInterference",
        "UNIFIlastConnectedToWiFiRssi",
        "UNIFIlastConnectedToWiFiChannel",
        "UNIFIlastConnectedToWiFiChannelWidth",
        "UNIFIlastConnectedToWiFiBand",
        "UNIFIconnectedToDevicePort",
        "UNIFIlastConnectedToDevicePort",
        "UNIFIaccessMethod",
        "UNIFIsettingsSection",
        "deviceInboundInterface",
        "deviceOutboundInterface",
        "act",
        "proto",
        "app",
        "spt",
        "dpt",
        "rt",
        "start",
        "end",
        "cat",
        "cs1Label",
        "cs2Label",
        "cs3Label",
        "cn1Label",
        "cn2Label",
    )
)

# CEF extension keys with a value handler. Anything not listed here and not
# in PRESERVE_CEF_KEYS gets the generic sweep (IP / MAC / domain / email
# only), which is what free-text keys like msg= and UNIFIsettingsChanges=
# want -- they must keep their prose and their punctuation.
CEF_VALUE_KINDS = {
    "UNIFIhost": "site",
    "UNIFIsrcClientHostname": "host",
    "UNIFIdstClientHostname": "host",
    "UNIFIclientHostname": "host",
    "UNIFIconnectedToDeviceName": "host",
    "UNIFIlastConnectedToDeviceName": "host",
    "UNIFIdeviceName": "host",
    "shost": "host",
    "dhost": "host",
    "dvchost": "host",
    "UNIFIsrcClientAlias": "alias",
    "UNIFIclientAlias": "alias",
    "UNIFIdstClientAlias": "alias",
    "UNIFIwifiName": "ssid",
    "UNIFIlastConnectedToWiFiName": "ssid",
    "UNIFIadmin": "user",
    "duser": "user",
    "suser": "user",
    "UNIFInetworkName": "net",
    "UNIFIsrcZone": "zone",
    "UNIFIdstZone": "zone",
    "UNIFIpolicyName": "pol",  # conditional -- see _scrub_cef_extensions
    "UNIFIispName": "isp",
    "UNIFIisp": "isp",
    "UNIFIsrcIsp": "isp",
    "UNIFIdstIsp": "isp",
    # WAN-status frames (UNIFIwanIsp) name the site's OWN provider, which is
    # the most identifying ISP field of the lot -- the others are usually a
    # remote party's. Missing here until 2026-08-14, which is how a real ISP
    # reached tests/corpus/real-network.txt. None of its UNIFIwan* siblings
    # need a rule: wanId/wanName/wanPort/wanSla/wanLatency are vendor
    # constants or numbers, and wanSubnet is caught by the generic sweep.
    "UNIFIwanIsp": "isp",
    "UNIFIdstCity": "geo",
    "UNIFIsrcCity": "geo",
    "UNIFIdstRegion": "geo_code",
    "UNIFIsrcRegion": "geo_code",
    "UNIFIdstCountry": "geo_code",
    "UNIFIsrcCountry": "geo_code",
    "UNIFIasn": "asn",
    "UNIFIdstAsn": "asn",
    "UNIFIsrcAsn": "asn",
    "UNIFInetworkSubnet": "cidr",
    # These three are addresses; the generic sweep would catch them anyway,
    # but naming them makes the finding kinds in --check output legible.
    "UNIFIdeviceIp": "ip",
    "UNIFIsrcClientIp": "ip",
    "UNIFIclientIp": "ip",
    "UNIFIconnectedToDeviceIp": "ip",
    "UNIFIlastConnectedToDeviceIp": "ip",
    "src": "ip",
    "dst": "ip",
    "UNIFIdeviceMac": "mac",
    "UNIFIsrcClientMac": "mac",
    "UNIFIclientMac": "mac",
    "UNIFIconnectedToDeviceMac": "mac",
    "UNIFIlastConnectedToDeviceMac": "mac",
    "UNIFIdstDomain": "domain",
    "UNIFIsrcDomain": "domain",
}

# JSON payload keys, scrubbed by key the same way CEF values are.
#
# Added after the first REAL capture, which is the whole argument for a
# hybrid corpus: `linkcheck` emits a pretty-printed speedtest result and
# none of this was reachable by the generic sweep, because none of it is
# address-shaped. A synthetic corpus could not have surfaced it -- nobody
# invents a fixture containing their own ISP.
#
# Why these are identifying, given they describe a speedtest SERVER
# rather than the household:
#
#   * a speedtest picks NEARBY servers, so the set of cities is a coarse
#     location fix on whoever is running it
#   * `timezone` is not the server's at all, it is the reporting device's
#     -- the same value this project already scrubs to Etc/UTC in the
#     collector config precisely because it is site-identifying
#   * provider / providerUrl name real companies and real domains
#
# coredns keys are listed too. The sweep already catches `domain`,
# `src_ip` and `mac` because they are address-shaped; naming them here
# makes the coverage intentional rather than incidental.
JSON_VALUE_KINDS = {
    # linkcheck / speedtest
    "provider": "isp",
    "providerUrl": "domain",
    "city": "geo",
    "region": "geo",
    "regionName": "geo",
    "country": "geo",
    "countryCode": "geo_code",
    "timezone": "tz",
    "latitude": "coord",
    "longitude": "coord",
    "lat": "coord",
    "lon": "coord",
    "isp": "isp",
    "org": "isp",
    "as": "asn",
    "asn": "asn",
    # coredns
    "domain": "domain",
    "src_ip": "ip",
    "dst_ip": "ip",
    "ip": "ip",
    "mac": "mac",
}

# Matches "key": value inside a JSON object, for string and numeric
# values. Deliberately tolerant of the pretty-printed one-pair-per-line
# form linkcheck emits: the frame arrives split across datagrams, so a
# whole-object json.loads is not available at this point.
_JSON_PAIR_RE = re.compile(
    r'"([A-Za-z_][A-Za-z0-9_]*)"(\s*:\s*)'
    r'(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?))'
)

# Every scrubbed coordinate becomes exactly this, which makes "is this
# scrubbed?" a trivial equality test for --check.
#
# The parsers DO read these now: since issue #9 the pair feeds
# destination.geo.location. Collapsing every server to null island is
# still right for a fixture -- the golden then asserts that the pair was
# parsed and mapped, which is the behaviour under test, rather than
# pinning a real location that would have to be scrubbed anyway. Do not
# add a "skip 0,0" guard to the config to make the fixture look tidier:
# that would leave the mapping untested.
SCRUBBED_COORD = "0.0"
SCRUBBED_TZ = "Etc/UTC"

# ═════════════════════════════════════════════════════════════════════
#  End of allowlist. Below here is machinery.
# ═════════════════════════════════════════════════════════════════════

DEFAULT_SALT = "unifi-otel/corpus-scrub/v1"

# Marker prefixes. Every name-like pseudonym starts with one of these, which
# is what makes the output recognisable as scrubbed (and therefore what makes
# --check exact). Keep them lowercase and hyphen-terminated.
PREFIXES = {
    "host": "host-",
    "site": "site-",
    "ssid": "ssid-",
    "alias": "alias-",
    "user": "user-",
    "isp": "isp-",
    "geo": "geo-",
    "net": "net-",
    "zone": "zone-",
    "pol": "pol-",
}

# Kinds allowed below the usual four-character floor for literal substitution,
# and the floor they get instead. See _remember for why this is only safe
# because _apply_literals anchors on non-word boundaries. Keep this set small
# and justified: every entry is a licence to rewrite two-character tokens
# throughout the corpus.
SHORT_LITERAL_KINDS = frozenset({"isp"})
SHORT_LITERAL_MIN = 2

_PSEUDONYM_RE = re.compile(
    r"^(?:" + "|".join(sorted(p[:-1] for p in PREFIXES.values())) + r")-"
    r"[0-9a-f]{2,}(?:\s+[0-9a-f]{2,})*$"
)

# RFC 5737. Private-scope addresses go in one /24, public-scope in another,
# and TEST-NET-1 is the shared overflow for whichever fills up first.
V4_POOL_PRIVATE = ipaddress.ip_network("198.51.100.0/24")
V4_POOL_PUBLIC = ipaddress.ip_network("203.0.113.0/24")
V4_POOL_OVERFLOW = ipaddress.ip_network("192.0.2.0/24")
V4_DOC_NETWORKS = (V4_POOL_PRIVATE, V4_POOL_PUBLIC, V4_POOL_OVERFLOW)

# RFC 3849.
V6_DOC_NETWORK = ipaddress.ip_network("2001:db8::/32")

# RFC 7042 s2.1.2: 00-00-5E-00-53-00 .. 00-00-5E-00-53-FF are reserved for
# documentation. That is 256 addresses, which is plenty for a fixture corpus
# but not for a large site, so anything past 256 spills into the
# locally-administered 02:00:5E:xx:xx:xx block (the 0x02 bit guarantees the
# result can never collide with a real IEEE assignment).
MAC_DOC_PREFIX = "00:00:5e:00:53:"
MAC_OVERFLOW_PREFIX = "02:00:5e:"

# RFC 5398 documentation ASNs (16-bit block).
ASN_DOC_LOW, ASN_DOC_HIGH = 64496, 64511

# RFC 2606 and friends. A name already ending in one of these is left alone,
# which is what makes domain scrubbing idempotent.
RESERVED_DOMAIN_SUFFIXES = (
    "example.com",
    "example.net",
    "example.org",
    "example.edu",
    "example",
    "test",
    "invalid",
    "localhost",
)

EXAMPLE_TLDS = ("com", "net", "org")

# ── Frame anatomy ────────────────────────────────────────────────────
# <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...   (RFC5424)
_RFC5424_HEAD = re.compile(r"^(<\d{1,3}>)(\d)(\s+)(\S+)(\s+)(\S+)(\s+)(.*)$", re.S)
# <PRI>Mmm DD HH:MM:SS rest                             (RFC3164; PRI optional
# because the receivers set allow_skip_pri_header: true)
_RFC3164_HEAD = re.compile(
    r"^(<\d{1,3}>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2})(\s+)(.*)$", re.S
)
_FIRST_TOKEN = re.compile(r"^(\S+)(\s*)(.*)$", re.S)
# What the RFC3164 parser will accept as a tag. Used only to decide whether a
# second bare word is a doubled hostname or the start of the message.
_TAGLIKE = re.compile(r"^[A-Za-z0-9_./-]+(?:\[[0-9]+\])?:$")

_CEF_START = re.compile(r"CEF:\d+\|")
# Seven envelope fields, then the extension string. Mirrors the regex_parser
# in collector/10-receivers-logs.yaml. The envelope is never rewritten.
_CEF_SPLIT = re.compile(r"^(CEF:\d+\|(?:[^|]*\|){6})(.*)$", re.S)
# The exact boundary transform/cef_extensions splits on: one whitespace byte
# followed by a CEF key. Expressed as a lookahead so the separator byte can be
# put back verbatim instead of being rewritten to a newline.
_CEF_BOUNDARY = re.compile(r"\s(?=[A-Za-z][A-Za-z0-9_]*=)")

# ── Value shapes ─────────────────────────────────────────────────────
_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:.-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])"
)
# Deliberately loose: this only produces CANDIDATES, and ipaddress does the
# deciding. A tight IPv6 regex is unreadable and gets it wrong anyway.
_IPV6_CAND_RE = re.compile(
    r"(?<![0-9A-Za-z:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?::(?:\d{1,3}\.){3}\d{1,3})?)(?![0-9A-Za-z:])"
)
_IPV4_RE = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9.])")
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24})"
)
_DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9._/@-])"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{1,23})"
    r"(?![A-Za-z0-9_/-])"
)
_HOMEDIR_RE = re.compile(r"(?<=/home/)([A-Za-z0-9._-]+)")

# The host of a URL. _DOMAIN_RE deliberately refuses to match after "/" so
# that it cannot eat a path segment (/usr/lib/thing.sh), and the price of
# that is it cannot see the host in "https://example.co.uk" either. This
# rule pays it back, anchored tightly on "://" so it can only ever fire on
# a real authority component.
#
# Found by the first real capture: linkcheck's providerUrl carried live
# company domains straight through a scrub that reported success.
_URL_HOST_RE = re.compile(r"(?<=://)([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)")

# ── Positional shapes inside the message body ────────────────────────
# dnsmasq-dhcp. Mirrors the ExtractPatterns in transform/device_syslog
# section 4, including the optional-IP branch that lets DHCPDISCOVER put a
# MAC where its siblings put an address. Only the trailing hostname is
# rewritten here; the IP and MAC fall to the generic sweep.
_DHCP_RE = re.compile(
    r"(DHCP[A-Z]+\([^)]+\)\s+(?:\d{1,3}(?:\.\d{1,3}){3}\s+)?[0-9a-fA-F:]{17})(\s+)(\S+)"
)
# sudo, shape 1-3: "<user> : [middle ;] PWD=... ; USER=... ; COMMAND=..."
_SUDO_ACTOR_RE = re.compile(r"(\bsudo(?:\[\d+\])?:\s+)(\S+)(\s+:\s+)")
_SUDO_TARGET_RE = re.compile(r"(\bUSER=)([^\s;]+)")
# sudo, shape 4: pam_unix auth failure. No COMMAND= to anchor on; the account
# arrives as a trailing "user=<name>", with ruser=/logname= often empty.
_PAM_USER_RE = re.compile(r"\b((?:r|log)?user=|logname=)([^\s;]+)")


def _looks_like_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


class Finding:
    __slots__ = ("path", "line", "kind", "value")

    def __init__(self, path, line, kind, value):
        self.path = path
        self.line = line
        self.kind = kind
        self.value = value

    def render(self, show_values: bool) -> str:
        if show_values:
            shown = self.value
        else:
            # The head is a reading aid, and must never BE the value: a
            # two-letter carrier brand was printed in full by the very gate
            # that exists to keep it out of public CI logs. Anything short
            # enough for the head to give it away is redacted whole.
            head = self.value[:2] if len(self.value) > 4 else ""
            # Count what is HIDDEN, not the total length -- the old wording
            # read as "<head> plus N more characters" when N was the whole
            # value, overstating how much had actually been withheld.
            shown = "{}<redacted {} chars>".format(head, len(self.value) - len(head))
        return "{}:{}: {}: {}".format(self.path, self.line, self.kind, shown)


class Scrubber:
    """Holds the value->pseudonym tables for one run.

    One instance per invocation, shared across every input file, so that a
    MAC in capture-a.txt and the same MAC in capture-b.txt still correlate.
    """

    def __init__(self, salt: str = DEFAULT_SALT):
        self._salt = salt.encode("utf-8")
        self._v4_map: dict[str, str] = {}
        self._v4_used: set[str] = set()
        self._mac_map: dict[str, str] = {}
        self._mac_used: set[str] = set()
        # Shared by every name-like kind so one string never gets two
        # pseudonyms -- see _scrub_name.
        self._name_map: dict[str, str] = {}
        # Original literal -> pseudonym, for the second pass. Structured
        # fields tell us a client is called "Toms-iPhone"; the msg= prose on
        # a different frame mentions it too, and only this table can catch it.
        self._literals: dict[str, str] = {}
        self.findings: list[Finding] = []
        self._path = "<stdin>"
        self._line = 0
        self._record = False

    # ── hashing ──────────────────────────────────────────────────────
    def _digest(self, namespace: str, value: str) -> str:
        h = hashlib.blake2b(digest_size=16)
        h.update(self._salt)
        h.update(b"\x00")
        h.update(namespace.encode("utf-8"))
        h.update(b"\x00")
        # casefold so "AA:BB:.." and "aa:bb:.." are the same device, and so a
        # hostname that arrives capitalised in one dataset and lowercase in
        # another still joins.
        h.update(value.casefold().encode("utf-8", "surrogatepass"))
        return h.hexdigest()

    @staticmethod
    def _hexpad(digest: str, width: int) -> str:
        return (digest * (width // len(digest) + 1))[:width]

    # ── bookkeeping ──────────────────────────────────────────────────
    def _note(self, kind: str, value: str) -> None:
        if self._record:
            self.findings.append(Finding(self._path, self._line, kind, value))

    def _remember(self, original: str, replacement: str, kind: str = "") -> None:
        # Short strings make terrible literals: a three-character hostname
        # would carpet-bomb the corpus. Allowlisted values never enter the
        # table, and neither does anything that is a word inside an
        # allowlisted phrase ("Internet" must not eat "Internet 1").
        #
        # ISP names are the exception, and need their own floor: national
        # carriers routinely have two-letter brand names, so the blanket
        # minimum silently excluded exactly the values most worth catching
        # in prose. WAN-status frames put the provider in UNIFIwanIsp= and
        # then again inside msg=, as "Internet connection WAN1 (<isp>) went
        # down ...", so the field rule alone leaves the name sitting in the
        # sentence. Safe to lower only because _apply_literals anchors every
        # match between non-word characters, so a two-letter literal cannot
        # bite into a longer token.
        #
        # No real provider name appears in this comment on purpose: an
        # example here would reintroduce, in the clear, the leak the rule
        # exists to close.
        minimum = SHORT_LITERAL_MIN if kind in SHORT_LITERAL_KINDS else 4
        if len(original) < minimum or original == replacement:
            return
        low = original.casefold()
        if low in ALLOWLIST_VALUES:
            return
        for allowed in ALLOWLIST_VALUES:
            if low in allowed.split():
                return
        self._literals[original] = replacement

    @staticmethod
    def _allowlisted(value: str) -> bool:
        return value.casefold() in ALLOWLIST_VALUES

    # ── pseudonyms ───────────────────────────────────────────────────
    def _is_pseudonym(self, value: str) -> bool:
        return bool(_PSEUDONYM_RE.match(value))

    def _pseudonym(self, kind: str, value: str, width: int | None = None) -> str:
        prefix = PREFIXES[kind]
        width = len(value) if width is None else width
        # Floor of prefix+3 so the marker survives on a two-character name.
        body = max(3, width - len(prefix))
        return prefix + self._hexpad(self._digest(kind, value), body)

    def _pseudonym_phrase(self, kind: str, value: str) -> str:
        """Length- and whitespace-preserving pseudonym for a possibly multi-word
        value. The first word carries the marker prefix; later words are bare
        hex of their own length. Interior whitespace bytes are copied through
        verbatim, so a spaced SSID stays a spaced SSID and keeps exercising
        the transform/cef_extensions boundary rule."""
        if self._is_pseudonym(value):
            return value
        out = []
        word_index = 0
        for chunk in re.split(r"(\s+)", value):
            if not chunk:
                continue
            if chunk.isspace():
                out.append(chunk)
                continue
            if word_index == 0:
                out.append(self._pseudonym(kind, value, len(chunk)))
            else:
                # Hash the WHOLE value, not the word, so the mapping is stable
                # and the words of one name cannot collide with another's.
                out.append(
                    self._hexpad(
                        self._digest("{}#{}".format(kind, word_index), value),
                        max(2, len(chunk)),
                    )
                )
            word_index += 1
        return "".join(out)

    def _scrub_name(self, kind: str, value: str) -> str:
        if not value or self._allowlisted(value) or self._is_pseudonym(value):
            return value
        if _looks_like_ip(value):
            return self._scrub_ip_text(value)
        # An admin "name" is routinely an email address; route it through the
        # email path so the same account scrubs identically whether it arrives
        # in UNIFIadmin= or in the middle of a msg= sentence.
        if "@" in value and _EMAIL_RE.fullmatch(value):
            return self._sweep(value)
        # A "hostname" with dots is a domain; route it so that the same string
        # maps identically wherever it turns up.
        if "." in value and _DOMAIN_RE.fullmatch(value):
            return self._scrub_domain(value)
        # ONE table for every name-like kind, keyed on the value alone. A site
        # that names a network and a zone the same thing must not get two
        # different pseudonyms for the one string -- inconsistency there is
        # indistinguishable from a scrubber bug when you are reading a diff.
        # First kind to see a value picks the marker prefix; that is stable for
        # a given input because the file is walked in order.
        cached = self._name_map.get(value.casefold())
        if cached is not None:
            if cached != value:
                self._note(kind, value)
            return cached
        replacement = self._pseudonym_phrase(kind, value)
        self._name_map[value.casefold()] = replacement
        if replacement != value:
            self._note(kind, value)
            self._remember(value, replacement, kind)
        return replacement

    # ── addresses ────────────────────────────────────────────────────
    def _scrub_ip_text(self, text: str) -> str:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        return self._scrub_ipv6(ip) if ip.version == 6 else self._scrub_ipv4(ip)

    def _scrub_ipv4(self, ip: ipaddress.IPv4Address) -> str:
        for net in PRESERVE_IP_NETWORKS:
            if net.version == 4 and ip in net:
                return str(ip)
        for net in V4_DOC_NETWORKS:
            if ip in net:
                return str(ip)  # already scrubbed
        key = str(ip)
        if key in self._v4_map:
            return self._v4_map[key]
        primary = V4_POOL_PRIVATE if (ip.is_private or ip.is_link_local) else V4_POOL_PUBLIC
        # Scope is preserved across the rewrite: RFC1918-ish addresses land in
        # 198.51.100/24 and routable ones in 203.0.113/24, so a reader of the
        # scrubbed corpus can still tell inside from outside. TEST-NET-1 is
        # only reached once the scope's own /24 is full.
        base = int(self._digest("ipv4", key)[:8], 16)
        for pool in (primary, V4_POOL_OVERFLOW):
            candidates = [str(host) for host in pool.hosts()]
            # Hash picks the starting slot; linear probing only ever moves a
            # value when a DIFFERENT value already sits there. Same input =>
            # same probe order => same output, which is the cross-run
            # guarantee that matters. Adding new frames can, in the rare
            # collision case, shift one address; the mapping stays internally
            # consistent, which is what related.* needs.
            for offset in range(len(candidates)):
                candidate = candidates[(base + offset) % len(candidates)]
                if candidate not in self._v4_used:
                    self._v4_used.add(candidate)
                    self._v4_map[key] = candidate
                    self._note("ipv4", key)
                    return candidate
        raise SystemExit(
            "scrub.py: RFC 5737 pools exhausted (>500 distinct IPv4 addresses "
            "of one scope). Widen V4_POOL_* or split the capture."
        )

    def _scrub_ipv6(self, ip: ipaddress.IPv6Address) -> str:
        for net in PRESERVE_IP_NETWORKS:
            if net.version == 6 and ip in net:
                return str(ip)
        if ip in V6_DOC_NETWORK:
            return str(ip)  # already scrubbed
        key = ip.compressed
        digest = self._digest("ipv6", key)
        # 2001:db8:<16 hex>::<4 hex>. 2^64 of space, so no probing is needed:
        # a collision here is not a thing that happens to a log corpus.
        out = "2001:db8:{}:{}:{}::{}".format(
            digest[0:4], digest[4:8], digest[8:12], digest[12:16]
        )
        self._note("ipv6", key)
        return str(ipaddress.IPv6Address(out))

    def _scrub_mac(self, text: str) -> str:
        sep = "-" if "-" in text else ":"
        normalised = text.casefold().replace("-", ":")
        if normalised in PRESERVE_MACS:
            return text
        if normalised.startswith(MAC_DOC_PREFIX) or normalised.startswith(
            MAC_OVERFLOW_PREFIX
        ):
            return text  # already scrubbed
        if normalised in self._mac_map:
            replacement = self._mac_map[normalised]
        else:
            digest = self._digest("mac", normalised)
            replacement = None
            base = int(digest[:4], 16)
            for offset in range(256):
                candidate = MAC_DOC_PREFIX + "{:02x}".format((base + offset) % 256)
                if candidate not in self._mac_used:
                    replacement = candidate
                    break
            if replacement is None:
                # Documentation block full. Locally-administered space next:
                # 2^24 slots, still deterministic, still never a real OUI.
                base = int(digest[4:10], 16)
                for offset in range(1 << 24):
                    tail = "{:06x}".format((base + offset) % (1 << 24))
                    candidate = MAC_OVERFLOW_PREFIX + ":".join(
                        (tail[0:2], tail[2:4], tail[4:6])
                    )
                    if candidate not in self._mac_used:
                        replacement = candidate
                        break
            self._mac_used.add(replacement)
            self._mac_map[normalised] = replacement
            self._note("mac", text)
        # Put back the separator and the case the capture used. 17 bytes in,
        # 17 bytes out -- the dhcp_mac pattern counts them.
        replacement = replacement.replace(":", sep)
        if any(c.isupper() for c in text):
            replacement = replacement.upper()
        return replacement

    # ── domains ──────────────────────────────────────────────────────
    @staticmethod
    def _is_scrubbed_domain(low: str) -> bool:
        return any(
            low == suffix or low.endswith("." + suffix)
            for suffix in RESERVED_DOMAIN_SUFFIXES
        )

    def _scrub_domain(self, name: str) -> str:
        trailing = ""
        if name.endswith("."):
            name, trailing = name[:-1], "."
        low = name.casefold()
        labels = low.split(".")
        if len(labels) < 2:
            return name + trailing
        if labels[-1] in NON_DOMAIN_SUFFIXES:
            return name + trailing
        if self._is_scrubbed_domain(low):
            return name + trailing
        if self._allowlisted(name):
            return name + trailing

        # Reverse-DNS names keep their shape: map the embedded address and
        # re-reverse it, so a PTR query still looks like a PTR query.
        if low.endswith(".in-addr.arpa") and len(labels) == 6:
            if all(part.isdigit() for part in labels[:4]):
                original_ip = ".".join(reversed(labels[:4]))
                mapped = self._scrub_ip_text(original_ip)
                if mapped != original_ip:
                    self._note("domain", name)
                return ".".join(reversed(mapped.split("."))) + ".in-addr.arpa" + trailing

        registrable = ".".join(labels[-2:])
        tld = EXAMPLE_TLDS[int(self._digest("domtld", registrable)[:8], 16) % len(EXAMPLE_TLDS)]
        # Label COUNT preserved; each label left of the registrable domain
        # keeps its own length. The registrable domain becomes example.<tld>,
        # which is where length preservation stops (see the module docstring).
        rebuilt = [
            self._hexpad(self._digest("domlabel", label), max(1, len(label)))
            for label in labels[:-2]
        ]
        rebuilt.extend(("example", tld))
        # Deliberately NOT added to the literal table: the generic sweep already
        # finds a domain wherever one appears, and a literal rule would also
        # fire inside PRESERVE_CEF_KEYS values, which are meant to be untouched.
        self._note("domain", name + trailing)
        return ".".join(rebuilt) + trailing

    # ── misc value kinds ─────────────────────────────────────────────
    def _scrub_asn(self, value: str) -> str:
        match = re.fullmatch(r"(AS)?(\d+)", value, re.I)
        if not match:
            return self._scrub_name("isp", value)
        number = int(match.group(2))
        if ASN_DOC_LOW <= number <= ASN_DOC_HIGH:
            return value  # already scrubbed
        span = ASN_DOC_HIGH - ASN_DOC_LOW + 1
        replacement = ASN_DOC_LOW + int(self._digest("asn", value)[:8], 16) % span
        self._note("asn", value)
        return (match.group(1) or "") + str(replacement)

    def _scrub_geo_code(self, value: str) -> str:
        # ISO 3166-1 reserves ZZ for user assignment, so it can never be a
        # real country. Two bytes in, two bytes out.
        if len(value) == 2 and value.isalpha():
            if value.upper() == "ZZ":
                return value
            self._note("geo_code", value)
            return "ZZ" if value.isupper() else "zz"
        return self._scrub_name("geo", value)

    def _scrub_cidr(self, value: str) -> str:
        """A subnet, e.g. UNIFInetworkSubnet=10.80.0.0/24.

        Mapped to the documentation /24 with the host bits zeroed, so the
        result is still a well-formed network with the original prefix length.
        Limitation, stated plainly: every private subnet in a capture collapses
        onto the same documentation network, because RFC 5737 does not give us
        enough space to keep them distinct. Subnet identity is not a join key
        for any dataset in this collector, so nothing downstream notices."""
        match = re.fullmatch(r"([0-9A-Fa-f:.]+)/(\d{1,3})", value)
        if not match:
            return value
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value
        if any(network.subnet_of(doc) for doc in V4_DOC_NETWORKS if doc.version == network.version):
            return value  # already scrubbed
        if network.version == 6:
            self._note("cidr", value)
            return "2001:db8::/{}".format(match.group(2))
        pool = V4_POOL_PRIVATE if network.network_address.is_private else V4_POOL_PUBLIC
        self._note("cidr", value)
        return "{}/{}".format(pool.network_address, match.group(2))

    def _scrub_by_kind(self, kind: str, value: str) -> str:
        if not value:
            return value
        if kind == "ip":
            return self._sweep(value)
        if kind == "mac":
            return self._sweep(value)
        if kind == "domain":
            return self._sweep(value)
        if kind == "asn":
            return self._scrub_asn(value)
        if kind == "geo_code":
            return self._scrub_geo_code(value)
        if kind == "cidr":
            return self._scrub_cidr(value)
        if kind == "tz":
            return self._scrub_tz(value)
        if kind == "coord":
            return self._scrub_coord(value)
        return self._scrub_name(kind, value)

    def _scrub_tz(self, value: str) -> str:
        # Etc/UTC is what the collector config itself defaults to, so a
        # scrubbed fixture and the shipped default agree. Already-scrubbed
        # input passes through, which is what keeps --check exact.
        if value == SCRUBBED_TZ:
            return value
        self._note("timezone", value)
        return SCRUBBED_TZ

    def _scrub_coord(self, value: str) -> str:
        # Numeric in, numeric out, so the JSON stays well-formed and the
        # value keeps its type. Any coordinate that is not the placeholder
        # is by definition unscrubbed, which is the whole detection rule.
        if value == SCRUBBED_COORD:
            return value
        self._note("coordinate", value)
        return SCRUBBED_COORD

    def _scrub_json_pairs(self, text: str) -> str:
        """Rewrite "key": value pairs whose key is in JSON_VALUE_KINDS.

        Runs before the generic sweep so that key-directed handling wins:
        `providerUrl` should go through the domain mapping as a domain,
        not be half-rewritten as an incidental URL.
        """
        if '"' not in text:
            return text

        def _one(match):
            key, sep = match.group(1), match.group(2)
            svalue, nvalue = match.group(3), match.group(4)
            kind = JSON_VALUE_KINDS.get(key)
            if not kind:
                return match.group(0)
            if nvalue is not None:                       # bare number
                return f'"{key}"{sep}{self._scrub_by_kind(kind, nvalue)}'
            return f'"{key}"{sep}"{self._scrub_by_kind(kind, svalue)}"'

        return _JSON_PAIR_RE.sub(_one, text)

    # ── the generic sweep ────────────────────────────────────────────
    def _sweep(self, text: str) -> str:
        """Rewrite every address-, MAC-, email- and domain-shaped substring.

        Order is load-bearing: MACs before IPv6 (both are colon-separated hex),
        IPv6 before IPv4, emails before domains."""
        if not text:
            return text
        text = _MAC_RE.sub(lambda m: self._scrub_mac(m.group(1)), text)

        def _v6(match):
            candidate = match.group(1)
            try:
                ip = ipaddress.IPv6Address(candidate)
            except ValueError:
                return candidate  # a timestamp, or a MAC-ish thing; leave it
            return self._scrub_ipv6(ip)

        text = _IPV6_CAND_RE.sub(_v6, text)

        def _v4(match):
            candidate = match.group(1)
            try:
                ip = ipaddress.IPv4Address(candidate)
            except ValueError:
                return candidate
            return self._scrub_ipv4(ip)

        text = _IPV4_RE.sub(_v4, text)

        def _email(match):
            # The local part is a person; it is scrubbed as a username but NOT
            # through _scrub_name, because "firstname.surname" would otherwise
            # be mistaken for a domain (surname looks exactly like a TLD).
            local, domain = match.group(1), match.group(2)
            if self._is_pseudonym(local):
                new_local = local
            else:
                new_local = self._name_map.get(local.casefold())
                if new_local is None:
                    new_local = self._pseudonym("user", local)
                    self._name_map[local.casefold()] = new_local
                    self._remember(local, new_local)
                self._note("user", local)
            return new_local + "@" + self._scrub_domain(domain)

        text = _EMAIL_RE.sub(_email, text)

        def _url_host(match):
            host = match.group(1)
            if "." not in host:
                return host          # bare hostname, no registrable domain
            try:
                ipaddress.ip_address(host)
                return host          # already rewritten by the IP rules above
            except ValueError:
                return self._scrub_domain(host)

        text = _URL_HOST_RE.sub(_url_host, text)
        text = _DOMAIN_RE.sub(lambda m: self._scrub_domain(m.group(1)), text)
        text = _HOMEDIR_RE.sub(lambda m: self._scrub_name("user", m.group(1)), text)
        return text

    # ── CEF ──────────────────────────────────────────────────────────
    def _scrub_cef_extensions(self, extensions: str) -> str:
        # Split exactly where transform/cef_extensions splits, but keep the
        # separator byte rather than rewriting it to a newline. Reassembly is
        # therefore byte-identical apart from the values themselves.
        segments = []
        position = 0
        for match in _CEF_BOUNDARY.finditer(extensions):
            segments.append((extensions[position : match.start()], match.group(0)))
            position = match.end()
        segments.append((extensions[position:], ""))

        parsed = []
        for segment, separator in segments:
            key, sep, value = segment.partition("=")
            parsed.append([key, sep, value, separator])
        by_key = {item[0]: item[2] for item in parsed if item[1]}

        for item in parsed:
            key, sep, value, _separator = item
            if not sep:
                continue  # not a key=value segment; leave it exactly as-is
            if key in PRESERVE_CEF_KEYS:
                continue
            kind = CEF_VALUE_KINDS.get(key)
            if kind == "pol":
                # UNIFIpolicyName is two different things wearing one key. On
                # an IDS/IPS record it is the signature name ("Scanning
                # Activity") -- vendor vocabulary, worth keeping, and named in
                # the taxonomy comments. On a Firewall record it is a rule the
                # operator named, which routinely embeds a site, a person or a
                # device. So: keep it when the sibling UNIFIpolicyType says
                # IDS/IPS, scrub it otherwise.
                if by_key.get("UNIFIpolicyType") == "IDS/IPS":
                    continue
            if kind:
                item[2] = self._scrub_by_kind(kind, value)
            else:
                # Free text (msg=, UNIFIsettingsChanges=, unknown keys): keep
                # the prose and the punctuation, rewrite only the identifiers.
                item[2] = self._sweep(value)

        return "".join(
            (key + sep + value + separator) for key, sep, value, separator in parsed
        )

    def _scrub_cef_frame(self, text: str) -> str:
        match = _CEF_SPLIT.match(text)
        if not match:
            return self._sweep(text)
        envelope, extensions = match.group(1), match.group(2)
        # The envelope (version|vendor|product|device-version|signature|name|
        # severity) is pure vendor vocabulary and is never touched. event.code,
        # event.action and observer.* all come straight out of it.
        return envelope + self._scrub_cef_extensions(extensions)

    # ── message body, non-CEF ────────────────────────────────────────
    def _scrub_message(self, text: str) -> str:
        # JSON pairs first, so a key-directed rule wins over the generic
        # sweep. This also catches linkcheck CONTINUATION lines, which have
        # no syslog header at all and arrive here via _scrub_body -- each
        # pretty-printed line is its own datagram, so there is never a
        # whole JSON object to parse.
        text = self._scrub_json_pairs(text)

        # DHCP: only the trailing client-supplied hostname is positional. The
        # IP and MAC are ordinary tokens and the sweep gets them, which is
        # exactly what keeps DHCPDISCOVER (MAC in the IP's slot) intact --
        # nothing here cares which slot they are in.
        def _dhcp(match):
            head, gap, host = match.group(1), match.group(2), match.group(3)
            return head + gap + self._scrub_name("host", host)

        text = _DHCP_RE.sub(_dhcp, text)

        if "sudo" in text:
            text = _SUDO_ACTOR_RE.sub(
                lambda m: m.group(1) + self._scrub_name("user", m.group(2)) + m.group(3),
                text,
            )
            text = _SUDO_TARGET_RE.sub(
                lambda m: m.group(1) + self._scrub_name("user", m.group(2)), text
            )
            text = _PAM_USER_RE.sub(
                lambda m: m.group(1) + self._scrub_name("user", m.group(2)), text
            )
        return self._sweep(text)

    # ── frame ────────────────────────────────────────────────────────
    def _scrub_after_header(self, rest: str) -> str:
        """`rest` is everything after the RFC3164 PRI+timestamp: the hostname,
        possibly a SECOND hostname, possibly a tag, then the message."""
        match = _FIRST_TOKEN.match(rest)
        if not match:
            return self._scrub_message(rest)
        host1, gap1, tail = match.group(1), match.group(2), match.group(3)
        new_host1 = self._scrub_name("host", host1)

        # The doubled hostname. The RFC3164 parser consumes host1, decides the
        # second word is not a tag (no colon), and leaves appname unset with
        # the word still inside `message` -- which is precisely the malformity
        # the fixture is there to prove. It has to come out doubled, and it has
        # to come out IDENTICAL, or transform/device_syslog's lazy
        # (?:\S+\s+)*? prefix stops exercising the case it was written for.
        second = _FIRST_TOKEN.match(tail)
        if second:
            host2, gap2, remainder = second.group(1), second.group(2), second.group(3)
            is_doubled = ":" not in host2 and (
                host2 == host1
                or bool(_TAGLIKE.match((remainder.split(None, 1) or [""])[0]))
            )
            if is_doubled and gap2:
                # Same input string => same pseudonym, so the doubling holds.
                new_host2 = self._scrub_name("host", host2)
                return new_host1 + gap1 + new_host2 + gap2 + self._scrub_body(remainder)
        return new_host1 + gap1 + self._scrub_body(tail)

    def _scrub_body(self, text: str) -> str:
        if _CEF_START.match(text):
            return self._scrub_cef_frame(text)
        return self._scrub_message(text)

    def scrub_frame(self, frame: str) -> str:
        match = _RFC5424_HEAD.match(frame)
        if match and (match.group(4)[:4].isdigit() or match.group(4) == "-"):
            pri, version, sp1, timestamp, sp2, hostname, sp3, rest = match.groups()
            return (
                pri
                + version
                + sp1
                + timestamp
                + sp2
                + self._scrub_name("host", hostname)
                + sp3
                + self._scrub_body(rest)
            )

        match = _RFC3164_HEAD.match(frame)
        if match:
            pri, timestamp, gap, rest = match.groups()
            return (pri or "") + timestamp + gap + self._scrub_after_header(rest)

        # No recognisable header: a bare JSON blob, a continuation line, or
        # something malformed. Sweep it and change nothing else -- the whole
        # point of allow_skip_pri_header is that these frames survive.
        return self._scrub_body(frame)

    # ── literals pass ────────────────────────────────────────────────
    def _apply_literals(self, text: str) -> str:
        for original in sorted(self._literals, key=len, reverse=True):
            replacement = self._literals[original]
            if original not in text:
                continue
            pattern = r"(?<![A-Za-z0-9_])" + re.escape(original) + r"(?![A-Za-z0-9_])"
            new_text, count = re.subn(pattern, replacement.replace("\\", "\\\\"), text)
            if count:
                self._note("name-in-text", original)
                text = new_text
        return text

    # ── public entry point ───────────────────────────────────────────
    def scrub_lines(self, lines, path: str, apply_literals: bool, record: bool):
        self._path = path
        self._record = record
        out = []
        for index, line in enumerate(lines, start=1):
            self._line = index
            body = line.rstrip("\r\n")
            eol = line[len(body) :]
            if not body.strip():
                out.append(line)
                continue
            scrubbed = self.scrub_frame(body)
            if apply_literals:
                scrubbed = self._apply_literals(scrubbed)
            out.append(scrubbed + eol)
        self._record = False
        return out


def _read(path: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines(keepends=True)
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as handle:
        return handle.read().splitlines(keepends=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="scrub.py",
        description="Scrub a UniFi syslog capture: rewrite values, preserve structure.",
        epilog="Exit codes: 0 clean, 1 findings (--check), 2 usage/IO error.",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        default=["-"],
        help="capture file(s), or - / omitted for stdin",
    )
    parser.add_argument(
        "-o", "--output", help="write here instead of stdout (ignored with --check)"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="dry run: exit 1 if anything still looks unscrubbed. This is the "
        "CI corpus privacy gate; nothing is written.",
    )
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="with --check, print the offending values in full instead of "
        "redacting them. Do NOT use in public CI.",
    )
    parser.add_argument(
        "--salt",
        default=os.environ.get("UNIFI_SCRUB_SALT", DEFAULT_SALT),
        help="hash salt. Defaults to a public constant so the reference "
        "corpus is reproducible; supply your own (and keep it) when "
        "scrubbing a capture you intend to publish.",
    )
    args = parser.parse_args(argv)

    inputs = args.inputs or ["-"]
    scrubber = Scrubber(salt=args.salt)

    try:
        documents = [(path, _read(path)) for path in inputs]
    except OSError as error:
        sys.stderr.write("scrub.py: {}\n".format(error))
        return 2

    # Pass 1 builds the tables (including the literal table) across every
    # input; pass 2 does the rewriting with literals enabled and is the only
    # pass that records findings. Two passes because a name learned from a
    # structured field on line 900 has to be redacted from the msg= prose on
    # line 3.
    for path, lines in documents:
        scrubber.scrub_lines(lines, path, apply_literals=False, record=False)

    results = [
        (path, scrubber.scrub_lines(lines, path, apply_literals=True, record=True))
        for path, lines in documents
    ]

    if args.check:
        if not scrubber.findings:
            sys.stderr.write(
                "scrub.py: OK -- {} file(s) contain nothing that looks unscrubbed\n".format(
                    len(documents)
                )
            )
            return 0
        for finding in scrubber.findings:
            sys.stdout.write(finding.render(args.show_values) + "\n")
        sys.stderr.write(
            "scrub.py: FAIL -- {} unscrubbed value(s) across {} file(s). "
            "Run `python3 scripts/scrub.py <file> -o <file>` before committing.\n".format(
                len(scrubber.findings), len(documents)
            )
        )
        return 1

    payload = "".join("".join(lines) for _path, lines in results)
    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8", errors="surrogateescape") as handle:
                handle.write(payload)
        else:
            sys.stdout.write(payload)
    except OSError as error:
        sys.stderr.write("scrub.py: {}\n".format(error))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
