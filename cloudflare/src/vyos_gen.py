"""
VyOS + BIRD configuration generation.
Uses Jinja2 templates for command/config generation.
"""

import hashlib
import ipaddress
import os
import re
from jinja2 import Environment, FileSystemLoader

from cache import validate_asn, TIER1_ASNS
from github import resolve_router_id

# Initialize Jinja2 environment for VyOS scripts
template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vyos')
env = Environment(loader=FileSystemLoader(template_path), trim_blocks=True, lstrip_blocks=True)

# Initialize Jinja2 environment for BIRD configuration
bird_template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bird')
bird_env = Environment(loader=FileSystemLoader(bird_template_path), trim_blocks=True, lstrip_blocks=True)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def is_ip(s):
    """Check whether a string is a valid IP address.

    Input: s — a candidate address string.
    Return: True if it parses as an IPv4 or IPv6 address, else False.
    """
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_unnumbered(s):
    """Check whether a string is a BIRD unnumbered neighbor address.

    Input: s — a candidate neighbor-address string.
    Return: True if it has the form "<link-local-IPv6>%<iface>" (e.g.
    "fe80::1%wg"), which BIRD accepts for unnumbered / interface BGP. Plain
    IPs and bare interface names return False.
    """
    if "%" not in str(s):
        return False
    addr, _, iface = str(s).partition("%")
    if not iface:
        return False
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.version == 6 and ip.is_link_local


def is_range(s):
    """Check whether a string is a BIRD dynamic-BGP neighbor range.

    Input: s — a candidate neighbor-address string.
    Return: the prefix string (e.g. "fe80::/64") if `s` has the form
    "range <prefix>" with a valid network, else None. Used to render
    `neighbor range <prefix> as <asn>` (dynamic BGP).
    """
    s = str(s).strip()
    if not s.startswith("range "):
        return None
    prefix = s[len("range "):].strip()
    try:
        ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    return prefix


def is_interface(s):
    """Check whether a string is a bare interface name (unnumbered auto-peering).

    Input: s — a candidate neighbor-address string.
    Return: True for a plain interface name like "wg1242" or "eth5" (letter
    then word chars / dot / dash; no IP punctuation, no "%", no "range ").
    Such a neighbor triggers auto RAdv + dynamic BGP over fe80::/64.
    """
    s = str(s)
    return bool(re.fullmatch(r"[A-Za-z][\w.-]*", s)) and not is_ip(s)


def get_neighbor_id(cs, neighbor):
    """Derive a stable unique numeric ID (nid) for a neighbor.

    Input: cs — the CacheStore (its neighbor_id_hashmap is read+written);
    neighbor — a neighbor dict (uses its "asn" and "neighbor-address").
    Return: an int nid in [1, 65536], a hash of ASN + sorted addresses.

    Side effect: records nid -> raw-key in cs.neighbor_id_hashmap. Raises
    ValueError on a hash collision (two different neighbors mapping to the
    same nid).
    """
    addrs = neighbor["neighbor-address"]
    if not isinstance(addrs, list):
        addrs = [addrs]
    raw = (str(neighbor["asn"]) if "asn" in neighbor else "") + "".join(sorted(addrs))
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    nid = 1 + int(h[-4:], 16)
    if nid in cs.neighbor_id_hashmap and cs.neighbor_id_hashmap[nid] != raw:
        raise ValueError("hash collision")
    cs.neighbor_id_hashmap[nid] = raw
    return nid


def ipv4_to_engineid(ipv4):
    """Encode an IPv4 address as an SNMP v3 engine-ID string.

    Input: ipv4 — a dotted-quad IPv4 string (e.g. "192.0.2.254").
    Return: "000000000000" + each octet zero-padded to 3 digits
    (e.g. "000000000000192000002254").
    """
    return "000000000000" + "".join(part.zfill(3) for part in ipv4.split("."))


# ---------------------------------------------------------------------------
# Pre-processing pass
# ---------------------------------------------------------------------------
#
# Template rendering is pure, so nothing fills in the derived state the
# templates rely on (cs.bad_asn_set, neighbor ids, local prefix lists, etc.).
# This pass computes that state before any template runs.


def _local_asn_prefixes(cs, ipversion):
    """Build the local-ASN prefix-set members for a `define` in policy.bird.j2.

    Input: cs — the CacheStore (reads cs.local_asn and cs.prefix_matrix_map);
    ipversion — 4 or 6.
    Return: a list of BIRD prefix strings for the local ASN's announced
    prefixes, e.g. ["203.0.113.0/24{24,32}", ...]. A prefix renders bare
    (no {ge,le}) when ge == len == le, otherwise with the {ge,le} suffix
    (le capped at 32/128). Rows whose ge..le range does not contain len are
    dropped.
    """
    la = cs.local_asn
    matrix = cs.prefix_matrix_map.get((ipversion, la), [])
    max_length = 32 if ipversion == 4 else 128
    out = []
    for network, length, ge, le in matrix:
        le_final = min(int(le), max_length)
        if int(ge) <= int(length) <= le_final:
            if int(ge) == int(length) and le_final == int(length):
                out.append(f"{network}/{length}")
            else:
                out.append(f"{network}/{length}{{{ge},{le_final}}}")
    return out


def _detect_bad_asn(cs, asn):
    """Flag an ASN as "bad" (session to be shut down) per cone/limit checks.

    Input: cs — the CacheStore (reads cs.config, cs.cone_map,
    cs.cone_members_exceeds, cs.cone_prefix_matrix_map, cs.cone_prefix_exceeds);
    asn — the ASN to evaluate.
    No return value. Side effects: adds asn to cs.bad_asn_set when any of the
    following hold, and appends a warning for the AS0 / Tier1 cases:
      - cone contains AS0 (warns: contamination)
      - cone contains a Tier1 AS and asn itself is not Tier1 (warns)
      - cone member count exceeds member-limit (unless asn is large-as-listed)
      - cone prefix count (v4 or v6) exceeds prefix-limit (unless large-as)
    A bad ASN's BGP protocol is later rendered with `disabled;` unless the ASN
    is in keepup-as-list (handled in the template).
    """
    config = cs.config
    large_as_list = config.get("as-set-limit", {}).get("large-as-list", [])
    member_limit = config.get("as-set-limit", {}).get("member-limit", 1000)

    cone_list = list(cs.cone_map.get(asn, []))
    if asn in cone_list:
        cone_list.remove(asn)

    if 0 in cone_list:
        cs.warnings.append(
            f"AS-SET of AS{asn} contains AS0, this session will be shutdown."
        )
        cs.bad_asn_set.add(asn)
    if asn not in TIER1_ASNS and (set(cone_list) & set(TIER1_ASNS)):
        cs.warnings.append(
            f"AS-SET of AS{asn} contains Tier1 AS, this session will be shutdown."
        )
        cs.bad_asn_set.add(asn)

    # AS-path (cone members) limit
    if (len(cone_list) + 1 > member_limit or asn in cs.cone_members_exceeds) and (
        asn not in large_as_list
    ):
        cs.bad_asn_set.add(asn)

    # Prefix limits (cone)
    prefix_limit = config.get("as-set-limit", {}).get("prefix-limit", 1000)
    for ipversion in (4, 6):
        pm = cs.cone_prefix_matrix_map.get((ipversion, asn), [])
        exceeds = len(pm) > prefix_limit or (ipversion, asn) in cs.cone_prefix_exceeds
        if exceeds and asn not in large_as_list:
            cs.bad_asn_set.add(asn)


_NTYPE_LABEL = {
    "upstream": "Upstream",
    "peer": "Peer",
    "downstream": "Downstream",
    "routeserver": "RouteServer",
    "ibgp": "IBGP",
}


def _prepare_neighbor(cs, neighbor, ntype, vrf):
    """Populate one neighbor's template-visible state; return its ASN.

    Input: cs — the CacheStore (mutated: neighbor_id_hashmap, warnings);
    neighbor — the neighbor dict (mutated in place); ntype — one of
    upstream/peer/downstream/routeserver/ibgp; vrf — None for the default
    context, else {"name", "id", "table"} (recorded as neighbor["_vrf"] so the
    protocol template binds the session to that VRF + tables).
    Return: the neighbor's ASN (the local ASN for ibgp).
    Side effects: normalizes neighbor-address to a list and assigns a unique
    `nid`; sets `_asn_public`, `_source_address`/`_source_family`, and the manual
    prefix-list split `_prefix4`/`_prefix6`/`_has_prefix_list`; a private ASN
    without a prefix-list gets an empty deny-all list + warning. Raises
    ValueError on an invalid neighbor-address (bare interface name).
    """
    addrs = neighbor["neighbor-address"]
    if not isinstance(addrs, list):
        addrs = [addrs]
    neighbor["neighbor-address"] = addrs
    neighbor["nid"] = get_neighbor_id(cs, neighbor)
    if vrf is not None:
        neighbor["_vrf"] = vrf

    asn = neighbor["asn"] if ntype != "ibgp" else cs.local_asn
    neighbor["_asn_public"] = validate_asn(asn) == 1

    # Private ASN without an explicit prefix-list => deny-all. Intentional and
    # exercised by the test fixture (AS65500).
    # Warn so the operator notices the session accepts nothing until a
    # prefix-list is declared.
    if not neighbor["_asn_public"] and "prefix-list" not in neighbor:
        neighbor["prefix-list"] = []
        cs.warnings.append(
            f"AS{asn} ({ntype}) {addrs}: private ASN without prefix-list "
            "=> deny-all (declare a prefix-list to accept routes)."
        )

    # Split a manual per-neighbor prefix-list into v4 / v6 buckets. Entries must
    # be CIDR prefixes; skip anything that does not parse (e.g. a stray interface
    # name) with a warning instead of crashing.
    if "prefix-list" in neighbor:
        p4, p6 = [], []
        for ip_str in neighbor["prefix-list"]:
            try:
                net = ipaddress.ip_network(ip_str)
            except ValueError:
                cs.warnings.append(
                    f"AS{asn} ({ntype}) {addrs}: ignoring invalid "
                    f"prefix-list entry '{ip_str}' (not a CIDR prefix)."
                )
                continue
            (p4 if net.version == 4 else p6).append(ip_str)
        neighbor["_prefix4"] = p4
        neighbor["_prefix6"] = p6
        neighbor["_has_prefix_list"] = True

    # source-address: BIRD `source address` requires an IP literal, and its
    # family must match the channel it is emitted on. Record the family so the
    # template only emits it on the matching channel. (Unnumbered peering is
    # expressed via the neighbor address itself as a link-local %iface, so there
    # is no separate interface field.)
    src = neighbor.get("source-address")
    if src:
        if is_ip(src):
            neighbor["_source_address"] = src
            neighbor["_source_family"] = ipaddress.ip_address(src).version
        else:
            cs.warnings.append(
                f"AS{asn} ({ntype}) {addrs}: source-address '{src}' is "
                "not an IP; ignored."
            )

    # neighbor-address forms (a dynamic form must be the SINGLE address, not
    # mixed into a list with IPs):
    #   - plain IP / "<ll>%<iface>" -> normal per-address session(s)
    #   - "range <prefix>"          -> dynamic BGP listening on that range
    #   - bare interface name       -> auto unnumbered: RAdv + dynamic BGP on fe80::/64
    rng = is_range(addrs[0]) if len(addrs) == 1 else None
    iface = addrs[0] if (len(addrs) == 1 and is_interface(addrs[0])) else None
    if rng:
        neighbor["_range"] = rng
    elif iface:
        neighbor["_unnumbered_iface"] = iface
        # One RAdv per interface; two unnumbered neighbors on the same interface
        # would emit duplicate `protocol radv` (BIRD rejects that).
        radv_ifaces = cs.__dict__.setdefault("radv_ifaces", set())
        if iface in radv_ifaces:
            cs.warnings.append(
                f"AS{asn} ({ntype}): interface '{iface}' is used by more than one "
                "unnumbered neighbor; BIRD rejects duplicate radv on one interface."
            )
        radv_ifaces.add(iface)
    else:
        # Plain IP / link-local only. Anything else (a bare name that is not a
        # valid interface, or a range/iface mixed into a list) is a config error.
        bad = [a for a in addrs if not is_ip(a) and not is_unnumbered(a)]
        if bad:
            raise ValueError(
                f"AS{asn} ({ntype}): invalid neighbor-address {bad} — must be an IP, "
                "link-local '%iface', 'range <prefix>', or a bare interface name."
            )
    return asn


def _routing_contexts(router_config):
    """Yield (vrf, bgp) for the default context plus each named VRF.

    vrf is None for the default context (master tables / main kernel table),
    else {"name", "id", "table"} — `name` is the raw VRF / OS device name used
    in `vrf "<name>";`, `id` is a sanitized identifier used in table / protocol
    names (`vrf_<id>_v4` etc.), `table` is the Linux routing-table id. `bgp` is
    that context's protocols.bgp dict.
    """
    yield None, router_config.get("protocols", {}).get("bgp", {})
    for vrf_name, vrf_cfg in (router_config.get("vrf") or {}).items():
        vrf = {
            "name": vrf_name,
            "id": str(vrf_name).lower().replace("-", "_"),
            "table": vrf_cfg["table"],
        }
        yield vrf, (vrf_cfg.get("protocols", {}) or {}).get("bgp", {})


def _prepare_for_bird(cs, router_config):
    """Populate the template-visible state the BIRD templates rely on.

    Input: cs — the CacheStore (read for pdb/bgpq4/as-set data; mutated:
    neighbor_id_hashmap, bad_asn_set, warnings); router_config — one router's
    config dict (mutated in place).
    No return value. Runs before any template renders and produces the derived
    state the templates rely on:
      - processes every neighbor across the default context AND each VRF
        (see _routing_contexts / _prepare_neighbor): nid, flags, prefix split;
        VRF neighbors are tagged `_vrf`
      - builds router_config["_render_neighbors"], a flat ordered list of
        (ntype_label, neighbor) the templates iterate for filters + protocols
      - runs bad-ASN detection over peer/downstream public ASNs (all contexts)
      - writes router_config["local_asn_prefix4"/"6"] for policy.bird.j2
      - expands blacklist as-sets into config["blacklist"]["_expanded_asn"]
    """
    config = cs.config

    # 1. Per-neighbor prep, flattened across the default context + every VRF, in
    #    render order. The VRF block mirrors the default `protocols`, so the same
    #    per-neighbor prep applies; only the protocol binding differs (_vrf).
    render_neighbors = []
    peer_downstream_asns = set()
    for vrf, bgp in _routing_contexts(router_config):
        for ntype in ["upstream", "peer", "downstream", "routeserver", "ibgp"]:
            for neighbor in bgp.get(ntype, []):
                asn = _prepare_neighbor(cs, neighbor, ntype, vrf)
                if ntype in ("peer", "downstream"):
                    peer_downstream_asns.add(asn)
                render_neighbors.append((_NTYPE_LABEL[ntype], neighbor))
    router_config["_render_neighbors"] = render_neighbors

    # 2. Bad-ASN detection (Tier1/AS0/limit) for peer+downstream public ASNs
    for asn in sorted(peer_downstream_asns):
        if validate_asn(asn) == 1:
            _detect_bad_asn(cs, asn)

    # 3. Local-ASN prefix sets (le32 / le128) consumed by policy.bird.j2
    router_config["local_asn_prefix4"] = _local_asn_prefixes(cs, 4)
    router_config["local_asn_prefix6"] = _local_asn_prefixes(cs, 6)

    # 4. Blacklist as-set expansion merged into a flat ASN list
    if "blacklist" in config:
        bl = config["blacklist"]
        expanded = list(bl.get("asn", []))
        for asset_name in bl.get("as-set", []):
            expanded += cs.blacklist_asset_members.get(asset_name, [])
        # de-dup, keep ints
        bl["_expanded_asn"] = sorted({int(x) for x in expanded})


# ---------------------------------------------------------------------------
# Template-based Generators
# ---------------------------------------------------------------------------


def gen_sflow(cs, sflow_config):
    """Render the VyOS sflow `set ...` commands.

    Input: cs — CacheStore (unused, kept for signature symmetry);
    sflow_config — the router's service.sflow dict.
    Return: the rendered sflow.j2 text (a block of VyOS set commands).
    """
    template = env.get_template('sflow.j2')
    return template.render(sflow=sflow_config)


def gen_snmp(cs, snmp_config, engineid):
    """Render the VyOS SNMP `set ...` commands.

    Input: cs — CacheStore (unused); snmp_config — the router's service.snmp
    dict; engineid — the SNMP v3 engine-ID string (see ipv4_to_engineid).
    Return: the rendered snmp.j2 text.
    """
    template = env.get_template('snmp.j2')
    return template.render(snmp=snmp_config, engineid=engineid)


def _bird_image(router_config):
    """Resolve the BIRD container image from a router's optional `bird` option.

    - absent            -> kawaiinetworks/bird:2 (default)
    - a bare version    -> kawaiinetworks/bird:<n>   (e.g. bird: 3)
    - a full image ref  -> used verbatim            (e.g. bird: "my/bird:123")

    A bare version must be a plain integer tag; for a specific patch use a full
    ref (e.g. "kawaiinetworks/bird:2.19.1").
    """
    val = router_config.get("bird")
    if val is None:
        return "kawaiinetworks/bird:2"
    s = str(val).strip()
    if s.isdigit():
        return f"kawaiinetworks/bird:{s}"
    return s


def _bird_major(router_config):
    """Best-effort BIRD major version (an int) from the `bird` option, used to
    pick version-specific config syntax (e.g. BIRD 3's `log fixed` ring buffer).

    Parses the leading integer of the resolved image tag, so a bare `bird: 3`,
    the default `:2`, and a full ref like `:2.19.1` all map correctly. Defaults
    to 2 when no tag/number can be found.
    """
    tag = _bird_image(router_config).rsplit(":", 1)[-1]
    m = re.match(r"\d+", tag)
    return int(m.group()) if m else 2


def gen_container_bird(cs, router_config):
    """Render the VyOS commands that set up the BIRD container on the host.

    Input: cs — CacheStore; router_config — one router's config dict.
    Return: the rendered container.j2 text (VyOS `set container ...` commands).
    """
    template = env.get_template('container.j2')
    return template.render(
        cs=cs,
        router_config=router_config,
        bird_image=_bird_image(router_config),
    )

def gen_bird_config(cs, router_config, router_id=None):
    """Generate the complete bird.conf for one router.

    Input: cs — CacheStore (preloaded with pdb/bgpq4/as-set data); router_config
    — one router's config dict; router_id — optional override, else taken from
    router_config["router-id"].
    Return: the full bird.conf text. Runs _prepare_for_bird() first (which
    mutates cs and router_config), then renders header.bird.j2 (which includes
    all the other bird templates).
    """
    _prepare_for_bird(cs, router_config)
    template = bird_env.get_template('header.bird.j2')
    return template.render(
        cs=cs,
        router_config=router_config,
        router_id=router_id or router_config.get("router-id"),
        local_asn=cs.local_asn,
        bird_major=_bird_major(router_config),
        rpki_servers=router_config.get("protocols", {}).get("rpki", []),
    )

# ---------------------------------------------------------------------------
# Full script assembly
# ---------------------------------------------------------------------------


async def generate_router_script(cs, router_config, worker_base_url=""):
    """Generate the VyOS host setup script for one router.

    Input: cs — CacheStore; router_config — one router's config dict;
    worker_base_url — the worker base URL embedded in the script (used by the
    container to fetch its bird.conf).
    Return: the full VyOS `configure.sh` text. This is the host-side script
    (sflow + snmp + BIRD container setup); it does NOT contain bird.conf —
    that is served separately via gen_bird_config.

    Resolves router-id via DNS-over-HTTPS (resolve_router_id) when the config
    omits "router-id", so this is async and may perform network I/O.
    """
    router_name = router_config["name"]
    router_id = router_config.get("router-id") or await resolve_router_id(router_name)

    configure_body = ""

    # Services
    # NOTE: BMP is not configured here — the BMP protocols are rendered
    # directly into bird.conf (header.bird.j2).
    if "service" in router_config:
        if "sflow" in router_config["service"]:
            configure_body += gen_sflow(cs, router_config["service"]["sflow"])
        if "snmp" in router_config["service"]:
            configure_body += gen_snmp(
                cs, router_config["service"]["snmp"], ipv4_to_engineid(router_id)
            )

    # BIRD Container Setup
    configure_body += gen_container_bird(cs, router_config)

    # Render final script wrapper
    wrapper_template = env.get_template('configure.sh.j2')
    return wrapper_template.render(
        cs=cs,
        router_config=router_config,
        router_id=router_id,
        configure_body=configure_body,
        worker_base_url=worker_base_url,
    )
