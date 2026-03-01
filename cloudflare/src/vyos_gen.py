"""
VyOS configuration command generation.

Ported from generate.py — all functions take a CacheStore (cs) instance
instead of using module-level globals.
"""

import hashlib
import ipaddress

from cache import validate_asn, TIER1_ASNS
from github import resolve_router_id


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def is_ip(s):
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def get_neighbor_id(cs, neighbor):
    """Generate a unique numeric neighbor ID from ASN + addresses."""
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
    """Convert an IPv4 address to an SNMP engine ID string."""
    return "000000000000" + "".join(part.zfill(3) for part in ipv4.split("."))


# ---------------------------------------------------------------------------
# Community / filter generators
# ---------------------------------------------------------------------------


def gen_as_community(cs, asn):
    la = cs.local_asn
    return f"""
    delete policy large-community-list AUTOGEN-DNA-AS{asn}
    set policy large-community-list AUTOGEN-DNA-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-DNA-AS{asn} rule 10 regex "{la}:1000:{asn}"
    delete policy large-community-list AUTOGEN-OLA-AS{asn}
    set policy large-community-list AUTOGEN-OLA-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-OLA-AS{asn} rule 10 regex "{la}:1100:{asn}"
    delete policy large-community-list AUTOGEN-Prepend-1X-AS{asn}
    set policy large-community-list AUTOGEN-Prepend-1X-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-Prepend-1X-AS{asn} rule 10 regex "{la}:2001:{asn}"
    delete policy large-community-list AUTOGEN-Prepend-2X-AS{asn}
    set policy large-community-list AUTOGEN-Prepend-2X-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-Prepend-2X-AS{asn} rule 10 regex "{la}:2002:{asn}"
    """


def gen_blacklist_filter(cs, blacklist_config):
    cmd = """
    delete policy as-path-list AUTOGEN-AS-BLACKLIST
    set policy as-path-list AUTOGEN-AS-BLACKLIST
    delete policy prefix-list AUTOGEN-PREFIX-BLACKLIST
    set policy prefix-list AUTOGEN-PREFIX-BLACKLIST
    delete policy prefix-list6 AUTOGEN-PREFIX6-BLACKLIST
    set policy prefix-list6 AUTOGEN-PREFIX6-BLACKLIST
    delete policy route-map AUTOGEN-FILTER-BLACKLIST
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 10 action deny
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 10 match as-path AUTOGEN-AS-BLACKLIST
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 20 action deny
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 20 match ip address prefix-list AUTOGEN-PREFIX-BLACKLIST
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 30 action deny
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 30 match ipv6 address prefix-list AUTOGEN-PREFIX6-BLACKLIST
    set policy route-map AUTOGEN-FILTER-BLACKLIST rule 100 action permit
    """
    as_r = 1
    if "asn" in blacklist_config:
        as_list = [str(x) for x in blacklist_config["asn"]]
        for n in range(0, len(as_list), 20):
            chunk = as_list[n : n + 20]
            cmd += f"""
            set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} action deny
            set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} regex '_({"|".join(chunk)})_'
            """
            as_r += 1
    if "as-set" in blacklist_config:
        for asset_name in blacklist_config["as-set"]:
            members = cs.blacklist_asset_members.get(asset_name, [])
            as_list = [str(x) for x in members]
            for n in range(0, len(as_list), 20):
                chunk = as_list[n : n + 20]
                cmd += f"""
                set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} action deny
                set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} regex '_({"|".join(chunk)})_'
                """
                as_r += 1
    p4_r = 1
    if "prefix4" in blacklist_config:
        for prefix in blacklist_config["prefix4"]:
            cmd += f"""
            set policy prefix-list AUTOGEN-PREFIX-BLACKLIST rule {p4_r} action deny
            set policy prefix-list AUTOGEN-PREFIX-BLACKLIST rule {p4_r} prefix {prefix}
            """
            p4_r += 1
    p6_r = 1
    if "prefix6" in blacklist_config:
        for prefix in blacklist_config["prefix6"]:
            cmd += f"""
            set policy prefix-list6 AUTOGEN-PREFIX6-BLACKLIST rule {p6_r} action deny
            set policy prefix-list6 AUTOGEN-PREFIX6-BLACKLIST rule {p6_r} prefix {prefix}
            """
            p6_r += 1
    return cmd


# ---------------------------------------------------------------------------
# AS path / prefix list
# ---------------------------------------------------------------------------


def gen_as_path(cs, asn):
    cmd = f"""
    delete policy as-path-list AUTOGEN-AS{asn}-IN
    set policy as-path-list AUTOGEN-AS{asn}-IN rule 10 action permit
    set policy as-path-list AUTOGEN-AS{asn}-IN rule 10 regex '^{asn}(_{asn})*$'
    """
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
    cone_list = [str(x) for x in cone_list]
    config = cs.config
    if len(cone_list) + 1 > config["as-set-limit"]["member-limit"]:
        if asn in config["as-set-limit"]["large-as-list"]:
            cmd += f"""
            set policy as-path-list AUTOGEN-AS{asn}-IN rule 20 action permit
            set policy as-path-list AUTOGEN-AS{asn}-IN rule 20 regex '^{asn}(_[0-9]+)*$'
            """
        else:
            cs.bad_asn_set.add(asn)
    else:
        if len(cone_list) > 0:
            for i in range(0, len(cone_list), 20):
                chunk = cone_list[i : i + 20]
                cmd += f"""
                set policy as-path-list AUTOGEN-AS{asn}-IN rule {20 + i} action permit
                set policy as-path-list AUTOGEN-AS{asn}-IN rule {20 + i} regex '^{asn}(_[0-9]+)*_({"|".join(chunk)})$'
                """
    return cmd


def gen_prefix_list(cs, ipversion, asn, max_length=None, filter_name=None, cone=False):
    if cone:
        fn = filter_name or f"AUTOGEN-AS{asn}-CONE"
    else:
        fn = filter_name or f"AUTOGEN-AS{asn}"
    pl = "prefix-list" if ipversion == 4 else "prefix-list6"
    cmd = f"delete policy {pl} {fn}\n"
    config = cs.config

    if cone:
        prefix_matrix = list(cs.cone_prefix_matrix_map.get((ipversion, asn), []))
    else:
        prefix_matrix = list(cs.prefix_matrix_map.get((ipversion, asn), []))

    if len(prefix_matrix) == 0:
        zero = "0.0.0.0/0" if ipversion == 4 else "::/0"
        le = 32 if ipversion == 4 else 128
        cmd += f"""
        set policy {pl} {fn} rule 10 action deny
        set policy {pl} {fn} rule 10 prefix {zero}
        set policy {pl} {fn} rule 10 le {le}
        """
    elif len(prefix_matrix) > config["as-set-limit"]["prefix-limit"]:
        if asn in config["as-set-limit"]["large-as-list"]:
            zero = "0.0.0.0/0" if ipversion == 4 else "::/0"
            le = 24 if ipversion == 4 else 48
            cmd += f"""
            set policy {pl} {fn} rule 10 action permit
            set policy {pl} {fn} rule 10 prefix {zero}
            set policy {pl} {fn} rule 10 le {le}
            """
        else:
            zero = "0.0.0.0/0" if ipversion == 4 else "::/0"
            le = 32 if ipversion == 4 else 128
            cmd += f"""
            set policy {pl} {fn} rule 10 action deny
            set policy {pl} {fn} rule 10 prefix {zero}
            set policy {pl} {fn} rule 10 le {le}
            """
            cs.bad_asn_set.add(asn)
    else:
        c = 1
        for prefix in prefix_matrix:
            network, length, ge, le = prefix[0], prefix[1], prefix[2], prefix[3]
            le_final = max_length if max_length else le
            if int(ge) <= int(length) <= int(le_final):
                cmd += f"""
                set policy {pl} {fn} rule {c} action permit
                set policy {pl} {fn} rule {c} prefix {network}/{length}
                set policy {pl} {fn} rule {c} ge {ge}
                set policy {pl} {fn} rule {c} le {le_final}
                """
            c += 1
    return cmd


def gen_as_filter(cs, asn):
    cmd = gen_as_path(cs, asn)
    cmd += gen_prefix_list(cs, 4, asn, cone=True)
    cmd += gen_prefix_list(cs, 6, asn, cone=True)
    return cmd


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def gen_policy(cs, policy):
    cmd = ""
    if "prefix-list" in policy:
        for p in policy["prefix-list"]:
            cmd += f"\n    delete policy prefix-list {p['name']}\n"
            n = 1
            for r in p["rule"]:
                cmd += f"""
                set policy prefix-list {p['name']} rule {n} action {r["action"]}
                set policy prefix-list {p['name']} rule {n} prefix {r["prefix"]}
                {f"set policy prefix-list {p['name']} rule {n} description '{r['description']}'" if "description" in r else ""}
                {f"set policy prefix-list {p['name']} rule {n} ge {r['ge']}" if "ge" in r else ""}
                {f"set policy prefix-list {p['name']} rule {n} le {r['le']}" if "le" in r else ""}
                """
                n += 1
    if "prefix-list6" in policy:
        for p in policy["prefix-list6"]:
            cmd += f"\n    delete policy prefix-list6 {p['name']}\n"
            n = 1
            for r in p["rule"]:
                cmd += f"""
                set policy prefix-list6 {p['name']} rule {n} action {r["action"]}
                set policy prefix-list6 {p['name']} rule {n} prefix {r["prefix"]}
                {f"set policy prefix-list6 {p['name']} rule {n} description '{r['description']}'" if "description" in r else ""}
                {f"set policy prefix-list6 {p['name']} rule {n} ge {r['ge']}" if "ge" in r else ""}
                {f"set policy prefix-list6 {p['name']} rule {n} le {r['le']}" if "le" in r else ""}
                """
                n += 1
    if "as-path-list" in policy:
        for p in policy["as-path-list"]:
            cmd += f"\n    delete policy as-path-list {p['name']}\n"
            n = 1
            for r in p["rule"]:
                cmd += f"""
                set policy as-path-list {p['name']} rule {n} action {r["action"]}
                set policy as-path-list {p['name']} rule {n} regex '{r["regex"]}'
                {f"set policy as-path-list {p['name']} rule {n} description '{r['description']}'" if "description" in r else ""}
                """
                n += 1
    return cmd


# ---------------------------------------------------------------------------
# Redistribute
# ---------------------------------------------------------------------------


def gen_redistribute(cs, redistribute):
    r_pre_filter = 100
    r_pre_accept = 1000
    f = f"""
    set protocols bgp address-family ipv4-unicast redistribute connected route-map AUTOGEN-Redistribute
    set protocols bgp address-family ipv4-unicast redistribute static route-map AUTOGEN-Redistribute
    set protocols bgp address-family ipv6-unicast redistribute connected route-map AUTOGEN-Redistribute
    set protocols bgp address-family ipv6-unicast redistribute static route-map AUTOGEN-Redistribute
    delete policy route-map AUTOGEN-Redistribute
    set policy route-map AUTOGEN-Redistribute rule 10 action permit
    set policy route-map AUTOGEN-Redistribute rule 10 match ip address prefix-list AUTOGEN-LOCAL-ASN-PREFIX4-le32
    set policy route-map AUTOGEN-Redistribute rule 10 on-match goto {r_pre_accept}
    set policy route-map AUTOGEN-Redistribute rule 20 action permit
    set policy route-map AUTOGEN-Redistribute rule 20 match ipv6 address prefix-list AUTOGEN-LOCAL-ASN-PREFIX6-le128
    set policy route-map AUTOGEN-Redistribute rule 20 on-match goto {r_pre_accept}
    set policy route-map AUTOGEN-Redistribute rule 999 action deny
    set policy route-map AUTOGEN-Redistribute rule 1000 action permit
    set policy route-map AUTOGEN-Redistribute rule 1000 on-match next
    set policy route-map AUTOGEN-Redistribute rule 10000 action permit
    """
    if "pre-filter" in redistribute:
        for c in redistribute["pre-filter"]:
            f += f"""
            set policy route-map AUTOGEN-Redistribute rule {r_pre_filter} action {c["action"]}
            set policy route-map AUTOGEN-Redistribute rule {r_pre_filter} match {c["match"]}
            set policy route-map AUTOGEN-Redistribute rule {r_pre_filter} on-match goto {r_pre_accept}
            """
            if "set" in c:
                set_list = c["set"] if isinstance(c["set"], list) else [c["set"]]
                for r_set in set_list:
                    f += f"""
                    set policy route-map AUTOGEN-Redistribute rule {r_pre_filter} set {r_set}
                    """
            r_pre_filter += 1
    r_pre_accept += 1
    if "pre-accept" in redistribute:
        for c in redistribute["pre-accept"]:
            f += f"""
            set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} action {c["action"]}
            set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} match {c["match"]}
            """
            if "set" in c:
                set_list = c["set"] if isinstance(c["set"], list) else [c["set"]]
                for r_set in set_list:
                    f += f"""
                    set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} set {r_set}
                    """
            if c["action"] == "permit" and (
                "on-match-next" not in c or c["on-match-next"]
            ):
                f += f"""
                set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} on-match next
                """
            r_pre_accept += 1
    return f


# ---------------------------------------------------------------------------
# RPKI
# ---------------------------------------------------------------------------


def gen_rpki(cs, server_list):
    cmd = "\n    delete protocols rpki\n    "
    for server in server_list:
        cmd += f"""set protocols rpki cache {server["server"]} port {server["port"]}
        set protocols rpki cache {server["server"]} preference {server["preference"]}
        """
    return cmd


# ---------------------------------------------------------------------------
# Route-map helpers
# ---------------------------------------------------------------------------


def _pre_accept_filter(route_map_name, r, c):
    cmd = f"""
    set policy route-map {route_map_name} rule {r} action {c["action"]}
    """
    if "match" in c:
        cmd += f"""
        set policy route-map {route_map_name} rule {r} match {c["match"]}
        """
    if "set" in c:
        set_list = c["set"] if isinstance(c["set"], list) else [c["set"]]
        for r_set in set_list:
            cmd += f"""
            set policy route-map {route_map_name} rule {r} set {r_set}
            """
    if c["action"] == "permit" and ("on-match-next" not in c or c["on-match-next"]):
        cmd += f"""
        set policy route-map {route_map_name} rule {r} on-match next
        """
    return cmd


def _neighbor_in_optional(cs, neighbor, rmi):
    f = ""
    if "local-pref" in neighbor:
        f += f"""
        set policy route-map {rmi} rule 100 set local-preference '{neighbor["local-pref"]}'
        """
    if "metric" in neighbor:
        f += f"""
        set policy route-map {rmi} rule 100 set metric {neighbor["metric"]}
        """
    if "in-prepend" in neighbor:
        f += f"""
        set policy route-map {rmi} rule 100 set as-path prepend '{neighbor["in-prepend"]}'
        """
    if "pre-import-accept" in neighbor:
        r = 1000
        for c in neighbor["pre-import-accept"]:
            f += _pre_accept_filter(rmi, r, c)
            r += 1
    return f


def _neighbor_out_optional(cs, neighbor, rmo):
    f = ""
    if "out-prepend" in neighbor:
        f += f"""
        set policy route-map {rmo} rule 100 set as-path prepend '{neighbor["out-prepend"]}'
        """
    if "pre-export-accept" in neighbor:
        r = 1000
        for c in neighbor["pre-export-accept"]:
            f += _pre_accept_filter(rmo, r, c)
            r += 1
    return f


# ---------------------------------------------------------------------------
# BGP neighbor
# ---------------------------------------------------------------------------


def _bgp_address_family(cs, ipversion, asn, addr, neighbor, ntype, rmi, rmo):
    la = cs.local_asn
    maximum_prefix = -1
    maximum_prefix_out = -1
    asn_type = validate_asn(asn)
    if ntype in ["Peer", "Downstream"]:
        mp = cs.maximum_prefix_map.get(asn, [1, 1])
        maximum_prefix = mp[0] if ipversion == 4 else mp[1]
    if ntype in ["Upstream", "RouteServer", "Peer"]:
        mp = cs.maximum_prefix_map.get(la, [1, 1])
        maximum_prefix_out = mp[0] if ipversion == 4 else mp[1]

    return f"""
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast default-originate" if "default-originate" in neighbor and neighbor["default-originate"] else ""}
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast addpath-tx-all" if "addpath" in neighbor and neighbor["addpath"] else ""}
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast prefix-list import AUTOGEN-AS{asn}-CONE" if ntype in ["Peer", "Downstream"] and asn_type == 1 else ""}
    {f"delete protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast prefix-list" if "disable-IRR" in neighbor and neighbor["disable-IRR"] else ""}
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast prefix-list import AUTOGEN-AS{asn}-{get_neighbor_id(cs, neighbor)}" if "prefix-list" in neighbor else ""}
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast filter-list import AUTOGEN-AS{asn}-IN" if ntype in ["Peer", "Downstream"] and asn_type == 1 else ""}
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast maximum-prefix {maximum_prefix}" if ntype in ["Peer", "Downstream"] else ""}
    {f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast maximum-prefix-out {maximum_prefix_out}" if ntype in ["Upstream", "RouteServer", "Peer"] else ""}
    set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast nexthop-self force
    set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast route-map export {rmo}
    set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast route-map import {rmi}
    {"" if ("soft-reconfiguration-inbound" in neighbor and not neighbor["soft-reconfiguration-inbound"]) else f"set protocols bgp neighbor {addr} address-family ipv{ipversion}-unicast soft-reconfiguration inbound"}
    """


def _bgp_neighbor_cmd(cs, neighbor, ntype, rmi, rmo):
    la = cs.local_asn
    config = cs.config
    asn = la if ntype == "IBGP" else neighbor["asn"]
    multihop = neighbor.get("multihop", False)
    if not isinstance(multihop, int):
        multihop = False
    password = neighbor.get("password")
    addrs = neighbor["neighbor-address"]
    if not isinstance(addrs, list):
        addrs = [addrs]

    bgp_cmd = ""

    # Private ASN without explicit prefix-list => empty deny-all prefix-list
    if validate_asn(asn) != 1 and "prefix-list" not in neighbor:
        neighbor["prefix-list"] = []

    if "prefix-list" in neighbor:
        nid = get_neighbor_id(cs, neighbor)
        bgp_cmd += f"""
        delete policy prefix-list AUTOGEN-AS{asn}-{nid}
        set policy prefix-list AUTOGEN-AS{asn}-{nid} rule 10000 action deny
        set policy prefix-list AUTOGEN-AS{asn}-{nid} rule 10000 prefix 0.0.0.0/0
        set policy prefix-list AUTOGEN-AS{asn}-{nid} rule 10000 ge 0
        set policy prefix-list AUTOGEN-AS{asn}-{nid} rule 10000 le 32
        delete policy prefix-list6 AUTOGEN-AS{asn}-{nid}
        set policy prefix-list6 AUTOGEN-AS{asn}-{nid} rule 10000 action deny
        set policy prefix-list6 AUTOGEN-AS{asn}-{nid} rule 10000 prefix ::/0
        set policy prefix-list6 AUTOGEN-AS{asn}-{nid} rule 10000 ge 0
        set policy prefix-list6 AUTOGEN-AS{asn}-{nid} rule 10000 le 128
        """
        for plc, ip_str in enumerate(neighbor["prefix-list"], start=1):
            net = ipaddress.ip_network(ip_str)
            if net.version == 4:
                bgp_cmd += f"""
                set policy prefix-list AUTOGEN-AS{asn}-{nid} rule {plc} action permit
                set policy prefix-list AUTOGEN-AS{asn}-{nid} rule {plc} prefix {ip_str}
                """
            else:
                bgp_cmd += f"""
                set policy prefix-list6 AUTOGEN-AS{asn}-{nid} rule {plc} action permit
                set policy prefix-list6 AUTOGEN-AS{asn}-{nid} rule {plc} prefix {ip_str}
                """

    for addr in addrs:
        if "default-originate" in neighbor and neighbor["default-originate"]:
            rmo_adopted = "AUTOGEN-REJECT-ALL"
        elif ntype == "IBGP" and "simple-out" in neighbor and neighbor["simple-out"]:
            rmo_adopted = "AUTOGEN-SIMPLE-IBGP-OUT"
        else:
            rmo_adopted = rmo

        bgp_cmd += f"""
        delete protocols bgp neighbor {addr}
        {f"set protocols bgp neighbor {addr} shutdown" if (("shutdown" in neighbor and neighbor["shutdown"]) or (asn in cs.bad_asn_set and asn not in config.get("keepup-as-list", []))) else ""}
        {f"set protocols bgp neighbor {addr} passive" if ("passive" in neighbor and neighbor["passive"]) else ""}
        set protocols bgp neighbor {addr} description '{neighbor.get("description", f"{ntype}: {cs.as_name_map.get(asn, f'AS{asn}')}")}'
        set protocols bgp neighbor {addr} graceful-restart enable
        {f"set protocols bgp neighbor {addr} remote-as {asn}" if is_ip(addr) else f"set protocols bgp neighbor {addr} interface remote-as {asn}"}
        {f"set protocols bgp neighbor {addr} password '{password}'" if password else ""}
        {f"set protocols bgp neighbor {addr} ebgp-multihop {multihop}" if multihop else ""}
        set protocols bgp neighbor {addr} solo
        set protocols bgp neighbor {addr} update-source {neighbor["update-source"]}
        {f"set protocols bgp neighbor {addr} interface source-interface {neighbor['update-source']}" if is_ip(addr) and not is_ip(neighbor["update-source"]) and not multihop else ""}
        {f"set protocols bgp neighbor {addr} timers holdtime {neighbor['holdtime']}" if "holdtime" in neighbor else ""}
        {f"set protocols bgp neighbor {addr} timers keepalive {neighbor['keepalive']}" if "keepalive" in neighbor else ""}
        {f"set protocols bgp neighbor {addr} capability extended-nexthop" if "extended-nexthop" in neighbor and neighbor["extended-nexthop"] else ""}
        """

        if "address-family" in neighbor:
            if (
                "ipv4" in neighbor["address-family"]
                and neighbor["address-family"]["ipv4"]
            ):
                bgp_cmd += _bgp_address_family(
                    cs, 4, asn, addr, neighbor, ntype, rmi, rmo_adopted
                )
            if (
                "ipv6" in neighbor["address-family"]
                and neighbor["address-family"]["ipv6"]
            ):
                bgp_cmd += _bgp_address_family(
                    cs, 6, asn, addr, neighbor, ntype, rmi, rmo_adopted
                )
        else:
            if is_ip(addr) and not (
                "extended-nexthop" in neighbor and neighbor["extended-nexthop"]
            ):
                iv = ipaddress.ip_address(addr).version
                bgp_cmd += _bgp_address_family(
                    cs, iv, asn, addr, neighbor, ntype, rmi, rmo_adopted
                )
            else:
                bgp_cmd += _bgp_address_family(
                    cs, 4, asn, addr, neighbor, ntype, rmi, rmo_adopted
                )
                bgp_cmd += _bgp_address_family(
                    cs, 6, asn, addr, neighbor, ntype, rmi, rmo_adopted
                )
    return bgp_cmd


def gen_bgp_neighbor(cs, ntype, neighbor):
    """Generate full config for a single BGP neighbor (route-maps + session)."""
    la = cs.local_asn
    nid = get_neighbor_id(cs, neighbor)
    asn = la if ntype == "IBGP" else neighbor["asn"]
    asn_type = validate_asn(asn)

    if asn_type != 1 and ntype != "Downstream":
        raise ValueError(f"Private ASN {asn} must be Downstream")

    if ntype == "IBGP":
        rmi = f"AUTOGEN-IBGP-IN-{nid}"
        rmo = f"AUTOGEN-IBGP-OUT-{nid}"
    else:
        rmi = f"AUTOGEN-AS{asn}-{ntype.upper()}-IN-{nid}"
        rmo = f"AUTOGEN-AS{asn}-{ntype.upper()}-OUT-{nid}"

    # IN route-map
    ff = f"""
    delete policy route-map {rmi}
    set policy route-map {rmi} rule 10 action permit
    {f"set policy route-map {rmi} rule 10 call AUTOGEN-{ntype.upper()}-IN" if asn_type == 1 else f"set policy route-map {rmi} rule 10 set as-path exclude all"}
    set policy route-map {rmi} rule 10 on-match next
    set policy route-map {rmi} rule 100 action permit
    set policy route-map {rmi} rule 100 on-match next
    set policy route-map {rmi} rule 200 action permit
    {f"set policy route-map {rmi} rule 200 set large-community add {la}:10000:{asn}" if ntype != "IBGP" else ""}
    set policy route-map {rmi} rule 200 set large-community add {la}:10001:{nid}
    set policy route-map {rmi} rule 200 on-match next
    set policy route-map {rmi} rule 10000 action permit
    """

    # OUT route-map
    ff += f"""
    delete policy route-map {rmo}
    set policy route-map {rmo} rule 10 action permit
    set policy route-map {rmo} rule 10 call AUTOGEN-{ntype.upper()}-OUT
    set policy route-map {rmo} rule 10 on-match next
    set policy route-map {rmo} rule 100 action permit
    set policy route-map {rmo} rule 100 on-match next
    """
    if asn_type == 1:
        ff += f"""
    set policy route-map {rmo} rule 200 action deny
    set policy route-map {rmo} rule 200 match large-community large-community-list AUTOGEN-DNA-ANY
    set policy route-map {rmo} rule 201 action deny
    set policy route-map {rmo} rule 201 match large-community large-community-list AUTOGEN-DNA-AS{asn}
    set policy route-map {rmo} rule 202 action deny
    set policy route-map {rmo} rule 202 match large-community large-community-list AUTOGEN-DNA-NID{nid}
    set policy route-map {rmo} rule 300 action permit
    set policy route-map {rmo} rule 300 match large-community large-community-list AUTOGEN-OLA-AS{asn}
    set policy route-map {rmo} rule 300 on-match goto 401
    set policy route-map {rmo} rule 301 action permit
    set policy route-map {rmo} rule 301 match large-community large-community-list AUTOGEN-OLA-NID{nid}
    set policy route-map {rmo} rule 301 on-match goto 401
    set policy route-map {rmo} rule 302 action deny
    set policy route-map {rmo} rule 302 match large-community large-community-list AUTOGEN-OLA-ALL
    set policy route-map {rmo} rule 401 action permit
    set policy route-map {rmo} rule 401 match large-community large-community-list AUTOGEN-Prepend-1X-AS{asn}
    set policy route-map {rmo} rule 401 set as-path prepend-last-as 1
    set policy route-map {rmo} rule 401 on-match next
    set policy route-map {rmo} rule 402 action permit
    set policy route-map {rmo} rule 402 match large-community large-community-list AUTOGEN-Prepend-2X-AS{asn}
    set policy route-map {rmo} rule 402 set as-path prepend-last-as 2
    set policy route-map {rmo} rule 402 on-match next
    """
    ff += f"""
    set policy route-map {rmo} rule 10000 action permit
    """

    # NID community lists
    if asn_type == 1:
        ff += f"""
    delete policy large-community-list AUTOGEN-DNA-NID{nid}
    set policy large-community-list AUTOGEN-DNA-NID{nid} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-DNA-NID{nid} rule 10 regex "{la}:1001:{nid}"
    delete policy large-community-list AUTOGEN-OLA-NID{nid}
    set policy large-community-list AUTOGEN-OLA-NID{nid} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-OLA-NID{nid} rule 10 regex "{la}:1101:{nid}"
    """

    ff += _neighbor_in_optional(cs, neighbor, rmi)
    ff += _neighbor_out_optional(cs, neighbor, rmo)
    ff += _bgp_neighbor_cmd(cs, neighbor, ntype, rmi, rmo)
    return ff


# ---------------------------------------------------------------------------
# BGP protocol
# ---------------------------------------------------------------------------


def gen_bgp(cs, bgp_config, router_id):
    la = cs.local_asn
    cmd = f"""
    delete protocols bgp address-family
    delete protocols bgp parameters
    delete protocols bgp system-as
    set protocols bgp address-family ipv4-unicast redistribute connected
    set protocols bgp address-family ipv4-unicast redistribute static
    set protocols bgp address-family ipv6-unicast redistribute connected
    set protocols bgp address-family ipv6-unicast redistribute static
    set protocols bgp parameters graceful-restart
    set protocols bgp parameters no-ipv6-auto-ra
    set protocols bgp parameters router-id {router_id}
    set protocols bgp system-as {la}
    """
    for ntype, label in [
        ("ibgp", "IBGP"),
        ("upstream", "Upstream"),
        ("routeserver", "RouteServer"),
        ("peer", "Peer"),
        ("downstream", "Downstream"),
    ]:
        for n in bgp_config.get(ntype, []):
            if "manual" in n and n["manual"]:
                continue
            cmd += gen_bgp_neighbor(cs, label, n)
    if "parameters" in bgp_config:
        for param in bgp_config["parameters"]:
            cmd += f"\n    set protocols bgp parameters {param}\n"
    return cmd


# ---------------------------------------------------------------------------
# System FRR / Kernel / BMP / sFlow / SNMP
# ---------------------------------------------------------------------------


def gen_system_frr(cs):
    """System FRR configuration (placeholder, matching generate.py)."""
    return """
    """


def gen_kernel(cs, kernel_config):
    cmd = ""
    for ipv, af in [("ipv4", "ip"), ("ipv6", "ipv6")]:
        if ipv in kernel_config:
            for rm in kernel_config[ipv]:
                proto = rm["protocol"]
                pfx = "IPv4" if ipv == "ipv4" else "IPv6"
                cmd += f"""
                delete policy route-map AUTOGEN-KERNEL-{pfx}-{proto}
                set policy route-map AUTOGEN-KERNEL-{pfx}-{proto} rule 100 action permit
                delete system {af} protocol {proto}
                set system {af} protocol {proto} route-map AUTOGEN-KERNEL-{pfx}-{proto}
                """
                if "src" in rm:
                    pl_name = f"AUTOGEN-{pfx}-ALL"
                    match_kw = "ip" if ipv == "ipv4" else "ipv6"
                    cmd += f"""
                    set policy route-map AUTOGEN-KERNEL-{pfx}-{proto} rule 1 action permit
                    set policy route-map AUTOGEN-KERNEL-{pfx}-{proto} rule 1 match {match_kw} address prefix-list '{pl_name}'
                    set policy route-map AUTOGEN-KERNEL-{pfx}-{proto} rule 1 set src '{rm["src"]}'
                    set policy route-map AUTOGEN-KERNEL-{pfx}-{proto} rule 1 on-match next
                    """
                if "pre-accept" in rm:
                    r = 10
                    for c in rm["pre-accept"]:
                        cmd += _pre_accept_filter(f"AUTOGEN-KERNEL-{pfx}-{proto}", r, c)
                        r += 1
    return cmd


def gen_bmp(cs, bmp_config):
    cmd = """
    delete system frr bmp
    set system frr bmp
    delete protocols bgp bmp
    """
    for s in bmp_config:
        cmd += f"""
        set protocols bgp bmp target {s["target"]} address {s["address"]}
        set protocols bgp bmp target {s["target"]} port {s["port"]}
        """
        if "mirror" in s and not s["mirror"]:
            cmd += f"""
            set protocols bgp bmp target {s["target"]} monitor ipv4-unicast post-policy
            set protocols bgp bmp target {s["target"]} monitor ipv6-unicast post-policy
            """
        else:
            cmd += f"""
            set protocols bgp bmp target {s["target"]} mirror
            """
    return cmd


def gen_sflow(cs, sflow_config):
    cmd = f"""
    delete system frr snmp
    set system frr snmp bgpd
    set system frr snmp isisd
    set system frr snmp ldpd
    set system frr snmp ospf6d
    set system frr snmp ospfd
    set system frr snmp ripd
    set system frr snmp zebra
    delete system sflow
    set system sflow agent-address {sflow_config["agent-address"]}
    """
    for sv in sflow_config["server"]:
        cmd += f"\n    set system sflow server {sv['address']} port {sv['port']}\n"
    for iface in sflow_config["interface"]:
        cmd += f"\n    set system sflow interface {iface}\n"
    return cmd


def gen_snmp(cs, snmp_config, engineid):
    return f"""
    delete service snmp
    set service snmp listen-address {snmp_config["listen-address"]}
    set service snmp location '{snmp_config["location"]}'
    set service snmp v3 engineid {engineid}
    set service snmp v3 group default mode ro
    set service snmp v3 group default view default
    set service snmp v3 user vyos auth encrypted-password {snmp_config["encrypted-password"]}
    set service snmp v3 user vyos auth type sha
    set service snmp v3 user vyos group default
    set service snmp v3 user vyos privacy encrypted-password {snmp_config["encrypted-password"]}
    set service snmp v3 user vyos privacy type aes
    set service snmp v3 view default oid 1
    """


# ---------------------------------------------------------------------------
# Full script assembly
# ---------------------------------------------------------------------------


async def generate_router_script(cs, router_config):
    """Generate the complete VyOS configure script for a single router."""
    la = cs.local_asn
    config = cs.config

    router_name = router_config["name"]
    router_id = await resolve_router_id(router_name)

    configure = ""

    # Collect connected ASNs
    upstream_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["upstream"]]
    routeserver_asns = [
        n["asn"] for n in router_config["protocols"]["bgp"]["routeserver"]
    ]
    peer_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["peer"]]
    downstream_asns = [
        n["asn"] for n in router_config["protocols"]["bgp"]["downstream"]
    ]
    connected_asns = sorted(
        set(upstream_asns + routeserver_asns + peer_asns + downstream_asns)
    )

    # Blacklist
    if "blacklist" in config:
        configure += gen_blacklist_filter(cs, config["blacklist"])

    # Community lists
    configure += gen_as_community(cs, la)
    for asn in connected_asns:
        if validate_asn(asn) == 1:
            configure += gen_as_community(cs, asn)

    # Local ASN prefix lists
    configure += gen_prefix_list(cs, 4, la, filter_name="AUTOGEN-LOCAL-ASN-PREFIX4")
    configure += gen_prefix_list(cs, 6, la, filter_name="AUTOGEN-LOCAL-ASN-PREFIX6")
    configure += gen_prefix_list(
        cs, 4, la, max_length=32, filter_name="AUTOGEN-LOCAL-ASN-PREFIX4-le32"
    )
    configure += gen_prefix_list(
        cs, 6, la, max_length=128, filter_name="AUTOGEN-LOCAL-ASN-PREFIX6-le128"
    )

    # Peer/downstream AS filters
    for asn in sorted(set(peer_asns + downstream_asns)):
        if validate_asn(asn) == 1:
            configure += gen_as_filter(cs, asn)

    # RPKI
    configure += gen_rpki(cs, router_config["protocols"]["rpki"])

    # Policy
    if "policy" in router_config:
        configure += gen_policy(cs, router_config["policy"])

    # BGP
    configure += gen_bgp(cs, router_config["protocols"]["bgp"], router_id)

    # Redistribute
    if "redistribute" in router_config:
        configure += gen_redistribute(cs, router_config["redistribute"])
    else:
        configure += gen_redistribute(cs, {})

    # System FRR
    configure += gen_system_frr(cs)

    # Services
    if "service" in router_config:
        if "bmp" in router_config["service"]:
            configure += gen_bmp(cs, router_config["service"]["bmp"])
        if "sflow" in router_config["service"]:
            configure += gen_sflow(cs, router_config["service"]["sflow"])
        if "snmp" in router_config["service"]:
            configure += gen_snmp(
                cs, router_config["service"]["snmp"], ipv4_to_engineid(router_id)
            )

    # Kernel
    if "kernel" in router_config:
        configure += gen_kernel(cs, router_config["kernel"])

    # Clean up whitespace
    configure = "\n".join(
        line.strip() for line in configure.splitlines() if line.strip()
    )

    # Assemble final script
    configure = (
        "\necho 'start configure'\n"
        + "\nconfigure\n"
        + cs.defaultconfig
        + configure
        + (
            router_config["custom-config"] + "\n"
            if "custom-config" in router_config
            else ""
        )
        + "\necho 'configure done'\n"
        + '\nvtysh -c "watchfrr ignore bgpd"\n'
        + "\ncommit\n"
        + "\nexit\n"
    )

    script_start = r"""#!/bin/vbash

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template
"""
    script_env = f"""
ASN={la}
ROUTER={router_name}
    """
    script_end = r"""exit"""
    return script_start + script_env + configure + script_end
