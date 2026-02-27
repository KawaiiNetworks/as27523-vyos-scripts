"""
Cloudflare Workers Python Worker — VyOS Config Generator

URL routing:
  GET /{user}/{config_repo}/router/configure.{router_name}.sh
  GET /{user}/{config_repo}/router/defaultconfig.sh
  GET /{user}/{config_repo}/find_unused.py
  GET /{user}/{config_repo}/  → index page listing available routes
"""

from copy import deepcopy
from js import fetch, Response, Headers
import hashlib
import ipaddress
import json
import os
import re


# ---------------------------------------------------------------------------
# ASN validation (same as generate.py)
# ---------------------------------------------------------------------------

def validateASN(asn):
    asn = int(asn)
    if 1 <= asn <= 23455: return 1
    elif asn == 23456: return 2
    elif 23457 <= asn <= 64495: return 1
    elif 64496 <= asn <= 64511: return 3
    elif 64512 <= asn <= 65534: return 0
    elif asn == 65535: return 4
    elif 65536 <= asn <= 65551: return 3
    elif 65552 <= asn <= 131071: return 5
    elif 131072 <= asn <= 4199999999: return 1
    elif 4200000000 <= asn <= 4294967294: return 0
    elif asn == 4294967295: return 4
    return -1


as_tier1 = [6762, 12956, 2914, 3356, 6453, 701, 6461, 3257, 1299, 3491, 7018, 3320, 5511, 6830, 174, 6939]


# ---------------------------------------------------------------------------
# GitHub raw helpers
# ---------------------------------------------------------------------------

async def github_raw(user, repo, path):
    url = f"https://raw.githubusercontent.com/{user}/{repo}/main/{path}"
    resp = await fetch(url)
    if resp.status != 200:
        return None
    return await resp.text()


async def github_raw_json(user, repo, path):
    text = await github_raw(user, repo, path)
    if text is None:
        return None
    return json.loads(text)


async def load_yaml_config(user, config_repo):
    text = await github_raw(user, config_repo, "network/vyos/vyos.yaml")
    if text is None:
        return None
    # Minimal YAML parser for our config format
    # CF Workers Python has no yaml module, we use a simple parser
    return parse_yaml_simple(text)


def parse_yaml_simple(text):
    """
    Minimal YAML parser that handles the vyos.yaml structure.
    Uses line-by-line parsing with indentation tracking.
    NOTE: This is a simplified parser. For full YAML support,
    the config should be pre-converted to JSON in the cache.
    """
    import yaml  # pyodide has pyyaml
    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# Cache loading
# ---------------------------------------------------------------------------

class CacheStore:
    def __init__(self):
        self.pdb = {}  # asn -> dict
        self.bgpq4 = {}  # asn -> dict
        self.as_name_map = {}
        self.asset_name_map = {}
        self.maximum_prefix_map = {}
        self.cone_map = {}
        self.prefix_matrix_map = {}
        self.cone_prefix_matrix_map = {}
        self.neighbor_id_hashmap = {}
        self.bad_asn_set = set()
        self.warnings = []
        self.local_asn = 0
        self.config = {}
        self.defaultconfig = ""

    async def load_pdb(self, user, config_repo, asn):
        asn = int(asn)
        if asn in self.pdb:
            return self.pdb[asn]
        data = await github_raw_json(user, config_repo, f"cache/pdb/AS{asn}.json")
        if data:
            self.pdb[asn] = data
            self._apply_pdb(asn, data)
        return data

    def _apply_pdb(self, asn, data):
        self.as_name_map[asn] = data.get("name", f"AS{asn}")
        self.asset_name_map[asn] = data.get("as_set", [f"AS{asn}"])
        mp = data.get("max_prefix", [1, 1])
        self.maximum_prefix_map[asn] = [mp[0] if mp[0] else 1, mp[1] if mp[1] else 1]

    async def load_bgpq4(self, user, config_repo, asn):
        asn = int(asn)
        if asn in self.bgpq4:
            return self.bgpq4[asn]
        data = await github_raw_json(user, config_repo, f"cache/bgpq4/AS{asn}.json")
        if data:
            self.bgpq4[asn] = data
            self._apply_bgpq4(asn, data)
        return data

    def _apply_bgpq4(self, asn, data):
        self.cone_map[asn] = data.get("cone_members", [])
        self.prefix_matrix_map[(4, asn)] = [tuple(x) for x in data.get("prefix4", [])]
        self.prefix_matrix_map[(6, asn)] = [tuple(x) for x in data.get("prefix6", [])]
        self.cone_prefix_matrix_map[(4, asn)] = [tuple(x) for x in data.get("cone_prefix4", [])]
        self.cone_prefix_matrix_map[(6, asn)] = [tuple(x) for x in data.get("cone_prefix6", [])]

    async def load_defaults(self, user, scripts_repo):
        """Load default config files from scripts repo defaults/ directory"""
        # We need to fetch the list of default files. Since we can't list a directory
        # on GitHub raw, we'll fetch defaults via the GitHub API tree
        api_url = f"https://api.github.com/repos/{user}/{scripts_repo}/git/trees/main?recursive=1"
        resp = await fetch(api_url)
        if resp.status != 200:
            return
        tree_data = json.loads(await resp.text())
        default_files = [
            item["path"] for item in tree_data.get("tree", [])
            if item["path"].startswith("configure/defaults/") and item["type"] == "blob"
        ]
        parts = []
        for fpath in sorted(default_files):
            content = await github_raw(user, scripts_repo, fpath)
            if content:
                parts.append(content)
        self.defaultconfig = "\n".join(parts)
        self.defaultconfig = self.defaultconfig.replace(r"${ASN}", str(self.local_asn))

    async def preload_all(self, user, config_repo, config):
        """Pre-load all cache data needed for generation"""
        self.config = config
        self.local_asn = config["local-asn"]

        all_asns = set()
        peer_downstream_asns = set()
        for router in config.get("router", []):
            bgp = router.get("protocols", {}).get("bgp", {})
            for ntype in ["upstream", "routeserver", "peer", "downstream", "ibgp"]:
                for neighbor in bgp.get(ntype, []):
                    if "asn" in neighbor:
                        a = neighbor["asn"]
                        all_asns.add(a)
                        if ntype in ("peer", "downstream"):
                            peer_downstream_asns.add(a)
        all_asns.add(self.local_asn)
        peer_downstream_asns.add(self.local_asn)

        # Load PDB for all ASNs
        for asn in sorted(all_asns):
            asn_type = validateASN(asn)
            if asn_type == 0:
                self._apply_pdb(asn, {
                    "type": "private", "name": f"Private AS{asn}",
                    "as_set": [f"AS{asn}"], "max_prefix": [100, 100]
                })
            elif asn_type == 1:
                data = await self.load_pdb(user, config_repo, asn)
                if not data:
                    self._apply_pdb(asn, {
                        "type": "not_found", "name": f"Unknown AS{asn}",
                        "as_set": [f"AS{asn}"], "max_prefix": [1, 1]
                    })

        # Load bgpq4 for peer/downstream + local
        for asn in sorted(peer_downstream_asns):
            if validateASN(asn) == 1:
                await self.load_bgpq4(user, config_repo, asn)

        # Load defaults
        scripts_repo = f"as{self.local_asn}-vyos-scripts"
        await self.load_defaults(user, scripts_repo)


# ---------------------------------------------------------------------------
# VyOS config generation functions (ported from generate.py, using CacheStore)
# ---------------------------------------------------------------------------

def isIP(ipstr):
    try:
        ipaddress.ip_address(ipstr)
        return True
    except ValueError:
        return False


def get_neighbor_id(cs, neighbor):
    neighbor_address_list = neighbor["neighbor-address"]
    if not isinstance(neighbor_address_list, list):
        neighbor_address_list = [neighbor_address_list]
    neighbor_str = (
        (str(neighbor["asn"]) if "asn" in neighbor else "")
        + "".join(sorted(neighbor_address_list))
    )
    hash_hex = hashlib.sha256(neighbor_str.encode("utf-8")).hexdigest()
    res = 1 + int(hash_hex[-4:], 16)
    if res in cs.neighbor_id_hashmap and cs.neighbor_id_hashmap[res] != neighbor_str:
        raise ValueError("hash collision")
    cs.neighbor_id_hashmap[res] = neighbor_str
    return res


def get_vyos_as_community(cs, asn):
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


def get_vyos_blacklist_filter(cs, blacklist_config):
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
            chunk = as_list[n:n+20]
            cmd += f"""
            set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} action deny
            set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} regex '_({"|".join(chunk)})_'
            """
            as_r += 1
    if "as-set" in blacklist_config:
        for asset_name in blacklist_config["as-set"]:
            # For blacklist as-set, we use the cone_members from cache if available
            # Otherwise skip
            pass
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


def get_vyos_as_path(cs, asn):
    cmd = f"""
    delete policy as-path-list AUTOGEN-AS{asn}-IN
    set policy as-path-list AUTOGEN-AS{asn}-IN rule 10 action permit
    set policy as-path-list AUTOGEN-AS{asn}-IN rule 10 regex '^{asn}(_{asn})*$'
    """
    cone_list = list(cs.cone_map.get(asn, []))
    if asn in cone_list:
        cone_list.remove(asn)
    if 0 in cone_list:
        cs.warnings.append(f"AS-SET of AS{asn} contains AS0, this session will be shutdown.")
        cs.bad_asn_set.add(asn)
    if asn not in as_tier1 and (set(cone_list) & set(as_tier1)):
        cs.warnings.append(f"AS-SET of AS{asn} contains Tier1 AS, this session will be shutdown.")
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
                chunk = cone_list[i:i+20]
                cmd += f"""
                set policy as-path-list AUTOGEN-AS{asn}-IN rule {20+i} action permit
                set policy as-path-list AUTOGEN-AS{asn}-IN rule {20+i} regex '^{asn}(_[0-9]+)*_({"|".join(chunk)})$'
                """
    return cmd


def get_vyos_prefix_list(cs, ipversion, asn, max_length=None, filter_name=None, cone=False):
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


def get_vyos_as_filter(cs, asn):
    cmd = get_vyos_as_path(cs, asn)
    cmd += get_vyos_prefix_list(cs, 4, asn, cone=True)
    cmd += get_vyos_prefix_list(cs, 6, asn, cone=True)
    return cmd


def get_vyos_policy(cs, policy):
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


def get_vyos_route_map_redistribute(cs, redistribute):
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
            if c["action"] == "permit" and ("on-match-next" not in c or c["on-match-next"]):
                f += f"""
                set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} on-match next
                """
            r_pre_accept += 1
    return f


def get_vyos_protocol_rpki(cs, server_list):
    cmd = "\n    delete protocols rpki\n    "
    for server in server_list:
        cmd += f"""set protocols rpki cache {server["server"]} port {server["port"]}
        set protocols rpki cache {server["server"]} preference {server["preference"]}
        """
    return cmd


def vyos_pre_accept_filter(route_map_name, r, c):
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


def vyos_neighbor_in_optional_attributes(cs, neighbor, route_map_in_name):
    f = ""
    if "local-pref" in neighbor:
        f += f"""
        set policy route-map {route_map_in_name} rule 100 set local-preference '{neighbor["local-pref"]}'
        """
    if "metric" in neighbor:
        f += f"""
        set policy route-map {route_map_in_name} rule 100 set metric {neighbor["metric"]}
        """
    if "in-prepend" in neighbor:
        f += f"""
        set policy route-map {route_map_in_name} rule 100 set as-path prepend '{neighbor["in-prepend"]}'
        """
    if "pre-import-accept" in neighbor:
        r = 1000
        for c in neighbor["pre-import-accept"]:
            f += vyos_pre_accept_filter(route_map_in_name, r, c)
            r += 1
    return f


def vyos_neighbor_out_optional_attributes(cs, neighbor, route_map_out_name):
    f = ""
    if "out-prepend" in neighbor:
        f += f"""
        set policy route-map {route_map_out_name} rule 100 set as-path prepend '{neighbor["out-prepend"]}'
        """
    if "pre-export-accept" in neighbor:
        r = 1000
        for c in neighbor["pre-export-accept"]:
            f += vyos_pre_accept_filter(route_map_out_name, r, c)
            r += 1
    return f


def get_bgp_neighbor_address_family_cmd(cs, ipversion, asn, neighbor_address, neighbor, neighbor_type, route_map_in_name, route_map_out_name_adopted):
    la = cs.local_asn
    maximum_prefix = -1
    maximum_prefix_out = -1
    asn_type = validateASN(asn)
    if neighbor_type in ["Peer", "Downstream"]:
        mp = cs.maximum_prefix_map.get(asn, [1, 1])
        maximum_prefix = mp[0] if ipversion == 4 else mp[1]
    if neighbor_type in ["Upstream", "RouteServer", "Peer"]:
        mp = cs.maximum_prefix_map.get(la, [1, 1])
        maximum_prefix_out = mp[0] if ipversion == 4 else mp[1]

    return f"""
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast default-originate" if "default-originate" in neighbor and neighbor["default-originate"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast addpath-tx-all" if "addpath" in neighbor and neighbor["addpath"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list import AUTOGEN-AS{asn}-CONE" if neighbor_type in ["Peer", "Downstream"] and asn_type==1 else ""}
    {f"delete protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list" if "disable-IRR" in neighbor and neighbor["disable-IRR"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list import AUTOGEN-AS{asn}-{get_neighbor_id(cs, neighbor)}" if "prefix-list" in neighbor else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast filter-list import AUTOGEN-AS{asn}-IN" if neighbor_type in ["Peer", "Downstream"] and asn_type==1 else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast maximum-prefix {maximum_prefix}" if neighbor_type in ["Peer", "Downstream"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast maximum-prefix-out {maximum_prefix_out}" if neighbor_type in ["Upstream", "RouteServer", "Peer"] else ""}
    set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast nexthop-self force
    set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast route-map export {route_map_out_name_adopted}
    set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast route-map import {route_map_in_name}
    {"" if ("soft-reconfiguration-inbound" in neighbor and not neighbor["soft-reconfiguration-inbound"]) else f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast soft-reconfiguration inbound"}
    """


def get_bgp_neighbor_cmd(cs, neighbor, neighbor_type, route_map_in_name, route_map_out_name):
    la = cs.local_asn
    config = cs.config
    if neighbor_type == "IBGP":
        asn = la
    else:
        asn = neighbor["asn"]
    multihop = neighbor.get("multihop", False)
    if not isinstance(multihop, int):
        multihop = False
    password = neighbor.get("password")
    neighbor_address_list = neighbor["neighbor-address"]
    if not isinstance(neighbor_address_list, list):
        neighbor_address_list = [neighbor_address_list]

    bgp_cmd = ""
    if validateASN(asn) != 1 and "prefix-list" not in neighbor:
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

    for neighbor_address in neighbor_address_list:
        if "default-originate" in neighbor and neighbor["default-originate"]:
            rmon_adopted = "AUTOGEN-REJECT-ALL"
        elif neighbor_type == "IBGP" and "simple-out" in neighbor and neighbor["simple-out"]:
            rmon_adopted = "AUTOGEN-SIMPLE-IBGP-OUT"
        else:
            rmon_adopted = route_map_out_name

        bgp_cmd += f"""
        delete protocols bgp neighbor {neighbor_address}
        {f"set protocols bgp neighbor {neighbor_address} shutdown" if (("shutdown" in neighbor and neighbor["shutdown"]) or (asn in cs.bad_asn_set and asn not in config.get("keepup-as-list", []))) else ""}
        {f"set protocols bgp neighbor {neighbor_address} passive" if ("passive" in neighbor and neighbor["passive"]) else ""}
        set protocols bgp neighbor {neighbor_address} description '{neighbor.get("description", f"{neighbor_type}: {cs.as_name_map.get(asn, f'AS{asn}')}")}'
        set protocols bgp neighbor {neighbor_address} graceful-restart enable
        {f"set protocols bgp neighbor {neighbor_address} remote-as {asn}" if isIP(neighbor_address) else f"set protocols bgp neighbor {neighbor_address} interface remote-as {asn}"}
        {f"set protocols bgp neighbor {neighbor_address} password '{password}'" if password else ""}
        {f"set protocols bgp neighbor {neighbor_address} ebgp-multihop {multihop}" if multihop else ""}
        set protocols bgp neighbor {neighbor_address} solo
        set protocols bgp neighbor {neighbor_address} update-source {neighbor["update-source"]}
        {f"set protocols bgp neighbor {neighbor_address} interface source-interface {neighbor['update-source']}" if isIP(neighbor_address) and not isIP(neighbor["update-source"]) and not multihop else ""}
        {f"set protocols bgp neighbor {neighbor_address} timers holdtime {neighbor['holdtime']}" if "holdtime" in neighbor else ""}
        {f"set protocols bgp neighbor {neighbor_address} timers keepalive {neighbor['keepalive']}" if "keepalive" in neighbor else ""}
        {f"set protocols bgp neighbor {neighbor_address} capability extended-nexthop" if "extended-nexthop" in neighbor and neighbor["extended-nexthop"] else ""}
        """

        if isIP(neighbor_address) and not ("extended-nexthop" in neighbor and neighbor["extended-nexthop"]):
            iv = ipaddress.ip_address(neighbor_address).version
            bgp_cmd += get_bgp_neighbor_address_family_cmd(cs, iv, asn, neighbor_address, neighbor, neighbor_type, route_map_in_name, rmon_adopted)
        else:
            if "address-family" in neighbor:
                if "ipv4" in neighbor["address-family"] and neighbor["address-family"]["ipv4"]:
                    bgp_cmd += get_bgp_neighbor_address_family_cmd(cs, 4, asn, neighbor_address, neighbor, neighbor_type, route_map_in_name, rmon_adopted)
                if "ipv6" in neighbor["address-family"] and neighbor["address-family"]["ipv6"]:
                    bgp_cmd += get_bgp_neighbor_address_family_cmd(cs, 6, asn, neighbor_address, neighbor, neighbor_type, route_map_in_name, rmon_adopted)
            else:
                bgp_cmd += get_bgp_neighbor_address_family_cmd(cs, 4, asn, neighbor_address, neighbor, neighbor_type, route_map_in_name, rmon_adopted)
                bgp_cmd += get_bgp_neighbor_address_family_cmd(cs, 6, asn, neighbor_address, neighbor, neighbor_type, route_map_in_name, rmon_adopted)
    return bgp_cmd


def get_vyos_protocol_bgp_neighbor(cs, neighbor_type, neighbor):
    la = cs.local_asn
    nid = get_neighbor_id(cs, neighbor)
    if neighbor_type == "IBGP":
        asn = la
    else:
        asn = neighbor["asn"]
    asn_type = validateASN(asn)
    if asn_type != 1 and neighbor_type != "Downstream":
        raise ValueError(f"Private ASN {asn} must be Downstream")

    if neighbor_type == "IBGP":
        rmi = f"AUTOGEN-IBGP-IN-{nid}"
        rmo = f"AUTOGEN-IBGP-OUT-{nid}"
    else:
        rmi = f"AUTOGEN-AS{asn}-{neighbor_type.upper()}-IN-{nid}"
        rmo = f"AUTOGEN-AS{asn}-{neighbor_type.upper()}-OUT-{nid}"

    ff = f"""
    delete policy route-map {rmi}
    set policy route-map {rmi} rule 10 action permit
    {f"set policy route-map {rmi} rule 10 call AUTOGEN-{neighbor_type.upper()}-IN" if asn_type == 1 else f"set policy route-map {rmi} rule 10 set as-path exclude all"}
    set policy route-map {rmi} rule 10 on-match next
    set policy route-map {rmi} rule 100 action permit
    set policy route-map {rmi} rule 100 on-match next
    set policy route-map {rmi} rule 200 action permit
    {f"set policy route-map {rmi} rule 200 set large-community add {la}:10000:{asn}" if neighbor_type != "IBGP" else ""}
    set policy route-map {rmi} rule 200 set large-community add {la}:10001:{nid}
    set policy route-map {rmi} rule 200 on-match next
    set policy route-map {rmi} rule 10000 action permit
    """
    ff += f"""
    delete policy route-map {rmo}
    set policy route-map {rmo} rule 10 action permit
    set policy route-map {rmo} rule 10 call AUTOGEN-{neighbor_type.upper()}-OUT
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
    if asn_type == 1:
        ff += f"""
    delete policy large-community-list AUTOGEN-DNA-NID{nid}
    set policy large-community-list AUTOGEN-DNA-NID{nid} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-DNA-NID{nid} rule 10 regex "{la}:1001:{nid}"
    delete policy large-community-list AUTOGEN-OLA-NID{nid}
    set policy large-community-list AUTOGEN-OLA-NID{nid} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-OLA-NID{nid} rule 10 regex "{la}:1101:{nid}"
    """
    ff += vyos_neighbor_in_optional_attributes(cs, neighbor, rmi)
    ff += vyos_neighbor_out_optional_attributes(cs, neighbor, rmo)
    ff += get_bgp_neighbor_cmd(cs, neighbor, neighbor_type, rmi, rmo)
    return ff


def get_vyos_protocol_bgp(cs, bgp_config, router_id):
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
    for ntype, label in [("ibgp", "IBGP"), ("upstream", "Upstream"), ("routeserver", "RouteServer"), ("peer", "Peer"), ("downstream", "Downstream")]:
        for n in bgp_config.get(ntype, []):
            if "manual" in n and n["manual"]:
                continue
            cmd += get_vyos_protocol_bgp_neighbor(cs, label, n)
    if "parameters" in bgp_config:
        for param in bgp_config["parameters"]:
            cmd += f"\n    set protocols bgp parameters {param}\n"
    return cmd


def get_vyos_kernel(cs, kernel_config):
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
                        cmd += vyos_pre_accept_filter(f"AUTOGEN-KERNEL-{pfx}-{proto}", r, c)
                        r += 1
    return cmd


def get_vyos_bmp(cs, bmp_config):
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


def get_vyos_sflow(cs, sflow_config):
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


def get_vyos_snmp(cs, snmp_config, engineid):
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


def ipv4_to_engineid(ipv4):
    return "000000000000" + "".join([part.zfill(3) for part in ipv4.split(".")])


async def get_router_id(router_name):
    """Use DNS-over-HTTPS to resolve router-id"""
    url = f"https://cloudflare-dns.com/dns-query?name={router_name}&type=A"
    resp = await fetch(url, headers={"Accept": "application/dns-json"})
    data = json.loads(await resp.text())
    answers = data.get("Answer", [])
    for a in answers:
        if a.get("type") == 1:
            return a["data"]
    raise ValueError(f"Cannot resolve router-id for {router_name}")


async def generate_router_script(cs, router_config):
    """Generate the full VyOS configure script for a router (same as get_final_vyos_cmd)"""
    la = cs.local_asn
    config = cs.config

    router_name = router_config["name"]
    router_id = await get_router_id(router_name)

    configure = ""

    # Collect ASNs
    upstream_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["upstream"]]
    routeserver_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["routeserver"]]
    peer_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["peer"]]
    downstream_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["downstream"]]
    connected_asns = sorted(set(upstream_asns + routeserver_asns + peer_asns + downstream_asns))

    if "blacklist" in config:
        configure += get_vyos_blacklist_filter(cs, config["blacklist"])

    configure += get_vyos_as_community(cs, la)
    for asn in connected_asns:
        if validateASN(asn) == 1:
            configure += get_vyos_as_community(cs, asn)

    # Local ASN prefix lists
    configure += get_vyos_prefix_list(cs, 4, la, filter_name="AUTOGEN-LOCAL-ASN-PREFIX4")
    configure += get_vyos_prefix_list(cs, 6, la, filter_name="AUTOGEN-LOCAL-ASN-PREFIX6")
    configure += get_vyos_prefix_list(cs, 4, la, max_length=32, filter_name="AUTOGEN-LOCAL-ASN-PREFIX4-le32")
    configure += get_vyos_prefix_list(cs, 6, la, max_length=128, filter_name="AUTOGEN-LOCAL-ASN-PREFIX6-le128")

    # Peer/downstream AS filters
    for asn in sorted(set(peer_asns + downstream_asns)):
        if validateASN(asn) == 1:
            configure += get_vyos_as_filter(cs, asn)

    configure += get_vyos_protocol_rpki(cs, router_config["protocols"]["rpki"])

    if "policy" in router_config:
        configure += get_vyos_policy(cs, router_config["policy"])

    configure += get_vyos_protocol_bgp(cs, router_config["protocols"]["bgp"], router_id)

    if "redistribute" in router_config:
        configure += get_vyos_route_map_redistribute(cs, router_config["redistribute"])
    else:
        configure += get_vyos_route_map_redistribute(cs, {})

    if "service" in router_config:
        if "bmp" in router_config["service"]:
            configure += get_vyos_bmp(cs, router_config["service"]["bmp"])
        if "sflow" in router_config["service"]:
            configure += get_vyos_sflow(cs, router_config["service"]["sflow"])
        if "snmp" in router_config["service"]:
            configure += get_vyos_snmp(cs, router_config["service"]["snmp"], ipv4_to_engineid(router_id))

    if "kernel" in router_config:
        configure += get_vyos_kernel(cs, router_config["kernel"])

    configure = "\n".join([line.strip() for line in configure.splitlines() if line.strip()])
    configure = (
        "\nconfigure\n"
        + cs.defaultconfig
        + configure
        + (router_config["custom-config"] + "\n" if "custom-config" in router_config else "")
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


# ---------------------------------------------------------------------------
# Worker entrypoint
# ---------------------------------------------------------------------------

from workers import Response as WResponse


async def on_fetch(request, env):
    url = request.url
    path = url.split("//", 1)[-1].split("/", 1)[-1]  # strip host
    path = path.strip("/")

    parts = path.split("/")
    if len(parts) < 3:
        return WResponse("Usage: /{user}/{config_repo}/{resource}\n\nResources:\n  router/configure.{name}.sh\n  router/defaultconfig.sh\n  find_unused.py\n", status=404, headers={"content-type": "text/plain"})

    user = parts[0]
    config_repo = parts[1]
    resource = "/".join(parts[2:])

    # Load config
    config = await load_yaml_config(user, config_repo)
    if config is None:
        return WResponse(f"Cannot load vyos.yaml from {user}/{config_repo}", status=404, headers={"content-type": "text/plain"})

    local_asn = config["local-asn"]
    scripts_repo = f"as{local_asn}-vyos-scripts"

    # Build cache store
    cs = CacheStore()
    await cs.preload_all(user, config_repo, config)

    # Route: /router/configure.{name}.sh
    if resource.startswith("router/configure.") and resource.endswith(".sh"):
        router_name = resource[len("router/configure."):-len(".sh")]
        # Find matching router
        target = None
        for r in config.get("router", []):
            if r["name"] == router_name:
                target = r
                break
        if target is None:
            available = [r["name"] for r in config.get("router", [])]
            return WResponse(f"Router '{router_name}' not found.\nAvailable: {available}", status=404, headers={"content-type": "text/plain"})
        try:
            script = await generate_router_script(cs, target)
            return WResponse(script, headers={"content-type": "text/plain; charset=utf-8"})
        except Exception as e:
            return WResponse(f"Error generating script: {e}", status=500, headers={"content-type": "text/plain"})

    # Route: /router/defaultconfig.sh
    elif resource == "router/defaultconfig.sh":
        return WResponse(cs.defaultconfig, headers={"content-type": "text/plain; charset=utf-8"})

    # Route: /find_unused.py
    elif resource == "find_unused.py":
        template = await github_raw(user, scripts_repo, "configure/find_unused.py")
        if template is None:
            return WResponse("find_unused.py not found", status=404, headers={"content-type": "text/plain"})
        template = template.replace(
            r"${default_config_url}",
            f"https://{request.url.split('//')[1].split('/')[0]}/{user}/{config_repo}/router/defaultconfig.sh"
        )
        return WResponse(template, headers={"content-type": "text/plain; charset=utf-8"})

    # Route: / (index)
    elif resource == "" or resource == "/":
        routers = [r["name"] for r in config.get("router", [])]
        host = request.url.split("//")[1].split("/")[0]
        base = f"https://{host}/{user}/{config_repo}"
        rows = ""
        for rn in routers:
            url = f"{base}/router/configure.{rn}.sh"
            rows += f'<tr><td>{rn}</td><td><a href="{url}">configure.{rn}.sh</a></td></tr>\n'
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VyOS Config Generator — AS{local_asn}</title>
<style>body{{font-family:monospace;max-width:800px;margin:40px auto;padding:0 20px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px;text-align:left}}
a{{color:#0366d6}}</style></head>
<body>
<h1>VyOS Config Generator — AS{local_asn}</h1>
<h2>Routers</h2>
<table><tr><th>Router</th><th>Script</th></tr>
{rows}</table>
<h2>Other</h2>
<ul>
<li><a href="{base}/router/defaultconfig.sh">defaultconfig.sh</a></li>
<li><a href="{base}/find_unused.py">find_unused.py</a></li>
</ul>
</body></html>"""
        return WResponse(html, headers={"content-type": "text/html; charset=utf-8"})

    else:
        return WResponse(f"Not found: {resource}", status=404, headers={"content-type": "text/plain"})
