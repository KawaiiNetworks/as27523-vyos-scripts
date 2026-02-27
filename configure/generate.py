from copy import deepcopy
import os
import subprocess
import ipaddress
import json
import time
import re
import hashlib
import requests
import xml.etree.ElementTree as ET
import yaml
import dns.resolver
from aggregate_prefixes import aggregate_prefixes

work_dir = os.path.dirname(os.path.abspath(__file__))
github_user = os.getenv("GITHUB_REPOSITORY").split("/")[0]
github_repo = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
local_asn = int(re.search(r"as(\d+)", github_repo.lower()).group(1))
config = yaml.safe_load(
    requests.get(
        f"https://raw.githubusercontent.com/{github_user}/AS{local_asn}/main/network/vyos/vyos.yaml",
        timeout=30,
    ).text
)


defaultconfig = ""
for root, dirs, files in os.walk(os.path.join(work_dir, "defaults")):
    for file in files:
        defaultconfig += open(os.path.join(root, file), "r", encoding="utf-8").read()
        defaultconfig += "\n"
defaultconfig = defaultconfig.replace(r"${ASN}", str(local_asn))

as_name_map = {}
"""as:name"""

asset_name_map = {}
"""as:as-set"""

maximum_prefix_map = {}
"""as:[maximum-prefix4, maximum-prefix6]"""

cone_map = {}
"""as:[as-set member]"""

prefix_matrix_map = {}
"""(ipversion, as):[(network, length, ge, le, object_mask, invert_mask)]"""

cone_prefix_matrix_map = {}
"""(ipversion, as):[(network, length, ge, le, object_mask, invert_mask)]"""

neighbor_id_hashmap = {}
"""neighbor_id:neighbor_str"""

bad_asn_set = set()
"""to storage bad asn when get as info from bgpq4, like containing AS0 in as-set, or have large cone but not tagged"""

warnings = []

as_tier1 = [
    6762,
    12956,
    2914,
    3356,
    6453,
    701,
    6461,
    3257,
    1299,
    3491,
    7018,
    3320,
    5511,
    6830,
    174,
    6939,
]


def get_neighbor_id(neighbor):
    """generate a unique neighbor id from neighbor asn and address"""

    neighbor_address_list = neighbor["neighbor-address"]
    if not isinstance(neighbor_address_list, list):
        neighbor_address_list = [neighbor_address_list]
    neighbor_str = (
        (str(neighbor["asn"]) if "asn" in neighbor else "")  # ibgp没有asn
        + "".join(sorted(neighbor_address_list))
        # + str(neighbor["update-source"])
    )
    hash_object = hashlib.sha256(neighbor_str.encode("utf-8"))
    hash_hex = hash_object.hexdigest()
    # res = 1 + int(hash_hex, 16) % (2**16)  # 1-65536
    res = 1 + int(hash_hex[-4:], 16)  # 1-65536
    if res in neighbor_id_hashmap and neighbor_id_hashmap[res] != neighbor_str:
        raise ValueError("hash collision")
    else:
        neighbor_id_hashmap[res] = neighbor_str
    return res


def get_router_id(router_name):
    """use dns to get router-id"""

    answer = dns.resolver.resolve(router_name, "A")
    if len(answer) != 1:
        raise ValueError("router-id for {router_name} is not unique")
    return answer[0].address


def isIP(ipstr):
    try:
        ipaddress.ip_address(ipstr)
        return True
    except ValueError:
        return False


def validateASN(asn):
    if 1 <= int(asn) <= 23455:
        return 1
    elif int(asn) == 23456:
        # Reserved for AS Pool Transition
        return 2
    elif 23457 <= int(asn) <= 64495:
        return 1
    elif 64496 <= int(asn) <= 64511:
        # Reserved for use in documentation and sample code
        return 3
    elif 64512 <= int(asn) <= 65534:
        # Reserved for private use
        return 0
    elif int(asn) == 65535:
        # Reserved
        return 4
    elif 65536 <= int(asn) <= 65551:
        # Reserved for use in documentation and sample code
        return 3
    elif 65552 <= int(asn) <= 131071:
        # Reserved
        return 5
    elif 131072 <= int(asn) <= 4199999999:
        return 1
    elif 4200000000 <= int(asn) <= 4294967294:
        # Reserved for private use
        return 0
    elif int(asn) == 4294967295:
        # Reserved
        return 4


def get_as_info(asn):
    """use peeringdb to get as info"""

    if validateASN(asn) == 0:
        as_name_map[asn] = f"Private AS{asn}"
        asset_name_map[asn] = [f"AS{asn}"]
        maximum_prefix_map[asn] = [100, 100]  # maximum_prefix for private ASN
        return 0
    elif validateASN(asn) != 1:
        raise ValueError(f"Invalid ASN: {asn}")

    if asn in as_name_map:
        return validateASN(asn)

    time.sleep(5)
    url = f"https://www.peeringdb.com/api/net?asn={asn}"
    print(f"getting AS{asn} info...")
    try:
        response = requests.get(url, timeout=10).json()["data"][0]
    except IndexError as e:
        print(f"AS{asn} does not exist in PeeringDB")
        warnings.append(f"AS{asn} does not exist in PeeringDB")
        as_name_map[asn] = f"Nonexistent AS{asn}"
        asset_name_map[asn] = [f"AS{asn}"]
        maximum_prefix_map[asn] = [100, 100]  # maximum_prefix for private ASN
        return 1

    maximum_prefix_map[asn] = [
        response["info_prefixes4"],
        response["info_prefixes6"],
    ]
    if maximum_prefix_map[asn][0] == 0 or maximum_prefix_map[asn][0] is None:
        warnings.append(f"AS{asn} maximum-prefix4 is 0, change to 1")
        maximum_prefix_map[asn][0] = 1
    if maximum_prefix_map[asn][1] == 0 or maximum_prefix_map[asn][1] is None:
        warnings.append(f"AS{asn} maximum-prefix6 is 0, change to 1")
        maximum_prefix_map[asn][1] = 1

    if response["aka"] != "" and len(response["aka"]) < len(response["name"]):
        as_name_map[asn] = response["aka"]
    else:
        as_name_map[asn] = response["name"]
    print(f"AS{asn} name: {as_name_map[asn]}")
    as_set_str = response["irr_as_set"].split()
    as_set_name_list = []
    for n in as_set_str:
        if "::" in n:
            # 虽然这里有一个-S且别的命令那也有-S，但是这边-S在后面，会覆盖掉那些更多的数据库，使得最终只用指定的数据库
            as_set_name_list.append(f"{n.split('::')[1]} -S {n.split('::')[0]}")
        else:
            as_set_name_list.append(n)
    if not as_set_name_list:
        warnings.append(f"AS{asn} as-set name not found, use default AS{asn}")
        as_set_name_list = [f"AS{asn}"]

    asset_name_map[asn] = as_set_name_list
    print(f"AS{asn} as-set name: {as_set_name_list}")
    return 1


def get_vyos_as_community(asn):
    """get vyos as community cmd"""

    return f"""
    delete policy large-community-list AUTOGEN-DNA-AS{asn}
    set policy large-community-list AUTOGEN-DNA-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-DNA-AS{asn} rule 10 regex "{local_asn}:1000:{asn}"

    delete policy large-community-list AUTOGEN-OLA-AS{asn}
    set policy large-community-list AUTOGEN-OLA-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-OLA-AS{asn} rule 10 regex "{local_asn}:1100:{asn}"

    delete policy large-community-list AUTOGEN-Prepend-1X-AS{asn}
    set policy large-community-list AUTOGEN-Prepend-1X-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-Prepend-1X-AS{asn} rule 10 regex "{local_asn}:2001:{asn}"
    delete policy large-community-list AUTOGEN-Prepend-2X-AS{asn}
    set policy large-community-list AUTOGEN-Prepend-2X-AS{asn} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-Prepend-2X-AS{asn} rule 10 regex "{local_asn}:2002:{asn}"
    """


def get_asset_name(asn):
    """use peeringdb to get as-set name"""

    if asn in asset_name_map:
        return deepcopy(asset_name_map[asn])
    else:
        get_as_info(asn)
        return deepcopy(asset_name_map[asn])


def get_as_cone_member(asn):
    """use bgpq4 to get as cone member from as-set from peeringdb"""

    if asn in cone_map:
        return deepcopy(cone_map[asn])

    asset_name_list = get_asset_name(asn)  # an asn may have multiple as-set
    res = []
    for asset_name in asset_name_list:
        res += get_as_set_member(asset_name)

    res = sorted(list(set(res)))
    cone_map[asn] = res
    print(f"AS{asn} cone list: {res}")
    return deepcopy(res)


def get_as_set_member(asset_name):
    """use bgpq4 to get as-set member"""

    cmd = f"bgpq4 -S RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB -jt {asset_name}"
    result = subprocess.run(
        cmd,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    res = json.loads(result.stdout)["NN"]
    res = sorted(list(set(res)))
    return res


def aggregate_prefixes_modified(prefix_matrix, ipversion):
    """use aggregate_prefixes to aggregate prefix list, ignore ge, le"""

    _prefixes = [f"{p[0]}/{p[1]}" for p in prefix_matrix]
    _prefixes = list(aggregate_prefixes(_prefixes))
    return [
        (
            str(p.network_address),
            str(p.prefixlen),
            str(p.prefixlen),
            str(24 if ipversion == 4 else 48),
        )
        for p in _prefixes
    ]


def get_prefix_matrix(ipversion, asn):
    """use bgpq4 to get prefix matrix"""

    if (ipversion, asn) in prefix_matrix_map:
        return deepcopy(prefix_matrix_map[(ipversion, asn)])

    cmd = rf'bgpq4 -S RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB -{ipversion} -A -F "%n,%l,%a,%A\n" as{asn} -l AS{asn}'  # network, length, ge, le (example: 1.1.0.0, 16, 20, 24)
    prefix_matrix = []

    result = subprocess.run(
        cmd,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    res = result.stdout.splitlines()
    res = [x for x in res if x]
    for line in res:
        prefix_matrix.append(tuple(line.split(",")))

    prefix_matrix = aggregate_prefixes_modified(prefix_matrix, ipversion)

    prefix_matrix_map[(ipversion, asn)] = prefix_matrix
    print(f"AS{asn} prefix{ipversion} matrix generated.")
    return deepcopy(prefix_matrix)


def get_cone_prefix_matrix(ipversion, asn):
    """use bgpq4 to get cone prefix matrix of an asn"""

    if (ipversion, asn) in cone_prefix_matrix_map:
        return deepcopy(cone_prefix_matrix_map[(ipversion, asn)])

    asset_name_list = get_asset_name(asn)
    cone_prefix_matrix = []
    for asset_name in asset_name_list:
        cmd = rf'bgpq4 -S RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB -{ipversion} -A -F "%n,%l,%a,%A\n" {asset_name}'  # network, length, ge, le (example: 1.1.0.0, 16, 20, 24)
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        res = result.stdout.splitlines()
        res = [x for x in res if x]
        for line in res:
            cone_prefix_matrix.append(tuple(line.split(",")))

    cone_prefix_matrix = sorted(list(set(cone_prefix_matrix)))
    cone_prefix_matrix = aggregate_prefixes_modified(cone_prefix_matrix, ipversion)
    cone_prefix_matrix_map[(ipversion, asn)] = cone_prefix_matrix
    print(f"AS{asn} cone prefix{ipversion} matrix generated.")
    return deepcopy(cone_prefix_matrix)


def get_vyos_blacklist_filter(blacklist_config):
    """cmd to configure vyos blacklist filter"""

    full_vyos_cmd = """
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
        for n in range(0, len(blacklist_config["asn"]), 20):
            full_vyos_cmd += f"""
            set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} action deny
            set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} regex '_({"|".join(as_list[n:n+20 if n+20 < len(as_list) else len(as_list)])})_'
            """
            as_r += 1
    if "as-set" in blacklist_config:
        for asset_name in blacklist_config["as-set"]:
            as_list = [str(x) for x in get_as_set_member(asset_name)]
            for n in range(0, len(as_list), 20):
                full_vyos_cmd += f"""
                set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} action deny
                set policy as-path-list AUTOGEN-AS-BLACKLIST rule {as_r} regex '_({"|".join(as_list[n:n+20 if n+20 < len(as_list) else len(as_list)])})_'
                """
                as_r += 1

    p4_r = 1
    if "prefix4" in blacklist_config:
        for prefix in blacklist_config["prefix4"]:
            full_vyos_cmd += f"""
            set policy prefix-list AUTOGEN-PREFIX-BLACKLIST rule {p4_r} action deny
            set policy prefix-list AUTOGEN-PREFIX-BLACKLIST rule {p4_r} prefix {prefix}
            """
            p4_r += 1

    p6_r = 1
    if "prefix6" in blacklist_config:
        for prefix in blacklist_config["prefix6"]:
            full_vyos_cmd += f"""
            set policy prefix-list6 AUTOGEN-PREFIX6-BLACKLIST rule {p6_r} action deny
            set policy prefix-list6 AUTOGEN-PREFIX6-BLACKLIST rule {p6_r} prefix {prefix}
            """
            p6_r += 1

    print("blacklist filter generated.")
    return full_vyos_cmd


def get_vyos_as_path(asn):
    """use bgpq4 to get as-path filter"""

    full_vyos_cmd = f"""
    delete policy as-path-list AUTOGEN-AS{asn}-IN
    set policy as-path-list AUTOGEN-AS{asn}-IN rule 10 action permit
    set policy as-path-list AUTOGEN-AS{asn}-IN rule 10 regex '^{asn}(_{asn})*$'
    """

    cone_list = get_as_cone_member(asn)
    if asn in cone_list:
        cone_list.remove(asn)
    if 0 in cone_list:
        warnings.append(
            f"AS-SET of AS{asn} contains AS0, this session will be shutdown."
        )
        bad_asn_set.add(asn)

    if asn not in as_tier1 and (set(cone_list) & set(as_tier1)):
        warnings.append(
            f"AS-SET of AS{asn} contains Tier1 AS {(set(cone_list) & set(as_tier1))}, this session will be shutdown."
        )
        bad_asn_set.add(asn)

    cone_list = [str(x) for x in cone_list]

    if len(cone_list) + 1 > config["as-set-limit"]["member-limit"]:
        if asn in config["as-set-limit"]["large-as-list"]:
            full_vyos_cmd += f"""
            set policy as-path-list AUTOGEN-AS{asn}-IN rule 20 action permit
            set policy as-path-list AUTOGEN-AS{asn}-IN rule 20 regex '^{asn}(_[0-9]+)*$'
            """
            warnings.append(
                f"AS{asn} cone number is {len(cone_list)+1}, filter will accept all as-path."
            )
        else:
            warnings.append(
                f"AS{asn} cone number is {len(cone_list)+1} and asn not in large-as-list, this session will be shutdown."
            )
            bad_asn_set.add(asn)
    else:
        if len(cone_list) > 0:
            for i in range(0, len(cone_list), 20):
                full_vyos_cmd += f"""
                set policy as-path-list AUTOGEN-AS{asn}-IN rule {20+i} action permit
                set policy as-path-list AUTOGEN-AS{asn}-IN rule {20+i} regex '^{asn}(_[0-9]+)*_({"|".join(cone_list[i:i+20 if i+20 < len(cone_list) else len(cone_list)])})$'
                """

    print(f"AS{asn} as-path filter generated.")
    return full_vyos_cmd


def get_vyos_prefix_list(ipversion, asn, max_length=None, filter_name=None, cone=False):
    """use bgpq4 to get prefix list filter"""

    def vyos_cmd(network, length, ge, le, rule):
        # r = str(rule)
        le_final=max_length if max_length else le
        if int(ge)<=int(length) and int(length)<=int(le_final):
            return f"""
            set policy {pl} {fn} rule {rule} action permit
            set policy {pl} {fn} rule {rule} prefix {network}/{length}
            set policy {pl} {fn} rule {rule} ge {ge}
            set policy {pl} {fn} rule {rule} le {le_final}
            """
        else:
            return ""

    if cone:
        fn = filter_name if filter_name else f"AUTOGEN-AS{asn}-CONE"
    else:
        fn = filter_name if filter_name else f"AUTOGEN-AS{asn}"

    if ipversion == 4:
        pl = "prefix-list"
    elif ipversion == 6:
        pl = "prefix-list6"
    else:
        raise ValueError("ipversion must be 4 or 6")

    full_vyos_cmd = f"delete policy {pl} {fn}\n"

    if cone:
        prefix_matrix = get_cone_prefix_matrix(ipversion, asn)
    else:
        prefix_matrix = get_prefix_matrix(ipversion, asn)

    if len(prefix_matrix) == 0:
        full_vyos_cmd += f"""
        set policy {pl} {fn} rule 10 action deny
        set policy {pl} {fn} rule 10 prefix {"0.0.0.0/0" if ipversion == 4 else "::/0"}
        set policy {pl} {fn} rule 10 le {32 if ipversion == 4 else 128}
        """
        warnings.append(
            f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} list generated. But no prefix in list."
        )
    elif len(prefix_matrix) > config["as-set-limit"]["prefix-limit"]:
        if asn in config["as-set-limit"]["large-as-list"]:
            full_vyos_cmd += f"""
            set policy {pl} {fn} rule 10 action permit
            set policy {pl} {fn} rule 10 prefix {"0.0.0.0/0" if ipversion == 4 else "::/0"}
            set policy {pl} {fn} rule 10 le {24 if ipversion == 4 else 48}
            """
            warnings.append(
                f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} number({len(prefix_matrix)}) is too large, filter will accept all prefix."
            )
        else:
            full_vyos_cmd += f"""
            set policy {pl} {fn} rule 10 action deny
            set policy {pl} {fn} rule 10 prefix {"0.0.0.0/0" if ipversion == 4 else "::/0"}
            set policy {pl} {fn} rule 10 le {32 if ipversion == 4 else 128}
            """
            warnings.append(
                f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} number({len(prefix_matrix)}) is too large, and asn not in large-as-list, this session will be shutdown."
            )
            bad_asn_set.add(asn)
    else:
        c = 1
        for prefix in prefix_matrix:
            full_vyos_cmd += vyos_cmd(*prefix, c)
            c += 1
        del c
        print(f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} list generated.")
    return full_vyos_cmd


def get_vyos_as_filter(asn):
    full_vyos_cmd = ""
    full_vyos_cmd += get_vyos_as_path(asn)
    full_vyos_cmd += get_vyos_prefix_list(4, asn, cone=True)
    full_vyos_cmd += get_vyos_prefix_list(6, asn, cone=True)

    return full_vyos_cmd


def get_vyos_policy(policy):
    """cmd to configure vyos policy"""

    cmd = ""

    if "prefix-list" in policy:
        for p in policy["prefix-list"]:
            cmd += f"""
            delete policy prefix-list {p["name"]}
            """
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
            cmd += f"""
            delete policy prefix-list6 {p["name"]}
            """
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
            cmd += f"""
            delete policy as-path-list {p["name"]}
            """
            n = 1
            for r in p["rule"]:
                cmd += f"""
                set policy as-path-list {p['name']} rule {n} action {r["action"]}
                set policy as-path-list {p['name']} rule {n} regex '{r["regex"]}'
                {f"set policy as-path-list {p['name']} rule {n} description '{r['description']}'" if "description" in r else ""}
                """
                n += 1

    # community-list, large-community-list, route-map not used now

    return cmd


def get_vyos_route_map_redistribute(redistribute):
    """cmd to configure vyos route-map redistribute"""

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
                if not isinstance(c["set"], list):
                    set_list = [c["set"]]
                else:
                    set_list = c["set"]
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
                if not isinstance(c["set"], list):
                    set_list = [c["set"]]
                else:
                    set_list = c["set"]
                for r_set in set_list:
                    f += f"""
                    set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} set {r_set}
                    """
            # 或者给这些on-match-next false的全部跳转到10000？目前没跳转，不影响
            if c["action"] == "permit" and (
                "on-match-next" not in c or c["on-match-next"]
            ):
                f += f"""
                set policy route-map AUTOGEN-Redistribute rule {r_pre_accept} on-match next
                """
            r_pre_accept += 1

    return f


def get_vyos_protocol_rpki(server_list):
    """cmd to configure vyos protocol rpki"""

    cmd = """
    delete protocols rpki
    """
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
        if not isinstance(c["set"], list):
            set_list = [c["set"]]
        else:
            set_list = c["set"]
        for r_set in set_list:
            cmd += f"""
            set policy route-map {route_map_name} rule {r} set {r_set}
            """
    if c["action"] == "permit" and ("on-match-next" not in c or c["on-match-next"]):
        cmd += f"""
        set policy route-map {route_map_name} rule {r} on-match next
        """
    return cmd


def vyos_neighbor_in_optional_attributes(neighbor, route_map_in_name):
    """cmd to configure vyos neighbor optional attributes"""

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


def vyos_neighbor_out_optional_attributes(neighbor, route_map_out_name):
    """cmd to configure vyos neighbor optional attributes"""

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


def get_bgp_neighbor_address_family_cmd(
    ipversion,
    asn,
    neighbor_address,
    neighbor,
    neighbor_type,
    route_map_in_name,
    route_map_out_name_adopted,
):
    maximum_prefix = -1  # 定义一下避免出现未引用错误，实际上不可能发生
    maximum_prefix_out = -1
    asn_type = validateASN(asn)
    if neighbor_type in ["Peer", "Downstream"]:
        maximum_prefix = (
            maximum_prefix_map[asn][0] if ipversion == 4 else maximum_prefix_map[asn][1]
        )
    if neighbor_type in ["Upstream", "RouteServer", "Peer"]:
        maximum_prefix_out = (
            maximum_prefix_map[local_asn][0]
            if ipversion == 4
            else maximum_prefix_map[local_asn][1]
        )

    return f"""
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast default-originate" if "default-originate" in neighbor and neighbor["default-originate"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast addpath-tx-all" if "addpath" in neighbor and neighbor["addpath"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list import AUTOGEN-AS{asn}-CONE" if neighbor_type in ["Peer", "Downstream"] and asn_type==1 else ""}
    {f"delete protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list" if "disable-IRR" in neighbor and neighbor["disable-IRR"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list import AUTOGEN-AS{asn}-{get_neighbor_id(neighbor)}" if "prefix-list" in neighbor else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast filter-list import AUTOGEN-AS{asn}-IN" if neighbor_type in ["Peer", "Downstream"] and asn_type ==1 else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast maximum-prefix {maximum_prefix}" if neighbor_type in ["Peer", "Downstream"] else ""}
    {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast maximum-prefix-out {maximum_prefix_out}" if neighbor_type in ["Upstream", "RouteServer", "Peer"] else ""}
    set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast nexthop-self force
    set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast route-map export {route_map_out_name_adopted}
    set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast route-map import {route_map_in_name}
    {"" if ("soft-reconfiguration-inbound" in neighbor and not neighbor["soft-reconfiguration-inbound"]) else f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast soft-reconfiguration inbound"}
    """


def get_bgp_neighbor_cmd(
    neighbor, neighbor_type, route_map_in_name, route_map_out_name
):
    if neighbor_type == "IBGP":
        asn = local_asn
    else:
        asn = neighbor["asn"]
    if "multihop" in neighbor and isinstance(neighbor["multihop"], int):
        multihop = neighbor["multihop"]
    else:
        multihop = False
    password = neighbor["password"] if "password" in neighbor else None
    neighbor_address_list = neighbor["neighbor-address"]
    if not isinstance(neighbor_address_list, list):
        neighbor_address_list = [neighbor_address_list]

    bgp_cmd = ""

    if validateASN(asn) != 1 and "prefix-list" not in neighbor:
        neighbor["prefix-list"] = []

    if "prefix-list" in neighbor:
        # If set this, The default AUTOGEN-AS{asn}-CONE / AUTOGEN-AS{asn} will be ignored
        neighbor_id = get_neighbor_id(neighbor)
        bgp_cmd += f"""
        delete policy prefix-list AUTOGEN-AS{asn}-{neighbor_id}
        set policy prefix-list AUTOGEN-AS{asn}-{neighbor_id} rule 10000 action deny
        set policy prefix-list AUTOGEN-AS{asn}-{neighbor_id} rule 10000 prefix 0.0.0.0/0
        set policy prefix-list AUTOGEN-AS{asn}-{neighbor_id} rule 10000 ge 0
        set policy prefix-list AUTOGEN-AS{asn}-{neighbor_id} rule 10000 le 32
        delete policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id}
        set policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id} rule 10000 action deny
        set policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id} rule 10000 prefix ::/0
        set policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id} rule 10000 ge 0
        set policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id} rule 10000 le 128
        """
        for prefix_list_count, ip_str in enumerate(neighbor["prefix-list"], start=1):
            _tmp_net = ipaddress.ip_network(ip_str)
            if _tmp_net.version == 4:
                bgp_cmd += f"""
                set policy prefix-list AUTOGEN-AS{asn}-{neighbor_id} rule {prefix_list_count} action permit
                set policy prefix-list AUTOGEN-AS{asn}-{neighbor_id} rule {prefix_list_count} prefix {ip_str}
                """
            else:
                bgp_cmd += f"""
                set policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id} rule {prefix_list_count} action permit
                set policy prefix-list6 AUTOGEN-AS{asn}-{neighbor_id} rule {prefix_list_count} prefix {ip_str}
                """

    for neighbor_address in neighbor_address_list:
        if "default-originate" in neighbor and neighbor["default-originate"]:
            route_map_out_name_adopted = "AUTOGEN-REJECT-ALL"
        elif (
            neighbor_type == "IBGP"
            and "simple-out" in neighbor
            and neighbor["simple-out"]
        ):
            route_map_out_name_adopted = "AUTOGEN-SIMPLE-IBGP-OUT"
        else:
            route_map_out_name_adopted = route_map_out_name

        bgp_cmd += f"""
        delete protocols bgp neighbor {neighbor_address}
        {f"set protocols bgp neighbor {neighbor_address} shutdown" if (("shutdown" in neighbor and neighbor["shutdown"]) or (asn in bad_asn_set and asn not in config["keepup-as-list"] )) else ""}
        {f"set protocols bgp neighbor {neighbor_address} passive" if ("passive" in neighbor and neighbor["passive"]) else ""}
        set protocols bgp neighbor {neighbor_address} description '{neighbor["description"] if "description" in neighbor else f"{neighbor_type}: {as_name_map[asn]}"}'
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

        if isIP(neighbor_address) and not (
            "extended-nexthop" in neighbor and neighbor["extended-nexthop"]
        ):
            # isIP and not extended-nexthop
            ipversion = ipaddress.ip_address(neighbor_address).version
            bgp_cmd += get_bgp_neighbor_address_family_cmd(
                ipversion,
                asn,
                neighbor_address,
                neighbor,
                neighbor_type,
                route_map_in_name,
                route_map_out_name_adopted,
            )
        else:
            # neighbor_address is an interface name or extended-nexthop enabled
            if "address-family" in neighbor:
                if (
                    "ipv4" in neighbor["address-family"]
                    and neighbor["address-family"]["ipv4"]
                ):
                    bgp_cmd += get_bgp_neighbor_address_family_cmd(
                        4,
                        asn,
                        neighbor_address,
                        neighbor,
                        neighbor_type,
                        route_map_in_name,
                        route_map_out_name_adopted,
                    )
                if (
                    "ipv6" in neighbor["address-family"]
                    and neighbor["address-family"]["ipv6"]
                ):
                    bgp_cmd += get_bgp_neighbor_address_family_cmd(
                        6,
                        asn,
                        neighbor_address,
                        neighbor,
                        neighbor_type,
                        route_map_in_name,
                        route_map_out_name_adopted,
                    )
            else:
                # default to both ipv4 and ipv6
                bgp_cmd += get_bgp_neighbor_address_family_cmd(
                    4,
                    asn,
                    neighbor_address,
                    neighbor,
                    neighbor_type,
                    route_map_in_name,
                    route_map_out_name_adopted,
                )
                bgp_cmd += get_bgp_neighbor_address_family_cmd(
                    6,
                    asn,
                    neighbor_address,
                    neighbor,
                    neighbor_type,
                    route_map_in_name,
                    route_map_out_name_adopted,
                )

    return bgp_cmd


def get_vyos_protocol_bgp_neighbor(neighbor_type, neighbor):
    """cmd to configure vyos protocol bgp"""

    neighbor_id = get_neighbor_id(neighbor)

    if neighbor_type == "IBGP":
        asn = local_asn
    else:
        asn = neighbor["asn"]

    asn_type = validateASN(asn)
    if asn_type != 1 and neighbor_type != "Downstream":
        raise ValueError(f"Private ASN {asn} must be Downstream")

    if neighbor_type == "IBGP":
        route_map_in_name = f"AUTOGEN-IBGP-IN-{neighbor_id}"
        route_map_out_name = f"AUTOGEN-IBGP-OUT-{neighbor_id}"
    else:
        route_map_in_name = f"AUTOGEN-AS{asn}-{neighbor_type.upper()}-IN-{neighbor_id}"
        route_map_out_name = (
            f"AUTOGEN-AS{asn}-{neighbor_type.upper()}-OUT-{neighbor_id}"
        )

    final_filter = ""
    final_filter += f"""
    delete policy route-map {route_map_in_name}
    set policy route-map {route_map_in_name} rule 10 action permit
    {f"set policy route-map {route_map_in_name} rule 10 call AUTOGEN-{neighbor_type.upper()}-IN" if asn_type == 1 else f"set policy route-map {route_map_in_name} rule 10 set as-path exclude all"}
    set policy route-map {route_map_in_name} rule 10 on-match next
    # rule 100 for setting attribute like local-pref, metric
    set policy route-map {route_map_in_name} rule 100 action permit
    set policy route-map {route_map_in_name} rule 100 on-match next
    # rule 200-999 for this code
    set policy route-map {route_map_in_name} rule 200 action permit
    {f"set policy route-map {route_map_in_name} rule 200 set large-community add {local_asn}:10000:{asn}" if neighbor_type!="IBGP" else ""}
    set policy route-map {route_map_in_name} rule 200 set large-community add {local_asn}:10001:{neighbor_id}
    set policy route-map {route_map_in_name} rule 200 on-match next
    # rule 1000-9999 for pre-import-accept in config
    set policy route-map {route_map_in_name} rule 10000 action permit
    """
    final_filter += f"""
    delete policy route-map {route_map_out_name}
    set policy route-map {route_map_out_name} rule 10 action permit
    set policy route-map {route_map_out_name} rule 10 call AUTOGEN-{neighbor_type.upper()}-OUT
    set policy route-map {route_map_out_name} rule 10 on-match next
    # rule 100 for controling like prepend
    set policy route-map {route_map_out_name} rule 100 action permit
    set policy route-map {route_map_out_name} rule 100 on-match next
    """
    # This disable others ability to control their prefixes to private ASN
    final_filter += (
        f"""
    # rule 200-999 for this code
    set policy route-map {route_map_out_name} rule 200 action deny
    set policy route-map {route_map_out_name} rule 200 match large-community large-community-list AUTOGEN-DNA-ANY
    set policy route-map {route_map_out_name} rule 201 action deny
    set policy route-map {route_map_out_name} rule 201 match large-community large-community-list AUTOGEN-DNA-AS{asn}
    set policy route-map {route_map_out_name} rule 202 action deny
    set policy route-map {route_map_out_name} rule 202 match large-community large-community-list AUTOGEN-DNA-NID{neighbor_id}
    set policy route-map {route_map_out_name} rule 300 action permit
    set policy route-map {route_map_out_name} rule 300 match large-community large-community-list AUTOGEN-OLA-AS{asn}
    set policy route-map {route_map_out_name} rule 300 on-match goto 401
    set policy route-map {route_map_out_name} rule 301 action permit
    set policy route-map {route_map_out_name} rule 301 match large-community large-community-list AUTOGEN-OLA-NID{neighbor_id}
    set policy route-map {route_map_out_name} rule 301 on-match goto 401
    set policy route-map {route_map_out_name} rule 302 action deny
    set policy route-map {route_map_out_name} rule 302 match large-community large-community-list AUTOGEN-OLA-ALL
    set policy route-map {route_map_out_name} rule 401 action permit
    set policy route-map {route_map_out_name} rule 401 match large-community large-community-list AUTOGEN-Prepend-1X-AS{asn}
    set policy route-map {route_map_out_name} rule 401 set as-path prepend-last-as 1 # will this prepend my asn or neighbor's asn?
    set policy route-map {route_map_out_name} rule 401 on-match next
    set policy route-map {route_map_out_name} rule 402 action permit
    set policy route-map {route_map_out_name} rule 402 match large-community large-community-list AUTOGEN-Prepend-2X-AS{asn}
    set policy route-map {route_map_out_name} rule 402 set as-path prepend-last-as 2
    set policy route-map {route_map_out_name} rule 402 on-match next
    # rule 1000-9999 for pre-export-accept in config
    """
        if asn_type == 1
        else ""
    )
    final_filter += f"""
    set policy route-map {route_map_out_name} rule 10000 action permit
    """
    # This disable others ability to control their prefixes to private ASN
    final_filter += (
        f"""

    delete policy large-community-list AUTOGEN-DNA-NID{neighbor_id}
    set policy large-community-list AUTOGEN-DNA-NID{neighbor_id} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-DNA-NID{neighbor_id} rule 10 regex "{local_asn}:1001:{neighbor_id}"
    delete policy large-community-list AUTOGEN-OLA-NID{neighbor_id}
    set policy large-community-list AUTOGEN-OLA-NID{neighbor_id} rule 10 action 'permit'
    set policy large-community-list AUTOGEN-OLA-NID{neighbor_id} rule 10 regex "{local_asn}:1101:{neighbor_id}"
    """
        if asn_type == 1
        else ""
    )

    final_filter += vyos_neighbor_in_optional_attributes(neighbor, route_map_in_name)
    final_filter += vyos_neighbor_out_optional_attributes(neighbor, route_map_out_name)

    bgp_cmd = get_bgp_neighbor_cmd(
        neighbor, neighbor_type, route_map_in_name, route_map_out_name
    )

    return final_filter + bgp_cmd


def get_vyos_protocol_bgp(bgp_config, _router_id):
    """cmd to configure vyos protocol bgp"""

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
    set protocols bgp parameters router-id {_router_id}
    set protocols bgp system-as {local_asn}
    """

    for ibgp_neighbor in bgp_config["ibgp"]:
        if "manual" in ibgp_neighbor and ibgp_neighbor["manual"]:
            continue
        cmd += get_vyos_protocol_bgp_neighbor("IBGP", ibgp_neighbor)
    for upstream_neighbor in bgp_config["upstream"]:
        if "manual" in upstream_neighbor and upstream_neighbor["manual"]:
            continue
        cmd += get_vyos_protocol_bgp_neighbor("Upstream", upstream_neighbor)
    for routeserver_neighbor in bgp_config["routeserver"]:
        if "manual" in routeserver_neighbor and routeserver_neighbor["manual"]:
            continue
        cmd += get_vyos_protocol_bgp_neighbor("RouteServer", routeserver_neighbor)
    for peer_neighbor in bgp_config["peer"]:
        if "manual" in peer_neighbor and peer_neighbor["manual"]:
            continue
        cmd += get_vyos_protocol_bgp_neighbor("Peer", peer_neighbor)
    for downstream_neighbor in bgp_config["downstream"]:
        if "manual" in downstream_neighbor and downstream_neighbor["manual"]:
            continue
        cmd += get_vyos_protocol_bgp_neighbor("Downstream", downstream_neighbor)

    if "parameters" in bgp_config:
        for param in bgp_config["parameters"]:
            cmd += f"""
            set protocols bgp parameters {param}
            """

    return cmd


def get_vyos_kernel(kernel_config):
    cmd = ""
    if "ipv4" in kernel_config:
        for routemap in kernel_config["ipv4"]:
            protocol = routemap["protocol"]
            cmd += f"""
            delete policy route-map AUTOGEN-KERNEL-IPv4-{protocol}
            set policy route-map AUTOGEN-KERNEL-IPv4-{protocol} rule 100 action permit
            delete system ip protocol {protocol}
            set system ip protocol {protocol} route-map AUTOGEN-KERNEL-IPv4-{protocol}
            """
            if "src" in routemap:
                cmd += f"""
                set policy route-map AUTOGEN-KERNEL-IPv4-{protocol} rule 1 action permit
                set policy route-map AUTOGEN-KERNEL-IPv4-{protocol} rule 1 match ip address prefix-list 'AUTOGEN-IPv4-ALL'
                set policy route-map AUTOGEN-KERNEL-IPv4-{protocol} rule 1 set src '{routemap["src"]}'
                set policy route-map AUTOGEN-KERNEL-IPv4-{protocol} rule 1 on-match next
                """
            if "pre-accept" in routemap:
                r = 10
                for c in routemap["pre-accept"]:
                    cmd += vyos_pre_accept_filter(
                        f"AUTOGEN-KERNEL-IPv4-{protocol}", r, c
                    )
                    r += 1

    if "ipv6" in kernel_config:
        for routemap in kernel_config["ipv6"]:
            protocol = routemap["protocol"]
            cmd += f"""
            delete policy route-map AUTOGEN-KERNEL-IPv6-{protocol}
            set policy route-map AUTOGEN-KERNEL-IPv6-{protocol} rule 100 action permit
            delete system ipv6 protocol {protocol}
            set system ipv6 protocol {protocol} route-map AUTOGEN-KERNEL-IPv6-{protocol}
            """
            if "src" in routemap:
                cmd += f"""
                set policy route-map AUTOGEN-KERNEL-IPv6-{protocol} rule 1 action permit
                set policy route-map AUTOGEN-KERNEL-IPv6-{protocol} rule 1 match ipv6 address prefix-list 'AUTOGEN-IPv6-ALL'
                set policy route-map AUTOGEN-KERNEL-IPv6-{protocol} rule 1 set src '{routemap["src"]}'
                set policy route-map AUTOGEN-KERNEL-IPv6-{protocol} rule 1 on-match next
                """
            if "pre-accept" in routemap:
                r = 10
                for c in routemap["pre-accept"]:
                    cmd += vyos_pre_accept_filter(
                        f"AUTOGEN-KERNEL-IPv6-{protocol}", r, c
                    )
                    r += 1
    return cmd


def get_vyos_system_frr():
    return """
    """


def get_vyos_bmp(bmp_config):
    cmd = """
    delete system frr bmp
    set system frr bmp
    delete protocols bgp bmp
    """
    for bmp_server in bmp_config:
        cmd += f"""
        set protocols bgp bmp target {bmp_server["target"]} address {bmp_server["address"]}
        set protocols bgp bmp target {bmp_server["target"]} port {bmp_server["port"]}
        """
        if "mirror" in bmp_server and not bmp_server["mirror"]:
            cmd += f"""
            set protocols bgp bmp target {bmp_server["target"]} monitor ipv4-unicast post-policy
            set protocols bgp bmp target {bmp_server["target"]} monitor ipv6-unicast post-policy
            """
        else:
            cmd += f"""
            set protocols bgp bmp target {bmp_server["target"]} mirror
            """
    return cmd


def get_vyos_sflow(sflow_config):
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
    for sflow_server in sflow_config["server"]:
        cmd += f"""
        set system sflow server {sflow_server["address"]} port {sflow_server["port"]}
        """
    for sflow_interface in sflow_config["interface"]:
        cmd += f"""
        set system sflow interface {sflow_interface}
        """
    return cmd


def get_vyos_snmp(snmp_config, engineid):
    cmd = f"""
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
    return cmd


def ipv4_to_engineid(ipv4):
    return "000000000000" + "".join([part.zfill(3) for part in ipv4.split(".")])


def get_final_vyos_cmd(router_config):
    """cmd to configure vyos"""

    router_name = router_config["name"]
    router_id = get_router_id(router_name)
    print(f"generate vyos bgp script for {router_name}({router_id})")

    configure = ""

    # AS prefix list and AS filter
    upstream_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["upstream"]]
    routeserver_asns = [
        n["asn"] for n in router_config["protocols"]["bgp"]["routeserver"]
    ]
    peer_asns = [n["asn"] for n in router_config["protocols"]["bgp"]["peer"]]
    downstream_asns = [
        n["asn"] for n in router_config["protocols"]["bgp"]["downstream"]
    ]
    connected_asns = upstream_asns + routeserver_asns + peer_asns + downstream_asns
    connected_asns = sorted(list(set(connected_asns)))
    if "blacklist" in config:
        # but it is in global config, this will cause waste of resource
        configure += get_vyos_blacklist_filter(config["blacklist"])
    get_as_info(local_asn)
    configure += get_vyos_as_community(
        local_asn
    )  # 权宜之计，实际上ibgp不该能这样操控？
    for asn in connected_asns:
        asn_type = get_as_info(asn)
        if asn_type == 1:
            configure += get_vyos_as_community(asn)

    # local asn prefix list
    # configure += get_vyos_prefix_list(
    #     4, local_asn, filter_name="AUTOGEN-LOCAL-ASN-CONE", cone=True
    # )
    # configure += get_vyos_prefix_list(
    #     6, local_asn, filter_name="AUTOGEN-LOCAL-ASN-CONE", cone=True
    # )
    configure += get_vyos_prefix_list(
        4, local_asn, filter_name="AUTOGEN-LOCAL-ASN-PREFIX4"
    )
    configure += get_vyos_prefix_list(
        6, local_asn, filter_name="AUTOGEN-LOCAL-ASN-PREFIX6"
    )
    configure += get_vyos_prefix_list(
        4, local_asn, max_length=32, filter_name="AUTOGEN-LOCAL-ASN-PREFIX4-le32"
    )
    configure += get_vyos_prefix_list(
        6, local_asn, max_length=128, filter_name="AUTOGEN-LOCAL-ASN-PREFIX6-le128"
    )

    # we only need to generate filter for peer and downstream
    for asn in sorted(list(set(peer_asns + downstream_asns))):
        if validateASN(asn) == 1:
            configure += get_vyos_as_filter(asn)

    # protocol rpki
    configure += get_vyos_protocol_rpki(router_config["protocols"]["rpki"])

    # policy
    if "policy" in router_config:
        configure += get_vyos_policy(router_config["policy"])

    # protocol bgp
    configure += get_vyos_protocol_bgp(router_config["protocols"]["bgp"], router_id)

    # redistribute
    if "redistribute" in router_config:
        configure += get_vyos_route_map_redistribute(router_config["redistribute"])
    else:
        configure += get_vyos_route_map_redistribute({})

    # system frr
    configure += get_vyos_system_frr()

    if "service" in router_config:
        # bmp
        if "bmp" in router_config["service"]:
            configure += get_vyos_bmp(router_config["service"]["bmp"])

        # sflow
        if "sflow" in router_config["service"]:
            configure += get_vyos_sflow(router_config["service"]["sflow"])

        # snmp
        if "snmp" in router_config["service"]:
            configure += get_vyos_snmp(
                router_config["service"]["snmp"], ipv4_to_engineid(router_id)
            )

    # kernel
    if "kernel" in router_config:
        configure += get_vyos_kernel(router_config["kernel"])

    configure = "\n".join(
        [line.strip() for line in configure.splitlines() if line.strip()]
    )

    configure = (
        "\nconfigure\n"
        + defaultconfig
        + configure
        + (
            router_config["custom-config"] + "\n"
            if "custom-config" in router_config
            else ""
        )
        + "\necho 'configure done'\n"
        + '\nvtysh -c "watchfrr ignore bgpd"\n'  # watchfrr ignore bgpd so bgpd won't be killed when it hasn't response in 90s
        + "\ncommit\n"
        # + '\nvtysh -c "no watchfrr ignore bgpd"\n'  # recover watchfrr config
        + "\nexit\n"
    )

    #################################

    script_start = r"""#!/bin/vbash

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template
"""
    script_end = r"""exit"""

    script_env = f"""
ASN={local_asn}
ROUTER={router_name}
GITHUB_REPOSITORY={os.getenv("GITHUB_REPOSITORY")}
    """

    #################################

    return script_start + script_env + configure + script_end


def update_arin_asset_members(api_key):
    """
    Update ARIN AS-SET members with downstream ASNs if the API key is valid
    and the local AS-SET is managed by ARIN.
    """
    print("----------------------------------------------------------------")
    print("Checking ARIN AS-SET consistency...")

    # 1. Determine Local AS-SET Name
    # We take the first AS-SET from PeeringDB info as the primary one to manage if available
    # Or fallback to AS{local_asn}
    if local_asn in asset_name_map and asset_name_map[local_asn]:
        target_asset_name_full = asset_name_map[local_asn][0]
        # remove ' -S ...' suffix if exists (from get_as_info logic)
        target_asset_name = target_asset_name_full.split(" -S")[0].strip()
    else:
        target_asset_name = f"AS{local_asn}"

    print(f"Target Local AS-SET: {target_asset_name}")

    base_url = "https://reg.arin.net/rest"
    # Use headers for XML content
    headers = {
        "Content-Type": "application/xml",
        "Accept": "application/xml"
    }

    # 2. Get Current AS-SET from ARIN
    # URL: https://reg.arin.net/rest/irr/as-set/{handle}
    url = f"{base_url}/irr/as-set/{target_asset_name}?apikey={api_key}"
    
    try:
        response = requests.get(url, headers=headers)
    except requests.RequestException as e:
        print(f"Skipping ARIN check: Request failed - {e}")
        return

    if response.status_code != 200:
        print(f"Skipping ARIN check: Could not retrieve AS-SET '{target_asset_name}' from ARIN (Status: {response.status_code}).")
        print("Reason might be: Invalid API Key, AS-SET not managed by ARIN, or server error.")
        return

    # Parse XML response
    try:
        # We need to register namespace to properly parse/find elements
        # ARIN usually uses this namespace
        namespaces = {'ns': 'http://www.arin.net/regrws/core/v1'}
        # Register for writing back without ns0: prefixes if possible, asking ElementTree
        ET.register_namespace('', namespaces['ns'])
        
        root = ET.fromstring(response.content)
        
        # Extract current members
        # Structure: <asSet ...><members><member name="AS12345"/>...</members>...</asSet>
        current_members = set()
        members_container = root.find("ns:members", namespaces)
        if members_container is not None:
            for member in members_container.findall("ns:member", namespaces):
                current_members.add(member.get("name"))
            
        print(f"Current ARIN members: {sorted(list(current_members))}")
        
    except ET.ParseError as e:
        print(f"Skipping ARIN check: Failed to parse XML response - {e}")
        return

    # 3. Collect Downstream AS-SETs from local config
    # We need to scan all downstream neighbors across all routers defined in config["router"]
    downstream_asset_members_map = {}
    
    # We need to iterate over config["router"] list
    if "router" in config:
        for router in config["router"]:
            if "protocols" in router and "bgp" in router["protocols"] and "downstream" in router["protocols"]["bgp"]:
                for neighbor in router["protocols"]["bgp"]["downstream"]:
                    ds_asn = neighbor["asn"]
                    
                    # Validate ASN first
                    if validateASN(ds_asn) != 1:
                        continue
                        
                    # Get AS-SET for this downstream ASN
                    # get_asset_name(ds_asn) returns a list of AS-SET names
                    # We usually pick the first one as the primary AS-SET to include
                    ds_assets = get_asset_name(ds_asn)
                    
                    if ds_assets:
                        # Extract clean name without -S suffix
                        ds_member_name = ds_assets[0].split(" -S")[0].strip()
                        downstream_asset_members_map[ds_asn] = ds_member_name

    expected_members = set(downstream_asset_members_map.values())
    print(f"Expected Downstream members from config: {sorted(list(expected_members))}")

    # 4. Compare and Update
    # Find members that are in expected but not in current
    members_to_add = expected_members - current_members
    
    if not members_to_add:
        print("ARIN AS-SET is up to date. No new members to add.")
        return

    print(f"Adding missing members to ARIN AS-SET: {members_to_add}")
    
    # Add new members to XML root
    # Note: We need to ensure we use the correct namespace for new elements
    ns_url = namespaces['ns']
    
    # If <members> container doesn't exist, create it (unlikely for valid AS-SET but possible if empty)
    if members_container is None:
        members_container = ET.Element(f"{{{ns_url}}}members")
        root.append(members_container)

    for new_member in members_to_add:
        # Create <member name="NEW_MEMBER"/>
        new_elem = ET.Element(f"{{{ns_url}}}member")
        new_elem.set("name", new_member)
        members_container.append(new_elem)
    
    # Generate new XML string
    new_xml_content = ET.tostring(root, encoding='utf-8')
    
    # 5. Push Update
    update_url = f"{base_url}/irr/as-set/{target_asset_name}?apikey={api_key}"
    try:
        update_response = requests.put(update_url, data=new_xml_content, headers=headers)
        
        if update_response.status_code == 200:
            print("Successfully updated ARIN AS-SET.")
        else:
            print(f"Failed to update ARIN AS-SET. Status: {update_response.status_code}")
            print(update_response.text)
    except requests.RequestException as e:
        print(f"Failed to push update to ARIN: {e}")


if __name__ == "__main__":

    router_list = config["router"]
    if not router_list:
        raise ValueError("router list is empty")

    if not os.path.exists(os.path.join(work_dir, "outputs")):
        os.makedirs(os.path.join(work_dir, "outputs"))

    for router in router_list:
        # try:
        script = get_final_vyos_cmd(router)
        with open(
            os.path.join(work_dir, "outputs", f"configure.{router['name']}.sh"),
            "w",
            encoding="utf-8",
        ) as f_txt:
            f_txt.write(script)
        print(f"configure.{router['name']}.sh generated.")

    with open(
        os.path.join(work_dir, "outputs", "defaultconfig.sh"),
        "w",
        encoding="utf-8",
    ) as f_txt:
        f_txt.write(defaultconfig)

    with open(
        os.path.join(work_dir, "outputs", "find_unused.py"),
        "w",
        encoding="utf-8",
    ) as f_txt:
        find_unused_template = open(
            os.path.join(work_dir, "find_unused.py"), "r", encoding="utf-8"
        ).read()
        find_unused_template = find_unused_template.replace(
            r"${default_config_url}",
            f"https://github.com/{github_user}/{github_repo}/releases/download/nightly/defaultconfig.sh",
        )
        f_txt.write(find_unused_template)

    print("All done. Below is the warnings: ----------------------------------")
    for w in warnings:
        print(w)
    print("Please note that there are issues with these ASNs: ----------------")
    print(bad_asn_set)

    if os.getenv("ARIN_API_KEY"):
        try:
            update_arin_asset_members(os.getenv("ARIN_API_KEY"))
        except Exception as e:
            print(f"An error occurred while updating ARIN AS-SET: {e}")
