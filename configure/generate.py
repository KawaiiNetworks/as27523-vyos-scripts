from copy import deepcopy
import requests
import os
import subprocess
import ipaddress
import json
import yaml
import time
import re
import dns.resolver
import hashlib

work_dir = os.path.dirname(os.path.abspath(__file__))
github_user = os.getenv("GITHUB_REPOSITORY").split("/")[0]
github_repo = os.getenv("GITHUB_REPOSITORY").split("/")[-1]
local_asn = re.search(r"as(\d+)", github_repo.lower()).group(1)
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
"""as:(maximum-prefix4, maximum-prefix6)"""

cone_map = {}
"""as:[as-set member]"""

prefix_matrix_map = {}
"""(ipversion, as):[(network, length, ge, le, object_mask, invert_mask)]"""

cone_prefix_matrix_map = {}
"""(ipversion, as):[(network, length, ge, le, object_mask, invert_mask)]"""


neighbor_id_hashmap = {}


def get_neighbor_id(neighbor):
    neighbor_address_list = neighbor["neighbor-address"]
    if not isinstance(neighbor_address_list, list):
        neighbor_address_list = [neighbor_address_list]
    neighbor_str = (
        str(neighbor["asn"])
        + "".join(sorted(neighbor_address_list))
        # + str(neighbor["update-source"])
    )
    hash_object = hashlib.sha256(neighbor_str.encode("utf-8"))
    hash_hex = hash_object.hexdigest()
    res = 1 + int(hash_hex, 16) % (2**16)  # 1-65536
    if res in neighbor_id_hashmap and neighbor_id_hashmap[res] != neighbor_str:
        raise ValueError("hash collision")
    else:
        neighbor_id_hashmap[res] = neighbor_str
    return res


def get_router_id(router_name):
    """use dns to get router-id"""

    answer = dns.resolver.resolve(router_name, "A")
    if len(answer) != 1:
        print("router-id for {router_name} is not unique")
        return None
    return answer[0].address


def get_as_info(asn):
    """use peeringdb to get as info"""

    if asn in as_name_map:
        return

    time.sleep(5)
    url = f"https://www.peeringdb.com/api/net?asn={asn}"
    print(f"getting AS{asn} info...")
    response = requests.get(url, timeout=10).json()["data"][0]

    maximum_prefix_map[asn] = (
        response["info_prefixes4"],
        response["info_prefixes6"],
    )
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
        print(f"AS{asn} as-set name not found, use default AS{asn}")
        as_set_name_list = [f"AS{asn}"]

    asset_name_map[asn] = as_set_name_list
    print(f"AS{asn} as-set name: {as_set_name_list}")


def get_vyos_as_community(asn):
    """get vyos as community cmd"""

    return f"""
    delete policy large-community-list DNA-AS{asn}
    set policy large-community-list DNA-AS{asn} rule 10 action 'permit'
    set policy large-community-list DNA-AS{asn} rule 10 regex "{local_asn}:1000:{asn}"
    """


def get_asset_name(asn):
    """use peeringdb to get as-set name"""

    return deepcopy(asset_name_map[asn])


def get_as_set_member(asn):
    """use bgpq4 to get as-set member"""

    if asn in cone_map:
        return deepcopy(cone_map[asn])

    asset_name_list = get_asset_name(asn)  # an asn may have multiple as-set

    res = []

    for asset_name in asset_name_list:
        cmd = (
            f"bgpq4 -S RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB -jt {asset_name}"
        )
        result = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        res += json.loads(result.stdout)["NN"]
    res = sorted(list(set(res)))
    cone_map[asn] = res
    print(f"AS{asn} cone list: {res}")
    return deepcopy(res)


def get_prefix_matrix(ipversion, asn):
    """use bgpq4 to get prefix matrix"""

    if (ipversion, asn) in prefix_matrix_map:
        return deepcopy(prefix_matrix_map[(ipversion, asn)])

    cmd = rf'bgpq4 -S RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB -{ipversion} -A -F "%n,%l,%a,%A\n" as{asn} -l AS{asn}'
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
        cmd = rf'bgpq4 -S RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB -{ipversion} -A -F "%n,%l,%a,%A\n" {asset_name}'
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
    cone_prefix_matrix_map[(ipversion, asn)] = cone_prefix_matrix
    print(f"AS{asn} cone prefix{ipversion} matrix generated.")
    return deepcopy(cone_prefix_matrix)


def get_vyos_as_path(asn):
    """use bgpq4 to get as-path filter"""

    full_vyos_cmd = f"""
    delete policy as-path-list AS{asn}-IN
    set policy as-path-list AS{asn}-IN rule 10 action permit
    set policy as-path-list AS{asn}-IN rule 10 regex '^{asn}(_{asn})*$'
    """

    cone_list = get_as_set_member(asn)
    if asn in cone_list:
        cone_list.remove(asn)
    cone_list = [str(x) for x in cone_list]

    if len(cone_list) + 1 > config["as-set"]["member-limit"]:
        if config["as-set"]["limit-violation"] == "accept":
            full_vyos_cmd += f"""
            set policy as-path-list AS{asn}-IN rule 20 action permit
            set policy as-path-list AS{asn}-IN rule 20 regex '^{asn}(_[0-9]+)*$'
            """
            print(
                f"Warn: AS{asn} as-path filter generated. But cone number is {len(cone_list)+1}, filter will accept all as-path."
            )
            return full_vyos_cmd
        elif config["as-set"]["limit-violation"] == "deny":
            full_vyos_cmd += f"""
            set policy as-path-list AS{asn}-IN rule 20 action deny
            set policy as-path-list AS{asn}-IN rule 20 regex '.*'
            """
            print(
                f"Warn: AS{asn} as-path filter generated. But cone number is {len(cone_list)+1}, filter will deny all as-path except {asn}."
            )
            return full_vyos_cmd
        else:
            raise ValueError("as-set limit-violation must be accept, deny")

    if len(cone_list) > 0:
        full_vyos_cmd += f"""
        set policy as-path-list AS{asn}-IN rule 20 action permit
        set policy as-path-list AS{asn}-IN rule 20 regex '^{asn}(_[0-9]+)*_({"|".join(cone_list)})$'
        """
    print(f"AS{asn} as-path filter generated.")
    return full_vyos_cmd


def get_vyos_prefix_list(ipversion, asn, max_length=None, filter_name=None, cone=False):
    """use bgpq4 to get prefix list filter"""

    def vyos_cmd(network, length, ge, le, rule):
        # r = str(rule)
        return f"""
        set policy {pl} {fn} rule {rule} action permit
        set policy {pl} {fn} rule {rule} prefix {network}/{length}
        set policy {pl} {fn} rule {rule} ge {ge}
        set policy {pl} {fn} rule {rule} le {max_length if max_length else le}
        """

    def vyos_cmd_when_limit_violation(pl, fn, prefix_count):
        if config["as-set"]["limit-violation"] == "accept":
            print(
                f"Warn: AS{asn} {'cone' if cone else ''} prefix{ipversion} list generated. But prefix number({prefix_count}) is too large, filter will accept all prefix."
            )
            return f"""
            set policy {pl} {fn} rule 10 action permit
            set policy {pl} {fn} rule 10 prefix {"0.0.0.0/0" if ipversion == 4 else "::/0"}
            set policy {pl} {fn} rule 10 le {24 if ipversion == 4 else 48}
            """
        elif config["as-set"]["limit-violation"] == "deny":
            print(
                f"Warn: AS{asn} {'cone' if cone else ''} prefix{ipversion} list generated. But prefix number({prefix_count}) is too large, filter will deny all prefix."
            )
            return f"""
            set policy {pl} {fn} rule 10 action deny
            set policy {pl} {fn} rule 10 prefix {"0.0.0.0/0" if ipversion == 4 else "::/0"}
            set policy {pl} {fn} rule 10 le {32 if ipversion == 4 else 128}
            """
        else:
            raise ValueError("as-set limit-violation must be accept, deny")

    if cone:
        fn = filter_name if filter_name else f"AS{asn}-CONE"
    else:
        fn = filter_name if filter_name else f"AS{asn}"

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
        print(
            f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} list generated. But no prefix in list."
        )
    elif len(prefix_matrix) > config["as-set"]["prefix-limit"]:
        full_vyos_cmd += vyos_cmd_when_limit_violation(pl, fn, len(prefix_matrix))
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

    if "pre-import-accept" in neighbor:
        r = 1000
        for c in neighbor["pre-import-accept"]:
            f += f"""
            set policy route-map {route_map_in_name} rule {r} action {c["action"]}
            set policy route-map {route_map_in_name} rule {r} match {c["match"]}
            """
            if "set" in c:
                f += f"""
                set policy route-map {route_map_in_name} rule {r} set {c["set"]}
                """
            # 或者给这些on-match-next false的全部跳转到1000？目前没跳转，不影响
            if c["action"] == "permit" and (
                "on-match-next" not in c or c["on-match-next"]
            ):
                f += f"""
                set policy route-map {route_map_in_name} rule {r} on-match next
                """
            r += 1
    return f


def vyos_neighbor_out_optional_attributes(neighbor, route_map_out_name):
    """cmd to configure vyos neighbor optional attributes"""

    f = ""
    if "prepend" in neighbor:
        f += f"""
        set policy route-map {route_map_out_name} rule 100 set as-path prepend '{neighbor["prepend"]}'
        """

    if "pre-export-accept" in neighbor:
        r = 1000
        for c in neighbor["pre-export-accept"]:
            f += f"""
            set policy route-map {route_map_out_name} rule {r} action {c["action"]}
            set policy route-map {route_map_out_name} rule {r} match {c["match"]}
            """
            if "set" in c:
                f += f"""
                set policy route-map {route_map_out_name} rule {r} set {c["set"]}
                """
            # 或者给这些on-match-next false的全部跳转到1000？目前没跳转，不影响
            if c["action"] == "permit" and (
                "on-match-next" not in c or c["on-match-next"]
            ):
                f += f"""
                set policy route-map {route_map_out_name} rule {r} on-match next
                """
            r += 1

    return f


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
    for neighbor_address in neighbor_address_list:
        ipversion = ipaddress.ip_address(neighbor_address).version
        maximum_prefix = -1  # 定义一下避免出现未引用错误，实际上不可能发生
        maximum_prefix_out = -1
        if neighbor_type in ["Peer", "Downstream"]:
            maximum_prefix = (
                maximum_prefix_map[asn][0]
                if ipversion == 4
                else maximum_prefix_map[asn][1]
            )
        if neighbor_type in ["Upstream", "RouteServer", "Peer"]:
            maximum_prefix_out = (
                maximum_prefix_map[local_asn][0]
                if ipversion == 4
                else maximum_prefix_map[local_asn][1]
            )
        bgp_cmd += f"""
        delete protocols bgp neighbor {neighbor_address}
        {f"set protocols bgp neighbor {neighbor_address} shutdown" if ("shutdown" in neighbor and neighbor["shutdown"]) else ""}
        {f"set protocols bgp neighbor {neighbor_address} passive" if ("passive" in neighbor and neighbor["passive"]) else ""}
        set protocols bgp neighbor {neighbor_address} description '{neighbor["description"] if "description" in neighbor else f"{neighbor_type}: {as_name_map[asn]}"}'
        set protocols bgp neighbor {neighbor_address} graceful-restart enable
        set protocols bgp neighbor {neighbor_address} remote-as {asn}
        {f"set protocols bgp neighbor {neighbor_address} password '{password}'" if password else ""}
        {f"set protocols bgp neighbor {neighbor_address} ebgp-multihop {multihop}" if multihop else ""}
        set protocols bgp neighbor {neighbor_address} solo
        set protocols bgp neighbor {neighbor_address} update-source {neighbor["update-source"]}
        {f"set protocols bgp neighbor {neighbor_address} shutdown" if neighbor_type in ["Peer", "Downstream"] and maximum_prefix==0 else ""}
        {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast prefix-list import AS{asn}-CONE" if neighbor_type in ["Peer", "Downstream"] else ""}
        {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast filter-list import AS{asn}-IN" if neighbor_type in ["Peer", "Downstream"] else ""}
        {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast maximum-prefix {maximum_prefix}" if neighbor_type in ["Peer", "Downstream"] else ""}
        {f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast maximum-prefix-out {maximum_prefix_out}" if neighbor_type in ["Upstream", "RouteServer", "Peer"] else ""}
        set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast nexthop-self force
        set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast route-map export {"SIMPLE-IBGP-OUT" if (neighbor_type=="IBGP" and "simple-out" in neighbor and neighbor["simple-out"]) else route_map_out_name}
        set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast route-map import {route_map_in_name}
        {"" if ("soft-reconfiguration-inbound" in neighbor and not neighbor["soft-reconfiguration-inbound"]) else f"set protocols bgp neighbor {neighbor_address} address-family ipv{ipversion}-unicast soft-reconfiguration inbound"}
        """

    return bgp_cmd


def get_vyos_protocol_bgp_neighbor(neighbor_type, neighbor):
    """cmd to configure vyos protocol bgp"""

    neighbor_id = get_neighbor_id(neighbor)

    if neighbor_type == "IBGP":
        asn = local_asn
    else:
        asn = neighbor["asn"]

    if neighbor_type == "IBGP":
        route_map_in_name = f"IBGP-IN-{neighbor_id}"
        route_map_out_name = f"IBGP-OUT-{neighbor_id}"
    else:
        route_map_in_name = f"AS{asn}-{neighbor_type.upper()}-IN-{neighbor_id}"
        route_map_out_name = f"AS{asn}-{neighbor_type.upper()}-OUT-{neighbor_id}"

    final_filter = f"""
    delete policy route-map {route_map_in_name}
    set policy route-map {route_map_in_name} rule 10 action permit
    set policy route-map {route_map_in_name} rule 10 call {neighbor_type.upper()}-IN
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

    delete policy route-map {route_map_out_name}
    set policy route-map {route_map_out_name} rule 10 action permit
    set policy route-map {route_map_out_name} rule 10 call {neighbor_type.upper()}-OUT
    set policy route-map {route_map_out_name} rule 10 on-match next
    # rule 100 for controling like prepend
    set policy route-map {route_map_out_name} rule 100 action permit
    set policy route-map {route_map_out_name} rule 100 on-match next
    # rule 200-999 for this code
    set policy route-map {route_map_out_name} rule 200 action deny
    set policy route-map {route_map_out_name} rule 200 match large-community large-community-list DNA-AS{asn}
    set policy route-map {route_map_out_name} rule 201 action deny
    set policy route-map {route_map_out_name} rule 201 match large-community large-community-list DNA-NID{neighbor_id}
    set policy route-map {route_map_out_name} rule 202 action deny
    set policy route-map {route_map_out_name} rule 202 match large-community large-community-list DNA-ANY
    # rule 1000-9999 for pre-export-accept in config
    set policy route-map {route_map_out_name} rule 10000 action permit

    delete policy large-community-list DNA-NID{neighbor_id}
    set policy large-community-list DNA-NID{neighbor_id} rule 10 action 'permit'
    set policy large-community-list DNA-NID{neighbor_id} rule 10 regex "{local_asn}:1001:{neighbor_id}"
    """

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

    return cmd


def get_vyos_set_src(router_config):
    cmd = """
    delete policy route-map SET-SRC
    set policy route-map SET-SRC rule 10 action 'permit'
    set policy route-map SET-SRC rule 10 match ip address prefix-list 'IPv4-ALL'
    set policy route-map SET-SRC rule 20 action 'permit'
    set policy route-map SET-SRC rule 20 match ipv6 address prefix-list 'IPv6-ALL'
    """

    if "src" in router_config:
        if "ipv4" in router_config["src"]:
            cmd += f"""
            set policy route-map SET-SRC rule 10 set src '{router_config["src"]["ipv4"]}'
            delete system ip protocol bgp
            set system ip protocol bgp route-map SET-SRC
            """
        if "ipv6" in router_config["src"]:
            cmd += f"""
            set policy route-map SET-SRC rule 20 set src '{router_config["src"]["ipv6"]}'
            delete system ipv6 protocol bgp
            set system ipv6 protocol bgp route-map SET-SRC
            """

    return cmd


def get_vyos_system_frr():
    return """
    delete system frr
    set system frr bmp
    set system frr snmp bgpd
    set system frr snmp isisd
    set system frr snmp ldpd
    set system frr snmp ospf6d
    set system frr snmp ospfd
    set system frr snmp ripd
    set system frr snmp zebra
    """


def get_vyos_bmp(bmp_config):
    cmd = """
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
    if not router_id:
        print(f"resolve router-id for {router_name} failed")
        return ""
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
    get_as_info(local_asn)
    for asn in connected_asns:
        get_as_info(asn)
        configure += get_vyos_as_community(asn)

    # local asn prefix list
    configure += get_vyos_prefix_list(
        4, local_asn, filter_name="LOCAL-ASN-CONE", cone=True
    )
    configure += get_vyos_prefix_list(
        6, local_asn, filter_name="LOCAL-ASN-CONE", cone=True
    )
    configure += get_vyos_prefix_list(4, local_asn, filter_name="LOCAL-ASN-PREFIX4")
    configure += get_vyos_prefix_list(6, local_asn, filter_name="LOCAL-ASN-PREFIX6")
    configure += get_vyos_prefix_list(
        4, local_asn, max_length=32, filter_name="LOCAL-ASN-PREFIX4-le32"
    )
    configure += get_vyos_prefix_list(
        6, local_asn, max_length=128, filter_name="LOCAL-ASN-PREFIX6-le128"
    )

    # we only need to generate filter for peer and downstream
    for asn in sorted(list(set(peer_asns + downstream_asns))):
        configure += get_vyos_as_filter(asn)

    # protocol rpki
    configure += get_vyos_protocol_rpki(router_config["protocols"]["rpki"])

    # protocol bgp
    configure += get_vyos_protocol_bgp(router_config["protocols"]["bgp"], router_id)

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

    # set route src
    if "src" in router_config:
        configure += get_vyos_set_src(router_config)

    configure = "\n".join(
        [line.strip() for line in configure.splitlines() if line.strip()]
    )

    configure = (
        "\nconfigure\n"
        + defaultconfig
        + (
            router_config["custom-config"] + "\n"
            if "custom-config" in router_config
            else ""
        )
        + configure
        + "\necho 'configure done'\n"
        + "\ncommit\nexit\n"
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
        ) as f:
            f.write(script)
        print(f"configure.{router['name']}.sh generated.")
        # except ValueError as e:
        #     if str(e) == "hash collision":
        #         print(f"generate configure.{router['name']}.sh failed: ", e)
        #         break
        #     else:
        #         print(f"generate configure.{router['name']}.sh failed: ", e)
        # except Exception as e:
        #     print(f"generate configure.{router['name']}.sh failed: ", e)
