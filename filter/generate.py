import requests
import os
import subprocess
import json
import yaml
import time

asset_name_map = {}
cone_map = {}
prefix_matrix_map = {}


def get_asset_name(asn):
    """use peeringdb to get as-set name"""

    time.sleep(5)

    if asn in asset_name_map:
        return asset_name_map[asn]

    url = f"https://www.peeringdb.com/api/net?asn={asn}"

    response = requests.get(url, timeout=10)
    data = response.json()
    asset_name_map[asn] = data["data"][0]["irr_as_set"]
    print(f"AS{asn} as-set name: {asset_name_map[asn]}")
    return asset_name_map[asn]


def get_as_set_number(asn):
    """use bgpq4 to get as-set number"""

    if asn in cone_map:
        return cone_map[asn]

    asset_name = get_asset_name(asn)
    if not asset_name:
        cone_map[asn] = [asn]
        print(f"AS{asn} cone list: {cone_map[asn]}")
        return cone_map[asn]

    cmd = f"bgpq4 -jt {asset_name}"

    result = subprocess.run(
        cmd,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    cone_map[asn] = json.loads(result.stdout)["NN"]
    print(f"AS{asn} cone list: {cone_map[asn]}")
    return cone_map[asn]


def get_as_path(asn):
    """use bgpq4 to get as-path filter"""

    full_vyos_cmd = f"""
    delete policy as-path-list AS{asn}-IN
    set policy as-path-list AS{asn}-IN rule 10 action permit
    set policy as-path-list AS{asn}-IN rule 10 regex '^{asn}(_{asn})*$'
    """

    cone_list = get_as_set_number(asn)
    if asn in cone_list:
        cone_list.remove(asn)
    cone_list = [str(x) for x in cone_list]

    if len(cone_list) > 0:
        full_vyos_cmd += f"""
        set policy as-path-list AS{asn}-IN rule 20 action permit
        set policy as-path-list AS{asn}-IN rule 20 regex '^{asn}(_[0-9]+)*_({"|".join(cone_list)})$'
        """
    print(f"AS{asn} as-path filter generated.")
    return full_vyos_cmd


def get_prefix_matrix(ipversion, asn):
    """use bgpq4 to get prefix matrix"""

    if (ipversion, asn) in prefix_matrix_map:
        return prefix_matrix_map[(ipversion, asn)]

    cmd = rf'bgpq4 -{ipversion} -A -F "%n,%l,%a,%A,%N,%m,%i\n" as{asn} -l AS{asn}'
    prefix_matrix = []
    try:
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
            prefix_matrix.append(line.split(","))
    except Exception as e:
        raise e
    prefix_matrix_map[(ipversion, asn)] = prefix_matrix
    print(f"AS{asn} prefix{ipversion} matrix generated.")
    return prefix_matrix


def get_prefix_list(ipversion, asn, max_length=None, filter_name=None, cone=False):
    """use bgpq4 to get prefix list filter"""

    if cone:
        cone_asn_list = get_as_set_number(asn)
        prefix_matrix = []
        for x in cone_asn_list:
            prefix_matrix.extend(get_prefix_matrix(ipversion, x))
        fn = filter_name if filter_name else f"AS{asn}-CONE"
    else:
        prefix_matrix = get_prefix_matrix(ipversion, asn)
        fn = filter_name if filter_name else f"AS{asn}"

    full_vyos_cmd = ""

    if ipversion == 4:
        full_vyos_cmd += f"delete policy prefix-list {fn}\n"
    elif ipversion == 6:
        full_vyos_cmd += f"delete policy prefix-list6 {fn}\n"
    else:
        raise ValueError("ipversion must be 4 or 6")

    def vyos_cmd(network, length, ge, le, object_name, object_mask, invert_mask, rule):
        r = str(rule)
        if ipversion == 4:
            return f"""
            set policy prefix-list {fn} rule {r} action permit
            set policy prefix-list {fn} rule {r} prefix {network}/{length}
            set policy prefix-list {fn} rule {r} ge {ge}
            set policy prefix-list {fn} rule {r} le {max_length if max_length else le}
            """
        elif ipversion == 6:
            return f"""
            set policy prefix-list6 {fn} rule {r} action permit
            set policy prefix-list6 {fn} rule {r} prefix {network}/{length}
            set policy prefix-list6 {fn} rule {r} ge {ge}
            set policy prefix-list6 {fn} rule {r} le {max_length if max_length else le}
            """
        else:
            raise ValueError("ipversion must be 4 or 6")

    c = 1
    for prefix in prefix_matrix:
        full_vyos_cmd += vyos_cmd(*prefix, c)
        c += 1
    del c
    print(f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} list generated.")
    return full_vyos_cmd


def get_as_filter(asn, config):
    full_vyos_cmd = ""
    full_vyos_cmd += get_as_path(asn)
    full_vyos_cmd += get_prefix_list(4, asn, cone=True)
    full_vyos_cmd += get_prefix_list(6, asn, cone=True)
    full_vyos_cmd += f"""
    delete policy route-map FILTER-AS{asn}-IN
    set policy route-map FILTER-AS{asn}-IN rule 10 action permit
    set policy route-map FILTER-AS{asn}-IN rule 10 match as-path AS{asn}-IN
    set policy route-map FILTER-AS{asn}-IN rule 10 on-match next
    set policy route-map FILTER-AS{asn}-IN rule 20 action permit
    set policy route-map FILTER-AS{asn}-IN rule 20 match ip address prefix-list AS{asn}
    set policy route-map FILTER-AS{asn}-IN rule 30 action permit
    set policy route-map FILTER-AS{asn}-IN rule 30 match ipv6 address prefix-list AS{asn}
    """
    if asn in config["peer"]:
        full_vyos_cmd += f"""
        delete policy route-map AS{asn}-PEER-IN
        set policy route-map AS{asn}-PEER-IN rule 10 action permit
        set policy route-map AS{asn}-PEER-IN rule 10 call PEER-IN
        set policy route-map AS{asn}-PEER-IN rule 20 action permit
        set policy route-map AS{asn}-PEER-IN rule 20 on-match next
        set policy route-map AS{asn}-PEER-IN rule 20 call FILTER-AS{asn}-IN
        """
    elif asn in config["downstream"]:
        full_vyos_cmd += f"""
        delete policy route-map AS{asn}-DOWNSTREAM-IN
        set policy route-map AS{asn}-DOWNSTREAM-IN rule 10 action permit
        set policy route-map AS{asn}-DOWNSTREAM-IN rule 10 call DOWNSTREAM-IN
        set policy route-map AS{asn}-DOWNSTREAM-IN rule 20 action permit
        set policy route-map AS{asn}-DOWNSTREAM-IN rule 20 on-match next
        set policy route-map AS{asn}-DOWNSTREAM-IN rule 20 call FILTER-AS{asn}-IN
        """
    return full_vyos_cmd


if __name__ == "__main__":
    work_dir = os.path.dirname(os.path.abspath(__file__))
    config = yaml.safe_load(
        open(os.path.join(work_dir, "config.yaml"), "r", encoding="utf-8")
    )
    local_asn = config["local-asn"]

    configure = ""

    configure += get_prefix_list(4, local_asn, filter_name="LOCAL-ASN-CONE", cone=True)
    configure += get_prefix_list(6, local_asn, filter_name="LOCAL-ASN-CONE", cone=True)
    configure += get_prefix_list(
        4, local_asn, max_length=24, filter_name="LOCAL-ASN-PREFIX4"
    )
    configure += get_prefix_list(
        6, local_asn, max_length=128, filter_name="LOCAL-ASN-PREFIX6"
    )

    peers = config["peer"] or []
    downstreams = config["downstream"] or []

    connected_asns = peers + downstreams
    connected_asns = sorted(list(set(connected_asns)))
    for asn in connected_asns:
        configure += get_as_filter(asn, config)

    configure = "\n".join(
        [line.strip() for line in configure.splitlines() if line.strip()]
    )

    configure = "configure\n" + configure + "\ncommit\nexit\n"

    script_start = r"""#!/bin/vbash

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template
"""
    script_end = r"""exit"""

    with open(os.path.join(work_dir, "set_filter.sh"), "w", encoding="utf-8") as f:
        f.write(configure)
    print("set_filter.sh generated.")
