import requests
import os
import subprocess
import json
import yaml
import time
from copy import deepcopy


work_dir = os.path.dirname(os.path.abspath(__file__))
config = yaml.safe_load(
    open(os.path.join(work_dir, "config.yaml"), "r", encoding="utf-8")
)

asset_name_map = {}
cone_map = {}
prefix_matrix_map = {}


def get_asset_name(asn):
    """use peeringdb to get as-set name"""

    time.sleep(5)

    if asn in asset_name_map:
        return deepcopy(asset_name_map[asn])

    url = f"https://www.peeringdb.com/api/net?asn={asn}"

    response = requests.get(url, timeout=10)
    res = response.json()["data"][0]["irr_as_set"].split()
    new_res = []
    for n in res:
        if "::" in n:
            new_res.append(f"{n.split('::')[1]} -S {n.split('::')[0]}")
        else:
            new_res.append(n)

    asset_name_map[asn] = new_res
    print(f"AS{asn} as-set name: {new_res}")
    return deepcopy(new_res)


def get_as_set_number(asn):
    """use bgpq4 to get as-set number"""

    if asn in cone_map:
        return deepcopy(cone_map[asn])

    asset_name_list = get_asset_name(asn)
    if not asset_name_list:
        cone_map[asn] = [asn]
        print(f"AS{asn} cone list: {cone_map[asn]}")
        return cone_map[asn]

    res = []

    for asset_name in asset_name_list:
        cmd = f"bgpq4 -jt {asset_name}"
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

    if len(cone_list) > config["as-set"]["member-limit"]:
        if config["as-set"]["member-limit-violation"] == "accept":
            full_vyos_cmd += f"""
            set policy as-path-list AS{asn}-IN rule 20 action permit
            set policy as-path-list AS{asn}-IN rule 20 regex '^{asn}(_[0-9]+)*$'
            """
            print(
                f"Warn: AS{asn} as-path filter generated. But cone member is {len(cone_list)}, filter will accept all as-path."
            )
            return full_vyos_cmd
        elif config["as-set"]["member-limit-violation"] == "deny":
            full_vyos_cmd += f"""
            set policy as-path-list AS{asn}-IN rule 20 action deny
            set policy as-path-list AS{asn}-IN rule 20 regex '.*'
            """
            print(
                f"Warn: AS{asn} as-path filter generated. But cone member is {len(cone_list)}, filter will deny all as-path except {asn}."
            )
            return full_vyos_cmd
        elif config["as-set"]["member-limit-violation"] == "ignore":
            pass
        else:
            raise ValueError(
                "as-set member-limit-violation must be accept, deny or ignore"
            )

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
        return deepcopy(prefix_matrix_map[(ipversion, asn)])

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
    return deepcopy(prefix_matrix)


def get_prefix_list(ipversion, asn, max_length=None, filter_name=None, cone=False):
    """use bgpq4 to get prefix list filter"""

    def vyos_cmd(network, length, ge, le, object_name, object_mask, invert_mask, rule):
        r = str(rule)
        return f"""
        set policy {pl} {fn} rule {r} action permit
        set policy {pl} {fn} rule {r} prefix {network}/{length}
        set policy {pl} {fn} rule {r} ge {ge}
        set policy {pl} {fn} rule {r} le {max_length if max_length else le}
        """

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
        cone_list = get_as_set_number(asn)
        if asn in cone_list:
            cone_list.remove(asn)

        if len(cone_list) > config["as-set"]["member-limit"]:
            if config["as-set"]["member-limit-violation"] == "accept":
                full_vyos_cmd += f"""
                set policy {pl} {fn} rule 10 action permit
                """
                print(
                    f"Warn: AS{asn} cone prefix{ipversion} list generated. But cone member is {len(cone_list)}, filter will accept all prefix."
                )
                return full_vyos_cmd
            elif config["as-set"]["member-limit-violation"] == "deny":
                full_vyos_cmd += f"""
                set policy {pl} {fn} rule 10 action deny
                """
                print(
                    f"Warn: AS{asn} cone prefix{ipversion} list generated. But cone member is {len(cone_list)}, filter will deny all prefix except {asn}."
                )
                return full_vyos_cmd
            elif config["as-set"]["member-limit-violation"] == "ignore":
                pass
            else:
                raise ValueError(
                    "as-set member-limit-violation must be accept, deny or ignore"
                )

    if cone:
        cone_asn_list = get_as_set_number(asn)
        prefix_matrix = []
        for x in cone_asn_list:
            prefix_matrix.extend(get_prefix_matrix(ipversion, x))
    else:
        prefix_matrix = get_prefix_matrix(ipversion, asn)

    if len(prefix_matrix) > 0:
        c = 1
        for prefix in prefix_matrix:
            full_vyos_cmd += vyos_cmd(*prefix, c)
            c += 1
        del c
        print(f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} list generated.")
    else:
        full_vyos_cmd += f"""
        set policy {pl} {fn} rule 10 action deny
        """
        print(
            f"AS{asn} {'cone ' if cone else ''}prefix{ipversion} list generated. But no prefix in list."
        )
    return full_vyos_cmd


def get_as_filter(asn):
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
    if config["peer"] and asn in config["peer"]:
        full_vyos_cmd += f"""
        delete policy route-map AS{asn}-PEER-IN
        set policy route-map AS{asn}-PEER-IN rule 10 action permit
        set policy route-map AS{asn}-PEER-IN rule 10 call PEER-IN
        set policy route-map AS{asn}-PEER-IN rule 20 action permit
        set policy route-map AS{asn}-PEER-IN rule 20 on-match next
        set policy route-map AS{asn}-PEER-IN rule 20 call FILTER-AS{asn}-IN
        """
    elif config["downstream"] and asn in config["downstream"]:
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
    local_asn = config["local-asn"]

    commonpolicy = (
        open(os.path.join(work_dir, "commonpolicy.sh"), "r", encoding="utf-8")
        .read()
        .replace("%ASN%", str(local_asn))
    )

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
        configure += get_as_filter(asn)

    configure = "\n".join(
        [line.strip() for line in configure.splitlines() if line.strip()]
    )

    configure = "\nconfigure\n" + commonpolicy + configure + "\ncommit\nexit\n"

    #################################

    script_start = r"""#!/bin/vbash

if [ "$(id -g -n)" != 'vyattacfg' ] ; then
    exec sg vyattacfg -c "/bin/vbash $(readlink -f $0) $@"
fi

source /opt/vyatta/etc/functions/script-template
"""
    script_end = r"""exit"""

    #################################

    script = script_start + configure + script_end

    with open(os.path.join(work_dir, "set-filter.sh"), "w", encoding="utf-8") as f:
        f.write(script)
    print("set_filter.sh generated.")
