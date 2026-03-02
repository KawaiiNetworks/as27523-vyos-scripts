#!/usr/bin/env python3
"""
save-cache.py — 将 PeeringDB 和 bgpq4 数据缓存到配置仓库的 cache/ 目录。

用法:
    python save-cache.py /path/to/AS27523
    python save-cache.py /path/to/AS27523 --pdb-only
    python save-cache.py /path/to/AS27523 --bgpq4-only
    python save-cache.py /path/to/AS27523 --fill-missing
    python save-cache.py /path/to/AS27523 --defaults-bundle --scripts-dir /path/to/scripts
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET

import requests
import yaml
from aggregate_prefixes import aggregate_prefixes


# ---------------------------------------------------------------------------
# ASN validation (same logic as generate.py)
# ---------------------------------------------------------------------------


def validateASN(asn):
    asn = int(asn)
    if 1 <= asn <= 23455:
        return 1
    elif asn == 23456:
        return 2  # Reserved for AS Pool Transition
    elif 23457 <= asn <= 64495:
        return 1
    elif 64496 <= asn <= 64511:
        return 3  # Documentation
    elif 64512 <= asn <= 65534:
        return 0  # Private
    elif asn == 65535:
        return 4  # Reserved
    elif 65536 <= asn <= 65551:
        return 3  # Documentation
    elif 65552 <= asn <= 131071:
        return 5  # Reserved
    elif 131072 <= asn <= 4199999999:
        return 1
    elif 4200000000 <= asn <= 4294967294:
        return 0  # Private
    elif asn == 4294967295:
        return 4  # Reserved
    return -1


# ---------------------------------------------------------------------------
# PDB helpers
# ---------------------------------------------------------------------------


def fetch_pdb_info(asn):
    """
    从 PeeringDB 获取 ASN 信息，返回 dict。
    对 private / not-found / 正常分别处理（与 generate.py get_as_info 完全一致）。
    """
    asn = int(asn)
    asn_type = validateASN(asn)

    if asn_type == 0:
        # Private ASN
        return {
            "type": "private",
            "name": f"Private AS{asn}",
            "as_set": [f"AS{asn}"],
            "max_prefix": [100, 100],
        }
    elif asn_type != 1:
        # Invalid / reserved / documentation
        return None

    # Public ASN — query PeeringDB
    time.sleep(3)
    url = f"https://www.peeringdb.com/api/net?asn={asn}"
    print(f"  [PDB] Fetching AS{asn} ...")
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        data = resp.json()["data"]
        if not data:
            raise IndexError("empty data")
        response = data[0]
    except (IndexError, KeyError, requests.exceptions.HTTPError):
        print(f"  [PDB] AS{asn} not found in PeeringDB")
        return {
            "type": "not_found",
            "name": f"Nonexistent AS{asn}",
            "as_set": [f"AS{asn}"],
            "max_prefix": [100, 100],
        }

    # max prefix
    max_p4 = response.get("info_prefixes4") or 0
    max_p6 = response.get("info_prefixes6") or 0
    if max_p4 == 0:
        max_p4 = 1
    if max_p6 == 0:
        max_p6 = 1

    # name
    aka = response.get("aka", "")
    name = response.get("name", "")
    chosen_name = aka if aka and len(aka) < len(name) else name

    # as-set (store original names from PeeringDB)
    as_set_name_list = response.get("irr_as_set", "").split()
    if not as_set_name_list:
        as_set_name_list = [f"AS{asn}"]

    return {
        "type": "normal",
        "name": chosen_name,
        "as_set": as_set_name_list,
        "max_prefix": [max_p4, max_p6],
    }


# ---------------------------------------------------------------------------
# bgpq4 helpers (same logic as generate.py)
# ---------------------------------------------------------------------------

BGPQ4_SOURCES = "RPKI,AFRINIC,ARIN,APNIC,LACNIC,RIPE,RADB,ALTDB"


def asset_to_bgpq4_arg(name):
    """Convert an IRR as-set name to bgpq4 command argument.

    e.g. 'RIPE::AS-EXAMPLE' -> 'AS-EXAMPLE -S RIPE'
         'AS-HURRICANE'     -> 'AS-HURRICANE'
    """
    if "::" in name:
        source, asset = name.split("::", 1)
        return f"{asset} -S {source}"
    return name


def bgpq4_as_set_member(asset_name):
    """bgpq4 -jt => list of ASN ints"""
    arg = asset_to_bgpq4_arg(asset_name)
    cmd = f"bgpq4 -S {BGPQ4_SOURCES} -jt {arg}"
    result = subprocess.run(
        cmd,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    members = json.loads(result.stdout).get("NN", [])
    return sorted(set(members))


def bgpq4_prefix_matrix(ipversion, target):
    """
    bgpq4 获取 prefix matrix，返回 list of [network, length, ge, le]。
    target 可以是 "as{ASN}" 或 AS-SET 名（如 "AS-HURRICANE"）。
    """
    cmd = (
        f"bgpq4 -S {BGPQ4_SOURCES} -{ipversion} -A "
        f'-F "%n,%l,%a,%A\\n" {asset_to_bgpq4_arg(target)} -l CACHE'
    )
    result = subprocess.run(
        cmd,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    lines = [x for x in result.stdout.splitlines() if x]
    matrix = [tuple(line.split(",")) for line in lines]
    matrix = aggregate_prefixes_modified(matrix, ipversion)
    return matrix


def aggregate_prefixes_modified(prefix_matrix, ipversion):
    """与 generate.py 一致的聚合逻辑"""
    if not prefix_matrix:
        return []
    prefixes = [f"{p[0]}/{p[1]}" for p in prefix_matrix]
    prefixes = list(aggregate_prefixes(prefixes))
    return [
        [
            str(p.network_address),
            str(p.prefixlen),
            str(p.prefixlen),
            str(24 if ipversion == 4 else 48),
        ]
        for p in prefixes
    ]


def fetch_bgpq4_data(asn, as_set_list):
    """
    对一个 ASN 获取全部 bgpq4 数据，返回 dict。
    as_set_list 来自 PDB 缓存。
    """
    asn = int(asn)
    data = {}

    # 1. cone members (从 as-set 获取)
    cone = []
    for asset_name in as_set_list:
        cone += bgpq4_as_set_member(asset_name)
    cone = sorted(set(cone))
    data["cone_members"] = cone
    print(f"    cone members: {len(cone)}")

    # 2. prefix4 / prefix6 (直接用 as{ASN})
    data["prefix4"] = bgpq4_prefix_matrix(4, f"as{asn}")
    print(f"    prefix4: {len(data['prefix4'])} entries")

    data["prefix6"] = bgpq4_prefix_matrix(6, f"as{asn}")
    print(f"    prefix6: {len(data['prefix6'])} entries")

    # 3. cone_prefix4 / cone_prefix6 (用 as-set 名)
    cone_p4 = []
    cone_p6 = []
    for asset_name in as_set_list:
        cone_p4 += [tuple(x) for x in bgpq4_prefix_matrix(4, asset_name)]
        cone_p6 += [tuple(x) for x in bgpq4_prefix_matrix(6, asset_name)]
    cone_p4 = sorted(set(cone_p4))
    cone_p6 = sorted(set(cone_p6))
    cone_p4 = aggregate_prefixes_modified(cone_p4, 4)
    cone_p6 = aggregate_prefixes_modified(cone_p6, 6)
    data["cone_prefix4"] = cone_p4
    data["cone_prefix6"] = cone_p6
    print(f"    cone_prefix4: {len(cone_p4)}, cone_prefix6: {len(cone_p6)}")

    return data


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------


def load_config(config_dir):
    yaml_path = os.path.join(config_dir, "network", "vyos", "vyos.yaml")
    if not os.path.isfile(yaml_path):
        print(f"ERROR: {yaml_path} not found")
        sys.exit(1)
    with open(yaml_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def collect_asns(config):
    """
    从 config 收集所有需要的 ASN。
    返回 (local_asn, all_connected_asns, peer_downstream_asns)
    - all_connected_asns: 需要 PDB 信息的 ASN（所有 neighbor + local）
    - peer_downstream_asns: 需要 bgpq4 filter 信息的 ASN（仅 peer+downstream 中 validateASN==1）
    """
    local_asn = config["local-asn"]
    all_asns = set()
    peer_downstream_asns = set()

    for router in config.get("router", []):
        bgp = router.get("protocols", {}).get("bgp", {})
        for ntype in ["upstream", "routeserver", "peer", "downstream", "ibgp"]:
            for neighbor in bgp.get(ntype, []):
                if "asn" in neighbor:
                    asn = neighbor["asn"]
                    all_asns.add(asn)
                    if ntype in ("peer", "downstream"):
                        peer_downstream_asns.add(asn)

    # local_asn needs both PDB and bgpq4 (for prefix list)
    all_asns.add(local_asn)
    # peer/downstream + local_asn need bgpq4
    peer_downstream_asns.add(local_asn)

    # blacklist as-set also may need bgpq4
    if "blacklist" in config and "as-set" in config["blacklist"]:
        # These are handled separately, not per-ASN bgpq4

        pass

    return local_asn, sorted(all_asns), sorted(peer_downstream_asns)


# ---------------------------------------------------------------------------
# Cache I/O
# ---------------------------------------------------------------------------


def pdb_cache_path(cache_dir, asn):
    return os.path.join(cache_dir, "pdb", f"AS{asn}.json")


def bgpq4_cache_path(cache_dir, asn):
    return os.path.join(cache_dir, "bgpq4", f"AS{asn}.json")


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_json(path):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------


def save_pdb_cache(config_dir, all_asns, fill_missing):
    cache_dir = os.path.join(config_dir, "cache")
    success = 0
    failed = 0
    skipped = 0
    failed_asns = []

    print("=" * 60)
    print("Updating PDB cache")
    print("=" * 60)

    for asn in all_asns:
        path = pdb_cache_path(cache_dir, asn)

        if fill_missing and os.path.isfile(path):
            skipped += 1
            continue

        asn_type = validateASN(asn)
        if asn_type not in (0, 1):
            print(f"  [SKIP] AS{asn}: invalid/reserved ASN (type={asn_type})")
            skipped += 1
            continue

        try:
            info = fetch_pdb_info(asn)
            if info is None:
                print(f"  [SKIP] AS{asn}: validateASN returned non-0/1")
                skipped += 1
                continue
            write_json(path, info)
            print(f"  [OK] AS{asn} -> {path}")
            success += 1
        except Exception as e:
            print(f"  [FAIL] AS{asn}: {e}")
            traceback.print_exc()
            failed += 1
            failed_asns.append(asn)

    print(f"\nPDB summary: {success} updated, {skipped} skipped, {failed} failed")
    if failed_asns:
        print(f"  Failed ASNs: {failed_asns}")
    return failed_asns


def save_bgpq4_cache(config_dir, peer_downstream_asns, fill_missing):
    cache_dir = os.path.join(config_dir, "cache")
    success = 0
    failed = 0
    skipped = 0
    failed_asns = []

    print("=" * 60)
    print("Updating bgpq4 cache")
    print("=" * 60)

    for asn in peer_downstream_asns:
        path = bgpq4_cache_path(cache_dir, asn)

        if fill_missing and os.path.isfile(path):
            skipped += 1
            continue

        asn_type = validateASN(asn)
        if asn_type != 1:
            print(
                f"  [SKIP] AS{asn}: not a public ASN (type={asn_type}), no bgpq4 data needed"
            )
            skipped += 1
            continue

        # Load PDB cache to get as_set for this ASN
        pdb_path = pdb_cache_path(cache_dir, asn)
        pdb_data = load_json(pdb_path)
        if pdb_data is None:
            print(
                f"  [WARN] AS{asn}: no PDB cache found at {pdb_path}, using fallback AS{asn}"
            )
            as_set_list = [f"AS{asn}"]
        else:
            as_set_list = pdb_data.get("as_set", [f"AS{asn}"])

        try:
            print(f"  [bgpq4] AS{asn} (as-set: {as_set_list}) ...")
            data = fetch_bgpq4_data(asn, as_set_list)
            write_json(path, data)
            print(f"  [OK] AS{asn} -> {path}")
            success += 1
        except Exception as e:
            print(f"  [FAIL] AS{asn}: {e}")
            traceback.print_exc()
            failed += 1
            failed_asns.append(asn)

    print(f"\nbgpq4 summary: {success} updated, {skipped} skipped, {failed} failed")
    if failed_asns:
        print(f"  Failed ASNs: {failed_asns}")
    return failed_asns


def save_asset_cache(config_dir, config):
    """展开所有 as-set 名称，缓存到 cache/as-set/summary.json"""
    cache_dir = os.path.join(config_dir, "cache")

    # 1. 从 PDB 缓存中收集所有 as-set 名称
    asset_names = set()
    pdb_summary_path = os.path.join(cache_dir, "pdb", "summary.json")
    pdb_summary = load_json(pdb_summary_path)
    if pdb_summary:
        for _, data in pdb_summary.items():
            for name in data.get("as_set", []):
                asset_names.add(name)

    # 2. 从 blacklist 中收集 as-set 名称
    for name in config.get("blacklist", {}).get("as-set", []):
        asset_names.add(name)

    if not asset_names:
        print("  [SKIP] No as-set names to expand")
        return

    print("=" * 60)
    print(f"Expanding {len(asset_names)} as-set names")
    print("=" * 60)

    result = {}
    asset_dir = os.path.join(cache_dir, "as-set")
    for name in sorted(asset_names):
        try:
            members = bgpq4_as_set_member(name)
            result[name] = members
            write_json(os.path.join(asset_dir, f"{name}.json"), members)
            print(f"  [OK] {name} -> {len(members)} members")
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            result[name] = []

    out = os.path.join(asset_dir, "summary.json")
    write_json(out, result)
    print(f"  [AS-SET] summary.json — {len(result)} as-sets")


def check_all_present(config_dir, all_asns, peer_downstream_asns, do_pdb, do_bgpq4):
    """检查所有需要的 JSON 是否都存在（包括旧缓存）。"""
    cache_dir = os.path.join(config_dir, "cache")
    missing = []

    if do_pdb:
        for asn in all_asns:
            asn_type = validateASN(asn)
            if asn_type not in (0, 1):
                continue
            path = pdb_cache_path(cache_dir, asn)
            if not os.path.isfile(path):
                missing.append(f"pdb/AS{asn}.json")

    if do_bgpq4:
        for asn in peer_downstream_asns:
            asn_type = validateASN(asn)
            if asn_type != 1:
                continue
            path = bgpq4_cache_path(cache_dir, asn)
            if not os.path.isfile(path):
                missing.append(f"bgpq4/AS{asn}.json")

    return missing


def build_summary(config_dir, subdir, config=None):
    """合并 cache/{subdir}/AS*.json → cache/{subdir}/summary.json

    当 subdir 为 "bgpq4" 且提供了 config 时，对每个字段独立判断：
    - cone_members 超过 member-limit  → 清空并标记 cone_members_exceeds
    - cone_prefix4 超过 prefix-limit  → 清空并标记 cone_prefix4_exceeds
    - cone_prefix6 超过 prefix-limit  → 清空并标记 cone_prefix6_exceeds
    """
    cache_sub = os.path.join(config_dir, "cache", subdir)
    if not os.path.isdir(cache_sub):
        return

    member_limit = None
    prefix_limit = None
    if subdir == "bgpq4" and config and "as-set-limit" in config:
        member_limit = config["as-set-limit"].get("member-limit")
        prefix_limit = config["as-set-limit"].get("prefix-limit")

    summary = {}
    trimmed = 0
    for fname in sorted(os.listdir(cache_sub)):
        m = re.match(r"^AS(\d+)\.json$", fname)
        if not m:
            continue
        asn = m.group(1)
        data = load_json(os.path.join(cache_sub, fname))
        if data is None:
            continue

        if member_limit is not None and prefix_limit is not None:
            did_trim = False
            # 每个字段独立判断
            if (len(data.get("cone_members", [])) + 1) > member_limit:
                data["cone_members"] = []
                data["cone_members_exceeds"] = True
                did_trim = True
            if len(data.get("cone_prefix4", [])) > prefix_limit:
                data["cone_prefix4"] = []
                data["cone_prefix4_exceeds"] = True
                did_trim = True
            if len(data.get("cone_prefix6", [])) > prefix_limit:
                data["cone_prefix6"] = []
                data["cone_prefix6_exceeds"] = True
                did_trim = True
            if did_trim:
                trimmed += 1
                print(f"  [TRIM] AS{asn}")

        summary[asn] = data
    out = os.path.join(cache_sub, "summary.json")
    write_json(out, summary)
    msg = f"  [SUMMARY] {subdir}/summary.json — {len(summary)} ASNs"
    if trimmed:
        msg += f" ({trimmed} trimmed)"
    print(msg)


def build_defaults_bundle(config_dir, scripts_dir):
    """将 scripts_dir/configure/defaults/ 下所有文件拼接成 config_dir/cache/defaults_bundle.txt"""
    defaults_dir = os.path.join(scripts_dir, "configure", "defaults")
    if not os.path.isdir(defaults_dir):
        print(f"ERROR: defaults directory not found: {defaults_dir}")
        sys.exit(1)

    parts = []
    count = 0
    for root, _dirs, files in sorted(os.walk(defaults_dir)):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            parts.append(content)
            if not content.endswith("\n"):
                parts.append("\n")
            count += 1

    bundle = "".join(parts)
    out = os.path.join(config_dir, "cache", "defaults_bundle.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(bundle)
    print(f"  [BUNDLE] defaults_bundle.txt — {count} files, {len(bundle)} bytes")


def update_arin_asset_members(config_dir, config):
    """
    Update ARIN AS-SET members with downstream ASNs if the API key is valid
    and the local AS-SET is managed by ARIN.
    """
    api_key = os.getenv("ARIN_API_KEY")
    if not api_key:
        print("  [SKIP] ARIN_API_KEY environment variable not set")
        return True

    print("=" * 60)
    print("Checking ARIN AS-SET consistency...")
    print("=" * 60)

    cache_dir = os.path.join(config_dir, "cache")
    local_asn = config["local-asn"]

    local_pdb = load_json(pdb_cache_path(cache_dir, local_asn))
    if local_pdb and "as_set" in local_pdb and local_pdb["as_set"]:
        target_asset_name_full = local_pdb["as_set"][0]
        target_asset_name = target_asset_name_full.split(" -S")[0].strip()
    else:
        target_asset_name = f"AS{local_asn}"

    print(f"  Target Local AS-SET: {target_asset_name}")

    base_url = "https://reg.arin.net/rest"
    headers = {
        "Content-Type": "application/xml",
        "Accept": "application/xml"
    }

    url = f"{base_url}/irr/as-set/{target_asset_name}?apikey={api_key}"
    try:
        response = requests.get(url, headers=headers)
    except requests.RequestException as e:
        print(f"  [FAIL] Skipping ARIN check: Request failed - {e}")
        return False

    if response.status_code != 200:
        print(f"  [FAIL] Skipping ARIN check: Could not retrieve AS-SET '{target_asset_name}' from ARIN (Status: {response.status_code}).")
        return False

    try:
        namespaces = {'ns': 'http://www.arin.net/regrws/core/v1'}
        ET.register_namespace('', namespaces['ns'])
        root = ET.fromstring(response.content)
        
        current_members = set()
        members_container = root.find("ns:members", namespaces)
        if members_container is not None:
            for member in members_container.findall("ns:member", namespaces):
                current_members.add(member.get("name"))
            
        print(f"  Current ARIN members: {sorted(list(current_members))}")
        
    except ET.ParseError as e:
        print(f"  [FAIL] Skipping ARIN check: Failed to parse XML response - {e}")
        return False

    downstream_asset_members_map = {}
    
    if "router" in config:
        for router in config["router"]:
            if "protocols" in router and "bgp" in router["protocols"] and "downstream" in router["protocols"]["bgp"]:
                for neighbor in router["protocols"]["bgp"]["downstream"]:
                    if "asn" not in neighbor:
                        continue
                    ds_asn = neighbor["asn"]
                    
                    if validateASN(ds_asn) != 1:
                        continue
                        
                    ds_pdb = load_json(pdb_cache_path(cache_dir, ds_asn))
                    if ds_pdb and "as_set" in ds_pdb and ds_pdb["as_set"]:
                        ds_member_name = ds_pdb["as_set"][0].split(" -S")[0].strip()
                        downstream_asset_members_map[ds_asn] = ds_member_name
                    else:
                        downstream_asset_members_map[ds_asn] = f"AS{ds_asn}"

    expected_members = set(downstream_asset_members_map.values())
    print(f"  Expected Downstream members from config: {sorted(list(expected_members))}")

    members_to_add = expected_members - current_members
    
    if not members_to_add:
        print("  [OK] ARIN AS-SET is up to date. No new members to add.")
        return True

    print(f"  Adding missing members to ARIN AS-SET: {members_to_add}")
    
    ns_url = namespaces['ns']
    if members_container is None:
        members_container = ET.Element(f"{{{ns_url}}}members")
        root.append(members_container)

    for new_member in members_to_add:
        new_elem = ET.Element(f"{{{ns_url}}}member")
        new_elem.set("name", new_member)
        members_container.append(new_elem)
    
    new_xml_content = ET.tostring(root, encoding='utf-8')
    
    update_url = f"{base_url}/irr/as-set/{target_asset_name}?apikey={api_key}"
    try:
        update_response = requests.put(update_url, data=new_xml_content, headers=headers)
        
        if update_response.status_code == 200:
            print("  [OK] Successfully updated ARIN AS-SET.")
            return True
        else:
            print(f"  [FAIL] Failed to update ARIN AS-SET. Status: {update_response.status_code}")
            print(update_response.text)
            return False
    except requests.RequestException as e:
        print(f"  [FAIL] Failed to push update to ARIN: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Cache PeeringDB and bgpq4 data for VyOS config generation."
    )
    parser.add_argument(
        "config_dir",
        help="Path to config repo (e.g. ../AS27523). Must contain network/vyos/vyos.yaml",
    )
    parser.add_argument("--pdb-only", action="store_true", help="Only update PDB cache")
    parser.add_argument(
        "--bgpq4-only", action="store_true", help="Only update bgpq4 cache"
    )
    parser.add_argument(
        "--arin-only", action="store_true", help="Only update ARIN AS-SET"
    )
    parser.add_argument(
        "--fill-missing",
        action="store_true",
        help="Only fetch data for missing cache files, don't overwrite existing",
    )
    parser.add_argument(
        "--defaults-bundle",
        action="store_true",
        help="Build defaults_bundle.txt from scripts repo defaults/ directory",
    )
    parser.add_argument(
        "--scripts-dir",
        default=None,
        help="Path to scripts repo (required with --defaults-bundle)",
    )
    args = parser.parse_args()

    # Handle --defaults-bundle mode (independent of PDB/bgpq4)
    if args.defaults_bundle:
        config_dir = os.path.abspath(args.config_dir)
        scripts_dir = args.scripts_dir
        if scripts_dir is None:
            print("ERROR: --scripts-dir is required with --defaults-bundle")
            sys.exit(1)
        scripts_dir = os.path.abspath(scripts_dir)
        build_defaults_bundle(config_dir, scripts_dir)
        return

    config_dir = os.path.abspath(args.config_dir)
    config = load_config(config_dir)
    local_asn, all_asns, peer_downstream_asns = collect_asns(config)

    any_only = args.pdb_only or args.bgpq4_only or args.arin_only
    do_pdb = args.pdb_only or not any_only
    do_bgpq4 = args.bgpq4_only or not any_only
    do_arin = args.arin_only or not any_only

    print(f"Config dir: {config_dir}")
    print(f"Local ASN: {local_asn}")
    print(f"All ASNs needing PDB: {len(all_asns)} — {all_asns}")
    print(f"ASNs needing bgpq4: {len(peer_downstream_asns)} — {peer_downstream_asns}")
    mode_strs = []
    if do_pdb: mode_strs.append("PDB")
    if do_bgpq4: mode_strs.append("bgpq4")
    if do_arin: mode_strs.append("ARIN")
    print(f"Mode: {' + '.join(mode_strs) if mode_strs else 'none'}")
    print(f"Fill missing: {args.fill_missing}")
    print()

    pdb_failed = []
    bgpq4_failed = []
    arin_failed = False

    if do_pdb:
        pdb_failed = save_pdb_cache(config_dir, all_asns, args.fill_missing)
        build_summary(config_dir, "pdb")
        print()

    if do_bgpq4:
        bgpq4_failed = save_bgpq4_cache(
            config_dir, peer_downstream_asns, args.fill_missing
        )
        save_asset_cache(config_dir, config)
        build_summary(config_dir, "bgpq4", config)
        print()

    if do_arin:
        try:
            success = update_arin_asset_members(config_dir, config)
            if not success and os.getenv("ARIN_API_KEY"):
                arin_failed = True
        except Exception as e:
            print(f"  [FAIL] An error occurred while updating ARIN AS-SET: {e}")
            arin_failed = True
        print()

    # Final status check
    missing = check_all_present(
        config_dir, all_asns, peer_downstream_asns, do_pdb, do_bgpq4
    )

    print("=" * 60)
    print("Final Status")
    print("=" * 60)
    if not missing:
        print("✅ All required cache JSON files are present.")
    else:
        print(f"❌ {len(missing)} required cache file(s) are MISSING:")
        for m in missing:
            print(f"   - {m}")

    if pdb_failed:
        print(f"\n⚠️  PDB fetch failed for: {pdb_failed}")
    if bgpq4_failed:
        print(f"⚠️  bgpq4 fetch failed for: {bgpq4_failed}")
    if arin_failed:
        print("⚠️  ARIN AS-SET update failed")

    # Exit code: 0 if all present, 1 otherwise
    sys.exit(0 if not missing else 1)


if __name__ == "__main__":
    main()
