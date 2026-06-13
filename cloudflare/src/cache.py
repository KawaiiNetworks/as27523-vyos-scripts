"""
Cache loading and ASN data management for the Cloudflare Worker.

Loads PDB/bgpq4 summary.json and defaults_bundle.txt from the config repo,
providing the data structures needed by vyos_gen.py.
"""

from github import github_raw, github_raw_json

# ---------------------------------------------------------------------------
# ASN validation
# ---------------------------------------------------------------------------

TIER1_ASNS = [
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


def validate_asn(asn):
    """Classify an ASN. Returns:
    0 = private, 1 = public, 2 = AS pool transition,
    3 = documentation, 4 = reserved, 5 = reserved block, -1 = invalid
    """
    asn = int(asn)
    if 1 <= asn <= 23455:
        return 1
    elif asn == 23456:
        return 2
    elif 23457 <= asn <= 64495:
        return 1
    elif 64496 <= asn <= 64511:
        return 3
    elif 64512 <= asn <= 65534:
        return 0
    elif asn == 65535:
        return 4
    elif 65536 <= asn <= 65551:
        return 3
    elif 65552 <= asn <= 131071:
        return 5
    elif 131072 <= asn <= 4199999999:
        return 1
    elif 4200000000 <= asn <= 4294967294:
        return 0
    elif asn == 4294967295:
        return 4
    return -1


def _router_bgp_blocks(router):
    """Yield each protocols.bgp dict for a router: the default one then every VRF.

    A VRF block (router["vrf"][name]["protocols"]) mirrors the top-level
    `protocols`, so ASN collection / generation treat them uniformly.
    """
    yield router.get("protocols", {}).get("bgp", {})
    for vrf_cfg in (router.get("vrf") or {}).values():
        yield (vrf_cfg.get("protocols", {}) or {}).get("bgp", {})


# ---------------------------------------------------------------------------
# CacheStore
# ---------------------------------------------------------------------------


class CacheStore:
    """Holds all cached data needed for VyOS config generation.

    每加一个缓存字段都在这里登记，否则没人记得住到底塞了多少。
    形状（key -> value）是最容易忘的，务必标注。tests/test_generators.py
    的 FakeCacheStore 必须 seed 出与下表一致的数据；BIRD 生成器
    (cloudflare/src/vyos_gen.py) 的 _prepare_for_bird 在渲染前补齐 B 组字段。

    A. 外部查询缓存（由 pdb / bgpq4 / as-set 填充，BIRD 模板只读）
      local_asn              : int                       本地 ASN（config["local-asn"]）
      config                 : dict                      整份解析后的 YAML 配置
      as_name_map            : {asn: "name"}             pdb；neighbors 的 description 兜底
      asset_name_map         : {asn: ["AS-SET", ...]}    pdb；当前生成逻辑未消费，保留备用
      maximum_prefix_map     : {asn: [v4_max, v6_max]}   pdb；import/export limit
      cone_map               : {asn: [member_asn, ...]}  bgpq4；bad-asn 检测、cone_asns
      prefix_matrix_map      : {(ipver, asn): [(net, len, ge, le), ...]}  bgpq4 prefix4/6；直连前缀集 + local-asn 前缀
      cone_prefix_matrix_map : {(ipver, asn): [(net, len, ge, le), ...]}  bgpq4 cone_prefix4/6；cone 前缀集 + 前缀超限检测
      cone_members_exceeds   : {asn}                     bgpq4 标志；bad-asn 检测
      cone_prefix_exceeds    : {(ipver, asn)}            bgpq4 标志；bad-asn 检测、as_filters
      blacklist_asset_members: {"AS-SET": [asn, ...]}    as-set 展开；blacklist 展开
      defaultconfig          : str                       合并后的 defaults 文本（已替换 ${ASN}）

    B. 运行时副作用状态（FRR 边生成边填；BIRD 由 _prepare_for_bird 预填）
      bad_asn_set            : {asn}                     Tier1 / AS0 / 超限标记
      neighbor_id_hashmap    : {nid: raw_str}            NID 去重 / 撞车检测
      warnings               : list[str]                 skip / bad-asn 告警

    注意：(ipver, asn) 元组键的有 prefix_matrix_map / cone_prefix_matrix_map /
    cone_prefix_exceeds（ipver ∈ {4, 6}）；而 cone_members_exceeds 只用 asn，别混。
    """

    def __init__(self):
        # --- A. 外部查询缓存（pdb / bgpq4 / as-set） ---
        self.as_name_map = {}                # {asn: "name"}
        self.asset_name_map = {}             # {asn: ["AS-SET", ...]}  当前无人读，保留备用
        self.maximum_prefix_map = {}         # {asn: [v4_max, v6_max]}
        self.cone_map = {}                   # {asn: [member_asn, ...]}
        self.prefix_matrix_map = {}          # {(ipver, asn): [(net, len, ge, le), ...]}
        self.cone_prefix_matrix_map = {}     # {(ipver, asn): [(net, len, ge, le), ...]}
        self.cone_members_exceeds = set()    # {asn}
        self.cone_prefix_exceeds = set()     # {(ipversion, asn)}
        self.blacklist_asset_members = {}    # {"AS-SET": [asn, ...]}
        self.local_asn = 0                   # int
        self.config = {}                     # dict（整份 YAML）
        self.defaultconfig = ""              # str（合并后 defaults，已替换 ${ASN}）
        # --- B. 运行时副作用状态（BIRD 由 _prepare_for_bird 预填） ---
        self.bad_asn_set = set()             # {asn}
        self.neighbor_id_hashmap = {}        # {nid: raw_str}
        self.warnings = []                   # list[str]

    def _apply_pdb(self, asn, data):
        """Store one ASN's PeeringDB-derived fields into the cache maps.

        Input: asn — the ASN; data — a pdb entry dict (uses "name", "as_set",
        "max_prefix"). No return value. Side effects: sets
        as_name_map[asn], asset_name_map[asn], and maximum_prefix_map[asn]
        (each max coerced to >=1, defaulting to [1, 1]).
        """
        self.as_name_map[asn] = data.get("name", f"AS{asn}")
        self.asset_name_map[asn] = data.get("as_set", [f"AS{asn}"])
        mp = data.get("max_prefix", [1, 1])
        self.maximum_prefix_map[asn] = [mp[0] if mp[0] else 1, mp[1] if mp[1] else 1]

    def _apply_bgpq4(self, asn, data):
        """Store one ASN's bgpq4-derived cone/prefix data into the cache maps.

        Input: asn — the ASN; data — a bgpq4 entry dict (uses cone_members,
        prefix4/6, cone_prefix4/6 and the *_exceeds flags). No return value.
        Side effects: populates cone_map[asn], prefix_matrix_map[(4|6, asn)],
        cone_prefix_matrix_map[(4|6, asn)] (rows tupled), and adds asn to
        cone_members_exceeds / (ipver, asn) to cone_prefix_exceeds when the
        corresponding exceeds flag is set.
        """
        if data.get("cone_members_exceeds"):
            self.cone_members_exceeds.add(asn)
        if data.get("cone_prefix4_exceeds"):
            self.cone_prefix_exceeds.add((4, asn))
        if data.get("cone_prefix6_exceeds"):
            self.cone_prefix_exceeds.add((6, asn))

        self.cone_map[asn] = data.get("cone_members", [])
        self.prefix_matrix_map[(4, asn)] = [tuple(x) for x in data.get("prefix4", [])]
        self.prefix_matrix_map[(6, asn)] = [tuple(x) for x in data.get("prefix6", [])]
        self.cone_prefix_matrix_map[(4, asn)] = [
            tuple(x) for x in data.get("cone_prefix4", [])
        ]
        self.cone_prefix_matrix_map[(6, asn)] = [
            tuple(x) for x in data.get("cone_prefix6", [])
        ]

    async def _load_defaults(self, user, config_repo):
        """Fetch and store the merged defaults bundle (one GitHub request).

        Input: user, config_repo — locate cache/defaults_bundle.txt in the
        config repo; reads self.local_asn for the ${ASN} substitution.
        No return value. Side effect: sets self.defaultconfig to the bundle
        text with ${ASN} replaced and a trailing newline ensured. Raises
        ValueError if the bundle file is missing.
        """
        text = await github_raw(user, config_repo, "cache/defaults_bundle.txt")
        if text is None:
            raise ValueError(
                f"defaults_bundle.txt not found in {user}/{config_repo}/cache/. "
                "Run save-cache.py --defaults-bundle first."
            )
        self.defaultconfig = text.replace(r"${ASN}", str(self.local_asn))
        if self.defaultconfig and not self.defaultconfig.endswith("\n"):
            self.defaultconfig += "\n"

    async def preload_all(self, user, config_repo, config):
        """Load every cache input needed to generate one router's config.

        Input: user, config_repo — the config repo to fetch from; config —
        the parsed vyos.yaml dict. No return value. Side effects: fills this
        CacheStore's "A" group maps in place — collects all ASNs (+ local ASN)
        from the config, fetches pdb / bgpq4 / as-set summaries and the
        defaults bundle from GitHub, then applies pdb data to every ASN and
        bgpq4 data to peer/downstream public ASNs.

        Network: 4 GitHub fetches (pdb + bgpq4 + defaults + as-set). Private
        ASNs get synthetic pdb defaults (no lookup); ASNs missing from the pdb
        summary get "Unknown AS" placeholders.
        """
        self.config = config
        self.local_asn = config["local-asn"]

        # Collect ASNs from config — the default protocols.bgp plus every VRF's
        # protocols.bgp (a VRF block mirrors the default one).
        all_asns = set()
        peer_downstream_asns = set()
        for router in config.get("router", []):
            for bgp in _router_bgp_blocks(router):
                for ntype in ["upstream", "routeserver", "peer", "downstream", "ibgp"]:
                    for neighbor in bgp.get(ntype, []):
                        if "asn" in neighbor:
                            a = neighbor["asn"]
                            all_asns.add(a)
                            if ntype in ("peer", "downstream"):
                                peer_downstream_asns.add(a)
        all_asns.add(self.local_asn)
        peer_downstream_asns.add(self.local_asn)

        # Fetch summary files (2 requests)
        pdb_summary = await github_raw_json(user, config_repo, "cache/pdb/summary.json")
        bgpq4_summary = await github_raw_json(
            user, config_repo, "cache/bgpq4/summary.json"
        )

        # Apply PDB data
        for asn in sorted(all_asns):
            asn_type = validate_asn(asn)
            if asn_type == 0:
                self._apply_pdb(
                    asn,
                    {
                        "type": "private",
                        "name": f"Private AS{asn}",
                        "as_set": [f"AS{asn}"],
                        "max_prefix": [100, 100],
                    },
                )
            elif asn_type == 1 and pdb_summary and str(asn) in pdb_summary:
                self._apply_pdb(asn, pdb_summary[str(asn)])
            else:
                self._apply_pdb(
                    asn,
                    {
                        "type": "not_found",
                        "name": f"Unknown AS{asn}",
                        "as_set": [f"AS{asn}"],
                        "max_prefix": [1, 1],
                    },
                )

        # Apply bgpq4 data
        for asn in sorted(peer_downstream_asns):
            if validate_asn(asn) == 1 and bgpq4_summary and str(asn) in bgpq4_summary:
                self._apply_bgpq4(asn, bgpq4_summary[str(asn)])

        # Load defaults bundle (1 request)
        await self._load_defaults(user, config_repo)

        # Load as-set member cache (1 request)
        asset_data = await github_raw_json(
            user, config_repo, "cache/as-set/summary.json"
        )
        if asset_data:
            self.blacklist_asset_members = asset_data
