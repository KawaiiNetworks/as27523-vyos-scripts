"""
Cache loading and ASN data management for the Cloudflare Worker.

Loads PDB/bgpq4 summary.json and defaults_bundle.txt from the config repo,
providing the data structures needed by vyos_gen.py.
"""

from .github import github_raw, github_raw_json

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


# ---------------------------------------------------------------------------
# CacheStore
# ---------------------------------------------------------------------------


class CacheStore:
    """Holds all cached data needed for VyOS config generation."""

    def __init__(self):
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

    def _apply_pdb(self, asn, data):
        """Apply PeeringDB cache entry for an ASN."""
        self.as_name_map[asn] = data.get("name", f"AS{asn}")
        self.asset_name_map[asn] = data.get("as_set", [f"AS{asn}"])
        mp = data.get("max_prefix", [1, 1])
        self.maximum_prefix_map[asn] = [mp[0] if mp[0] else 1, mp[1] if mp[1] else 1]

    def _apply_bgpq4(self, asn, data):
        """Apply bgpq4 cache entry for an ASN."""
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
        """Load defaults_bundle.txt (single fetch instead of 40+)."""
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
        """Load all cache data needed for script generation.

        Total fetches: pdb_summary(1) + bgpq4_summary(1) + defaults_bundle(1) = 3
        (plus vyos.yaml(1) and DoH(1) done elsewhere = 5 total)
        """
        self.config = config
        self.local_asn = config["local-asn"]

        # Collect ASNs from config
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
