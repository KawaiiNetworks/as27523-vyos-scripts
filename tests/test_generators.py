import asyncio
import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = ROOT / "tests" / "fixtures"
CACHE_DIR = FIXTURES_DIR / "cache"
RESULTS_DIR = ROOT / "tests" / "results"      # gitignored scratch for generated output
EXPECTED_DIR = ROOT / "tests" / "expected"    # committed golden references

# Set UPDATE_GOLDEN=1 to (re)write the golden files instead of comparing.
UPDATE_GOLDEN = os.environ.get("UPDATE_GOLDEN") == "1"


def _production_names(router):
    """Return the (script, conf) filenames exactly as the Worker serves them.

    Production routes are configure.{name}.sh and bird.{name}.conf (see
    cloudflare/src/entry.py). The tests write and compare under these same
    names so the fixtures mirror what a router actually fetches.
    """
    name = router["name"]
    return f"configure.{name}.sh", f"bird.{name}.conf"


def _load_yaml(name):
    return yaml.safe_load((FIXTURES_DIR / name).read_text())


def _load_json(path):
    return json.loads((CACHE_DIR / path).read_text())


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


async def _stub_resolve_router_id(router_name):
    return "192.0.2.254"


async def _stub_github_raw(*args, **kwargs):
    return None


async def _stub_github_raw_json(*args, **kwargs):
    return None


def _install_worker_stubs():
    github = types.ModuleType("github")
    github.resolve_router_id = _stub_resolve_router_id
    github.github_raw = _stub_github_raw
    github.github_raw_json = _stub_github_raw_json
    sys.modules["github"] = github

    return _load_module("cache", ROOT / "cloudflare" / "src" / "cache.py")


def _load_generators():
    cache_module = _install_worker_stubs()
    bird = _load_module("bird_vyos_gen", ROOT / "cloudflare" / "src" / "vyos_gen.py")
    return cache_module, bird


class FakeCacheStore:
    def __init__(self, config, cache_module):
        self.as_name_map = {}
        self.asset_name_map = {}
        self.maximum_prefix_map = {}
        self.cone_map = {}
        self.prefix_matrix_map = {}
        self.cone_prefix_matrix_map = {}
        self.neighbor_id_hashmap = {}
        self.bad_asn_set = set()
        self.cone_members_exceeds = set()
        self.cone_prefix_exceeds = set()
        self.warnings = []
        self.local_asn = config["local-asn"]
        self.config = config
        self.blacklist_asset_members = _load_json("as-set/summary.json")
        self._validate_asn = cache_module.validate_asn

        self._seed_pdb_data()
        self._seed_bgpq4_data()

    def _collect_asns(self):
        all_asns = {self.local_asn}
        peer_downstream_asns = {self.local_asn}
        for router in self.config.get("router", []):
            # default protocols.bgp + every VRF's protocols.bgp
            bgp_blocks = [router.get("protocols", {}).get("bgp", {})]
            for vrf_cfg in (router.get("vrf") or {}).values():
                bgp_blocks.append((vrf_cfg.get("protocols", {}) or {}).get("bgp", {}))
            for bgp in bgp_blocks:
                for ntype in ["upstream", "routeserver", "peer", "downstream", "ibgp"]:
                    for neighbor in bgp.get(ntype, []):
                        if "asn" not in neighbor:
                            continue
                        asn = neighbor["asn"]
                        all_asns.add(asn)
                        if ntype in ("peer", "downstream"):
                            peer_downstream_asns.add(asn)
        return all_asns, peer_downstream_asns

    def _apply_pdb(self, asn, data):
        self.as_name_map[asn] = data.get("name", f"AS{asn}")
        self.asset_name_map[asn] = data.get("as_set", [f"AS{asn}"])
        max_prefix = data.get("max_prefix", [1, 1])
        self.maximum_prefix_map[asn] = [
            max_prefix[0] if max_prefix[0] else 1,
            max_prefix[1] if max_prefix[1] else 1,
        ]

    def _seed_pdb_data(self):
        pdb_summary = _load_json("pdb/summary.json")
        all_asns, _peer_downstream_asns = self._collect_asns()

        for asn in sorted(all_asns):
            asn_type = self._validate_asn(asn)
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
            elif asn_type == 1 and str(asn) in pdb_summary:
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

    def _apply_bgpq4(self, asn, data):
        if data.get("cone_members_exceeds"):
            self.cone_members_exceeds.add(asn)
        if data.get("cone_prefix4_exceeds"):
            self.cone_prefix_exceeds.add((4, asn))
        if data.get("cone_prefix6_exceeds"):
            self.cone_prefix_exceeds.add((6, asn))

        self.cone_map[asn] = data.get("cone_members", [])
        self.prefix_matrix_map[(4, asn)] = [
            tuple(row) for row in data.get("prefix4", [])
        ]
        self.prefix_matrix_map[(6, asn)] = [
            tuple(row) for row in data.get("prefix6", [])
        ]
        self.cone_prefix_matrix_map[(4, asn)] = [
            tuple(row) for row in data.get("cone_prefix4", [])
        ]
        self.cone_prefix_matrix_map[(6, asn)] = [
            tuple(row) for row in data.get("cone_prefix6", [])
        ]

    def _seed_bgpq4_data(self):
        bgpq4_summary = _load_json("bgpq4/summary.json")
        _all_asns, peer_downstream_asns = self._collect_asns()

        for asn in sorted(peer_downstream_asns):
            if self._validate_asn(asn) == 1 and str(asn) in bgpq4_summary:
                self._apply_bgpq4(asn, bgpq4_summary[str(asn)])


def build_config():
    return _load_yaml("vyos.yaml")


def build_cache(config, cache_module):
    return FakeCacheStore(copy.deepcopy(config), cache_module)


class GeneratorCoverageTest(unittest.TestCase):
    maxDiff = None  # show the full diff when a golden comparison fails

    @classmethod
    def setUpClass(cls):
        cls.cache_module, cls.bird = _load_generators()

    def generate_outputs(self):
        """Generate both artifacts and write them to RESULTS_DIR.

        Output is written under the exact filenames the Worker serves
        (configure.{name}.sh / bird.{name}.conf, see entry.py) rather than
        generic names. Returns a dict keyed by those production filenames plus
        the conf's CacheStore.
        """
        config = build_config()
        router = config["router"][0]
        script_name, conf_name = _production_names(router)

        bird_script_cs = build_cache(config, self.cache_module)
        bird_script = asyncio.run(
            self.bird.generate_router_script(
                bird_script_cs,
                copy.deepcopy(router),
                "https://worker.example/kawaii/as27523",
            )
        )

        bird_conf_cs = build_cache(config, self.cache_module)
        bird_conf = self.bird.gen_bird_config(
            bird_conf_cs,
            copy.deepcopy(router),
            router_id=router["router-id"],
        )

        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / script_name).write_text(bird_script)
        (RESULTS_DIR / conf_name).write_text(bird_conf)
        return {
            "script_name": script_name,
            "script": bird_script,
            "conf_name": conf_name,
            "conf": bird_conf,
            "conf_cs": bird_conf_cs,
        }

    def assertMatchesGolden(self, filename, content):
        """Assert `content` equals the committed golden tests/expected/<filename>.

        With UPDATE_GOLDEN=1 the golden is (re)written instead of compared —
        use that after an intentional generator change, then review the diff.
        """
        golden = EXPECTED_DIR / filename
        if UPDATE_GOLDEN:
            EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
            golden.write_text(content)
            return
        self.assertTrue(
            golden.exists(),
            msg=f"missing golden {golden}; run UPDATE_GOLDEN=1 to create it",
        )
        self.assertEqual(
            content,
            golden.read_text(),
            msg=(
                f"generated {filename} differs from golden {golden}. If this "
                "change is intended, regenerate with:\n"
                "  UPDATE_GOLDEN=1 pixi run python -m unittest tests.test_generators"
            ),
        )

    def test_generate_bird_outputs(self):
        """Generated script and bird.conf must match the golden files exactly."""
        out = self.generate_outputs()
        self.assertMatchesGolden(out["script_name"], out["script"])
        self.assertMatchesGolden(out["conf_name"], out["conf"])

    def test_bird_config_parses(self):
        """bird.conf must parse cleanly under the real BIRD parser.

        Prefers a local `bird` binary on PATH; otherwise falls back to running
        our BIRD image (which ships BMP) with podman. Skipped only when neither
        a bird binary nor podman is available. `bird -p` is parse-only: it
        returns non-zero on any syntax/type error and 0 otherwise (warnings
        still allow 0).

        Set BIRD_IMAGE to override the image used by the podman fallback
        (default kawaiinetworks/bird:2).
        """
        bird_bin = shutil.which("bird") or shutil.which("bird2")
        podman_bin = shutil.which("podman")
        if not bird_bin and not podman_bin:
            self.skipTest("no bird binary or podman on PATH")

        out = self.generate_outputs()
        conf_name = out["conf_name"]
        conf_path = RESULTS_DIR / conf_name

        if bird_bin:
            cmd = [bird_bin, "-p", "-c", str(conf_path)]
        else:
            # Mount the results dir into the container and parse there. ',Z' is
            # a no-op without SELinux, so this works on CI and SELinux hosts.
            # The image's ENTRYPOINT is `bird`, so pass only its arguments.
            image = os.environ.get("BIRD_IMAGE", "kawaiinetworks/bird:2")
            cmd = [
                podman_bin, "run", "--rm",
                "-v", f"{RESULTS_DIR}:/conf:ro,Z",
                image,
                "-p", "-c", f"/conf/{conf_name}",
            ]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(
            proc.returncode, 0, msg=f"bird -p failed:\n{proc.stderr}{proc.stdout}"
        )


if __name__ == "__main__":
    unittest.main()
