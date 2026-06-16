/**
 * Cache loading and ASN data management (port of cache.py).
 *
 * Loads PDB/bgpq4/as-set summary.json from the config repo and builds the maps
 * the BIRD generator consumes. Keys are numeric ASNs; the (ipver, asn) tuple
 * maps from Python use string keys "ip:asn" here, with accessor helpers.
 */

import { githubRawJson } from "./github.js";

// A prefix-set row: [network, length, ge, le]. The JSON stores length/ge/le as
// strings; we normalize the last three to numbers (renders identically to the
// Python `| int` at use sites).
export type PrefixRow = [string, number, number, number];

export const TIER1_ASNS: number[] = [
  6762, 12956, 2914, 3356, 6453, 701, 6461, 3257, 1299, 3491, 7018, 3320, 5511,
  6830, 174, 6939,
];

/**
 * Classify an ASN. Returns:
 * 0 = private, 1 = public, 2 = AS pool transition,
 * 3 = documentation, 4 = reserved, 5 = reserved block, -1 = invalid
 */
export function validateAsn(asnIn: number | string): number {
  const asn = Number(asnIn);
  if (asn >= 1 && asn <= 23455) return 1;
  if (asn === 23456) return 2;
  if (asn >= 23457 && asn <= 64495) return 1;
  if (asn >= 64496 && asn <= 64511) return 3;
  if (asn >= 64512 && asn <= 65534) return 0;
  if (asn === 65535) return 4;
  if (asn >= 65536 && asn <= 65551) return 3;
  if (asn >= 65552 && asn <= 131071) return 5;
  if (asn >= 131072 && asn <= 4199999999) return 1;
  if (asn >= 4200000000 && asn <= 4294967294) return 0;
  if (asn === 4294967295) return 4;
  return -1;
}

/** Yield each protocols.bgp dict for a router: the default one then every VRF. */
function* routerBgpBlocks(router: any): Generator<any> {
  yield router?.protocols?.bgp ?? {};
  const vrf = router?.vrf ?? {};
  for (const vrfCfg of Object.values<any>(vrf)) {
    yield (vrfCfg?.protocols ?? {})?.bgp ?? {};
  }
}

const NTYPES = ["upstream", "routeserver", "peer", "downstream", "ibgp"];

function normalizeRows(rows: any[] | undefined): PrefixRow[] {
  return (rows ?? []).map(
    (r) => [r[0], Number(r[1]), Number(r[2]), Number(r[3])] as PrefixRow,
  );
}

export class CacheStore {
  // --- A. external query cache (pdb / bgpq4 / as-set) ---
  asNameMap = new Map<number, string>();
  assetNameMap = new Map<number, string[]>();
  maximumPrefixMap = new Map<number, [number, number]>();
  coneMap = new Map<number, number[]>();
  prefixMatrixMap = new Map<string, PrefixRow[]>(); // key "ip:asn"
  conePrefixMatrixMap = new Map<string, PrefixRow[]>(); // key "ip:asn"
  coneMembersExceeds = new Set<number>();
  conePrefixExceeds = new Set<string>(); // key "ip:asn"
  blacklistAssetMembers: Record<string, number[]> = {};
  localAsn = 0;
  config: any = {};
  // --- B. runtime side-effect state (filled by prepareForBird) ---
  badAsnSet = new Set<number>();
  neighborIdHashmap = new Map<number, string>();
  warnings: string[] = [];
  radvIfaces = new Set<string>();

  // Accessors for the (ipver, asn) tuple maps.
  prefixMatrix(ip: number, asn: number): PrefixRow[] {
    return this.prefixMatrixMap.get(`${ip}:${asn}`) ?? [];
  }
  conePrefixMatrix(ip: number, asn: number): PrefixRow[] {
    return this.conePrefixMatrixMap.get(`${ip}:${asn}`) ?? [];
  }
  conePrefixExceedsHas(ip: number, asn: number): boolean {
    return this.conePrefixExceeds.has(`${ip}:${asn}`);
  }

  applyPdb(asn: number, data: any): void {
    this.asNameMap.set(asn, data.name ?? `AS${asn}`);
    this.assetNameMap.set(asn, data.as_set ?? [`AS${asn}`]);
    const mp = data.max_prefix ?? [1, 1];
    this.maximumPrefixMap.set(asn, [mp[0] ? mp[0] : 1, mp[1] ? mp[1] : 1]);
  }

  applyBgpq4(asn: number, data: any): void {
    if (data.cone_members_exceeds) this.coneMembersExceeds.add(asn);
    if (data.cone_prefix4_exceeds) this.conePrefixExceeds.add(`4:${asn}`);
    if (data.cone_prefix6_exceeds) this.conePrefixExceeds.add(`6:${asn}`);

    this.coneMap.set(asn, data.cone_members ?? []);
    this.prefixMatrixMap.set(`4:${asn}`, normalizeRows(data.prefix4));
    this.prefixMatrixMap.set(`6:${asn}`, normalizeRows(data.prefix6));
    this.conePrefixMatrixMap.set(`4:${asn}`, normalizeRows(data.cone_prefix4));
    this.conePrefixMatrixMap.set(`6:${asn}`, normalizeRows(data.cone_prefix6));
  }

  /** Collect (allAsns, peerDownstreamAsns) from the config, incl. local ASN. */
  collectAsns(config: any): { allAsns: Set<number>; peerDownstream: Set<number> } {
    const allAsns = new Set<number>([this.localAsn]);
    const peerDownstream = new Set<number>([this.localAsn]);
    for (const router of config.router ?? []) {
      for (const bgp of routerBgpBlocks(router)) {
        for (const ntype of NTYPES) {
          for (const neighbor of bgp[ntype] ?? []) {
            if (neighbor.asn === undefined || neighbor.asn === null) continue;
            const a = neighbor.asn;
            allAsns.add(a);
            if (ntype === "peer" || ntype === "downstream") peerDownstream.add(a);
          }
        }
      }
    }
    return { allAsns, peerDownstream };
  }

  /** Seed pdb/bgpq4 data from already-fetched summaries (shared by Worker + tests). */
  seedFromSummaries(
    config: any,
    pdbSummary: Record<string, any> | null,
    bgpq4Summary: Record<string, any> | null,
    assetData: Record<string, number[]> | null,
  ): void {
    this.config = config;
    this.localAsn = config["local-asn"];
    const { allAsns, peerDownstream } = this.collectAsns(config);

    for (const asn of [...allAsns].sort((a, b) => a - b)) {
      const t = validateAsn(asn);
      if (t === 0) {
        this.applyPdb(asn, {
          type: "private",
          name: `Private AS${asn}`,
          as_set: [`AS${asn}`],
          max_prefix: [100, 100],
        });
      } else if (t === 1 && pdbSummary && String(asn) in pdbSummary) {
        this.applyPdb(asn, pdbSummary[String(asn)]);
      } else {
        this.applyPdb(asn, {
          type: "not_found",
          name: `Unknown AS${asn}`,
          as_set: [`AS${asn}`],
          max_prefix: [1, 1],
        });
      }
    }

    for (const asn of [...peerDownstream].sort((a, b) => a - b)) {
      if (validateAsn(asn) === 1 && bgpq4Summary && String(asn) in bgpq4Summary) {
        this.applyBgpq4(asn, bgpq4Summary[String(asn)]);
      }
    }

    if (assetData) this.blacklistAssetMembers = assetData;
  }

  /** Fetch all cache inputs from GitHub and seed (port of preload_all). */
  async preloadAll(user: string, configRepo: string, config: any): Promise<void> {
    const pdbSummary = await githubRawJson(user, configRepo, "cache/pdb/summary.json");
    const bgpq4Summary = await githubRawJson(user, configRepo, "cache/bgpq4/summary.json");
    const assetData = await githubRawJson(user, configRepo, "cache/as-set/summary.json");
    this.seedFromSummaries(config, pdbSummary, bgpq4Summary, assetData);
  }
}
