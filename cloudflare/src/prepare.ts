/**
 * BIRD pre-processing pass (port of the prep half of vyos_gen.py).
 *
 * Besides the Python logic (nid, prefix split, bad-ASN detection, local-ASN
 * prefix sets, blacklist expansion), this also PRECOMPUTES every Jinja-only
 * construct the templates can't express in Nunjucks: concatenated names,
 * metric mode, the per-address proto list, extra-import expressions, and the
 * per-AS filter blocks. Templates then consume plain fields.
 */

import ipaddr from "ipaddr.js";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

import { CacheStore, validateAsn, TIER1_ASNS, PrefixRow } from "./cache.js";

// ---------------------------------------------------------------------------
// IP / hashing utilities
// ---------------------------------------------------------------------------

export function isIp(s: any): boolean {
  try {
    return ipaddr.isValid(String(s));
  } catch {
    return false;
  }
}

export function isUnnumbered(s: any): boolean {
  const str = String(s);
  if (!str.includes("%")) return false;
  const i = str.indexOf("%");
  const addr = str.slice(0, i);
  const iface = str.slice(i + 1);
  if (!iface) return false;
  let ip: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    ip = ipaddr.parse(addr);
  } catch {
    return false;
  }
  return ip.kind() === "ipv6" && (ip as ipaddr.IPv6).range() === "linkLocal";
}

export function isRange(s: any): string | null {
  const str = String(s).trim();
  if (!str.startsWith("range ")) return null;
  const prefix = str.slice("range ".length).trim();
  try {
    ipaddr.parseCIDR(prefix);
  } catch {
    return null;
  }
  return prefix;
}

export function isInterface(s: any): boolean {
  const str = String(s);
  return /^[A-Za-z][\w.-]*$/.test(str) && !isIp(str);
}

/** Network version (4 or 6) of a CIDR prefix, or null if it doesn't parse. */
function networkVersion(s: string): number | null {
  try {
    const [addr] = ipaddr.parseCIDR(s);
    return addr.kind() === "ipv4" ? 4 : 6;
  } catch {
    return null;
  }
}

export function getNeighborId(cs: CacheStore, neighbor: any): number {
  let addrs = neighbor["neighbor-address"];
  if (!Array.isArray(addrs)) addrs = [addrs];
  const raw =
    ("asn" in neighbor ? String(neighbor.asn) : "") +
    [...addrs].sort().join("");
  const h = bytesToHex(sha256(new TextEncoder().encode(raw)));
  const nid = 1 + parseInt(h.slice(-4), 16);
  if (cs.neighborIdHashmap.has(nid) && cs.neighborIdHashmap.get(nid) !== raw) {
    throw new Error("hash collision");
  }
  cs.neighborIdHashmap.set(nid, raw);
  return nid;
}

export function ipv4ToEngineId(ipv4: string): string {
  return (
    "000000000000" +
    ipv4
      .split(".")
      .map((p) => p.padStart(3, "0"))
      .join("")
  );
}

// ---------------------------------------------------------------------------
// Local-ASN prefix sets / bad-ASN detection
// ---------------------------------------------------------------------------

function localAsnPrefixes(cs: CacheStore, ipversion: number): string[] {
  const la = cs.localAsn;
  const matrix = cs.prefixMatrix(ipversion, la);
  const maxLength = ipversion === 4 ? 32 : 128;
  const out: string[] = [];
  for (const [network, length, ge, le] of matrix) {
    const leFinal = Math.min(le, maxLength);
    if (ge <= length && length <= leFinal) {
      if (ge === length && leFinal === length) {
        out.push(`${network}/${length}`);
      } else {
        out.push(`${network}/${length}{${ge},${leFinal}}`);
      }
    }
  }
  return out;
}

function detectBadAsn(cs: CacheStore, asn: number): void {
  const config = cs.config;
  const asl = config["as-set-limit"] ?? {};
  const largeAsList: number[] = asl["large-as-list"] ?? [];
  const memberLimit: number = asl["member-limit"] ?? 1000;

  const coneList = [...(cs.coneMap.get(asn) ?? [])];
  const idx = coneList.indexOf(asn);
  if (idx !== -1) coneList.splice(idx, 1);

  if (coneList.includes(0)) {
    cs.warnings.push(
      `AS-SET of AS${asn} contains AS0, this session will be shutdown.`,
    );
    cs.badAsnSet.add(asn);
  }
  if (!TIER1_ASNS.includes(asn) && coneList.some((a) => TIER1_ASNS.includes(a))) {
    cs.warnings.push(
      `AS-SET of AS${asn} contains Tier1 AS, this session will be shutdown.`,
    );
    cs.badAsnSet.add(asn);
  }

  if (
    (coneList.length + 1 > memberLimit || cs.coneMembersExceeds.has(asn)) &&
    !largeAsList.includes(asn)
  ) {
    cs.badAsnSet.add(asn);
  }

  const prefixLimit: number = asl["prefix-limit"] ?? 1000;
  for (const ipversion of [4, 6]) {
    const pm = cs.conePrefixMatrix(ipversion, asn);
    const exceeds = pm.length > prefixLimit || cs.conePrefixExceedsHas(ipversion, asn);
    if (exceeds && !largeAsList.includes(asn)) cs.badAsnSet.add(asn);
  }
}

// ---------------------------------------------------------------------------
// Per-neighbor preparation + precompute
// ---------------------------------------------------------------------------

const NTYPE_LABEL: Record<string, string> = {
  upstream: "Upstream",
  peer: "Peer",
  downstream: "Downstream",
  routeserver: "RouteServer",
  ibgp: "IBGP",
};

/** Build the `extra-import-prefixes` match terms (define name or inline prefix). */
function extraImportTerms(items: any[] | undefined): string[] {
  return (items ?? []).map((nm) => {
    const s = String(nm);
    return s.includes("/")
      ? `net ~ [ ${s} ]`
      : `net ~ ${s.toLowerCase().replace(/-/g, "_")}`;
  });
}

function prepareNeighbor(
  cs: CacheStore,
  neighbor: any,
  ntype: string,
  vrf: any,
): number {
  let addrs = neighbor["neighbor-address"];
  if (!Array.isArray(addrs)) addrs = [addrs];
  neighbor["neighbor-address"] = addrs;
  neighbor["nid"] = getNeighborId(cs, neighbor);
  if (vrf !== null) neighbor["_vrf"] = vrf;

  const asn = ntype !== "ibgp" ? neighbor.asn : cs.localAsn;
  neighbor["_asn_public"] = validateAsn(asn) === 1;

  if (!neighbor["_asn_public"] && !("prefix-list" in neighbor)) {
    neighbor["prefix-list"] = [];
    cs.warnings.push(
      `AS${asn} (${ntype}) [${addrs.map((a: any) => `'${a}'`).join(", ")}]: ` +
        `private ASN without prefix-list => deny-all (declare a prefix-list to accept routes).`,
    );
  }

  if ("prefix-list" in neighbor) {
    const p4: string[] = [];
    const p6: string[] = [];
    for (const ipStr of neighbor["prefix-list"]) {
      const v = networkVersion(ipStr);
      if (v === null) {
        cs.warnings.push(
          `AS${asn} (${ntype}) [${addrs.map((a: any) => `'${a}'`).join(", ")}]: ` +
            `ignoring invalid prefix-list entry '${ipStr}' (not a CIDR prefix).`,
        );
        continue;
      }
      (v === 4 ? p4 : p6).push(ipStr);
    }
    neighbor["_prefix4"] = p4;
    neighbor["_prefix6"] = p6;
    neighbor["_has_prefix_list"] = true;
  }

  const src = neighbor["source-address"];
  if (src) {
    if (isIp(src)) {
      neighbor["_source_address"] = src;
      neighbor["_source_family"] = ipaddr.parse(String(src)).kind() === "ipv4" ? 4 : 6;
    } else {
      cs.warnings.push(
        `AS${asn} (${ntype}) [${addrs.map((a: any) => `'${a}'`).join(", ")}]: ` +
          `source-address '${src}' is not an IP; ignored.`,
      );
    }
  }

  const rng = addrs.length === 1 ? isRange(addrs[0]) : null;
  const iface =
    addrs.length === 1 && isInterface(addrs[0]) ? addrs[0] : null;
  if (rng) {
    neighbor["_range"] = rng;
  } else if (iface) {
    neighbor["_unnumbered_iface"] = iface;
    if (cs.radvIfaces.has(iface)) {
      cs.warnings.push(
        `AS${asn} (${ntype}): interface '${iface}' is used by more than one ` +
          `unnumbered neighbor; BIRD rejects duplicate radv on one interface.`,
      );
    }
    cs.radvIfaces.add(iface);
  } else {
    const bad = addrs.filter((a: any) => !isIp(a) && !isUnnumbered(a));
    if (bad.length) {
      throw new Error(
        `AS${asn} (${ntype}): invalid neighbor-address [${bad
          .map((a: any) => `'${a}'`)
          .join(", ")}] — must be an IP, link-local '%iface', 'range <prefix>', ` +
          `or a bare interface name.`,
      );
    }
  }
  return asn;
}

/** Parse the `metric` option into {mode, value} or null. */
function parseMed(metric: any): { mode: "abs" | "add" | "sub"; value: number } | null {
  if (metric === undefined || metric === null || metric === "") return null;
  const m = String(metric);
  if (m.startsWith("+")) return { mode: "add", value: parseInt(m.slice(1), 10) };
  if (m.startsWith("-")) return { mode: "sub", value: parseInt(m.slice(1), 10) };
  return { mode: "abs", value: Number(m) };
}

/** Fill the template-visible `_*` fields on one neighbor (Nunjucks-friendly). */
function precomputeNeighbor(
  cs: CacheStore,
  ntypeLabel: string,
  neighbor: any,
): void {
  const asn = ntypeLabel !== "IBGP" ? neighbor.asn : cs.localAsn;
  const tletter = { Upstream: "u", Peer: "p", Downstream: "d", RouteServer: "r", IBGP: "i" }[
    ntypeLabel
  ]!;
  const vrf = neighbor["_vrf"];
  const vrfPfx = vrf ? `vrf_${vrf.id}_` : "";
  const nid = neighbor["nid"];
  const base = `${vrfPfx}${tletter}_as${asn}_nid${nid}`;

  neighbor["_asn"] = asn;
  neighbor["_tletter"] = tletter;
  neighbor["_proto_base"] = base;
  neighbor["_filter_prefix"] = `filter_${base}`;

  const keepupList: number[] = cs.config["keepup-as-list"] ?? [];
  neighbor["_is_shutdown"] =
    !!neighbor.shutdown || (cs.badAsnSet.has(asn) && !keepupList.includes(asn));
  neighbor["_keep_filtered"] = neighbor["keep-filtered"] !== false;

  neighbor["_mp_in"] = cs.maximumPrefixMap.get(asn) ?? [1, 1];
  neighbor["_mp_out"] = cs.maximumPrefixMap.get(cs.localAsn) ?? [1, 1];
  neighbor["_local_as"] = neighbor["local-asn"] ? neighbor["local-asn"] : cs.localAsn;

  const asName = cs.asNameMap.get(asn) ?? `AS${asn}`;
  const initial = ntypeLabel.slice(0, 1).toUpperCase();
  neighbor["_desc_proto"] =
    neighbor.description !== undefined && neighbor.description !== null
      ? neighbor.description
      : `${initial}: ${asName}`;
  neighbor["_desc_filter"] =
    neighbor.description !== undefined && neighbor.description !== null
      ? neighbor.description
      : `Session ${nid}`;

  neighbor["_irr_cone"] =
    (ntypeLabel === "Peer" || ntypeLabel === "Downstream") &&
    !!neighbor["_asn_public"] &&
    !("disable-IRR" in neighbor) &&
    !neighbor["_has_prefix_list"];

  neighbor["_no_in_filter"] = "no-in-filter" in neighbor;
  neighbor["_is_simple"] = ntypeLabel === "IBGP" && !!neighbor["simple-out"];
  neighbor["_med"] = parseMed(neighbor["metric"]);
  if (neighbor["in-prepend"]) {
    neighbor["_in_prepend"] = String(neighbor["in-prepend"]).split(/\s+/).filter(Boolean);
  }
  if (neighbor["out-prepend"]) {
    neighbor["_out_prepend"] = String(neighbor["out-prepend"]).split(/\s+/).filter(Boolean);
  }

  neighbor["_extra_import_expr"] =
    neighbor["extra-import-prefixes"] && neighbor["extra-import-prefixes"].length
      ? extraImportTerms(neighbor["extra-import-prefixes"]).join(" || ")
      : "false";

  // Address forms.
  const addrs: any[] = neighbor["neighbor-address"];
  const af = neighbor["address-family"];
  const unnum = neighbor["_unnumbered_iface"];
  const rangeVal = neighbor["_range"];
  if (unnum || rangeVal) {
    const rng = unnum ? "fe80::/64" : rangeVal;
    const rngV6 = String(rng).includes(":");
    let want4: boolean;
    let want6: boolean;
    if (af) {
      want4 = !!af.ipv4;
      want6 = !!af.ipv6;
    } else if (unnum || neighbor["extended-nexthop"]) {
      want4 = true;
      want6 = true;
    } else {
      want4 = !rngV6;
      want6 = rngV6;
    }
    neighbor["_dyn"] = { unnum: unnum ?? null, rng, rng_v6: rngV6, want4, want6 };
  } else {
    // One protocol per address; suffix _v4/_v6 (+ _N when >1 in a family).
    const famTotal = { v4: 0, v6: 0 };
    for (const a of addrs) {
      if (String(a).includes(":")) famTotal.v6++;
      else famTotal.v4++;
    }
    const famIdx = { v4: 0, v6: 0 };
    const protos: any[] = [];
    for (const addr of addrs) {
      const isV6 = String(addr).includes(":");
      const fam = isV6 ? "v6" : "v4";
      let idx: number;
      let famCount: number;
      if (isV6) {
        famIdx.v6++;
        idx = famIdx.v6;
        famCount = famTotal.v6;
      } else {
        famIdx.v4++;
        idx = famIdx.v4;
        famCount = famTotal.v4;
      }
      const protoName = `${base}_${fam}${famCount > 1 ? `_${idx}` : ""}`;
      let want4: boolean;
      let want6: boolean;
      if (af) {
        want4 = !!af.ipv4;
        want6 = !!af.ipv6;
      } else if (neighbor["extended-nexthop"]) {
        want4 = true;
        want6 = true;
      } else {
        want4 = !isV6;
        want6 = isV6;
      }
      // `source address` is emitted only on the matching-family channel.
      const srcMatch =
        neighbor["_source_address"] &&
        (neighbor["_source_family"] === 6) === isV6;
      protos.push({
        addr,
        is_v6: isV6,
        proto_name: protoName,
        want4,
        want6,
        src_match: !!srcMatch,
      });
    }
    neighbor["_addr_protos"] = protos;
  }
}

// ---------------------------------------------------------------------------
// Routing contexts + main prep pass
// ---------------------------------------------------------------------------

function* routingContexts(routerConfig: any): Generator<[any, any]> {
  yield [null, routerConfig?.protocols?.bgp ?? {}];
  const vrf = routerConfig?.vrf ?? {};
  for (const [vrfName, vrfCfg] of Object.entries<any>(vrf)) {
    const v = {
      name: vrfName,
      id: String(vrfName).toLowerCase().replace(/-/g, "_"),
      table: vrfCfg.table,
    };
    yield [v, (vrfCfg?.protocols ?? {})?.bgp ?? {}];
  }
}

/** Build the per-AS filter blocks consumed by as_filters.bird.j2. */
function buildAsFilterBlocks(cs: CacheStore, renderNeighbors: [string, any][]): any[] {
  // connected ASNs: non-IBGP neighbor.asn, unique, numeric-sorted.
  const seen = new Set<number>();
  const connected: number[] = [];
  for (const [ntype, n] of renderNeighbors) {
    if (ntype !== "IBGP" && !seen.has(n.asn)) {
      seen.add(n.asn);
      connected.push(n.asn);
    }
  }
  connected.sort((a, b) => a - b);

  const asl = cs.config["as-set-limit"] ?? {};
  const largeAsList: number[] = asl["large-as-list"] ?? [];
  const prefixLimit: number = asl["prefix-limit"] ?? 1000;
  const memberLimit: number = asl["member-limit"] ?? 100;

  const blocks: any[] = [];
  for (const asn of connected) {
    if (cs.badAsnSet.has(asn)) {
      blocks.push({ asn, bad: true });
      continue;
    }
    const mkSet = (ip: number, rows: PrefixRow[]) => ({
      exceeds: cs.conePrefixExceedsHas(ip, asn) || rows.length > prefixLimit,
      large_as: largeAsList.includes(asn),
      rows,
    });
    const coneList = cs.coneMap.get(asn) ?? [];
    const pathExceeds =
      cs.coneMembersExceeds.has(asn) || coneList.length + 1 > memberLimit;
    // ([asn] + cone_list) unique, order-preserving.
    const coneAsnsSeen = new Set<number>();
    const coneAsns: number[] = [];
    for (const m of [asn, ...coneList]) {
      if (!coneAsnsSeen.has(m)) {
        coneAsnsSeen.add(m);
        coneAsns.push(m);
      }
    }
    blocks.push({
      asn,
      bad: false,
      prefix4: mkSet(4, cs.prefixMatrix(4, asn)),
      prefix6: mkSet(6, cs.prefixMatrix(6, asn)),
      cone_prefix4: mkSet(4, cs.conePrefixMatrix(4, asn)),
      cone_prefix6: mkSet(6, cs.conePrefixMatrix(6, asn)),
      path_exceeds: pathExceeds,
      large_as_path: largeAsList.includes(asn),
      cone_asns: coneAsns,
    });
  }
  return blocks;
}

/** Attach `_extra_suffix` to a direct block (used by header/vrf direct filters). */
function precomputeDirect(direct: any): void {
  if (!direct) return;
  const terms = extraImportTerms(direct["extra-import-prefixes"]);
  direct["_extra_suffix"] = terms.map((t) => ` || ${t}`).join("");
}

export function prepareForBird(cs: CacheStore, routerConfig: any): void {
  const config = cs.config;

  const renderNeighbors: [string, any][] = [];
  const peerDownstream = new Set<number>();
  for (const [vrf, bgp] of routingContexts(routerConfig)) {
    for (const ntype of ["upstream", "peer", "downstream", "routeserver", "ibgp"]) {
      for (const neighbor of bgp[ntype] ?? []) {
        const asn = prepareNeighbor(cs, neighbor, ntype, vrf);
        if (ntype === "peer" || ntype === "downstream") peerDownstream.add(asn);
        renderNeighbors.push([NTYPE_LABEL[ntype], neighbor]);
      }
    }
  }
  routerConfig["_render_neighbors"] = renderNeighbors;

  // Bad-ASN detection over peer+downstream public ASNs (sorted).
  for (const asn of [...peerDownstream].sort((a, b) => a - b)) {
    if (validateAsn(asn) === 1) detectBadAsn(cs, asn);
  }

  // Now that bad_asn_set is final, precompute per-neighbor template fields.
  for (const [ntypeLabel, neighbor] of renderNeighbors) {
    precomputeNeighbor(cs, ntypeLabel, neighbor);
  }

  routerConfig["_record_filtered"] = routerConfig["record-filtered"] !== false;
  routerConfig["local_asn_prefix4"] = localAsnPrefixes(cs, 4);
  routerConfig["local_asn_prefix6"] = localAsnPrefixes(cs, 6);

  // extra-import suffixes for direct filters (default + each VRF).
  precomputeDirect(routerConfig?.protocols?.direct);
  for (const vrfCfg of Object.values<any>(routerConfig?.vrf ?? {})) {
    precomputeDirect((vrfCfg?.protocols ?? {})?.direct);
  }

  // Per-AS filter blocks for as_filters.bird.j2.
  routerConfig["_as_filter_blocks"] = buildAsFilterBlocks(cs, renderNeighbors);

  // Blacklist as-set expansion.
  if ("blacklist" in config) {
    const bl = config["blacklist"];
    const expanded: number[] = [...(bl.asn ?? [])];
    for (const assetName of bl["as-set"] ?? []) {
      expanded.push(...(cs.blacklistAssetMembers[assetName] ?? []));
    }
    bl["_expanded_asn"] = [...new Set(expanded.map((x) => Number(x)))].sort(
      (a, b) => a - b,
    );
  }
}

// ---------------------------------------------------------------------------
// BIRD image / version
// ---------------------------------------------------------------------------

export function birdImage(routerConfig: any): string {
  const val = routerConfig["bird"];
  if (val === undefined || val === null) return "kawaiinetworks/bird:2";
  const s = String(val).trim();
  if (/^\d+$/.test(s)) return `kawaiinetworks/bird:${s}`;
  return s;
}

export function birdMajor(routerConfig: any): number {
  const tag = birdImage(routerConfig).split(":").pop() ?? "";
  const m = tag.match(/^\d+/);
  return m ? parseInt(m[0], 10) : 2;
}
