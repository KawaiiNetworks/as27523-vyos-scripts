/**
 * Template-based generators (port of the render half of vyos_gen.py).
 */

import { CacheStore } from "./cache.js";
import {
  prepareForBird,
  birdImage,
  birdMajor,
  ipv4ToEngineId,
} from "./prepare.js";
import { resolveRouterId } from "./github.js";
import { birdEnv, vyosEnv } from "./nunjucksEnv.js";

/** Plain, Nunjucks-readable view of the CacheStore (templates can't read Maps). */
function csView(cs: CacheStore) {
  return { warnings: cs.warnings, local_asn: cs.localAsn, config: cs.config };
}

export function genSflow(_cs: CacheStore, sflowConfig: any): string {
  return vyosEnv.render("sflow.njk", { sflow: sflowConfig });
}

export function genSnmp(_cs: CacheStore, snmpConfig: any, engineid: string): string {
  return vyosEnv.render("snmp.njk", { snmp: snmpConfig, engineid });
}

export function genContainerBird(cs: CacheStore, routerConfig: any): string {
  return vyosEnv.render("container.njk", {
    cs: csView(cs),
    router_config: routerConfig,
    bird_image: birdImage(routerConfig),
  });
}

export function genBirdConfig(
  cs: CacheStore,
  routerConfig: any,
  routerId?: string,
): string {
  prepareForBird(cs, routerConfig);
  return birdEnv.render("header.bird.njk", {
    cs: csView(cs),
    router_config: routerConfig,
    router_id: routerId ?? routerConfig["router-id"],
    local_asn: cs.localAsn,
    bird_major: birdMajor(routerConfig),
    rpki_servers: routerConfig?.protocols?.rpki ?? [],
  });
}

export async function generateRouterScript(
  cs: CacheStore,
  routerConfig: any,
  workerBaseUrl = "",
): Promise<string> {
  const routerName = routerConfig["name"];
  const routerId = routerConfig["router-id"] || (await resolveRouterId(routerName));

  let configureBody = "";
  const service = routerConfig["service"];
  if (service) {
    if ("sflow" in service) configureBody += genSflow(cs, service["sflow"]);
    if ("snmp" in service) {
      configureBody += genSnmp(cs, service["snmp"], ipv4ToEngineId(routerId));
    }
  }
  configureBody += genContainerBird(cs, routerConfig);

  return vyosEnv.render("configure.sh.njk", {
    cs: csView(cs),
    router_config: routerConfig,
    router_id: routerId,
    configure_body: configureBody,
    worker_base_url: workerBaseUrl,
  });
}
