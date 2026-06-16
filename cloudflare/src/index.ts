/**
 * Cloudflare Worker entrypoint (port of entry.py).
 *
 * URL routing:
 *   GET /{user}/{config_repo}/                             → index page
 *   GET /{user}/{config_repo}/router/configure.{name}.sh  → VyOS host setup script
 *   GET /{user}/{config_repo}/router/bird.{name}.conf     → generated bird.conf
 *   GET /{user}/{config_repo}/birds                       → birds helper script (static)
 */

import { loadYamlConfig, resolveRouterId } from "./github.js";
import { CacheStore } from "./cache.js";
import { genBirdConfig, generateRouterScript } from "./generate.js";
import { buildIndexHtml } from "./indexPage.js";

// Static helper script the host downloads to /usr/local/bin/birds.
import birdsScript from "./templates/vyos/birds.py";

function text(body: string, status = 200, contentType = "text/plain"): Response {
  return new Response(body, { status, headers: { "content-type": contentType } });
}

export default {
  async fetch(request: Request, _env: unknown): Promise<Response> {
    try {
      return await handle(request);
    } catch (err) {
      const stack = err instanceof Error && err.stack ? err.stack : String(err);
      return text(`Worker error:\n${stack}`, 500);
    }
  },
};

async function handle(request: Request): Promise<Response> {
  const url = request.url;
  const afterScheme = url.slice(url.indexOf("//") + 2);
  const path = afterScheme.slice(afterScheme.indexOf("/") + 1).replace(/^\/+|\/+$/g, "");

  if (!path || (path.match(/\//g)?.length ?? 0) < 1) {
    return text(
      "Usage: /{user}/{config_repo}/\n\n" +
        "Resources:\n" +
        "  router/configure.{name}.sh\n" +
        "  router/bird.{name}.conf\n",
    );
  }

  const parts = path.split("/");
  const user = parts[0];
  const configRepo = parts[1];
  const resource = parts.length > 2 ? parts.slice(2).join("/") : "";

  // --- Route: birds helper (static; no config needed) ---
  if (resource === "birds") {
    return text(birdsScript, 200, "text/x-python; charset=utf-8");
  }

  const config = await loadYamlConfig(user, configRepo);
  if (config === null || config === undefined) {
    return text(`Cannot load vyos.yaml from ${user}/${configRepo}`, 404);
  }

  const localAsn = config["local-asn"];
  const host = url.split("//")[1].split("/")[0];
  const workerBaseUrl = `https://${host}/${user}/${configRepo}`;

  const findRouter = (name: string): any =>
    (config.router ?? []).find((r: any) => r.name === name) ?? null;

  if (resource.startsWith("router/configure.") && resource.endsWith(".sh")) {
    const routerName = resource.slice("router/configure.".length, -".sh".length);
    const target = findRouter(routerName);
    if (target === null) {
      const available = (config.router ?? []).map((r: any) => r.name);
      return text(
        `Router '${routerName}' not found.\nAvailable: [${available
          .map((n: string) => `'${n}'`)
          .join(", ")}]`,
        404,
      );
    }
    const cs = new CacheStore();
    await cs.preloadAll(user, configRepo, config);
    const script = await generateRouterScript(cs, target, workerBaseUrl);
    return text(script, 200, "text/plain; charset=utf-8");
  }

  if (resource.startsWith("router/bird.") && resource.endsWith(".conf")) {
    const routerName = resource.slice("router/bird.".length, -".conf".length);
    const target = findRouter(routerName);
    if (target === null) return text("Router not found", 404);
    const cs = new CacheStore();
    await cs.preloadAll(user, configRepo, config);
    const routerId = target["router-id"] || (await resolveRouterId(target.name));
    const birdConf = genBirdConfig(cs, target, routerId);
    return text(birdConf, 200, "text/plain; charset=utf-8");
  }

  if (resource === "" || resource === "/") {
    const html = buildIndexHtml(config, localAsn, workerBaseUrl);
    return text(html, 200, "text/html; charset=utf-8");
  }

  return text(`Not found: ${resource}`, 404);
}
