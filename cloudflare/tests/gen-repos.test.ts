// Opt-in driver (GEN_REPOS=1) — generates bird.conf + configure.sh for every
// router in the local tmp config repos, for byte-comparison against the live
// production worker. Not part of the normal suite.
import { describe, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { CacheStore } from "../src/cache.js";
import { genBirdConfig, generateRouterScript } from "../src/generate.js";
import { resolveRouterId } from "../src/github.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");

const REPOS = [
  { dir: "tmp/AS27523", user: "kawaiinetworks", repo: "AS27523" },
  { dir: "tmp/AS395909", user: "kawaiinetworks", repo: "AS395909" },
];

const WORKER = "https://vyos-config-generator.projectk.workers.dev";

describe.skipIf(!process.env.GEN_REPOS)("generate real repo configs", () => {
  it("writes bird.conf + configure.sh for every router", async () => {
    for (const { dir, user, repo } of REPOS) {
      const base = path.join(REPO_ROOT, dir);
      const config: any = yaml.load(
        fs.readFileSync(path.join(base, "network/vyos/vyos.yaml"), "utf8"),
      );
      const pdb = JSON.parse(fs.readFileSync(path.join(base, "cache/pdb/summary.json"), "utf8"));
      const bgpq4 = JSON.parse(fs.readFileSync(path.join(base, "cache/bgpq4/summary.json"), "utf8"));
      const asset = JSON.parse(fs.readFileSync(path.join(base, "cache/as-set/summary.json"), "utf8"));

      const outDir = path.join(REPO_ROOT, "tmp", "gen", repo);
      fs.mkdirSync(outDir, { recursive: true });
      const workerBaseUrl = `${WORKER}/${user}/${repo}`;
      const names: string[] = [];

      for (const router of config.router ?? []) {
        const name = router.name;
        const overrides = JSON.parse(process.env.RID_OVERRIDES || "{}");
        let routerId: string;
        try {
          routerId = router["router-id"] || overrides[name] || (await resolveRouterId(name));
        } catch (e) {
          // No router-id and DoH unavailable in this sandbox — skip (can't
          // reproduce production's resolved id deterministically offline).
          // eslint-disable-next-line no-console
          console.log(`  SKIP ${name}: ${(e as Error).message}`);
          continue;
        }
        names.push(name);

        const confCs = new CacheStore();
        confCs.seedFromSummaries(structuredClone(config), pdb, bgpq4, asset);
        const conf = genBirdConfig(confCs, structuredClone(router), routerId);
        fs.writeFileSync(path.join(outDir, `bird.${name}.conf`), conf);

        const scriptCs = new CacheStore();
        scriptCs.seedFromSummaries(structuredClone(config), pdb, bgpq4, asset);
        // Inject the (possibly overridden) router-id so the script path doesn't
        // re-resolve via DoH.
        const scriptRouter = { ...structuredClone(router), "router-id": routerId };
        const script = await generateRouterScript(scriptCs, scriptRouter, workerBaseUrl);
        fs.writeFileSync(path.join(outDir, `configure.${name}.sh`), script);
      }
      fs.writeFileSync(path.join(outDir, "_routers.txt"), names.join("\n") + "\n");
      // eslint-disable-next-line no-console
      console.log(`${repo}: generated ${names.length} routers -> ${outDir}`);
    }
  }, 60000);
});
