import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import yaml from "js-yaml";

import { CacheStore } from "../src/cache.js";
import { genBirdConfig, generateRouterScript } from "../src/generate.js";
import { birdImage } from "../src/prepare.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, "fixtures");
const CACHE = path.join(FIXTURES, "cache");
const EXPECTED = path.join(HERE, "expected");
const RESULTS = path.join(HERE, "results");
const UPDATE_GOLDEN = process.env.UPDATE_GOLDEN === "1";

function loadYaml(name: string): any {
  return yaml.load(fs.readFileSync(path.join(FIXTURES, name), "utf8"));
}
function loadJson(rel: string): any {
  return JSON.parse(fs.readFileSync(path.join(CACHE, rel), "utf8"));
}
function buildCache(config: any): CacheStore {
  const cs = new CacheStore();
  cs.seedFromSummaries(
    config,
    loadJson("pdb/summary.json"),
    loadJson("bgpq4/summary.json"),
    loadJson("as-set/summary.json"),
  );
  return cs;
}
function assertMatchesGolden(filename: string, content: string): void {
  const golden = path.join(EXPECTED, filename);
  if (UPDATE_GOLDEN) {
    fs.writeFileSync(golden, content);
    return;
  }
  expect(content).toBe(fs.readFileSync(golden, "utf8"));
}

describe("generator golden parity", () => {
  it("configure.sh + bird.conf match the committed goldens", async () => {
    const config = loadYaml("vyos.yaml");
    const router = config.router[0];
    const scriptName = `configure.${router.name}.sh`;
    const confName = `bird.${router.name}.conf`;

    const scriptCs = buildCache(structuredClone(config));
    const script = await generateRouterScript(
      scriptCs,
      structuredClone(router),
      "https://worker.example/kawaii/as27523",
    );

    const confCs = buildCache(structuredClone(config));
    const conf = genBirdConfig(confCs, structuredClone(router), router["router-id"]);

    fs.mkdirSync(RESULTS, { recursive: true });
    fs.writeFileSync(path.join(RESULTS, scriptName), script);
    fs.writeFileSync(path.join(RESULTS, confName), conf);

    assertMatchesGolden(scriptName, script);
    assertMatchesGolden(confName, conf);
  });
});

describe("empty-collection robustness (clean config)", () => {
  it("omits WARNINGS / RPKI / BMP sections when those are absent", () => {
    // Empty list/dict are falsy in Python; the equivalent Nunjucks guards must
    // keep these sections out when the config has none.
    const config: any = {
      "local-asn": 65001,
      "as-set-limit": { "member-limit": 100, "prefix-limit": 100, "large-as-list": [] },
      router: [
        {
          name: "clean",
          "router-id": "192.0.2.1",
          protocols: {
            bgp: {
              upstream: [
                { asn: 174, "neighbor-address": "203.0.113.1", "source-address": "203.0.113.2" },
              ],
            },
          },
        },
      ],
    };
    const cs = new CacheStore();
    cs.seedFromSummaries(structuredClone(config), null, null, null);
    const conf = genBirdConfig(cs, structuredClone(config).router[0], "192.0.2.1");

    expect(conf).not.toContain("# WARNINGS / SKIPPED ITEMS");
    expect(conf).not.toContain("protocol rpki");
    expect(conf).not.toContain("protocol bmp");
    expect(conf).toContain("# No RPKI servers configured.");
    expect(conf).toContain("protocol bgp u_as174_nid");
  });
});

describe("bird -p parse check", () => {
  it("the generated bird.conf parses under the real BIRD parser", () => {
    const config = loadYaml("vyos.yaml");
    const router = config.router[0];
    const conf = genBirdConfig(buildCache(structuredClone(config)), structuredClone(router), router["router-id"]);

    fs.mkdirSync(RESULTS, { recursive: true });
    const confName = `bird.${router.name}.conf`;
    fs.writeFileSync(path.join(RESULTS, confName), conf);

    const which = (bin: string): string | null => {
      try {
        return execFileSync("sh", ["-c", `command -v ${bin}`]).toString().trim() || null;
      } catch {
        return null;
      }
    };
    const birdBin = which("bird") || which("bird2");
    if (birdBin) {
      execFileSync(birdBin, ["-p", "-c", path.join(RESULTS, confName)]);
      return;
    }
    const podman = which("podman");
    if (!podman) return; // neither available — skip
    const image = process.env.BIRD_IMAGE || birdImage(router);
    // Only run if the image is already pulled (CI pre-pulls it); never pull here.
    try {
      execFileSync(podman, ["image", "exists", image]);
    } catch {
      return;
    }
    execFileSync(podman, [
      "run", "--rm", "-v", `${RESULTS}:/conf:ro,Z`, image, "-p", "-c", `/conf/${confName}`,
    ]);
  });
});
