/**
 * Nunjucks environments for the bird/ and vyos/ template sets.
 *
 * Templates are bundled as strings (wrangler Text rule / vitest plugin) and
 * served via an in-memory loader keyed by the exact {% include %} names. Custom
 * filters reproduce Jinja semantics that Nunjucks lacks (indent-with-first,
 * global replace).
 */

import nunjucks from "nunjucks";

// bird/ templates
import headerBird from "./templates/bird/header.bird.njk";
import neighborsBird from "./templates/bird/neighbors.bird.njk";
import policyBird from "./templates/bird/policy.bird.njk";
import rpkiBird from "./templates/bird/rpki.bird.njk";
import asFiltersBird from "./templates/bird/as_filters.bird.njk";
import vrfBird from "./templates/bird/vrf.bird.njk";
import prefixListsBird from "./templates/bird/defaults/prefix_lists.bird";
import asPathsBird from "./templates/bird/defaults/as_paths.bird";
import communitiesBird from "./templates/bird/defaults/communities.bird";
import filtersBird from "./templates/bird/defaults/filters.bird";

// vyos/ templates
import configureSh from "./templates/vyos/configure.sh.njk";
import containerNjk from "./templates/vyos/container.njk";
import sflowNjk from "./templates/vyos/sflow.njk";
import snmpNjk from "./templates/vyos/snmp.njk";

const BIRD_TEMPLATES: Record<string, string> = {
  "header.bird.njk": headerBird,
  "neighbors.bird.njk": neighborsBird,
  "policy.bird.njk": policyBird,
  "rpki.bird.njk": rpkiBird,
  "as_filters.bird.njk": asFiltersBird,
  "vrf.bird.njk": vrfBird,
  "defaults/prefix_lists.bird": prefixListsBird,
  "defaults/as_paths.bird": asPathsBird,
  "defaults/communities.bird": communitiesBird,
  "defaults/filters.bird": filtersBird,
};

const VYOS_TEMPLATES: Record<string, string> = {
  "configure.sh.njk": configureSh,
  "container.njk": containerNjk,
  "sflow.njk": sflowNjk,
  "snmp.njk": snmpNjk,
};

class InMemoryLoader implements nunjucks.ILoader {
  constructor(private readonly map: Record<string, string>) {}
  getSource(name: string): nunjucks.LoaderSource {
    let src = this.map[name];
    if (src === undefined) throw new Error(`template not found: ${name}`);
    // Jinja trim_blocks removes the newline after a comment `#}`; Nunjucks
    // trimBlocks does not. Replicate it so comment lines emit nothing.
    src = src.replace(/#\}\n/g, "#}");
    // Match Jinja's keep_trailing_newline=False: strip one trailing newline
    // from every template source (entry templates, includes, macros).
    if (src.endsWith("\n")) src = src.slice(0, -1);
    return { src, path: name, noCache: true };
  }
}

/** Jinja2 `indent(width, first)` — indents every non-empty line; leaves empty
 *  lines untouched; indents the first line only when `first` is true. */
function jinjaIndent(s: string, width = 4, first = false): string {
  const indention = " ".repeat(width);
  const lines = String(s).split("\n");
  let rv = lines[0] ?? "";
  if (lines.length > 1) {
    rv +=
      "\n" +
      lines
        .slice(1)
        .map((line) => (line ? indention + line : line))
        .join("\n");
  }
  if (first) rv = indention + rv;
  return rv;
}

function configure(env: nunjucks.Environment): nunjucks.Environment {
  env.addFilter("indent", jinjaIndent);
  // Jinja `replace` replaces ALL occurrences (Nunjucks' may not).
  env.addFilter("replace", (s: any, from: string, to: string) =>
    String(s).split(from).join(to),
  );
  // Order-preserving unique (safety; most uses are precomputed).
  env.addFilter("unique", (arr: any[]) => {
    const seen = new Set();
    const out: any[] = [];
    for (const x of arr ?? []) {
      if (!seen.has(x)) {
        seen.add(x);
        out.push(x);
      }
    }
    return out;
  });
  return env;
}

const ENV_OPTS = { autoescape: false, trimBlocks: true, lstripBlocks: true, throwOnUndefined: false };

export const birdEnv = configure(
  new nunjucks.Environment(new InMemoryLoader(BIRD_TEMPLATES), ENV_OPTS),
);
export const vyosEnv = configure(
  new nunjucks.Environment(new InMemoryLoader(VYOS_TEMPLATES), ENV_OPTS),
);
