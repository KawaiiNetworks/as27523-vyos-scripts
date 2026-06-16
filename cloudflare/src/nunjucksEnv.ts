/**
 * Nunjucks environments for the bird/ and vyos/ template sets.
 *
 * Templates are PRECOMPILED at build time (scripts/precompile-templates.mjs →
 * templates.generated.ts) into plain JS functions, so the Worker never compiles
 * from strings at runtime — the Cloudflare runtime forbids eval/new Function.
 * Custom filters reproduce Jinja semantics Nunjucks lacks (indent-with-first,
 * global replace).
 */

import nunjucks from "nunjucks";
import precompiled from "./templates.generated.js";

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

// PrecompiledLoader isn't in @types/nunjucks; reach it off the namespace.
const PrecompiledLoader = (nunjucks as any).PrecompiledLoader as new (
  templates: Record<string, unknown>,
) => nunjucks.ILoader;

// autoescape:false matches the precompile step (escaping is baked in at compile
// time). trimBlocks/lstripBlocks are NOT needed here — whitespace handling is
// already compiled into the precompiled functions.
const ENV_OPTS = { autoescape: false, throwOnUndefined: false };

function makeEnv(): nunjucks.Environment {
  return configure(new nunjucks.Environment(new PrecompiledLoader(precompiled), ENV_OPTS));
}

export const birdEnv = makeEnv();
export const vyosEnv = makeEnv();
