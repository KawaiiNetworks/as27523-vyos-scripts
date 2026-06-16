import { defineConfig } from "vitest/config";
import fs from "node:fs";

// Load .njk/.bird/.py template files as string default-exports, mirroring the
// wrangler `Text` rule used in the deployed Worker. This lets the same
// `import header from "./templates/bird/header.bird.njk"` work under vitest.
function rawText() {
  return {
    name: "raw-text-templates",
    load(id: string) {
      const clean = id.split("?")[0];
      if (clean.endsWith(".njk") || clean.endsWith(".bird") || clean.endsWith(".py")) {
        const src = fs.readFileSync(clean, "utf8");
        return `export default ${JSON.stringify(src)};`;
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [rawText()],
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
  },
});
