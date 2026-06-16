import { defineConfig } from "vitest/config";
import fs from "node:fs";

// Load the birds.py helper as a string default-export (mirrors the wrangler
// Text rule). Templates are precompiled separately and don't go through here.
function rawText() {
  return {
    name: "raw-text-templates",
    load(id: string) {
      const clean = id.split("?")[0];
      if (clean.endsWith(".py")) {
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
