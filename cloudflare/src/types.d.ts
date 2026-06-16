// Text-module imports: at deploy time the wrangler `Text` rule turns these into
// string default-exports; in tests the Vite plugin in vitest.config.ts does the
// same. Keep the two loaders in sync.
declare module "*.njk" {
  const content: string;
  export default content;
}
declare module "*.bird" {
  const content: string;
  export default content;
}
declare module "*.py" {
  const content: string;
  export default content;
}
