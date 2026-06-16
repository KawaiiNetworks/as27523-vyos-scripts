// The birds.py helper is imported as a string (wrangler Text rule / vitest
// plugin). Templates are precompiled to templates.generated.ts, not imported
// as text.
declare module "*.py" {
  const content: string;
  export default content;
}
