/**
 * GitHub data fetching layer (port of github.py).
 *
 * Uses the native Workers fetch/Headers/AbortSignal (no Pyodide shim).
 */

import yaml from "js-yaml";

const UA = { "User-Agent": "VyOS-Config-Worker" };

// Subrequest timeouts: a stalled origin otherwise hangs the whole request.
const HTTP_TIMEOUT_MS = 3000;
const DOH_TIMEOUT_MS = 3000;

const DOH_PROVIDERS: [string, string][] = [
  ["google-json", "https://dns.google/resolve?name={qname}&type=A"],
  ["cloudflare-json", "https://cloudflare-dns.com/dns-query?name={qname}&type=A"],
];

/** Percent-encode like Python urllib.parse.quote(safe=""). */
function quote(s: string): string {
  return encodeURIComponent(s).replace(
    /[!*'()]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

/** Fetch one file's raw text from GitHub `main`; null on non-200. */
export async function githubRaw(
  user: string,
  repo: string,
  path: string,
): Promise<string | null> {
  const url = `https://raw.githubusercontent.com/${user}/${repo}/main/${path}`;
  const resp = await fetch(url, {
    headers: new Headers(UA),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  if (resp.status !== 200) return null;
  return await resp.text();
}

/** Fetch one file from GitHub and parse it as JSON; null if missing. */
export async function githubRawJson(
  user: string,
  repo: string,
  path: string,
): Promise<any> {
  const text = await githubRaw(user, repo, path);
  if (text === null) return null;
  return JSON.parse(text);
}

/** Load and parse the router config YAML from the config repo; null if missing. */
export async function loadYamlConfig(
  user: string,
  configRepo: string,
): Promise<any> {
  const text = await githubRaw(user, configRepo, "network/vyos/vyos.yaml");
  if (text === null) return null;
  return yaml.load(text);
}

function extractARecords(data: any): string[] {
  const set = new Set<string>();
  for (const answer of data?.Answer ?? []) {
    if (answer?.type === 1 && "data" in answer) set.add(answer.data);
  }
  return [...set].sort();
}

function shortenErrorBody(text: string, limit = 120): string {
  const compact = text.split(/\s+/).filter(Boolean).join(" ");
  if (compact.length <= limit) return compact;
  return compact.slice(0, limit - 3) + "...";
}

/**
 * Resolve a router hostname to its single IPv4 via DNS-over-HTTPS, failing over
 * across providers. Throws if the name is ambiguous or every provider fails.
 */
export async function resolveRouterId(routerName: string): Promise<string> {
  const qname = quote(routerName);
  const errors: string[] = [];

  for (const [providerName, urlTemplate] of DOH_PROVIDERS) {
    const url = urlTemplate.replace("{qname}", qname);
    let text: string;
    let resp: Response;
    try {
      resp = await fetch(url, {
        method: "GET",
        headers: new Headers({ ...UA, Accept: "application/dns-json" }),
        signal: AbortSignal.timeout(DOH_TIMEOUT_MS),
      });
      text = await resp.text();
    } catch (e) {
      errors.push(`${providerName}=fetch error (${e})`);
      continue;
    }
    if (resp.status !== 200) {
      errors.push(`${providerName}=HTTP ${resp.status} (${shortenErrorBody(text)})`);
      continue;
    }

    let data: any;
    try {
      data = JSON.parse(text);
    } catch {
      errors.push(`${providerName}=invalid JSON (${shortenErrorBody(text)})`);
      continue;
    }

    const answers = extractARecords(data);
    if (answers.length === 1) return answers[0];
    if (answers.length > 1) {
      throw new Error(
        `router-id for ${routerName} is not unique: ${answers.join(", ")}`,
      );
    }

    const status = data?.Status;
    if (status !== undefined && status !== null && status !== 0) {
      errors.push(`${providerName}=DNS status ${status}`);
    } else {
      errors.push(`${providerName}=no A record`);
    }
  }

  throw new Error(`DNS query failed for ${routerName}: ${errors.join("; ")}`);
}
