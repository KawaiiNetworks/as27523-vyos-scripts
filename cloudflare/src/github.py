"""
GitHub data fetching layer for the Cloudflare Worker.

Uses JS `fetch` and `Headers` from Pyodide to make HTTP requests,
as the Cloudflare Workers Python runtime does not support `requests`.
"""

from js import fetch, Headers
import json
import urllib.parse


def _make_headers(d):
    """Create a JS Headers object from a Python dict.

    CF Workers Python (Pyodide) requires JS Headers objects,
    not Python dicts, for the fetch() headers option.
    """
    h = Headers.new()
    for k, v in d.items():
        h.set(k, v)
    return h


_UA = {"User-Agent": "VyOS-Config-Worker"}


async def github_raw(user, repo, path):
    """Fetch a single file from GitHub raw content."""
    url = f"https://raw.githubusercontent.com/{user}/{repo}/main/{path}"
    resp = await fetch(url, {"headers": _make_headers(_UA)})
    if resp.status != 200:
        return None
    return await resp.text()


async def github_raw_json(user, repo, path):
    """Fetch and parse a JSON file from GitHub raw content."""
    text = await github_raw(user, repo, path)
    if text is None:
        return None
    return json.loads(text)


async def load_yaml_config(user, config_repo):
    """Load and parse vyos.yaml from the config repo."""
    import yaml

    text = await github_raw(user, config_repo, "network/vyos/vyos.yaml")
    if text is None:
        return None
    return yaml.safe_load(text)


async def resolve_router_id(router_name):
    """Resolve a router hostname to its IPv4 address via DNS-over-HTTPS."""
    qname = urllib.parse.quote(router_name)
    url = f"https://cloudflare-dns.com/dns-query?name={qname}&type=A&ct=application/dns-json"
    resp = await fetch(
        url, {"headers": _make_headers({"Accept": "application/dns-json"})}
    )
    text = await resp.text()
    if resp.status != 200:
        raise ValueError(f"DNS query failed (status {resp.status}) for {router_name}")
    data = json.loads(text)
    for a in data.get("Answer", []):
        if a.get("type") == 1:
            return a["data"]
    raise ValueError(f"No A record found for {router_name}")
