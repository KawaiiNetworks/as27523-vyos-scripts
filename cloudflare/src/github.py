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
_DOH_PROVIDERS = [
    (
        "google-json",
        "https://dns.google/resolve?name={qname}&type=A",
    ),
    (
        "cloudflare-json",
        "https://cloudflare-dns.com/dns-query?name={qname}&type=A",
    ),
]


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


def _extract_a_records(data):
    """Return unique IPv4 answers from a DoH JSON response."""
    return sorted(
        {
            answer["data"]
            for answer in data.get("Answer", [])
            if answer.get("type") == 1 and "data" in answer
        }
    )


def _shorten_error_body(text, limit=120):
    """Keep upstream error bodies short enough for worker traces."""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


async def resolve_router_id(router_name):
    """Resolve a router hostname to its IPv4 address via DNS-over-HTTPS."""
    qname = urllib.parse.quote(router_name, safe="")
    errors = []

    for provider_name, url_template in _DOH_PROVIDERS:
        url = url_template.format(qname=qname)
        resp = await fetch(
            url,
            {
                "method": "GET",
                "headers": _make_headers(
                    {**_UA, "Accept": "application/dns-json"}
                ),
            },
        )
        text = await resp.text()
        if resp.status != 200:
            errors.append(
                f"{provider_name}=HTTP {resp.status} ({_shorten_error_body(text)})"
            )
            continue

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            errors.append(
                f"{provider_name}=invalid JSON ({_shorten_error_body(text)})"
            )
            continue

        answers = _extract_a_records(data)
        if len(answers) == 1:
            return answers[0]
        if len(answers) > 1:
            raise ValueError(
                f"router-id for {router_name} is not unique: {', '.join(answers)}"
            )

        status = data.get("Status")
        if status not in (None, 0):
            errors.append(f"{provider_name}=DNS status {status}")
        else:
            errors.append(f"{provider_name}=no A record")

    raise ValueError(
        f"DNS query failed for {router_name}: {'; '.join(errors)}"
    )
