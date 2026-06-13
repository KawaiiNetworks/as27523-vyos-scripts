"""
GitHub data fetching layer for the Cloudflare Worker.

Uses JS `fetch` and `Headers` from Pyodide to make HTTP requests,
as the Cloudflare Workers Python runtime does not support `requests`.
"""

from js import fetch, Headers
import json
import urllib.parse


def _make_headers(d):
    """Convert a Python dict of headers into a JS Headers object.

    Input: d — a dict of {header-name: value} strings.
    Return: a JS Headers object with each pair set on it.

    CF Workers Python (Pyodide) requires JS Headers objects, not Python
    dicts, for the fetch() `headers` option, hence this adapter.
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
    """Fetch one file's raw text from GitHub.

    Input: user, repo, path — locate the file at
    raw.githubusercontent.com/{user}/{repo}/main/{path} (always the `main`
    branch).
    Return: the file body as a str, or None if the response status is not 200
    (e.g. 404 missing file). Network/fetch errors propagate as exceptions.
    """
    url = f"https://raw.githubusercontent.com/{user}/{repo}/main/{path}"
    resp = await fetch(url, {"headers": _make_headers(_UA)})
    if resp.status != 200:
        return None
    return await resp.text()


async def github_raw_json(user, repo, path):
    """Fetch one file from GitHub and parse it as JSON.

    Input: user, repo, path — same locator as github_raw().
    Return: the parsed JSON value (dict/list/...), or None if the file is
    missing (status != 200). Raises json.JSONDecodeError if the body is not
    valid JSON.
    """
    text = await github_raw(user, repo, path)
    if text is None:
        return None
    return json.loads(text)


async def load_yaml_config(user, config_repo):
    """Load and parse the router config YAML from the config repo.

    Input: user, config_repo — the file is fetched from
    {config_repo}/network/vyos/vyos.yaml on `main`.
    Return: the parsed YAML as a Python dict, or None if the file is missing.
    Raises yaml.YAMLError if the body is not valid YAML.
    """
    import yaml

    text = await github_raw(user, config_repo, "network/vyos/vyos.yaml")
    if text is None:
        return None
    return yaml.safe_load(text)


def _extract_a_records(data):
    """Pull the unique IPv4 answers out of a DoH JSON response.

    Input: data — a parsed DNS-over-HTTPS JSON response (dict with an
    "Answer" list).
    Return: a sorted list of unique IPv4 address strings, taken from answers
    whose type == 1 (A record). Empty list if there are no A answers.
    """
    return sorted(
        {
            answer["data"]
            for answer in data.get("Answer", [])
            if answer.get("type") == 1 and "data" in answer
        }
    )


def _shorten_error_body(text, limit=120):
    """Collapse and truncate an upstream error body for log lines.

    Input: text — an arbitrary response body; limit — max output length.
    Return: the body with all runs of whitespace collapsed to single spaces,
    truncated to `limit` chars (last 3 replaced with "..." when it overflows)
    so it fits on one worker-trace line.
    """
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


async def resolve_router_id(router_name):
    """Resolve a router hostname to its single IPv4 address via DNS-over-HTTPS.

    Input: router_name — the hostname to resolve (used as the router-id).
    Return: the resolved IPv4 address as a str, returned as soon as a provider
    yields exactly one A record.

    Tries each provider in _DOH_PROVIDERS in order, accumulating a per-provider
    error reason whenever one fails (fetch/transport error, non-200, invalid
    JSON, DNS error status, or no A record), and failing over to the next.
    Raises ValueError if the name resolves to more than one address (ambiguous
    router-id) or if every provider fails (the message lists all collected
    reasons).
    """
    qname = urllib.parse.quote(router_name, safe="")
    errors = []

    for provider_name, url_template in _DOH_PROVIDERS:
        url = url_template.format(qname=qname)
        try:
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
        except Exception as e:
            # Transport-level failure (unreachable provider, TLS error,
            # timeout): treat like any other provider failure and fail over
            # to the next one rather than aborting the whole resolution.
            errors.append(f"{provider_name}=fetch error ({e})")
            continue
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
