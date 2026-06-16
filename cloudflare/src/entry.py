"""
Cloudflare Workers Python Worker — VyOS + BIRD Config Generator

URL routing:
  GET /{user}/{config_repo}/                             → index page
  GET /{user}/{config_repo}/router/configure.{name}.sh  → VyOS host setup script
                                                          (container, sflow, snmp, defaults)
  GET /{user}/{config_repo}/router/bird.{name}.conf     → generated bird.conf for the router
  GET /{user}/{config_repo}/bird-summary                → bird-summary helper script (static)
"""

import os

from workers import Response

from github import load_yaml_config, resolve_router_id
from cache import CacheStore
from vyos_gen import generate_router_script, gen_bird_config
from index_page import build_index_html

# Static helper script the host downloads to /usr/local/bin/bird-summary. Read
# lazily (like the jinja2 templates) so a bundling issue can't crash startup.
_BIRD_SUMMARY_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "vyos", "bird-summary.py"
)


async def on_fetch(request, env):
    """Worker entrypoint — wraps _handle with a catch-all 500 handler.

    Input: request — the incoming JS Request (has .url); env — the Worker
    environment bindings (unused here).
    Return: a Response. Delegates to _handle; on any uncaught exception,
    returns a 500 with the full traceback as plain text (for debugging).
    """
    try:
        return await _handle(request)
    except Exception:
        import traceback

        return Response(
            f"Worker error:\n{traceback.format_exc()}",
            status=500,
            headers={"content-type": "text/plain"},
        )


async def _handle(request):
    """Route one request to the matching handler and build its Response.

    Input: request — the incoming JS Request; the path is parsed as
    /{user}/{config_repo}/{resource}.
    Return: a Response. Loads vyos.yaml from the config repo (404 if missing),
    then dispatches on `resource`:
      - router/configure.{name}.sh → VyOS host setup script
      - router/bird.{name}.conf     → generated bird.conf
      - "" (index)                  → HTML overview page
      - anything else               → 404
    May perform network I/O (GitHub fetches, DoH router-id resolution).
    """
    url = request.url
    path = url.split("//", 1)[-1].split("/", 1)[-1].strip("/")

    # Root — usage hint
    if not path or path.count("/") < 1:
        return Response(
            "Usage: /{user}/{config_repo}/\n\n"
            "Resources:\n"
            "  router/configure.{name}.sh\n"
            "  router/bird.{name}.conf\n",
            headers={"content-type": "text/plain"},
        )

    parts = path.split("/")
    user = parts[0]
    config_repo = parts[1]
    resource = "/".join(parts[2:]) if len(parts) > 2 else ""

    # --- Route: bird-summary helper (static; no config needed) ---
    if resource == "bird-summary":
        with open(_BIRD_SUMMARY_PATH, encoding="utf-8") as f:
            return Response(
                f.read(),
                headers={"content-type": "text/x-python; charset=utf-8"},
            )

    # Load vyos.yaml (1 fetch)
    config = await load_yaml_config(user, config_repo)
    if config is None:
        return Response(
            f"Cannot load vyos.yaml from {user}/{config_repo}",
            status=404,
            headers={"content-type": "text/plain"},
        )

    local_asn = config["local-asn"]
    host = url.split("//")[1].split("/")[0]
    worker_base_url = f"https://{host}/{user}/{config_repo}"

    def _find_router(name):
        """Return the router dict whose "name" == name, or None if not found."""
        for r in config.get("router", []):
            if r["name"] == name:
                return r
        return None

    # --- Route: VyOS host setup script (container + services + defaults) ---
    if resource.startswith("router/configure.") and resource.endswith(".sh"):
        router_name = resource[len("router/configure.") : -len(".sh")]
        target = _find_router(router_name)
        if target is None:
            available = [r["name"] for r in config.get("router", [])]
            return Response(
                f"Router '{router_name}' not found.\nAvailable: {available}",
                status=404,
                headers={"content-type": "text/plain"},
            )
        cs = CacheStore()
        await cs.preload_all(user, config_repo, config)
        script = await generate_router_script(cs, target, worker_base_url)
        return Response(script, headers={"content-type": "text/plain; charset=utf-8"})

    # --- Route: generated bird.conf ---
    elif resource.startswith("router/bird.") and resource.endswith(".conf"):
        router_name = resource[len("router/bird.") : -len(".conf")]
        target = _find_router(router_name)
        if target is None:
            return Response(
                "Router not found",
                status=404,
                headers={"content-type": "text/plain"},
            )
        cs = CacheStore()
        await cs.preload_all(user, config_repo, config)
        router_id = target.get("router-id") or await resolve_router_id(target["name"])
        bird_conf = gen_bird_config(cs, target, router_id)
        return Response(
            bird_conf, headers={"content-type": "text/plain; charset=utf-8"}
        )

    # --- Route: index page ---
    elif resource == "" or resource == "/":
        html = build_index_html(config, local_asn, worker_base_url)
        return Response(html, headers={"content-type": "text/html; charset=utf-8"})

    else:
        return Response(
            f"Not found: {resource}",
            status=404,
            headers={"content-type": "text/plain"},
        )
