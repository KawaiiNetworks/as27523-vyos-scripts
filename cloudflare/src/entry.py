"""
Cloudflare Workers Python Worker — VyOS Config Generator

URL routing:
  GET /{user}/{config_repo}/                            → index page
  GET /{user}/{config_repo}/router/configure.{name}.sh  → router script
  GET /{user}/{config_repo}/router/defaultconfig.sh     → default config
  GET /{user}/{config_repo}/find_unused.py              → cleanup tool
"""

from workers import Response

from github import github_raw, load_yaml_config
from cache import CacheStore
from vyos_gen import generate_router_script
from index_page import build_index_html


async def on_fetch(request, env):
    """Worker entrypoint with top-level error handling."""
    try:
        return await _handle(request)
    except Exception as e:
        import traceback

        return Response(
            f"Worker error:\n{traceback.format_exc()}",
            status=500,
            headers={"content-type": "text/plain"},
        )


async def _handle(request):
    """Route the request to the appropriate handler."""
    url = request.url
    path = url.split("//", 1)[-1].split("/", 1)[-1].strip("/")

    # Root — usage hint
    if not path or path.count("/") < 1:
        return Response(
            "Usage: /{user}/{config_repo}/\n\n"
            "Resources:\n"
            "  router/configure.{name}.sh\n"
            "  router/defaultconfig.sh\n"
            "  find_unused.py\n",
            headers={"content-type": "text/plain"},
        )

    parts = path.split("/")
    user = parts[0]
    config_repo = parts[1]
    resource = "/".join(parts[2:]) if len(parts) > 2 else ""

    # Load vyos.yaml (1 fetch)
    config = await load_yaml_config(user, config_repo)
    if config is None:
        return Response(
            f"Cannot load vyos.yaml from {user}/{config_repo}",
            status=404,
            headers={"content-type": "text/plain"},
        )

    local_asn = config["local-asn"]
    scripts_repo = f"as{local_asn}-vyos-scripts"
    host = url.split("//")[1].split("/")[0]
    worker_base_url = f"https://{host}/{user}/{config_repo}"

    # --- Route: generate router script ---
    if resource.startswith("router/configure.") and resource.endswith(".sh"):
        router_name = resource[len("router/configure.") : -len(".sh")]
        target = None
        for r in config.get("router", []):
            if r["name"] == router_name:
                target = r
                break
        if target is None:
            available = [r["name"] for r in config.get("router", [])]
            return Response(
                f"Router '{router_name}' not found.\nAvailable: {available}",
                status=404,
                headers={"content-type": "text/plain"},
            )
        cs = CacheStore()
        await cs.preload_all(user, config_repo, config)
        # Also replace ${WORKER_BASE_URL} in defaults
        cs.defaultconfig = cs.defaultconfig.replace(
            r"${WORKER_BASE_URL}", worker_base_url
        )
        script = await generate_router_script(cs, target)
        return Response(script, headers={"content-type": "text/plain; charset=utf-8"})

    # --- Route: default config ---
    elif resource == "router/defaultconfig.sh":
        cs = CacheStore()
        cs.local_asn = local_asn
        await cs._load_defaults(user, config_repo)
        cs.defaultconfig = cs.defaultconfig.replace(
            r"${WORKER_BASE_URL}", worker_base_url
        )
        return Response(
            cs.defaultconfig,
            headers={"content-type": "text/plain; charset=utf-8"},
        )

    # --- Route: find_unused.py ---
    elif resource == "find_unused.py":
        template = await github_raw(user, scripts_repo, "configure/find_unused.py")
        if template is None:
            return Response(
                "find_unused.py not found",
                status=404,
                headers={"content-type": "text/plain"},
            )
        template = template.replace(
            r"${default_config_url}", f"{worker_base_url}/router/defaultconfig.sh"
        )
        return Response(template, headers={"content-type": "text/plain; charset=utf-8"})

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
