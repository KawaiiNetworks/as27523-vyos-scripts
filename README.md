# VyOS Scripts for Player ISP

## Features

-   automatically generate filters based on the AS number of the BGP neighbor
-   publish per-router VyOS configure scripts through Cloudflare Workers
-   update all managed configurations periodically

This repository provides the logic and default templates used to configure a VyOS router for an ISP.
The router runs **BIRD3** inside a container; VyOS itself only handles the host plumbing.

The generated **VyOS host script** (`configure.{router}.sh`) manages:

```
system host-name
system task-scheduler task update-config
container name bird          (the BIRD3 container)
system sflow
service snmp
```

The generated **`bird.conf`** (served separately, run inside the container) manages all routing policy:

```
RPKI ROA tables + RTR protocols
prefix / as-path / community filter sets (autogen defaults)
per-neighbor import/export filters
BGP protocol instances (upstream / downstream / peer / routeserver / ibgp)
kernel + direct + static protocols (redistribution)
BMP monitoring
```

## Current Architecture

-   `AS{ASN}` is the config repository. It stores `network/vyos/vyos.yaml` and the generated cache files under `cache/`.
-   This repository stores the generator code, default templates, helper tools, and the Cloudflare Worker.
-   `configure/save-cache.py` prepares `cache/pdb/summary.json`, `cache/bgpq4/summary.json`, and `cache/as-set/summary.json` for the config repository.
-   The Cloudflare Worker reads `vyos.yaml` and the cache files directly from GitHub, then serves:
    -   `/{user}/{config_repo}/router/configure.{router}.sh` — VyOS host setup script
    -   `/{user}/{config_repo}/router/bird.{router}.conf` — generated `bird.conf` for the router
-   The `configure.{router}.sh` installs an `update-config` scheduler that re-downloads and re-applies the script from the Worker every 12 hours.
    The host script in turn fetches `bird.{router}.conf` into the container and reloads BIRD.

## How to use

-   Fork this repository and name it `{Your Organization}/as{Your ASN}-vyos-scripts`.
-   Create a new repository named `AS{Your ASN}`.
-   Create `network/vyos/vyos.yaml` in the `AS{Your ASN}` repository. You can refer to the example at https://github.com/KawaiiNetworks/AS27523/tree/main/network/vyos/vyos.yaml
-   Install local dependencies for cache generation:
    -   Python deps are managed by [pixi](https://pixi.sh): run `pixi install` in the repo root.
    -   `bgpq4` is a separate system tool (not on conda-forge) — install it via your package manager, e.g. `apt-get install bgpq4` or `brew install bgpq4`.
-   Build cache files into the config repository:
    -   `pixi run python configure/save-cache.py /path/to/AS{Your ASN}`
-   Deploy the Cloudflare Worker from this repository using the `Deploy Cloudflare Worker` GitHub Actions workflow.
-   Use the Worker URL to fetch `configure.{router}.sh`, or let the installed `update-config` scheduler refresh it automatically on the router.

## Note

For a route-map, we divide it into 3 parts: gather, filter, modifier.

gather: to gather routes and then goto filter
filter: to filter routes and then goto modifier
modifier: to modify attributes of routes

adding item to gather will increase the number of routes of filter (it can only add routes because it's whitelist) we call it pre-(import/export/none)-filter.
EBGP import route-map do not have a gather now because we directly import all route to filter. For EBGP export route-map we will design a gather section in future. Now it's available for redistribution route-map.

in modifier, you can modify attributes of routes, or deny routes (it can only modify or deny routes because it's applied after filter) we call it pre-(import/export/none)-accept.
