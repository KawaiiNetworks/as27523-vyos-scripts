# VyOS Scripts for Player ISP

## Features

-   automatically generate filters based on the AS number of the BGP neighbor
-   publish per-router VyOS configure scripts through Cloudflare Workers
-   update all managed configurations periodically

This repository provides the logic and default templates used to configure a VyOS router for an ISP.
The generated scripts manage the following sections:

```
system task-scheduler task update-config
policy as-path-list
policy prefix-list
policy prefix-list6
policy large-community-list
policy route-map
protocols rpki
protocols bgp address-family
protocols bgp parameters
protocols bgp system-as
protocols bgp neighbor
protocols bgp bmp
system frr
system sflow
service snmp
system ip protocol bgp
system ipv6 protocol bgp
```

## Current Architecture

-   `AS{ASN}` is the config repository. It stores `network/vyos/vyos.yaml` and the generated cache files under `cache/`.
-   This repository stores the generator code, default templates, helper tools, and the Cloudflare Worker.
-   `configure/save-cache.py` prepares `cache/pdb/summary.json`, `cache/bgpq4/summary.json`, `cache/as-set/summary.json`, and `cache/defaults_bundle.txt` for the config repository.
-   The Cloudflare Worker reads `vyos.yaml` and the cache files directly from GitHub, then serves:
    -   `/{user}/{config_repo}/router/configure.{router}.sh`
    -   `/{user}/{config_repo}/router/defaultconfig.sh`
    -   `/{user}/{config_repo}/find_unused.py`
-   The default scheduler downloads the latest script from the Worker every 12 hours and applies it on the router.

## How to use

-   Fork this repository and name it `{Your Organization}/as{Your ASN}-vyos-scripts`.
-   Create a new repository named `AS{Your ASN}`.
-   Create `network/vyos/vyos.yaml` in the `AS{Your ASN}` repository. You can refer to the example at https://github.com/KawaiiNetworks/AS27523/tree/main/network/vyos/vyos.yaml
-   Install local dependencies for cache generation:
    -   `cd configure`
    -   `./install-dependencies.sh`
-   Build cache files into the config repository:
    -   `python save-cache.py /path/to/AS{Your ASN}`
    -   `python save-cache.py /path/to/AS{Your ASN} --defaults-bundle --scripts-dir /path/to/as{Your ASN}-vyos-scripts`
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
