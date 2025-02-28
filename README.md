# VyOS Scripts for Player ISP

## Features

-   automatically generate filters based on the AS number of the BGP neighbor
-   update all managed configurations periodically

This repository generate a set of scripts to configure a VyOS router for an ISP.
They will configure the following items and update them periodically:

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

All you need is a YAML file, and then please enjoy :)

## How to use

-   Fork this repository and name it as `{Your Organization}/as{Your ASN}-vyos-scripts`
-   Create a new repository named `AS{Your ASN}`
-   Create vyos.yaml at `/network/vyos/vyos.yaml` in the repository `AS{Your ASN}`, please refer to the example https://github.com/KawaiiNetworks/AS27523/tree/main/network/vyos/vyos.yaml
-   In the repository `as{Your ASN}-vyos-scripts`, enable GitHub Actions `Generate and Upload configure.sh`
-   manually run the workflow `Generate and Upload configure.sh`, and then download the generated scripts from Releases - nightly vyos configuration
-   Run the downloaded scripts on your VyOS router
