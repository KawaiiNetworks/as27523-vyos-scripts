"""
HTML index page builder for the Cloudflare Worker.
"""


def build_index_html(config, local_asn, base_url):
    """Build a dark-themed HTML overview page showing vyos.yaml info."""

    css = (
        "body{font-family:monospace;max-width:960px;margin:40px auto;padding:0 20px;"
        "color:#e0e0e0;background:#1a1a2e}"
        "a{color:#4fc3f7;text-decoration:none}a:hover{text-decoration:underline}"
        "h1{color:#e0e0e0;border-bottom:2px solid #4fc3f7;padding-bottom:8px}"
        "h2{color:#b0bec5;margin-top:24px}h3{color:#90caf9;margin:16px 0 8px}"
        "table{border-collapse:collapse;width:100%;margin-bottom:16px}"
        "th{background:#2a2a4a;color:#90caf9;padding:6px 10px;text-align:left;border:1px solid #3a3a5a}"
        "td{padding:6px 10px;border:1px solid #3a3a5a}"
        "tr:nth-child(even){background:#22223a}tr:nth-child(odd){background:#1e1e36}"
        ".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.85em;margin-right:4px}"
        ".upstream{background:#2e4a2e;color:#81c784}.routeserver{background:#2e3e5e;color:#90caf9}"
        ".peer{background:#4a4a2e;color:#ffd54f}.downstream{background:#4a2e2e;color:#ef9a9a}"
        ".ibgp{background:#3e2e4e;color:#ce93d8}"
        ".section{background:#22223a;border:1px solid #3a3a5a;border-radius:6px;padding:12px 16px;margin:12px 0}"
        "code{background:#2a2a4a;padding:2px 6px;border-radius:3px}"
    )

    p = []
    p.append(
        f'<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<title>VyOS Config Generator \u2014 AS{local_asn}</title>"
        f"<style>{css}</style></head><body>"
    )
    p.append(f"<h1>VyOS Config Generator \u2014 AS{local_asn}</h1>")

    # AS-Set Limits
    asl = config.get("as-set-limit", {})
    p.append('<div class="section"><h2>AS-Set Limits</h2>')
    p.append(
        f'<p>Member limit: <code>{asl.get("member-limit", "N/A")}</code> &nbsp; '
        f'Prefix limit: <code>{asl.get("prefix-limit", "N/A")}</code></p>'
    )
    lal = asl.get("large-as-list", [])
    if lal:
        p.append(
            "<p>Large AS list: "
            + ", ".join(f"<code>AS{a}</code>" for a in lal)
            + "</p>"
        )
    p.append("</div>")

    # Keepup
    keepup = config.get("keepup-as-list", [])
    if keepup:
        p.append('<div class="section"><h2>Keep-Up AS List</h2>')
        p.append(
            "<p>" + ", ".join(f"<code>AS{a}</code>" for a in keepup) + "</p></div>"
        )

    # Blacklist
    bl = config.get("blacklist", {})
    if bl:
        p.append('<div class="section"><h2>Blacklist</h2>')
        bl_asns = bl.get("asn", [])
        if bl_asns:
            p.append(
                "<p><strong>ASN:</strong> "
                + ", ".join(f"<code>AS{a}</code>" for a in bl_asns)
                + "</p>"
            )
        bl_asset = bl.get("as-set", [])
        if bl_asset:
            p.append(
                "<p><strong>AS-Set:</strong> "
                + ", ".join(f"<code>{a}</code>" for a in bl_asset)
                + "</p>"
            )
        bl_p4 = bl.get("prefix4", [])
        if bl_p4:
            p.append(
                "<p><strong>IPv4:</strong> "
                + ", ".join(f"<code>{px}</code>" for px in bl_p4)
                + "</p>"
            )
        bl_p6 = bl.get("prefix6", [])
        if bl_p6:
            p.append(
                "<p><strong>IPv6:</strong> "
                + ", ".join(f"<code>{px}</code>" for px in bl_p6)
                + "</p>"
            )
        p.append("</div>")

    # Routers
    p.append("<h2>Routers</h2>")
    for router in config.get("router", []):
        rn = router["name"]
        script_url = f"{base_url}/router/configure.{rn}.sh"
        p.append('<div class="section">')
        p.append(
            f'<h3>{rn} &nbsp; <a href="{script_url}">\u2b07 configure.{rn}.sh</a></h3>'
        )

        bgp = router.get("protocols", {}).get("bgp", {})
        for ntype in ["upstream", "routeserver", "peer", "downstream", "ibgp"]:
            neighbors = bgp.get(ntype, [])
            if not neighbors:
                continue
            p.append(
                f'<p><span class="badge {ntype}">{ntype}</span> ({len(neighbors)} sessions)</p>'
            )
            p.append(
                "<table><tr><th>ASN</th><th>Neighbor Address</th><th>Interface</th></tr>"
            )
            for nb in neighbors:
                asn_val = nb.get("asn", "?")
                addrs = nb.get("neighbor-address", [])
                if isinstance(addrs, str):
                    addrs = [addrs]
                addr_str = "<br>".join(str(a) for a in addrs)
                iface = nb.get("update-source", "")
                p.append(
                    f"<tr><td>AS{asn_val}</td><td>{addr_str}</td><td>{iface}</td></tr>"
                )
            p.append("</table>")

        rpki = router.get("protocols", {}).get("rpki", [])
        if rpki:
            rpki_str = ", ".join(
                f'{r.get("server", "?")}:{r.get("port", "?")}' for r in rpki
            )
            p.append(f"<p><strong>RPKI:</strong> {rpki_str}</p>")

        p.append("</div>")

    # Other resources
    p.append("<h2>Other Resources</h2><ul>")
    p.append(
        f'<li><a href="{base_url}/router/defaultconfig.sh">defaultconfig.sh</a></li>'
    )
    p.append(f'<li><a href="{base_url}/find_unused.py">find_unused.py</a></li>')
    p.append("</ul></body></html>")

    return "\n".join(p)
