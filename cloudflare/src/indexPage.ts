/** HTML index page builder (port of index_page.py). Pure function. */

export function buildIndexHtml(config: any, localAsn: number, baseUrl: string): string {
  const css =
    "body{font-family:monospace;max-width:960px;margin:40px auto;padding:0 20px;" +
    "color:#e0e0e0;background:#1a1a2e}" +
    "a{color:#4fc3f7;text-decoration:none}a:hover{text-decoration:underline}" +
    "h1{color:#e0e0e0;border-bottom:2px solid #4fc3f7;padding-bottom:8px}" +
    "h2{color:#b0bec5;margin-top:24px}h3{color:#90caf9;margin:16px 0 8px}" +
    "table{border-collapse:collapse;width:100%;margin-bottom:16px}" +
    "th{background:#2a2a4a;color:#90caf9;padding:6px 10px;text-align:left;border:1px solid #3a3a5a}" +
    "td{padding:6px 10px;border:1px solid #3a3a5a}" +
    "tr:nth-child(even){background:#22223a}tr:nth-child(odd){background:#1e1e36}" +
    ".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.85em;margin-right:4px}" +
    ".upstream{background:#2e4a2e;color:#81c784}.routeserver{background:#2e3e5e;color:#90caf9}" +
    ".peer{background:#4a4a2e;color:#ffd54f}.downstream{background:#4a2e2e;color:#ef9a9a}" +
    ".ibgp{background:#3e2e4e;color:#ce93d8}" +
    ".section{background:#22223a;border:1px solid #3a3a5a;border-radius:6px;padding:12px 16px;margin:12px 0}" +
    "code{background:#2a2a4a;padding:2px 6px;border-radius:3px}";

  const p: string[] = [];
  p.push(
    `<!DOCTYPE html><html><head><meta charset="utf-8">` +
      `<title>VyOS Config Generator — AS${localAsn}</title>` +
      `<style>${css}</style></head><body>`,
  );
  p.push(`<h1>VyOS Config Generator — AS${localAsn}</h1>`);

  const asl = config["as-set-limit"] ?? {};
  p.push('<div class="section"><h2>AS-Set Limits</h2>');
  p.push(
    `<p>Member limit: <code>${asl["member-limit"] ?? "N/A"}</code> &nbsp; ` +
      `Prefix limit: <code>${asl["prefix-limit"] ?? "N/A"}</code></p>`,
  );
  const lal: any[] = asl["large-as-list"] ?? [];
  if (lal.length) {
    p.push("<p>Large AS list: " + lal.map((a) => `<code>AS${a}</code>`).join(", ") + "</p>");
  }
  p.push("</div>");

  const keepup: any[] = config["keepup-as-list"] ?? [];
  if (keepup.length) {
    p.push('<div class="section"><h2>Keep-Up AS List</h2>');
    p.push("<p>" + keepup.map((a) => `<code>AS${a}</code>`).join(", ") + "</p></div>");
  }

  const bl = config["blacklist"] ?? {};
  if (bl && Object.keys(bl).length) {
    p.push('<div class="section"><h2>Blacklist</h2>');
    const blAsns: any[] = bl["asn"] ?? [];
    if (blAsns.length) {
      p.push(
        "<p><strong>ASN:</strong> " +
          blAsns.map((a) => `<code>AS${a}</code>`).join(", ") +
          "</p>",
      );
    }
    const blAsset: any[] = bl["as-set"] ?? [];
    if (blAsset.length) {
      p.push(
        "<p><strong>AS-Set:</strong> " +
          blAsset.map((a) => `<code>${a}</code>`).join(", ") +
          "</p>",
      );
    }
    const blP4: any[] = bl["prefix4"] ?? [];
    if (blP4.length) {
      p.push(
        "<p><strong>IPv4:</strong> " +
          blP4.map((px) => `<code>${px}</code>`).join(", ") +
          "</p>",
      );
    }
    const blP6: any[] = bl["prefix6"] ?? [];
    if (blP6.length) {
      p.push(
        "<p><strong>IPv6:</strong> " +
          blP6.map((px) => `<code>${px}</code>`).join(", ") +
          "</p>",
      );
    }
    p.push("</div>");
  }

  p.push("<h2>Routers</h2>");
  for (const router of config["router"] ?? []) {
    const rn = router["name"];
    const scriptUrl = `${baseUrl}/router/configure.${rn}.sh`;
    const birdUrl = `${baseUrl}/router/bird.${rn}.conf`;
    p.push('<div class="section">');
    p.push(
      `<h3>${rn} &nbsp; <a href="${scriptUrl}">⬇ configure.${rn}.sh</a>` +
        ` &nbsp; <a href="${birdUrl}">⬇ bird.${rn}.conf</a></h3>`,
    );

    const bgp = router?.protocols?.bgp ?? {};
    for (const ntype of ["upstream", "routeserver", "peer", "downstream", "ibgp"]) {
      const neighbors: any[] = bgp[ntype] ?? [];
      if (!neighbors.length) continue;
      p.push(
        `<p><span class="badge ${ntype}">${ntype}</span> (${neighbors.length} sessions)</p>`,
      );
      p.push("<table><tr><th>ASN</th><th>Neighbor Address</th><th>Source</th></tr>");
      for (const nb of neighbors) {
        const asnVal = nb["asn"] ?? "?";
        let addrs = nb["neighbor-address"] ?? [];
        if (typeof addrs === "string") addrs = [addrs];
        const addrStr = addrs.map((a: any) => String(a)).join("<br>");
        const src = nb["source-address"] ?? "";
        p.push(`<tr><td>AS${asnVal}</td><td>${addrStr}</td><td>${src}</td></tr>`);
      }
      p.push("</table>");
    }

    const rpki: any[] = router?.protocols?.rpki ?? [];
    if (rpki.length) {
      const rpkiStr = rpki.map((r) => `${r["server"] ?? "?"}:${r["port"] ?? "?"}`).join(", ");
      p.push(`<p><strong>RPKI:</strong> ${rpkiStr}</p>`);
    }

    p.push("</div>");
  }

  p.push("</body></html>");
  return p.join("\n");
}
