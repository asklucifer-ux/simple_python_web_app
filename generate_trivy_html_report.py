#!/usr/bin/env python3
# generate_trivy_html_report.py
# Usage: python generate_trivy_html_report.py trivy-report.json trivy-report.html

import json, sys, html, datetime
from pathlib import Path

def short(s, n=300):
    if not s: return ""
    s = s.strip()
    return s if len(s)<=n else s[:n].rsplit(' ',1)[0] + "..."

def generate(json_path, out_path):
    p = Path(json_path)
    if not p.exists():
        print(f"JSON file not found: {json_path}")
        Path(out_path).write_text("<html><body><h3>No JSON report found</h3></body></html>", encoding="utf-8")
        return

    data = json.loads(p.read_text(encoding="utf-8"))
    rows = []
    totals = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0}
    for result in data.get("Results", []):
        target = result.get("Target","")
        # If result contains Vulnerabilities (image scans) handle those; otherwise handle language pkgs
        if result.get("Vulnerabilities"):
            for v in (result.get("Vulnerabilities") or []):
                sev = (v.get("Severity") or "UNKNOWN").upper()
                totals.setdefault(sev,0)
                totals[sev] = totals.get(sev,0) + 1
                rows.append({
                    "target": target,
                    "id": v.get("VulnerabilityID",""),
                    "pkg": v.get("PkgName",""),
                    "installed": v.get("InstalledVersion",""),
                    "fixed": v.get("FixedVersion",""),
                    "severity": sev,
                    "title": v.get("Title",""),
                    "desc": v.get("Description",""),
                    "refs": v.get("References") or []
                })
        # handle language-specific packages (trivy fs for venv)
        elif result.get("Packages"):
            for pkg in (result.get("Packages") or []):
                # there is no Severity per package in fs results; treat as UNKNOWN
                rows.append({
                    "target": target,
                    "id": pkg.get("Identifier", {}).get("PURL",""),
                    "pkg": pkg.get("Name",""),
                    "installed": pkg.get("Version",""),
                    "fixed": "",
                    "severity": "UNKNOWN",
                    "title": "",
                    "desc": "",
                    "refs": []
                })

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_lines = []
    html_lines.append("<!doctype html><html><head><meta charset='utf-8'><title>Trivy Vulnerability Scan Report</title>")
    html_lines.append("<style>")
    html_lines.append("body{font-family:Arial,Helvetica,sans-serif;margin:18px} h1{color:#2b2b2b}")
    html_lines.append(".summary{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap}")
    html_lines.append(".card{padding:10px;border-radius:6px;background:#f5f7fa;border:1px solid #e3e6ea}")
    html_lines.append("table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}")
    html_lines.append("th{background:#0b6fb8;color:white}")
    html_lines.append(".CRITICAL{color:#8b0000;font-weight:bold}.HIGH{color:#d9534f}.MEDIUM{color:#f0ad4e}.LOW{color:#5cb85c}.UNKNOWN{color:gray}")
    html_lines.append(".desc{font-size:0.9em;color:#333;margin-top:6px;padding:8px;background:#fff;border-left:3px solid #eee}")
    html_lines.append(".filter{margin-bottom:12px}")
    html_lines.append(".small{font-size:0.9em;color:#666}")
    html_lines.append("</style>")
    html_lines.append("</head><body>")
    html_lines.append(f"<h1>Trivy Vulnerability Scan Report</h1><p class='small'>Generated: {now}</p>")

    # Summary
    total = sum(totals.values()) if any(totals.values()) else len(rows)
    html_lines.append("<div class='summary'>")
    html_lines.append(f"<div class='card'><strong>Total issues/packages</strong><div style='font-size:24px'>{total}</div></div>")
    for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
        html_lines.append(f"<div class='card'><strong>{k}</strong><div class='{k}' style='font-size:20px'>{totals.get(k,0)}</div></div>")
    html_lines.append("</div>")

    # Filters
    html_lines.append("<div class='filter'><label>Filter: </label>")
    html_lines.append("<button onclick=\"filter('ALL')\">All</button> ")
    for k in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
        html_lines.append(f"<button onclick=\"filter('{k}')\">{k}</button> ")
    html_lines.append("</div>")

    # Table header
    html_lines.append("<table id='vulnTable'><thead><tr><th>Target</th><th>ID</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title / Description</th></tr></thead><tbody>")
    for r in rows:
        html_lines.append("<tr data-sev='%s'>" % r["severity"])
        html_lines.append(f"<td>{html.escape(r['target'])}</td>")
        idcell = html.escape(r['id'] or '')
        html_lines.append(f"<td>{idcell}</td>")
        html_lines.append(f"<td>{html.escape(r['pkg'] or '')}</td>")
        html_lines.append(f"<td>{html.escape(r['installed'] or '')}</td>")
        html_lines.append(f"<td>{html.escape(r['fixed'] or '')}</td>")
        html_lines.append(f"<td class='{r['severity']}'>{r['severity']}</td>")
        # Title + description + refs
        detail = ""
        if r.get("title"):
            detail += f"<strong>{html.escape(r.get('title'))}</strong><br/>"
        if r.get("desc"):
            detail += html.escape(short(r.get("desc"),800)).replace('\n','<br/>')
        if r.get("refs"):
            detail += "<div style='margin-top:8px'><em>References:</em><ul>"
            for ref in r.get("refs"):
                detail += f"<li><a href='{html.escape(ref)}' target='_blank'>{html.escape(ref)}</a></li>"
            detail += "</ul></div>"
        html_lines.append(f"<td>{detail}</td>")
        html_lines.append("</tr>")
    html_lines.append("</tbody></table>")

    # JS for filtering
    html_lines.append("""
<script>
function filter(sev){
  var rows = document.querySelectorAll('#vulnTable tbody tr');
  rows.forEach(r => {
    if(sev==='ALL'){ r.style.display=''; return; }
    var s = r.getAttribute('data-sev')||'';
    r.style.display = (s===sev) ? '' : 'none';
  });
}
</script>
""")

    html_lines.append("</body></html>")

    Path(out_path).write_text("\n".join(html_lines), encoding="utf-8")
    print("HTML report written to", out_path)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: generate_trivy_html_report.py <trivy-json> <output-html>")
        sys.exit(1)
    generate(sys.argv[1], sys.argv[2])
