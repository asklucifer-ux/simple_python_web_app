{{- /* Minimal Trivy HTML template — tweak styling as you like */ -}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Trivy Report - {{ .ArtifactName }}</title>
  <style>
    body{font-family: Arial, Helvetica, sans-serif; padding:20px}
    h1{font-size:20px}
    table{border-collapse:collapse; width:100%}
    th,td{border:1px solid #ddd; padding:8px; text-align:left}
    th{background:#f2f2f2}
    .severity-CRITICAL{background:#ffcccc}
    .severity-HIGH{background:#ffe6cc}
    .severity-MEDIUM{background:#fff2cc}
    .severity-LOW{background:#e6ffcc}
  </style>
</head>
<body>
  <h1>Trivy Report — {{ .ArtifactName }}</h1>
  <p>Scan time: {{ .GeneratedAt }}</p>

  {{ range .Results }}
    <h2>Target: {{ .Target }}</h2>
    {{ if .Vulnerabilities }}
      <table>
        <thead><tr><th>VulnerabilityID</th><th>Pkg</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr></thead>
        <tbody>
        {{ range .Vulnerabilities }}
          <tr class="severity-{{ .Severity }}">
            <td>{{ .VulnerabilityID }}</td>
            <td>{{ .PkgName }}</td>
            <td>{{ .InstalledVersion }}</td>
            <td>{{ .FixedVersion }}</td>
            <td>{{ .Severity }}</td>
            <td>{{ .Title }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
    {{ else }}
      <p>No vulnerabilities found for this target.</p>
    {{ end }}
  {{ end }}

</body>
</html>
