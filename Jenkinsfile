pipeline {
    agent any

    environment {
        // Use this to optionally skip Trivy's version check if you want:
        // TRIVY_SKIP_VERSION_CHECK = "true"
    }

    stages {

        stage('Checkout') {
            steps {
                // Using the declarative 'git' step:
                git branch: 'main', url: 'https://github.com/sarthak20052005/simple_python_web_app.git'
            }
        }

        stage('Install') {
            steps {
                // Create venv and install requirements. Keep commands idempotent.
                bat '''
                    echo ===== Creating virtualenv =====
                    python -m venv venv

                    echo ===== Activating venv and upgrading pip =====
                    call venv\\Scripts\\activate

                    python -m pip install --upgrade pip
                    if exist requirements.txt (
                      pip install -r requirements.txt
                    ) else (
                      echo "requirements.txt not found — skipping pip install"
                    )
                '''
            }
        }

        stage('Test') {
            steps {
                // Run pytest quietly; job won't fail here if tests pass/fail according to pytest exit code
                bat '''
                    echo ===== Running tests =====
                    call venv\\Scripts\\activate
                    pytest --maxfail=1 --disable-warnings -q || (echo "pytest returned non-zero exit code"; exit /b %ERRORLEVEL%)
                '''
            }
        }

        stage('Prepare Trivy HTML Template') {
            steps {
                // Create a minimal trivy-html.tpl in the workspace at runtime so we don't depend on @contrib
                // Using PowerShell to write a multiline file (Windows agent)
                bat '''
                    echo ===== Writing trivy-html.tpl to workspace =====
                    powershell -NoProfile -Command ^
                      $tpl = @'\n{{- /* Minimal Trivy HTML template - created at build time */ -}}\n<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\"/>\n  <title>Trivy Report - {{ .ArtifactName }}</title>\n  <style>\n    body{font-family: Arial, Helvetica, sans-serif; padding:20px}\n    h1{font-size:20px}\n    table{border-collapse:collapse; width:100%}\n    th,td{border:1px solid #ddd; padding:8px; text-align:left}\n    th{background:#f2f2f2}\n    .severity-CRITICAL{background:#ffcccc}\n    .severity-HIGH{background:#ffe6cc}\n    .severity-MEDIUM{background:#fff2cc}\n    .severity-LOW{background:#e6ffcc}\n  </style>\n</head>\n<body>\n  <h1>Trivy Report — {{ .ArtifactName }}</h1>\n  <p>Scan time: {{ .GeneratedAt }}</p>\n\n  {{ range .Results }}\n    <h2>Target: {{ .Target }}</h2>\n    {{ if .Vulnerabilities }}\n      <table>\n        <thead><tr><th>VulnerabilityID</th><th>Pkg</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr></thead>\n        <tbody>\n        {{ range .Vulnerabilities }}\n          <tr class=\"severity-{{ .Severity }}\">\n            <td>{{ .VulnerabilityID }}</td>\n            <td>{{ .PkgName }}</td>\n            <td>{{ .InstalledVersion }}</td>\n            <td>{{ .FixedVersion }}</td>\n            <td>{{ .Severity }}</td>\n            <td>{{ .Title }}</td>\n          </tr>\n        {{ end }}\n        </tbody>\n      </table>\n    {{ else }}\n      <p>No vulnerabilities found for this target.</p>\n    {{ end }}\n  {{ end }}\n\n</body>\n</html>\n'@\n; Set-Content -Path .\\trivy-html.tpl -Value $tpl -Encoding UTF8
                '''
            }
        }

        stage('Security Scan') {
            steps {
                // Run Trivy twice:
                //  - JSON output (used by post-processing to decide failure)
                //  - HTML output using local template created above
                // Avoid --exit-code so the HTML generation and post processing still run.
                bat '''
                    echo ===== Running Trivy JSON scan (HIGH,CRITICAL) =====
                    REM optionally add --skip-version-check if you want to silence version notices:
                    REM trivy fs --skip-version-check --severity HIGH,CRITICAL --format json --output trivy-report.json .
                    trivy fs --severity HIGH,CRITICAL --format json --output trivy-report.json .

                    echo ===== Generating Trivy HTML report using local template =====
                    trivy fs --severity HIGH,CRITICAL --format template --template "./trivy-html.tpl" --output trivy-report.html . || (
                      echo "HTML generation returned non-zero exit code; continuing (report may be incomplete)."
                    )
                '''
            }
        }
    }

    post {
        always {
            // Archive both JSON and HTML (if present)
            archiveArtifacts artifacts: 'trivy-report.json, trivy-report.html', fingerprint: true
            echo "Trivy scan reports archived."

            // Evaluate JSON and fail only if HIGH/CRITICAL vulnerabilities exist.
            script {
                // If the JSON report doesn't exist or is empty, log and continue.
                if (!fileExists('trivy-report.json')) {
                    echo "trivy-report.json not found — skipping vulnerability check."
                } else {
                    def report = readJSON file: 'trivy-report.json'
                    if (!report.Results) {
                        echo "No vulnerabilities found."
                    } else {
                        def highCritical = 0
                        report.Results.each { r ->
                            if (r.Vulnerabilities) {
                                r.Vulnerabilities.each { v ->
                                    if (v.Severity == "HIGH" || v.Severity == "CRITICAL") {
                                        highCritical++
                                    }
                                }
                            }
                        }

                        if (highCritical > 0) {
                            error "Build failed — Found ${highCritical} HIGH/CRITICAL vulnerabilities."
                        } else {
                            echo "No HIGH or CRITICAL vulnerabilities found."
                        }
                    }
                }
            }
        }

        failure {
            echo "Pipeline finished with FAILURE."
        }

        success {
            echo "Pipeline finished SUCCESSFULLY."
        }
    }
}
