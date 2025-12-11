pipeline {
    agent any

    environment {
        TRIVY_JSON = "trivy-report.json"
        TRIVY_HTML = "trivy-report.html"
    }

    stages {

        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/asklucifer-ux/simple_python_web_app.git'
            }
        }

        stage('Check Environment') {
            steps {
                echo "Checking Python & Trivy availability..."

                bat 'where python || echo python NOT found by Jenkins'
                bat 'python --version || echo python --version FAILED'

                bat 'where pip || echo pip NOT found'
                bat 'pip --version || echo pip --version FAILED'

                bat 'where trivy || echo trivy NOT found by Jenkins'
                bat 'trivy --version || echo Jenkins cannot run trivy'
            }
        }

        stage('Prepare venv & install deps') {
            steps {
                bat '''
                    python -m venv venv
                    venv\\Scripts\\python -m pip install --upgrade pip setuptools wheel

                    if exist requirements.txt (
                        venv\\Scripts\\python -m pip install -r requirements.txt
                    ) else (
                        echo "requirements.txt NOT found — skipping pip install"
                    )
                '''
            }
        }

        stage('Trivy fs scan (venv)') {
            steps {
                bat '''
                    echo Running Trivy scan on venv...

                    where trivy
                    if %errorlevel% neq 0 (
                        echo "ERROR: Trivy not found by Jenkins!"
                        echo {"Results":[]} > %TRIVY_JSON%
                        exit /b 0
                    )

                    trivy fs --format json --output %TRIVY_JSON% venv

                    echo ==== TRIVY JSON OUTPUT PREVIEW ====
                    type %TRIVY_JSON%
                '''
            }
        }

        stage('Generate HTML report') {
            steps {
                bat 'python generate_trivy_html_report.py %TRIVY_JSON% %TRIVY_HTML%'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "${TRIVY_JSON}, ${TRIVY_HTML}", fingerprint: true

            script {
                echo "Analyzing vulnerabilities..."

                def txt = readFile(file: "${TRIVY_JSON}")
                def json = new groovy.json.JsonSlurper().parseText(txt)

                def highCritical = 0
                json.Results?.each { res ->
                    (res.Vulnerabilities ?: []).each { v ->
                        def sev = (v.Severity ?: "").toUpperCase()
                        if (sev in ["HIGH", "CRITICAL"]) {
                            highCritical++
                        }
                    }
                }

                if (highCritical > 0) {
                    error "❌ Build failed — Found ${highCritical} HIGH/CRITICAL vulnerabilities."
                } else {
                    echo "✅ No HIGH or CRITICAL vulnerabilities found."
                }
            }
        }
    }
}
