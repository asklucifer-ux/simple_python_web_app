pipeline {
    agent any

    stages {

        stage('Checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/sarthak20052005/simple_python_web_app.git'
            }
        }

        stage('Install') {
            steps {
                bat '''
                    python -m venv venv
                    venv\\Scripts\\activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Test') {
            steps {
                bat '''
                    venv\\Scripts\\activate
                    pytest --maxfail=1 --disable-warnings -q
                '''
            }
        }

        stage('Security Scan') {
            steps {
                bat '''
                    echo Running Trivy scan (JSON + HTML)...
                    REM produce JSON (used by post-processing/failing logic)
                    trivy fs --severity HIGH,CRITICAL --format json --output trivy-report.json .

                    REM produce HTML using Trivy's contrib template (if available)
                    REM If your Trivy binary doesn't include @contrib/html.tpl, put a local template (e.g. trivy-html.tpl) in the repo and use --template ./trivy-html.tpl
                    trivy fs --severity HIGH,CRITICAL --format template --template "@contrib/html.tpl" --output trivy-report.html .
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'trivy-report.json, trivy-report.html', fingerprint: true
            echo "Trivy scan reports archived."

            // Fail the build manually if HIGH/CRITICAL vulnerabilities exist
            script {
                def report = readJSON file: 'trivy-report.json'
                if (!report.Results) {
                    echo "No vulnerabilities found."
                    return
                }

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
