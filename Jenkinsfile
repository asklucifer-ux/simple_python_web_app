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
                    echo Running Trivy scan...
                    trivy fs --severity HIGH,CRITICAL --exit-code 1 --format json --output trivy-report.json .
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'trivy-report.json', fingerprint: true
            echo "Trivy scan report archived."

            // Fail the build manually if vulnerabilities exist
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
