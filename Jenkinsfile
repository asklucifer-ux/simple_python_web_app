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
                sh '''
                    python3 -m venv venv        # create virtual environment
                    . venv/bin/activate         # activate it
                    pip install --upgrade pip   # upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Test') {
            steps {
                sh '''
                    . venv/bin/activate
                    pytest --maxfail=1 --disable-warnings -q
                '''
            }
        }

        // CORRECTED stage for Trivy Security Scan
        stage('Security Scan') {
            steps {
                sh '''
                    # Scan the filesystem for vulnerabilities based on requirements.txt
                    # Fail the build if any HIGH or CRITICAL severity vulnerabilities are found.
                    trivy fs --exit-code 1 --severity HIGH,CRITICAL .

                    # Generate an HTML report using the reliable, built-in html format.
                    trivy fs --format html --output trivy-report.html .
                '''
            }
        }
    }

    // This block runs after all stages are complete
    post {
        always {
            // Archive the Trivy report so you can view it from the Jenkins build page
            echo 'Archiving reports...'
            archiveArtifacts artifacts: 'trivy-report.html', allowEmptyArchive: true
        }
    }
}