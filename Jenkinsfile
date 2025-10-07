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
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
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

        // FINAL stage for Trivy Security Scan
        stage('Security Scan') {
            steps {
                sh '''
                    # Specifically scan requirements.txt and output the results as a JSON file.
                    # This command will no longer fail the build immediately. The plugin will handle it.
                    trivy fs --format json --output trivy-report.json requirements.txt
                '''
            }
        }
    }

    post {
        always {
            // Use the Warnings NG plugin to parse the Trivy report and display the results.
            recordIssues(
                tools: [trivy(pattern: 'trivy-report.json')],
                failOnError: true,
                qualityGates: [
                    [threshold: 1, type: 'HIGH', unstable: false],
                    [threshold: 1, type: 'CRITICAL', unstable: false]
                ]
            )
        }
    }
}