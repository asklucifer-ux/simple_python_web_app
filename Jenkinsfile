pipeline {
  agent any

  environment {
    IMAGE_NAME = "simple_python_web_app_scan"
    IMAGE_TAG  = "jenkins"
    TRIVY_JSON = "trivy-report.json"
    TRIVY_HTML = "trivy-report.html"
  }

  stages {
    stage('Checkout') {
      steps { git branch: 'main', url: 'https://github.com/asklucifer-ux/simple_python_web_app.git' }
    }

    stage('Build Docker Image') {
      steps {
        // Build the Docker image from the repo
        bat "docker build -t %IMAGE_NAME%:%IMAGE_TAG% ."
      }
    }

    stage('Trivy: scan image') {
      steps {
        // If trivy binary exists locally use it; otherwise use the aquasec/trivy container to scan the image.
        // Windows Docker Desktop uses the named pipe mapping for image access from inside containers.
        bat '''
          where trivy >nul 2>&1
          if %errorlevel%==0 (
            echo Running local trivy CLI on image...
            trivy image --format json --output %TRIVY_JSON% %IMAGE_NAME%:%IMAGE_TAG%
          ) else (
            echo Local trivy not installed — using aquasec/trivy container (requires Docker)...
            docker run --rm -v //./pipe/docker_engine://./pipe/docker_engine -v "%cd%":/report -w /report aquasec/trivy:latest image --format json --output /report/%TRIVY_JSON% %IMAGE_NAME%:%IMAGE_TAG%
          )
        '''
      }
    }

    stage('Generate HTML report') {
      steps {
        // Runs python script in-place to convert JSON -> HTML
        // ensure Python is available to Jenkins (we set this up earlier)
        bat 'python generate_trivy_html_report.py %TRIVY_JSON% %TRIVY_HTML%'
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: "${TRIVY_JSON}, ${TRIVY_HTML}", fingerprint: true
      echo "Artifacts archived: ${TRIVY_JSON}, ${TRIVY_HTML}"
      script {
        // read and fail on HIGH/CRITICAL
        def txt = readFile(file: "${TRIVY_JSON}")
        def json = new groovy.json.JsonSlurper().parseText(txt)
        def highCritical = 0
        json.Results?.each { r -> (r.Vulnerabilities ?: []).each { v -> if ((v.Severity?:'').toUpperCase() in ['HIGH','CRITICAL']) highCritical++ } }
        if (highCritical > 0) { error("Found ${highCritical} HIGH/CRITICAL vulnerabilities") }
        else { echo "No HIGH/CRITICAL vulnerabilities found." }
      }
    }
  }
}
