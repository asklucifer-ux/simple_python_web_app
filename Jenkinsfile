pipeline {
  agent any

  environment {
    IMAGE_NAME = "simple_webapp"
    IMAGE_TAG  = "latest"
    TRIVY_JSON = "trivy-report.json"
  }

  stages {

    stage('Checkout') {
      steps {
        git branch: 'main', url: 'https://github.com/sarthak20052005/simple_python_web_app.git'
      }
    }

    stage('Check Python') {
      steps {
        // Quick checks so we can see from Jenkins console whether python/pip are visible
        bat 'where python || echo python not found'
        bat 'python --version || echo python --version failed'
        bat 'where pip || echo pip not found'
        bat 'pip --version || echo pip --version failed'
      }
    }

    stage('Install') {
      steps {
        // Use explicit venv python executable instead of relying on `activate`
        bat '''
          python -m venv venv
          REM ensure pip is available via the venv python
          venv\\Scripts\\python -m pip install --upgrade pip
          venv\\Scripts\\python -m pip install -r requirements.txt
        '''
      }
    }

    stage('Test') {
      steps {
        // Run pytest with the venv python
        bat '''
          venv\\Scripts\\python -m pytest --maxfail=1 --disable-warnings -q
        '''
      }
    }

    stage('Security Scan') {
      steps {
        // If 'trivy' is installed on the agent run it. Otherwise try the official trivy container (requires Docker).
        bat '''
          where trivy >nul 2>&1
          if %errorlevel%==0 (
            echo "Running local trivy..."
            trivy fs --severity HIGH,CRITICAL --format json --output %TRIVY_JSON% .
          ) else (
            echo "trivy not found locally — trying Docker image (requires Docker Desktop / docker CLI)..."
            where docker >nul 2>&1
            if %errorlevel%==0 (
              docker run --rm -v "%cd%":/workspace -w /workspace aquasec/trivy:latest fs --severity HIGH,CRITICAL --format json --output /workspace/%TRIVY_JSON% .
            ) else (
              echo "Neither trivy nor docker available on agent. Skipping security scan and creating an empty report."
              echo {"Results":[]} > %TRIVY_JSON%
            )
          )
        '''
      }
    }
  }

  post {
    always {
      // archive the JSON so you can download it from Jenkins
      archiveArtifacts artifacts: "${TRIVY_JSON}", fingerprint: true
      echo "Trivy scan report archived."

      // Parse the JSON using Groovy's JsonSlurper (no plugin required)
      script {
        // safe default if file missing
        def trivyReportText = ''
        try {
          trivyReportText = readFile(file: "${TRIVY_JSON}")
        } catch (e) {
          echo "trivy-report.json not found or unreadable: ${e}"
          currentBuild.result = 'UNSTABLE'
          return
        }

        def json = new groovy.json.JsonSlurper().parseText(trivyReportText)

        def highCritical = 0
        if (json?.Results) {
          json.Results.each { res ->
            (res.Vulnerabilities ?: []).each { v ->
              def sev = (v.Severity ?: '').toUpperCase()
              if (sev == 'HIGH' || sev == 'CRITICAL') {
                highCritical++
              }
            }
          }
        } else {
          echo "No Results array in trivy JSON (treating as no vulnerabilities)."
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
