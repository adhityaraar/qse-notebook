// =============================================================================
// Jenkinsfile — IBM Quantum Safe Explorer CI/CD
// Repo    : https://github.com/adhityaraar/qse-notebook
// Project : cryptchat-server (Maven, Java 17)
//
// FLOW:
//   1. Detect changed .java files vs previous commit
//   2. Build cryptchat-server with Maven
//   3. Tunnel to QSE (socat localhost:8000 -> qse-host:8000)
//   4. Trigger QSE REST API scan, poll until complete
//   5. Fetch findings + CBOM + summary → archive as build artifacts
// =============================================================================

pipeline {
    agent any

    // Poll GitHub every minute — triggers new build when .java files change
    triggers {
        pollSCM('* * * * *')
    }

    environment {
        PROJECT_DIR = "cryptchat-server"
        QSE_URL     = "http://localhost:8000"
        APP_NAME    = "cryptchat-server"
        APP_VERSION = "0.0.1-SNAPSHOT"
    }

    stages {

        // -----------------------------------------------------------------
        // Stage 1: Show which Java files changed
        // -----------------------------------------------------------------
        stage('Detect Changes') {
            steps {
                script {
                    def changed = []
                    try {
                        changed = sh(
                            script: "git diff --name-only HEAD~1 HEAD 2>/dev/null | grep '\\.java' || true",
                            returnStdout: true
                        ).trim().split('\n').findAll { it }
                    } catch (e) { /* first run */ }

                    if (changed) {
                        echo "Changed Java files (${changed.size()}):"
                        changed.each { echo "  -> ${it}" }
                    } else {
                        echo "No Java changes since last commit (running baseline scan)."
                    }
                }
            }
        }

        // -----------------------------------------------------------------
        // Stage 2: Build with Maven
        // -----------------------------------------------------------------
        stage('Build') {
            steps {
                sh """
                    echo '=== Building ${PROJECT_DIR} ==='
                    cd ${PROJECT_DIR}
                    mvn clean install -DskipTests -q
                    mvn dependency:copy-dependencies -q
                    echo "Classes: \$(find target/classes -name '*.class' 2>/dev/null | wc -l | tr -d ' ')"
                """
            }
        }

        // -----------------------------------------------------------------
        // Stage 3: Start QSE tunnel (socat localhost:8000 -> qse-host:8000)
        // This lets the container reach QSE as if from localhost,
        // bypassing QSE's Spring Security localhost-only restriction.
        // -----------------------------------------------------------------
        stage('Start QSE Tunnel') {
            steps {
                sh """
                    # Kill any existing socat on port 8000
                    pkill -f 'socat.*8000' 2>/dev/null || true
                    sleep 1
                    # Start fresh tunnel in background
                    nohup socat TCP-LISTEN:8000,fork,reuseaddr TCP:qse-host:8000 &>/dev/null &
                    sleep 2
                    # Verify tunnel is alive
                    STATUS=\$(curl -sf -o /dev/null -w '%{http_code}' http://localhost:8000/api-docs 2>/dev/null || echo '000')
                    echo "QSE tunnel status: \$STATUS"
                    if [ "\$STATUS" != "200" ]; then
                        echo "ERROR: Cannot reach QSE at localhost:8000 — is IBM Quantum Safe Explorer running on your Mac?"
                        exit 1
                    fi
                """
            }
        }

        // -----------------------------------------------------------------
        // Stage 4: Trigger QSE scan via REST API
        // -----------------------------------------------------------------
        stage('QSE Scan') {
            steps {
                script {
                    def projPath = "${env.WORKSPACE}/${env.PROJECT_DIR}"
                    def cp       = "${projPath}/target/classes;${projPath}/target/dependency"

                    echo "=== Triggering QSE scan ==="
                    echo "Project : ${projPath}"

                    // POST scan request
                    def payload = '{"extensions":[".java"]' +
                        ',"rootFolderPath":"' + projPath + '"' +
                        ',"classFilePath":"'  + cp + '"' +
                        ',"enableLogging":false' +
                        ',"appName":"' + env.APP_NAME + '"' +
                        ',"appVersion":"' + env.APP_VERSION + '"' +
                        ',"pathExclusionFilter":["src/test"]}'

                    def resp = sh(
                        script: "curl -sf -X POST '${env.QSE_URL}/api/v2/scan/scanAnalyticsProject' -H 'Content-Type: application/json' -d '${payload}'",
                        returnStdout: true
                    ).trim()

                    echo "QSE response: ${resp}"
                    def scanId = readJSON(text: resp).scanId
                    echo "Scan ID: ${scanId}"
                    env.QSE_SCAN_ID = scanId

                    // Poll for COMPLETED
                    def status = ""
                    def n = 0
                    while (!(status in ["COMPLETED","FAILED"]) && n < 72) {
                        sleep(time: 5, unit: 'SECONDS')
                        def s = sh(script: "curl -sf '${env.QSE_URL}/api/v1/scan/${scanId}/status'", returnStdout: true).trim()
                        try { status = readJSON(text: s).status ?: "" } catch(e) { status = "" }
                        n++
                        echo "  [${n}] status: ${status}"
                    }
                    if (status == "FAILED") error("QSE scan FAILED — scanId: ${scanId}")
                    if (n >= 72)           error("QSE scan timed out after 6 minutes")
                    echo "Scan COMPLETED."
                }
            }
        }

        // -----------------------------------------------------------------
        // Stage 5: Fetch and archive findings
        // -----------------------------------------------------------------
        stage('Findings & CBOM') {
            steps {
                script {
                    def id  = env.QSE_SCAN_ID
                    def url = env.QSE_URL

                    def findings = sh(script: "curl -sf '${url}/api/v2/scan/${id}/list_findings'", returnStdout: true).trim()
                    def summary  = sh(script: "curl -sf '${url}/api/v1/scan/${id}/report'",        returnStdout: true).trim()
                    def cbom     = sh(script: "curl -sf '${url}/api/v2/scan/${id}/cbom'",          returnStdout: true).trim()

                    writeFile file: 'qse-findings.json', text: findings
                    writeFile file: 'qse-summary.json',  text: summary
                    writeFile file: 'qse-cbom.json',     text: cbom

                    // Print summary to console
                    echo "========================================"
                    echo " QSE SCAN RESULTS  (scanId: ${id})"
                    echo "========================================"
                    try {
                        def s = readJSON text: summary
                        echo " Total findings : ${s.totalFindings ?: 'N/A'}"
                        echo " Quantum unsafe : ${s.quantumUnsafe  ?: 'N/A'}"
                        echo " Weak crypto    : ${s.weakCrypto     ?: 'N/A'}"
                    } catch(e) {
                        echo summary.take(500)
                    }
                    echo "Artifacts: qse-findings.json, qse-summary.json, qse-cbom.json"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'qse-*.json', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        success {
            echo "BUILD #${env.BUILD_NUMBER} PASSED — QSE scan complete. Check archived qse-findings.json for crypto posture."
        }
        failure {
            echo "BUILD #${env.BUILD_NUMBER} FAILED — check console output."
        }
    }
}
