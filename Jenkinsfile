// =============================================================================
// Jenkinsfile — IBM Quantum Safe Explorer CI/CD
// Repo    : https://github.com/adhityaraar/qse-notebook
// Project : cryptchat-server (Maven, Java 17)
// =============================================================================

pipeline {
    agent any

    triggers { pollSCM('* * * * *') }

    environment {
        PROJECT_DIR = "cryptchat-server"
        QSE_URL     = "http://localhost:8000"
        APP_NAME    = "cryptchat-server"
        APP_VERSION = "0.0.1-SNAPSHOT"
    }

    stages {

        stage('Detect Changes') {
            steps {
                script {
                    def changed = sh(
                        script: "git diff --name-only HEAD~1 HEAD 2>/dev/null | grep '\\.java' || true",
                        returnStdout: true
                    ).trim()
                    echo changed ? "Changed Java files:\n${changed}" : "No Java changes (running baseline scan)."
                }
            }
        }

        stage('Build') {
            steps {
                sh '''
                    echo "=== Building cryptchat-server ==="
                    cd cryptchat-server
                    mvn clean install -DskipTests -q
                    mvn dependency:copy-dependencies -q
                    echo "Classes: $(find target/classes -name '*.class' 2>/dev/null | wc -l | tr -d ' ')"
                '''
            }
        }

        stage('Start QSE Tunnel') {
            steps {
                sh '''
                    pkill -f "socat.*8000" 2>/dev/null || true
                    sleep 1
                    nohup socat TCP-LISTEN:8000,fork,reuseaddr TCP:qse-host:8000 >/dev/null 2>&1 &
                    sleep 2
                    STATUS=$(curl -sf -o /dev/null -w '%{http_code}' http://localhost:8000/api-docs 2>/dev/null || echo 000)
                    echo "QSE tunnel: $STATUS"
                    [ "$STATUS" = "200" ] || { echo "ERROR: QSE not reachable — start IBM Quantum Safe Explorer on your Mac first."; exit 1; }
                '''
            }
        }

        stage('QSE Scan') {
            steps {
                script {
                    def projPath = "${env.WORKSPACE}/${env.PROJECT_DIR}"
                    def cp       = "${projPath}/target/classes;${projPath}/target/dependency"

                    echo "=== Triggering QSE scan: ${projPath} ==="

                    // Write payload to a temp file to avoid quoting issues
                    def payload = """{
  "extensions": [".java"],
  "rootFolderPath": "${projPath}",
  "classFilePath": "${cp}",
  "enableLogging": false,
  "appName": "${env.APP_NAME}",
  "appVersion": "${env.APP_VERSION}",
  "pathExclusionFilter": ["src/test"]
}"""
                    writeFile file: '/tmp/qse-payload.json', text: payload

                    def resp = sh(
                        script: "curl -sf -X POST '${env.QSE_URL}/api/v2/scan/scanAnalyticsProject' -H 'Content-Type: application/json' -d @/tmp/qse-payload.json",
                        returnStdout: true
                    ).trim()

                    echo "QSE response: ${resp}"
                    def scanId = readJSON(text: resp).scanId
                    echo "Scan ID: ${scanId}"
                    env.QSE_SCAN_ID = scanId

                    // Poll until COMPLETED
                    def status = "", n = 0
                    while (!(status in ["COMPLETED","FAILED"]) && n < 72) {
                        sleep(time: 5, unit: 'SECONDS')
                        def s = sh(script: "curl -sf '${env.QSE_URL}/api/v1/scan/${scanId}/status' || echo '{}'", returnStdout: true).trim()
                        try { status = readJSON(text: s).status ?: "" } catch(e) { status = "" }
                        n++
                        echo "  [${n}] status: ${status}"
                    }
                    if (status == "FAILED") error("QSE scan FAILED — scanId: ${scanId}")
                    if (n >= 72)           error("QSE scan timed out after 6 min")
                }
            }
        }

        stage('Findings & CBOM') {
            steps {
                script {
                    def id  = env.QSE_SCAN_ID
                    def url = env.QSE_URL

                    def findings = sh(script: "curl -sf '${url}/api/v2/scan/${id}/list_findings' || echo '{}'", returnStdout: true).trim()
                    def summary  = sh(script: "curl -sf '${url}/api/v1/scan/${id}/report' || echo '{}'",        returnStdout: true).trim()
                    def cbom     = sh(script: "curl -sf '${url}/api/v2/scan/${id}/cbom' || echo '{}'",          returnStdout: true).trim()

                    writeFile file: 'qse-findings.json', text: findings
                    writeFile file: 'qse-summary.json',  text: summary
                    writeFile file: 'qse-cbom.json',     text: cbom

                    echo "========================================"
                    echo " QSE SCAN RESULTS  (scanId: ${id})"
                    echo "========================================"
                    try {
                        def s = readJSON text: summary
                        echo " Total findings : ${s.totalFindings ?: 'see qse-findings.json'}"
                        echo " Quantum unsafe : ${s.quantumUnsafe  ?: 'see qse-findings.json'}"
                        echo " Weak crypto    : ${s.weakCrypto     ?: 'see qse-findings.json'}"
                    } catch(e) {
                        echo summary.take(500)
                    }
                    echo "Artifacts archived: qse-findings.json | qse-summary.json | qse-cbom.json"
                }
            }
            post {
                always { archiveArtifacts artifacts: 'qse-*.json', allowEmptyArchive: true }
            }
        }
    }

    post {
        success { echo "BUILD #${env.BUILD_NUMBER} SUCCESS — QSE scan complete. Review qse-findings.json for crypto posture." }
        failure { echo "BUILD #${env.BUILD_NUMBER} FAILED — check console output above." }
    }
}
