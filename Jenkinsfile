// =============================================================================
// Jenkinsfile — IBM Quantum Safe Explorer CI/CD
// Repo    : https://github.com/adhityaraar/qse-notebook
// Project : cryptchat-server (Maven, Java 17)
//
// FLOW:
//   1. Detect if any .java file changed
//   2. Build cryptchat-server with Maven
//   3. Trigger QSE scan via REST API (http://host.containers.internal:8000)
//   4. Poll scan status until complete
//   5. Print findings — quantum-unsafe crypto visible in Jenkins console
// =============================================================================

pipeline {
    agent any

    triggers {
        pollSCM('* * * * *')
    }

    environment {
        PROJECT_DIR = "cryptchat-server"
        QSE_URL     = "http://host.containers.internal:8000"
        APP_NAME    = "cryptchat-server"
        APP_VERSION = "0.0.1-SNAPSHOT"
    }

    stages {

        stage('Check for Java Changes') {
            steps {
                script {
                    def changed = []
                    try {
                        changed = sh(
                            script: "git diff --name-only HEAD~1 HEAD 2>/dev/null || echo ''",
                            returnStdout: true
                        ).trim().split('\n').findAll { it.endsWith('.java') }
                    } catch (e) {
                        echo "First build — running full scan."
                    }
                    if (changed.size() > 0) {
                        echo "Changed Java files (${changed.size()}):"
                        changed.each { echo "  -> ${it}" }
                    } else {
                        echo "No Java changes detected — running baseline scan."
                    }
                }
            }
        }

        stage('Build') {
            steps {
                echo "=== Building cryptchat-server ==="
                sh """
                    cd ${PROJECT_DIR}
                    mvn clean install -DskipTests -q
                    mvn dependency:copy-dependencies -q
                    echo "Classes compiled: \$(find target/classes -name '*.class' 2>/dev/null | wc -l | tr -d ' ')"
                """
            }
        }

        stage('QSE Scan') {
            steps {
                script {
                    def ws       = env.WORKSPACE
                    def projPath = "${ws}/${env.PROJECT_DIR}"
                    def cp       = "${projPath}/target/classes;${projPath}/target/dependency"

                    echo "=== Triggering IBM QSE REST API scan ==="
                    echo "Path: ${projPath}"

                    def payload = """{"extensions":[".java"],"rootFolderPath":"${projPath}","classFilePath":"${cp}","enableLogging":false,"appName":"${env.APP_NAME}","appVersion":"${env.APP_VERSION}","pathExclusionFilter":["src/test"]}"""

                    def resp = sh(
                        script: "curl -sf -X POST '${env.QSE_URL}/api/v2/scan/scanAnalyticsProject' -H 'Content-Type: application/json' -d '${payload}'",
                        returnStdout: true
                    ).trim()

                    echo "QSE response: ${resp}"
                    def scanId = readJSON(text: resp).scanId
                    echo "Scan ID: ${scanId}"
                    env.QSE_SCAN_ID = scanId

                    // Poll for completion
                    def status = ""
                    def attempts = 0
                    while (!(status in ["COMPLETED","FAILED"]) && attempts < 60) {
                        sleep(time: 5, unit: 'SECONDS')
                        def s = sh(
                            script: "curl -sf '${env.QSE_URL}/api/v1/scan/${scanId}/status'",
                            returnStdout: true
                        ).trim()
                        try { status = readJSON(text: s).status ?: "" } catch(e) { status = "" }
                        echo "  [${++attempts}] status: ${status}"
                    }
                    if (status == "FAILED") error("QSE scan failed — scanId: ${scanId}")
                    if (attempts >= 60)    error("QSE scan timed out")
                    echo "Scan complete!"
                }
            }
        }

        stage('Findings Report') {
            steps {
                script {
                    def id = env.QSE_SCAN_ID

                    def findings = sh(script: "curl -sf '${env.QSE_URL}/api/v2/scan/${id}/list_findings'", returnStdout: true).trim()
                    def summary  = sh(script: "curl -sf '${env.QSE_URL}/api/v1/scan/${id}/report'",       returnStdout: true).trim()
                    def cbom     = sh(script: "curl -sf '${env.QSE_URL}/api/v2/scan/${id}/cbom'",         returnStdout: true).trim()

                    writeFile file: 'qse-findings.json', text: findings
                    writeFile file: 'qse-summary.json',  text: summary
                    writeFile file: 'qse-cbom.json',     text: cbom

                    echo "=== QSE FINDINGS SUMMARY (scanId: ${id}) ==="
                    try {
                        def s = readJSON text: summary
                        echo "Total findings : ${s.totalFindings ?: 'see qse-findings.json'}"
                        echo "Quantum unsafe : ${s.quantumUnsafe  ?: 'see qse-findings.json'}"
                    } catch(e) {
                        echo summary.take(300)
                    }
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
        success { echo "BUILD #${env.BUILD_NUMBER}: QSE scan passed. Artifacts: qse-findings.json, qse-cbom.json" }
        failure { echo "BUILD #${env.BUILD_NUMBER}: QSE scan FAILED — check console." }
    }
}
