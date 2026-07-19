// =============================================================================
// Jenkinsfile — IBM Quantum Safe Explorer CI/CD
// Repo    : https://github.com/adhityaraar/qse-notebook
// Project : cryptchat-server  |  Java 17  |  Maven
// =============================================================================

pipeline {
    agent any
    triggers { pollSCM('* * * * *') }

    stages {

        stage('Detect Changes') {
            steps {
                sh '''
                    CHANGED=$(git diff --name-only HEAD~1 HEAD 2>/dev/null | grep "\\.java" || true)
                    if [ -n "$CHANGED" ]; then
                        echo "Changed Java files:"
                        echo "$CHANGED"
                    else
                        echo "No Java changes detected — running baseline scan."
                    fi
                '''
            }
        }

        stage('Build') {
            steps {
                sh '''
                    echo "=== Building cryptchat-server ==="
                    cd cryptchat-server
                    mvn clean install -DskipTests -q
                    mvn dependency:copy-dependencies -q
                    COUNT=$(find target/classes -name "*.class" 2>/dev/null | wc -l | tr -d " ")
                    echo "Compiled classes: $COUNT"
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
                    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api-docs 2>/dev/null)
                    echo "QSE tunnel status: $STATUS"
                    if [ "$STATUS" != "200" ]; then
                        echo "ERROR: Cannot reach QSE. Start IBM Quantum Safe Explorer on your Mac first."
                        exit 1
                    fi
                '''
            }
        }

        stage('QSE Scan') {
            steps {
                sh '''
                    PROJ="${WORKSPACE}/cryptchat-server"
                    CLASSPATH="${PROJ}/target/classes;${PROJ}/target/dependency"

                    # Write payload
                    cat > /tmp/qse-payload.json << PAYLOAD
{
  "extensions": [".java"],
  "rootFolderPath": "${PROJ}",
  "classFilePath": "${CLASSPATH}",
  "enableLogging": false,
  "appName": "cryptchat-server",
  "appVersion": "0.0.1-SNAPSHOT",
  "pathExclusionFilter": ["src/test"]
}
PAYLOAD

                    echo "=== Sending scan request to QSE ==="
                    cat /tmp/qse-payload.json

                    RESP=$(curl -s -X POST http://localhost:8000/api/v2/scan/scanAnalyticsProject \
                        --header "Content-Type: application/json" \
                        --data-binary @/tmp/qse-payload.json)

                    echo "QSE response: $RESP"
                    SCAN_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['scanId'])")
                    echo "Scan ID: $SCAN_ID"
                    echo "$SCAN_ID" > /tmp/qse-scan-id.txt

                    # Poll for completion
                    STATUS=""
                    N=0
                    while [ "$STATUS" != "COMPLETED" ] && [ "$STATUS" != "FAILED" ] && [ $N -lt 72 ]; do
                        sleep 5
                        SRESP=$(curl -s http://localhost:8000/api/v1/scan/${SCAN_ID}/status || echo "{}")
                        STATUS=$(echo "$SRESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
                        N=$((N+1))
                        echo "  [$N] status: $STATUS"
                    done

                    if [ "$STATUS" = "FAILED" ]; then
                        echo "QSE scan FAILED"
                        exit 1
                    fi
                    if [ $N -ge 72 ]; then
                        echo "QSE scan timed out"
                        exit 1
                    fi
                    echo "Scan COMPLETED."
                '''
            }
        }

        stage('Findings & CBOM') {
            steps {
                sh '''
                    SCAN_ID=$(cat /tmp/qse-scan-id.txt)
                    echo "Fetching results for scan: $SCAN_ID"

                    curl -s http://localhost:8000/api/v2/scan/${SCAN_ID}/list_findings > qse-findings.json
                    curl -s http://localhost:8000/api/v1/scan/${SCAN_ID}/report         > qse-summary.json
                    curl -s http://localhost:8000/api/v2/scan/${SCAN_ID}/cbom           > qse-cbom.json

                    echo "========================================"
                    echo " QSE SCAN RESULTS  (scanId: $SCAN_ID)"
                    echo "========================================"
                    python3 -c "
import json,sys
try:
    s = json.load(open('qse-summary.json'))
    print(' Total findings :', s.get('totalFindings','N/A'))
    print(' Quantum unsafe :', s.get('quantumUnsafe','N/A'))
    print(' Weak crypto    :', s.get('weakCrypto','N/A'))
except:
    print(open('qse-summary.json').read()[:300])
"
                    echo "Artifacts: qse-findings.json | qse-summary.json | qse-cbom.json"
                '''
            }
            post {
                always { archiveArtifacts artifacts: 'qse-*.json', allowEmptyArchive: true }
            }
        }
    }

    post {
        success { echo "BUILD #${BUILD_NUMBER} SUCCESS — QSE scan complete." }
        failure { echo "BUILD #${BUILD_NUMBER} FAILED — check console." }
    }
}
