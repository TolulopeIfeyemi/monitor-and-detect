"""
Unified anomaly detection monitor.

Merges two feature streams:
  - Container-level  : docker stats / docker exec / docker logs (per-container view)
  - Host-level       : /proc/stat, /proc/vmstat, tracked host processes (full-system view)

Container-only monitoring is blind to cgroup escape attacks because the escaped
work runs outside the container's cgroup — docker stats stays near the quota
while the host absorbs the real cost.  The host feature stream closes that gap.
"""

import subprocess
import time
import pandas as pd
from sklearn.ensemble import IsolationForest

from cve_detector import detect_cve_patterns, format_cve_alert
from host_monitor import HostMonitor

# ==============================
# CONFIG
# ==============================
CONTAINER_NAME = "dvwa"
TRAINING_ROUNDS = 25  # Reduced for faster startup
DETECTION_INTERVAL = 1  # Faster detection
CVE_DETECTION_THRESHOLD = 1  # Lower threshold for better sensitivity

# Thresholds that immediately force anomaly regardless of IsolationForest score
# Container-level hard limits
CONTAINER_HARD = {
    "webshell_files":       5,
    "command_injection":    3,
    "privilege_escalation": 2,
    "total_processes":     20,
}
# Host-level hard limits (cgroup escape signals)
HOST_HARD = {
    "coredump_helper_cpu":   30.0,   # Case 1: apport/systemd-coredump eating >30% of a core
    "coredump_helper_active": 1,     # Case 1: helper process present at all
    "host_iowait_pct":       40.0,   # Case 2: heavy global writeback stalling victim
    "dirty_pages":         5000,     # Case 2: large dirty page backlog
    "writeback_rate_pages_s": 10000, # Case 2: writeback rate surge
    "proc_systemd_journald_cpu": 5.0,   # Case 3: journald CPU spike
    "journald_write_rate_kb_s": 200.0,  # Case 3: journald flushing at high rate
    "engine_overhead_cpu":   80.0,   # Case 4: dockerd+containerd+kworker overhead
    "cpu_divergence":        80.0,   # Cases 1/4: host CPU >> sum of container quotas
    "softirq_composite":     30.0,   # Case 5: host softirq + ksoftirqd
    "host_softirq_pct":      20.0,   # Case 5: raw softirq column from /proc/stat
}


# ==============================
# STEP 1: Container data capture
# ==============================
def capture_container(duration=1):
    """Poll the target container via docker CLI and return a raw log string."""
    cmds = {
        "stats": [
            "docker", "stats", CONTAINER_NAME, "--no-stream", "--format",
            "table {{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"
        ],
        "logs": [
            "docker", "logs", CONTAINER_NAME, "--tail", "100", "--since", f"{duration*2}s"
        ],
        "ps": [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "ps auxww && netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || true"
        ],
        "find": [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c",
            "find /tmp -name '*.php' -o -name '*.sh' -o -name '*shell*' 2>/dev/null; "
            "find /var/log /var/www -type f -newer /proc/uptime 2>/dev/null | head -10 || true"
        ],
        "net": [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "cat /proc/net/tcp /proc/net/udp 2>/dev/null | wc -l || echo 0"
        ],
        "procs": [
            "docker", "exec", CONTAINER_NAME, "sh", "-c", "ps aux | wc -l"
        ],
        "attack": [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c",
            "ls -la /tmp/*.php /tmp/*.sh 2>/dev/null | wc -l; "
            "ps aux | grep -E '(shell|php|eval|system)' | wc -l"
        ],
    }

    parts = []
    proc_count = "0"
    for key, cmd in cmds.items():
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            out = (r.stdout + r.stderr).lower()
            if key == "procs":
                proc_count = r.stdout.strip()
            parts.append(out)
        except Exception:
            parts.append("")

    log = " ".join(parts) + f" processes:{proc_count}"
    print("RAW (container):", log[:200])
    return log


# ==============================
# STEP 2: Feature extraction
# ==============================
def extract_container_features(log):
    """Extract container-level numeric features from the combined docker log string."""
    proc_count = 0
    for line in log.split("\n"):
        if "processes:" in line:
            try:
                proc_count = int(line.split("processes:")[1].strip())
            except ValueError:
                pass

    def cnt(*words):
        return sum(log.count(w) for w in words)

    return {
        "total_processes":      proc_count,
        "apache_processes":     cnt("apache", "httpd"),
        "php_processes":        cnt("php"),
        "mysql_processes":      cnt("mysql", "mariadb"),
        "shell_processes":      cnt("/bin/sh", "/bin/bash", "dash"),
        "root_shells":          log.count("root") * (log.count("bash") + log.count("sh")),
        "suspicious_commands":  cnt("whoami", "id ", "uname", "cat /etc/passwd"),
        "error_logs":           cnt("error", "warning", "fail"),
        "access_logs":          cnt("get ", "post ", "request"),
        "login_attempts":       cnt("login", "password", "auth"),
        "file_changes":         cnt("/var/log", "/tmp", "/var/www"),
        "tmp_files":            log.count("/tmp/"),
        "log_files":            log.count("/var/log/"),
        "network_connections":  cnt("established", "listen", "tcp", "udp"),
        "network_activity":     cnt(":80", ":443", ":22"),
        "high_cpu": int(any(
            w.endswith("%") and "." in w and float(w[:-1]) > 1.0
            for w in log.split()
        )),
        "memory_usage":         cnt("mib", "gib"),
        "pid_count":            log.count("pid"),
        "webshell_files":       cnt(".php", "shell", "webshell", "backdoor"),
        "command_injection":    cnt("system", "exec", "eval", "`;", "&&", "<?php"),
        "privilege_escalation": cnt("sudo", "su ", "chmod +s", "whoami", "/etc/passwd"),
        "reconnaissance":       cnt("nmap", "netstat", "ps aux", "find /", "uname", "id "),
        "cve_patterns":         cnt("cat /etc/passwd", "jndi:", "ldap://", "<?php system"),
    }


# ==============================
# STEP 3: Build baseline model
# ==============================
def train_model(host_mon):
    print("[+] Training baseline model on clean behaviour...")
    data = []
    cve_scores_during_training = {}  # cve_id -> max score seen during training

    for i in range(TRAINING_ROUNDS):
        container_log      = capture_container(duration=1)
        container_features = extract_container_features(container_log)
        host_features      = host_mon.collect()
        merged = {**container_features, **host_features}
        data.append(merged)

        # Record which CVEs score during clean baseline so we can suppress them later
        for match in detect_cve_patterns(container_log, container_features, host_features):
            cid = match["cve_id"]
            cve_scores_during_training[cid] = max(
                cve_scores_during_training.get(cid, 0), match["score"]
            )

        print(f"[TRAIN] {i+1}/{TRAINING_ROUNDS}: divergence={host_features['cpu_divergence']:.1f}% "
              f"softirq={host_features['host_softirq_pct']:.1f}%")
        time.sleep(1)

    df    = pd.DataFrame(data)
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df)

    if cve_scores_during_training:
        print(f"[+] Baseline CVEs suppressed (seen during training): "
              f"{', '.join(cve_scores_during_training.keys())}")
    print("[+] Baseline established.\n")
    return model, list(df.columns), cve_scores_during_training


# ==============================
# STEP 4: Detection loop
# ==============================
def _check_hard_thresholds(container_f, host_f):
    """
    Return (triggered, reason) if any hard threshold is exceeded.
    These fire immediately without waiting for IsolationForest.
    """
    for key, limit in CONTAINER_HARD.items():
        if container_f.get(key, 0) >= limit:
            return True, f"container:{key}={container_f[key]} >= {limit}"

    for key, limit in HOST_HARD.items():
        val = host_f.get(key, 0)
        if val >= limit:
            return True, f"host:{key}={val:.2f} >= {limit}"

    return False, ""


def _classify_escape_case(host_f):
    """
    Heuristic: given elevated host features, name which cgroup escape case is most likely.
    Returns a short string label, or "" if none match.
    """
    # Check specific process signals first — they are unambiguous
    # iowait is checked last for Case 2 because it is a side-effect of Case 3 too
    if host_f.get("coredump_helper_cpu", 0) > 10 or host_f.get("coredump_helper_active", 0):
        return "CASE-1 (exception/coredump helper)"
    if (host_f.get("proc_systemd_journald_cpu", 0) > 3
            or host_f.get("journald_write_rate_kb_s", 0) > 150
            or host_f.get("proc_auditd_cpu", 0) > 2):
        return "CASE-3 (journald amplification)"
    if host_f.get("engine_overhead_cpu", 0) > 18 or host_f.get("proc_dockerd_cpu", 0) > 8:
        return "CASE-4 (container engine / TTY)"
    if host_f.get("softirq_composite", 0) > 15 or host_f.get("host_softirq_pct", 0) > 10:
        return "CASE-5 (NET softirq / iptables)"
    if host_f.get("host_iowait_pct", 0) > 25 or host_f.get("dirty_pages", 0) > 3000:
        # Case 4 TTY flood also generates dirty pages via the TTY line discipline,
        # but iowait stays near 0. True Case 2 always has elevated iowait.
        if host_f.get("engine_overhead_cpu", 0) > 18 and host_f.get("host_iowait_pct", 0) < 5:
            return "CASE-4 (container engine / TTY)"
        return "CASE-2 (data sync / RFA writeback)"
    return ""


def _filter_cves(matches, baseline_scores):
    """
    Drop CVEs whose score is not meaningfully above their baseline training score.
    A CVE seen during training at score=6 will only alert if score reaches 10+.
    Houdini host-level cases are never in the baseline so they always pass through.
    """
    filtered = []
    for m in matches:
        baseline = baseline_scores.get(m["cve_id"], 0)
        # Require score to exceed baseline by at least 4 points (2 new pattern hits)
        if m["score"] >= baseline + 4 or baseline == 0:
            filtered.append(m)
    return filtered


def detect(model, columns, host_mon, baseline_scores):
    print("[+] Starting real-time detection (container + host)...\n")

    while True:
        container_log = capture_container(duration=1)
        container_f   = extract_container_features(container_log)
        host_f        = host_mon.collect()
        merged        = {**container_f, **host_f}

        # Align columns to what the model was trained on
        df = pd.DataFrame([merged]).reindex(columns=columns, fill_value=0)
        prediction = model.predict(df)[0]

        # Print compact host snapshot
        print(
            f"[HOST] divergence={host_f['cpu_divergence']:.1f}%  "
            f"softirq={host_f['host_softirq_pct']:.1f}%  "
            f"iowait={host_f['host_iowait_pct']:.1f}%  "
            f"dirty_pages={host_f['dirty_pages']}  "
            f"engine_overhead={host_f['engine_overhead_cpu']:.1f}%  "
            f"coredump_helper={host_f['coredump_helper_cpu']:.1f}%"
        )

        hard_hit, hard_reason = _check_hard_thresholds(container_f, host_f)
        if hard_hit:
            prediction = -1
            print(f"[FORCED-ANOMALY] Hard threshold: {hard_reason}")

        if prediction == -1:
            escape_case = _classify_escape_case(host_f)
            cves = _filter_cves(
                detect_cve_patterns(container_log, container_f, host_f), baseline_scores
            )

            # Only escalate to ALERT if a hard threshold fired OR CVEs/escape were found.
            # Bare IsolationForest anomalies with no supporting evidence are INFO.
            real_signal = hard_hit or escape_case or cves
            label = "[ALERT]" if real_signal else "[INFO]"

            print(f"{label} {'Anomaly detected!' if real_signal else 'Statistical anomaly (no specific signal)'}")
            if escape_case:
                print(f"[CGROUP-ESCAPE] Likely {escape_case}")

            if real_signal:
                print("\n[CVE-ANALYSIS] Scanning for known patterns...")
                if cves:
                    print(format_cve_alert(cves))
                    critical = [c for c in cves if c["risk"] == "CRITICAL"]
                    high     = [c for c in cves if c["risk"] == "HIGH"]
                    if critical:
                        print(f"\n🔥 CRITICAL: {len(critical)} CVE(s)")
                        for c in critical:
                            print(f"   • {c['cve_id']}: {c['description']}")
                    if len(high) >= 2:
                        print(f"\n⚠️  HIGH: {len(high)} CVE(s)")
                        for c in high[:3]:
                            print(f"   • {c['cve_id']}: {c['description']}")
                else:
                    print("No specific CVE patterns; anomalous behaviour detected.")
            print()

        else:
            # Early warning — only show if score >= 4 (at least 2 strong pattern hits)
            # to avoid false positives from DVWA's normal SQL/MySQL/tmp activity
            cves = _filter_cves(
                detect_cve_patterns(container_log, container_f, host_f), baseline_scores
            )
            high_risk = [c for c in cves if c["risk"] in ("HIGH", "CRITICAL") and c["score"] >= 4]
            if high_risk:
                print("[WARNING] Suspicious patterns (not anomalous yet):")
                for c in high_risk[:2]:
                    print(f"   • {c['cve_id']} [{c['risk']}]: {c['description']}")
                print("[OK] Normal (with warnings)\n")
            else:
                print("[OK] Normal\n")

        time.sleep(DETECTION_INTERVAL)


# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    host_mon = HostMonitor()
    model, columns, baseline_scores = train_model(host_mon)
    detect(model, columns, host_mon, baseline_scores)
