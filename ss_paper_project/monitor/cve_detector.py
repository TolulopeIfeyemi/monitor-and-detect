# CVE + Houdini cgroup escape pattern database.
#
# Two types of entries:
#   Standard CVEs   — matched against container log strings and container features
#   Houdini cases   — matched against host-level features from host_monitor.py
#
# detect_cve_patterns() now accepts host_features as a third argument so that
# cgroup escape attacks (which leave no trace in docker stats or docker exec)
# can still be correlated to a named attack pattern.

# ---------------------------------------------------------------------------
# Standard container-level CVE patterns
# ---------------------------------------------------------------------------
CVE_PATTERNS = {
    "CVE-2019-5736": {
        "description": "runc container escape via malicious container image",
        "patterns": ["runc", "proc/self/exe", "container_escape"],
        "features": ["privilege_escalation", "suspicious_commands", "file_changes"],
        "risk": "CRITICAL",
        "source": "container",
    },
    "CVE-2022-0847": {
        "description": "Dirty Pipe — kernel privilege escalation",
        "patterns": ["pipe", "splice", "kernel", "/proc/version"],
        "features": ["privilege_escalation", "reconnaissance", "file_changes"],
        "risk": "HIGH",
        "source": "container",
    },
    "CVE-2020-15257": {
        "description": "containerd information disclosure",
        "patterns": ["/etc/passwd", "/etc/shadow", "/proc/", "cat "],
        "features": ["suspicious_commands", "reconnaissance", "file_changes"],
        "risk": "MEDIUM",
        "source": "container",
    },
    "CVE-2021-30465": {
        "description": "runc mount destinations information disclosure",
        "patterns": ["/proc/mounts", "/etc/hosts", "mount", "filesystem"],
        "features": ["reconnaissance", "file_changes", "suspicious_commands"],
        "risk": "MEDIUM",
        "source": "container",
    },
    "CVE-2020-1472": {
        "description": "Netlogon privilege escalation (Zerologon) — command injection pattern",
        "patterns": ["netlogon", "system(", "eval(", "exec("],
        "features": ["command_injection", "privilege_escalation", "network_activity"],
        "risk": "CRITICAL",
        "source": "container",
    },
    "CVE-2019-14271": {
        "description": "Docker cp arbitrary file write via symlink",
        "patterns": ["docker cp", "symlink", "/tmp/", "suspicious_file", "exploit", "malicious", "backdoor", ".sh", "chmod +x"],
        "features": ["file_changes", "tmp_files", "suspicious_commands", "webshell_files"],
        "risk": "HIGH",
        "source": "container",
    },
    "CVE-2018-15664": {
        "description": "Docker symlink-exchange attack",
        "patterns": ["symlink", "chroot", "/proc/self/root"],
        "features": ["privilege_escalation", "file_changes", "root_shells"],
        "risk": "HIGH",
        "source": "container",
    },
    "CVE-2021-41089": {
        "description": "Moby/Docker CLI path traversal",
        "patterns": ["../", "path_traversal", "directory_traversal"],
        "features": ["file_changes", "suspicious_commands", "tmp_files"],
        "risk": "MEDIUM",
        "source": "container",
    },
    "CVE-2020-13401": {
        "description": "Docker Engine API exposure",
        "patterns": [":2375", ":2376", "docker.sock", "api_exposure"],
        "features": ["network_activity", "network_connections", "high_cpu"],
        "risk": "HIGH",
        "source": "container",
    },
    "CVE-2019-16278": {
        "description": "DVWA SQL injection vulnerability",
        "patterns": ["sql", "injection", "select", "union"],
        "features": ["network_activity", "access_logs", "mysql_processes"],
        "risk": "HIGH",
        "source": "container",
    },
    "CVE-2020-25613": {
        "description": "Web application file upload / webshell",
        "patterns": ["upload", "webshell", ".php", "shell.php"],
        "features": ["tmp_files", "php_processes", "command_injection"],
        "risk": "HIGH",
        "source": "container",
    },
    "CVE-2021-44228": {
        "description": "Log4j remote code execution (Log4Shell)",
        "patterns": ["log4j", "jndi", "ldap://", "${"],
        "features": ["command_injection", "network_activity", "access_logs"],
        "risk": "CRITICAL",
        "source": "container",
    },
}

# ---------------------------------------------------------------------------
# Houdini cgroup escape attack patterns (host-level features only)
#
# Each entry lists:
#   host_feature_thresholds  : {feature_name: min_value_to_score}
#   score_per_hit            : points added per threshold exceeded
# ---------------------------------------------------------------------------
HOUDINI_PATTERNS = {
    "HOUDINI-CASE1": {
        "description": "Cgroup escape via exception handling — coredump helper runs in root cgroup",
        "detail": (
            "Container triggers crash loop; kernel hands core dump to piped usermode "
            "helper (apport/systemd-coredump) which runs outside the container's cgroup. "
            "Host CPU saturates while docker stats shows the container near its quota."
        ),
        "host_feature_thresholds": {
            "coredump_helper_cpu":    10.0,
            "coredump_helper_active":  1,
            "cpu_divergence":         50.0,
            "host_system_pct":        30.0,
        },
        "risk": "CRITICAL",
    },
    "HOUDINI-CASE2": {
        "description": "Cgroup escape via data sync (RFA) — global writeback stalls victim container",
        "detail": (
            "Attacker floods sync(); kernel-wide dirty-page writeback blocks victim fio "
            "in D-state. Attacker's sysbench gains CPU beyond its quota. Writeback cost "
            "is not billed to the attacker's cgroup."
        ),
        "host_feature_thresholds": {
            "host_iowait_pct":           25.0,
            "dirty_pages":             2000,
            "writeback_pages":          200,
            "writeback_rate_pages_s": 5000,
        },
        "risk": "HIGH",
    },
    "HOUDINI-CASE3": {
        "description": "Cgroup escape via journald — host logging daemon absorbs I/O and CPU",
        "detail": (
            "Container floods su/useradd/logger, triggering PAM and systemd-journald on "
            "the host. journald CPU and I/O are not charged to the container's cgroup."
        ),
        "host_feature_thresholds": {
            "journald_write_rate_kb_s":  150.0,  # primary: journald flushing >150 KB/s (sustained flood)
            "proc_systemd_journald_cpu":   3.0,  # secondary: measurable journald CPU spike
            "proc_auditd_cpu":             2.0,
        },
        "risk": "HIGH",
    },
    "HOUDINI-CASE4": {
        "description": "Cgroup escape via container engine — dockerd/kworker TTY processing outside cgroup",
        "detail": (
            "Container floods TTY output; traffic flows through dockerd → containerd → "
            "LDISC → kworker on the host. Engine and kworker CPU is not attributed to "
            "the container. Effective CPU load is ~3× what docker stats reports."
        ),
        "host_feature_thresholds": {
            "engine_overhead_cpu": 18.0,   # dockerd+containerd+kworker; ~22-24% on 2-core VM
            "proc_dockerd_cpu":     8.0,   # dockerd alone is 8-9% during TTY flood
            "proc_kworker_cpu":     3.0,
        },
        "risk": "CRITICAL",
    },
    "HOUDINI-CASE5": {
        "description": "Cgroup escape via NET softirq — iptables chain traversal burns host CPU",
        "detail": (
            "Container sends UDP packets that must traverse a long iptables decoy chain. "
            "All packet processing runs in softirq / ksoftirqd context on the host, "
            "outside any container cgroup. The 'si' column in top rises; docker stats "
            "shows the container near its CPU cap."
        ),
        "host_feature_thresholds": {
            "host_softirq_pct":    10.0,
            "softirq_composite":   15.0,
            "proc_ksoftirqd_cpu":  10.0,
        },
        "risk": "HIGH",
    },
}

# Attack behaviour to CVE mapping (container-level)
ATTACK_CVE_MAPPING = {
    "reconnaissance":       ["CVE-2020-15257", "CVE-2021-30465", "CVE-2020-13401"],
    "file_disclosure":      ["CVE-2020-15257", "CVE-2021-30465"],
    "tmp_file_creation":    ["CVE-2019-14271", "CVE-2021-41089", "CVE-2020-25613"],
    "webshell_creation":    ["CVE-2020-25613", "CVE-2019-16278"],
    "process_manipulation": ["CVE-2019-5736",  "CVE-2018-15664"],
    "network_reconnaissance":["CVE-2020-13401","CVE-2021-30465"],
    "privilege_usage":      ["CVE-2019-5736",  "CVE-2018-15664", "CVE-2022-0847"],
}


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def detect_cve_patterns(log_data, container_features, host_features=None):
    """
    Analyse container log + features and host features; return list of matches
    sorted by score descending.

    log_data           : raw combined docker log string
    container_features : dict from extract_container_features()
    host_features      : dict from HostMonitor.collect() — required for Houdini cases
    """
    host_features = host_features or {}
    matches = []
    log_lower = log_data.lower()

    # --- Container-level CVE patterns ---
    for cve_id, info in CVE_PATTERNS.items():
        score = 0
        matched_patterns  = []
        matched_features  = []

        for pattern in info["patterns"]:
            if pattern.lower() in log_lower:
                score += 2
                matched_patterns.append(pattern)

        for feat in info["features"]:
            if container_features.get(feat, 0) > 0:
                score += 1
                matched_features.append(f"{feat}({container_features[feat]})")

        # score >= 3 requires at least one actual pattern string match (worth 2)
        # plus one feature hit — prevents DVWA's normal MySQL/PHP activity
        # from scoring container CVEs on feature matches alone
        if score >= 3:
            matches.append({
                "cve_id":           cve_id,
                "description":      info["description"],
                "risk":             info["risk"],
                "score":            score,
                "matched_patterns": matched_patterns,
                "matched_features": matched_features,
                "source":           "container",
            })

    # --- Host-level Houdini cgroup escape patterns ---
    for attack_id, info in HOUDINI_PATTERNS.items():
        score = 0
        matched_features = []

        for feat, threshold in info["host_feature_thresholds"].items():
            val = host_features.get(feat, 0)
            if val >= threshold:
                score += 2
                matched_features.append(f"{feat}={val:.2f}")

        if score >= 2:  # require at least one host threshold hit
            matches.append({
                "cve_id":           attack_id,
                "description":      info["description"],
                "risk":             info["risk"],
                "score":            score,
                "matched_patterns": [],
                "matched_features": matched_features,
                "source":           "host",
                "detail":           info.get("detail", ""),
            })

    return sorted(matches, key=lambda x: x["score"], reverse=True)


def format_cve_alert(matches):
    """Format detection results into a human-readable alert string."""
    if not matches:
        return "No known patterns detected."

    lines = ["POTENTIAL MATCHES DETECTED:"]
    for m in matches:
        src = f"[{m['source'].upper()}]"
        lines.append(f"\n• {m['cve_id']} {src} [{m['risk']}] (score={m['score']})")
        lines.append(f"  {m['description']}")
        if m.get("detail"):
            lines.append(f"  Detail: {m['detail']}")
        if m["matched_patterns"]:
            lines.append(f"  Patterns : {', '.join(m['matched_patterns'])}")
        if m["matched_features"]:
            lines.append(f"  Features : {', '.join(m['matched_features'])}")

    return "\n".join(lines)
