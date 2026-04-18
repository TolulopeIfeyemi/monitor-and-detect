"""
Host-level /proc reader for cgroup escape detection.

All 5 Houdini escape attacks cause work outside the attacker container's cgroup.
docker stats stays near the container's CPU limit; this module reads what the
host kernel is actually doing and surfaces the gap.

Signals per case:
  Case 1 (exception/coredump) : apport / systemd-coredump process CPU spikes
  Case 2 (data sync / RFA)    : nr_dirty, nr_writeback, iowait rise
  Case 3 (journald)           : systemd-journald process CPU spikes
  Case 4 (container engine)   : dockerd + containerd + kworker CPU rise; divergence
  Case 5 (NET softirq)        : softirq % spikes in /proc/stat; ksoftirqd CPU
"""

import os
import subprocess
import time

# Processes whose CPU we track individually on the host
TRACKED_PROCS = [
    "apport",
    "systemd-coredump",
    "dockerd",
    "containerd",
    "kworker",
    "ksoftirqd",
    "systemd-journald",
    "containerd-shim",
    "auditd",
]

_CLK_TCK = os.sysconf("SC_CLK_TCK")  # typically 100 on Linux


# ---------------------------------------------------------------------------
# Low-level /proc readers
# ---------------------------------------------------------------------------

def _read_proc_stat():
    """Return aggregate CPU tick counters from /proc/stat (first 'cpu' line)."""
    with open("/proc/stat") as fh:
        for line in fh:
            if line.startswith("cpu "):
                fields = line.split()
                # fields: cpu user nice system idle iowait irq softirq steal guest guest_nice
                keys = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]
                return {k: int(fields[i + 1]) for i, k in enumerate(keys)}
    return {}


def _read_proc_vmstat():
    """Return selected counters from /proc/vmstat."""
    want = {"nr_dirty", "nr_writeback", "pgpgout", "pgpgin", "nr_vmscan_write"}
    result = {}
    try:
        with open("/proc/vmstat") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 2 and parts[0] in want:
                    result[parts[0]] = int(parts[1])
    except OSError:
        pass
    return result


def _read_proc_meminfo():
    """Return Dirty and Writeback kB from /proc/meminfo."""
    want = {"Dirty", "Writeback"}
    result = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, *rest = line.split()
                key = key.rstrip(":")
                if key in want and rest:
                    result[key] = int(rest[0])
    except OSError:
        pass
    return result


def _scan_proc_ticks():
    """
    Walk /proc/<pid>/comm + /proc/<pid>/stat + /proc/<pid>/io for each TRACKED_PROC.
    Returns (ticks_dict, counts_dict, io_write_bytes_dict) keyed by process name.
    ticks = utime + stime (raw kernel ticks).
    io_write_bytes = cumulative bytes written (from /proc/PID/io write_bytes).
    """
    ticks      = {p: 0 for p in TRACKED_PROCS}
    counts     = {p: 0 for p in TRACKED_PROCS}
    io_wbytes  = {p: 0 for p in TRACKED_PROCS}
    try:
        pids = [e for e in os.listdir("/proc") if e.isdigit()]
    except OSError:
        return ticks, counts, io_wbytes

    for pid in pids:
        comm_path = f"/proc/{pid}/comm"
        stat_path = f"/proc/{pid}/stat"
        io_path   = f"/proc/{pid}/io"
        try:
            with open(comm_path) as fh:
                comm = fh.read().strip()
        except OSError:
            continue

        for name in TRACKED_PROCS:
            # /proc/PID/comm is truncated to 15 chars by the kernel
            if name[:15] in comm:
                try:
                    with open(stat_path) as fh:
                        fields = fh.read().split()
                    utime = int(fields[13])
                    stime = int(fields[14])
                    ticks[name]  += utime + stime
                    counts[name] += 1
                except (OSError, IndexError, ValueError):
                    pass
                try:
                    with open(io_path) as fh:
                        for line in fh:
                            if line.startswith("write_bytes:"):
                                io_wbytes[name] += int(line.split()[1])
                                break
                except OSError:
                    pass
                break  # a pid only matches one name

    return ticks, counts, io_wbytes


def _get_total_container_cpu():
    """
    Sum CPU% across all running containers via docker stats (cgroup view).
    Used to compute divergence = host_total_cpu - container_sum.
    Returns float (percent, e.g. 95.3).
    """
    try:
        result = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}"],
            capture_output=True, text=True, timeout=5,
        )
        total = 0.0
        for line in result.stdout.splitlines():
            line = line.strip().rstrip("%")
            if line:
                try:
                    total += float(line)
                except ValueError:
                    pass
        return total
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Stateful monitor class (call .collect() every second)
# ---------------------------------------------------------------------------

class HostMonitor:
    """
    Stateful host-level metric collector.
    Call collect() once per poll interval; it returns a flat dict of features
    ready to be merged with container-level features for the IsolationForest.
    """

    def __init__(self):
        self._prev_stat = None
        self._prev_vmstat = None
        self._prev_ticks = None
        self._prev_io_wbytes = None
        self._prev_time = None

    def collect(self):
        """
        Read /proc sources, compute deltas against previous call, return feature dict.
        On the first call all rate-based features are 0.
        """
        now = time.monotonic()
        stat = _read_proc_stat()
        vmstat = _read_proc_vmstat()
        meminfo = _read_proc_meminfo()
        proc_ticks, proc_counts, proc_io_wbytes = _scan_proc_ticks()
        container_cpu = _get_total_container_cpu()

        features = {}

        if self._prev_stat and self._prev_time:
            dt = now - self._prev_time  # seconds

            # --- CPU breakdown (% of wall time across all cores) ---
            total_delta = sum(stat[k] - self._prev_stat.get(k, 0) for k in stat)
            if total_delta > 0:
                def _pct(key):
                    return 100.0 * (stat[key] - self._prev_stat.get(key, 0)) / total_delta

                features["host_softirq_pct"]  = _pct("softirq")
                features["host_iowait_pct"]   = _pct("iowait")
                features["host_system_pct"]   = _pct("system")
                features["host_user_pct"]     = _pct("user")
                idle_delta = stat["idle"] - self._prev_stat.get("idle", 0)
                features["host_total_cpu_pct"] = 100.0 * (total_delta - idle_delta) / total_delta
            else:
                for k in ("softirq", "iowait", "system", "user", "total_cpu"):
                    features[f"host_{k}_pct"] = 0.0

            # --- Divergence: host active CPU that docker stats doesn't account for ---
            # High divergence = cgroup escape work happening outside container accounting
            features["cpu_divergence"] = max(0.0, features["host_total_cpu_pct"] - container_cpu)

            # --- Writeback / dirty page rates ---
            if self._prev_vmstat and dt > 0:
                pgpgout_rate = max(0, vmstat.get("pgpgout", 0) - self._prev_vmstat.get("pgpgout", 0)) / dt
                features["writeback_rate_pages_s"] = pgpgout_rate
            else:
                features["writeback_rate_pages_s"] = 0.0

            # --- Per-process CPU (% of one core) and I/O write rate ---
            if self._prev_ticks and dt > 0:
                for name in TRACKED_PROCS:
                    delta = proc_ticks[name] - self._prev_ticks.get(name, 0)
                    cpu_pct = (delta / _CLK_TCK) / dt * 100.0
                    safe = name.replace("-", "_")
                    features[f"proc_{safe}_cpu"] = max(0.0, cpu_pct)
                    features[f"proc_{safe}_count"] = proc_counts[name]
                    # write rate in KB/s
                    wdelta = proc_io_wbytes[name] - self._prev_io_wbytes.get(name, 0)
                    features[f"proc_{safe}_write_kb_s"] = max(0.0, wdelta / 1024.0 / dt)
            else:
                for name in TRACKED_PROCS:
                    safe = name.replace("-", "_")
                    features[f"proc_{safe}_cpu"] = 0.0
                    features[f"proc_{safe}_count"] = proc_counts[name]
                    features[f"proc_{safe}_write_kb_s"] = 0.0

        else:
            # First call: return zeroed rates, still populate counts and absolutes
            for k in ("softirq", "iowait", "system", "user", "total_cpu"):
                features[f"host_{k}_pct"] = 0.0
            features["cpu_divergence"] = 0.0
            features["writeback_rate_pages_s"] = 0.0
            for name in TRACKED_PROCS:
                safe = name.replace("-", "_")
                features[f"proc_{safe}_cpu"] = 0.0
                features[f"proc_{safe}_count"] = proc_counts[name]
                features[f"proc_{safe}_write_kb_s"] = 0.0

        # Absolute values (not rates) — always valid
        features["dirty_pages"]   = vmstat.get("nr_dirty", 0)
        features["writeback_pages"] = vmstat.get("nr_writeback", 0)
        features["dirty_kb"]       = meminfo.get("Dirty", 0)
        features["writeback_kb"]   = meminfo.get("Writeback", 0)
        features["container_cpu_sum"] = container_cpu

        # --- Case-specific composite signals ---
        # Case 1: coredump helper appearing / gaining CPU
        features["coredump_helper_cpu"] = (
            features.get("proc_apport_cpu", 0) +
            features.get("proc_systemd_coredump_cpu", 0)
        )
        features["coredump_helper_active"] = int(
            features.get("proc_apport_count", 0) +
            features.get("proc_systemd_coredump_count", 0) > 0
        )

        # Case 4: engine overhead = dockerd + containerd + kworker above baseline
        features["engine_overhead_cpu"] = (
            features.get("proc_dockerd_cpu", 0) +
            features.get("proc_containerd_cpu", 0) +
            features.get("proc_kworker_cpu", 0) +
            features.get("proc_containerd_shim_cpu", 0)
        )

        # Case 5: softirq composite (kernel stat + ksoftirqd process)
        features["softirq_composite"] = (
            features.get("host_softirq_pct", 0) +
            features.get("proc_ksoftirqd_cpu", 0)
        )

        # Case 3: journald write rate (KB/s) — spikes when container floods PAM/logger events
        # More reliable than CPU% at low PARALLEL_SU because I/O is the bottleneck, not CPU
        features["journald_write_rate_kb_s"] = features.get("proc_systemd_journald_write_kb_s", 0.0)

        self._prev_stat = stat
        self._prev_vmstat = vmstat
        self._prev_ticks = proc_ticks
        self._prev_io_wbytes = proc_io_wbytes
        self._prev_time = now

        return features


def feature_names():
    """Return list of all feature keys this module produces (for DataFrame columns)."""
    dummy = HostMonitor()
    dummy._prev_time = None  # force first-call path
    return list(dummy.collect().keys())
