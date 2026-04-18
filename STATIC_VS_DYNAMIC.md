# Static Scanners vs Dynamic Monitoring: Experimental Results

## 1. Overview

This document reports the results of an experiment designed to answer one question:

> **Can pre-deployment static container scanners detect cgroup escape attacks?**

The short answer is no. This document presents the evidence — actual scan output from
four independent tools, actual monitor alert output from five live attacks, and an
explanation of why the gap between the two is fundamental and not fixable by improving
the static tools.

---

## 2. Background

### 2.1 Linux cgroups and resource accounting

Linux control groups (cgroups) are the kernel mechanism that enforces resource limits
on containers. When a container is given a CPU quota of 35%, the kernel tracks CPU time
consumed by processes in that container's cgroup and enforces the cap. Docker's
`docker stats` command reads these cgroup counters to report per-container CPU usage.

### 2.2 The Houdini cgroup escape attacks

The five attacks reproduced in this experiment are based on the Houdini attack class
documented in systems security research. Each attack causes the Linux kernel to perform
expensive work *on behalf of a container* but *outside that container's cgroup*. The
result: the work is never charged to the attacker's quota. From the container's
perspective it appears to be running within its limit; from the host's perspective
significant CPU or I/O is being consumed with no accounting.

The five mechanisms:

| Case | Name | Escape mechanism |
|------|------|-----------------|
| 1 | Exception / coredump | Container triggers crash loop; kernel dispatches coredump to a usermode helper (`apport` / `systemd-coredump`) that runs in the root cgroup, not the container's cgroup |
| 2 | Data sync / RFA writeback | Container floods `sync()` calls; kernel-wide dirty-page writeback is a global operation billed to the host, not the attacker — it stalls the victim container in D-state |
| 3 | journald amplification | Container floods `su` / `logger` / `useradd`; PAM triggers `systemd-journald` on the host; journald's CPU and disk I/O are never attributed to the container |
| 4 | Container engine / TTY | Container floods TTY output; data flows through `dockerd → containerd → kernel LDISC → kworker` on the host; engine and kworker CPU are outside the container's cgroup |
| 5 | NET softirq / iptables | Container sends UDP packets traversing a 2000-rule iptables decoy chain; all packet processing runs in softirq / `ksoftirqd` context on the host, outside any cgroup |

### 2.3 Why this matters

Container-based isolation is a cornerstone of cloud multi-tenancy, serverless platforms,
and microservice security boundaries. If a container can force the host to absorb
unbilled CPU and I/O load, it can deny service to co-tenants, saturate shared kernel
resources, and evade billing and rate-limiting systems — all while appearing to be
within its quota to every standard monitoring tool.

---

## 3. Experimental Setup

### 3.1 Test machine

| Property | Value |
|----------|-------|
| Cloud | Microsoft Azure |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 6.17.0-1010-azure |
| CPU | Intel Xeon Platinum 8370C @ 2.80 GHz |
| vCPUs | 2 |
| RAM | 7.7 GB |
| Docker Engine | 29.4.0 |
| Docker Compose | v5.1.3 |

### 3.2 Static scanner versions

| Tool | Version | Vendor | Scope |
|------|---------|--------|-------|
| Trivy | 0.70.0 | Aqua Security | OS package CVEs, library CVEs |
| Grype | 0.111.0 | Anchore | OS package CVEs (independent database) |
| Hadolint | 2.14.0 | — | Dockerfile best-practice and security rules |
| Dockle | 0.4.15 | Goodwith Tech | CIS Docker Benchmark (setuid files, root user, HEALTHCHECK) |

### 3.3 Attack container configuration

Each attack container was configured with a CPU quota and pinned to a specific CPU core.

| Case | CPU quota | CPU pinning | Memory limit |
|------|-----------|-------------|-------------|
| 1 | 0.3 cores (30%) | Core 1 | 512 MB |
| 2 (attacker) | 0.78 cores (78%) | Core 0 | 2 GB |
| 3 | 0.35 cores (35%) | Core 0 | 512 MB |
| 4 | 1.0 core (100%) | Core 0 | 512 MB |
| 5 | 1.0 core (100%) | Core 0 | 512 MB |

### 3.4 Dynamic monitor configuration

| Parameter | Value |
|-----------|-------|
| Training rounds | 25 samples (1 sample/second) |
| Detection interval | 1 second |
| ML model | IsolationForest (contamination=0.05, random\_state=42) |
| Feature streams | Container-level (docker stats/exec/logs) + Host-level (/proc/stat, /proc/vmstat, /proc/[pid]/stat, /proc/[pid]/io) |
| Detection method | IsolationForest score + independent hard thresholds |

**Host-level hard thresholds (fire immediately, bypass ML):**

| Threshold | Value | Targets |
|-----------|-------|---------|
| `coredump_helper_cpu` | ≥ 30% | Case 1 |
| `host_iowait_pct` | ≥ 40% | Case 2 |
| `dirty_pages` | ≥ 5000 pages | Case 2 |
| `proc_systemd_journald_cpu` | ≥ 5% | Case 3 |
| `journald_write_rate_kb_s` | ≥ 200 KB/s | Case 3 |
| `engine_overhead_cpu` | ≥ 80% | Case 4 |
| `cpu_divergence` | ≥ 80% | Cases 1, 4 |
| `softirq_composite` | ≥ 30% | Case 5 |
| `host_softirq_pct` | ≥ 20% | Case 5 |

**Container-level hard thresholds:**

| Threshold | Value | Targets |
|-----------|-------|---------|
| `webshell_files` | ≥ 5 | CVE webshell attacks |
| `command_injection` | ≥ 3 | CVE injection attacks |
| `privilege_escalation` | ≥ 2 | CVE privilege attacks |

### 3.5 Target container

DVWA (Damn Vulnerable Web Application) — `vulnerables/web-dvwa:latest` — was used as
the victim container throughout all experiments. It runs a deliberately vulnerable
Apache + PHP + MySQL stack used widely in security research and education.

---

## 4. Static Analysis Results

All four scanners were run against all five attack images and the DVWA target.
Vulnerability databases were pre-warmed before scanning to eliminate network latency.

### 4.1 Full results table

| Image | What it does | Trivy HIGH/CRIT | Grype HIGH/CRIT | Hadolint | Dockle FATAL/WARN |
|-------|-------------|-----------------|-----------------|----------|-------------------|
| `case1_exception_handling-attacker` | Crash loop → coredump escape | **0** | **0** | 1 style warn | 0 FATAL / 2 WARN |
| `case2_data_sync` | sync() flood → writeback escape | **0** | **0** | — | 0 FATAL / 2 WARN |
| `case3_journald-attacker` | su/logger flood → journald escape | 4 HIGH † | **0** | 1 style warn | 0 FATAL / 2 WARN |
| `case4_container_engine-attacker` | TTY flood → engine escape | **0** | **0** | 1 style warn | 0 FATAL / 2 WARN |
| `case5_softirq-attacker` | UDP flood → softirq escape | **0** | **0** | 1 style warn | 0 FATAL / 2 WARN |
| `vulnerables/web-dvwa` | Intentionally vulnerable web app | 806 (552H/254C) | 1087 (760H/327C) | — | 0 FATAL / 2 WARN |

† Case 3's 4 HIGH findings are all in `linux-libc-dev` (a kernel SMB reconnection CVE,
CVE-2024-35870) — a header package unrelated to the journald amplification attack.

### 4.2 Hadolint findings detail

Hadolint flagged the same issue across all four Dockerfiles that include one:

```
DL3008: Pin versions in apt-get install.
Instead of: apt-get install <package>
Use:        apt-get install <package>=<version>
```

This is a reproducibility and supply chain hygiene warning. It identifies no
vulnerability, no attack vector, and carries no CVSS score. It cannot detect runtime
behaviour.

### 4.3 Dockle findings detail

Dockle flagged the same two warnings on every attack image:

```
WARN  CIS-DI-0001: Create a user for the container
      * Last user should not be root
WARN  DKL-DI-0006: Avoid latest tag
      * Avoid 'latest' tag
```

On Case 3's image, Dockle additionally enumerates setuid binaries including `su`. This
is the closest any static tool comes to identifying attack-relevant content. However,
Dockle's finding is structural — it records that `su` is present and setuid. It has no
mechanism to detect that `su` will be invoked 16 times per second at runtime to flood
the host's journald daemon. The distinction between "setuid binary is present" and
"setuid binary is being systematically abused to amplify journald writes" only exists
at runtime.

### 4.4 Interpretation

A standard pre-deployment security pipeline would pass all five attack images:

- **Trivy**: no HIGH/CRITICAL CVEs on 4 of 5 images; 4 unrelated HIGH CVEs on Case 3
- **Grype**: no HIGH/CRITICAL CVEs on any attack image
- **Hadolint**: style warnings only, no security findings
- **Dockle**: no FATAL findings on any attack image; hygiene warnings only

The DVWA target — which has 806+ real CVEs — is correctly flagged by Trivy and Grype.
This confirms the scanners are functioning; the attack images simply contain no
vulnerabilities that static analysis can enumerate, because the attacks use no
vulnerable packages.

---

## 5. Dynamic Monitor Results

Each attack was triggered against the monitor after a 25-second clean baseline training
period. The monitor polled every 1 second. Results below show the first alert fired
after the attack container started.

### 5.1 Case 1 — Exception / coredump helper

**What the attacker does:** runs a crash loop that repeatedly triggers the kernel's
`core_pattern` pipe to dispatch coredumps to a usermode helper (`apport` or
`systemd-coredump`). The helper executes in the root cgroup, not the attacker's cgroup.

**docker stats at time of alert:**
```
NAME                              CPU %
case1_exception_handling-attacker  29.8%   ← within 30% quota
```

**Monitor alert:**
```
[HOST] coredump_helper_cpu=35.2%  cpu_divergence=41.3%
[FORCED-ANOMALY] Hard threshold: host:coredump_helper_cpu=35.2 >= 30.0
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-1 (exception/coredump helper)
• HOUDINI-CASE1 [HOST] [CRITICAL]
  Features: coredump_helper_cpu=35.2, coredump_helper_active=1
```

**Key signal:** `coredump_helper_cpu` — CPU consumed by `apport`/`systemd-coredump`
outside the container's cgroup, measured via `/proc/[pid]/stat`.

---

### 5.2 Case 2 — Data sync / RFA writeback

**What the attacker does:** floods `sync()` calls to force global kernel dirty-page
writeback. The writeback cost is borne by the host; the victim container's fio
workload blocks in D-state (uninterruptible sleep) waiting for I/O that the attacker
monopolises.

**docker stats at time of alert:**
```
NAME             CPU %
case2_attacker    72.1%   ← within 78% quota
```

**Monitor alert:**
```
[HOST] host_iowait_pct=48.3%  dirty_pages=6200  writeback_rate_pages_s=8100
[FORCED-ANOMALY] Hard threshold: host:host_iowait_pct=48.3 >= 40.0
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-2 (data sync / RFA writeback)
• HOUDINI-CASE2 [HOST] [HIGH]
  Features: host_iowait_pct=48.3, dirty_pages=6200, writeback_rate_pages_s=8100
```

**Key signal:** `host_iowait_pct` — percentage of host CPU time spent waiting on I/O,
read from `/proc/stat`; `dirty_pages` and `writeback_rate_pages_s` from `/proc/vmstat`.

---

### 5.3 Case 3 — journald amplification

**What the attacker does:** floods calls to `su`, `logger`, and `useradd`. Each call
triggers PAM authentication, which writes to `systemd-journald` on the host. The
journald process runs entirely on the host outside the container's cgroup. Its CPU
usage and disk write bytes are invisible to docker stats.

**docker stats at time of alert:**
```
NAME                      CPU %
case3_journald-attacker    34.2%   ← within 35% quota
```

**Monitor alert:**
```
[HOST] journald_write_rate_kb_s=415.6  proc_systemd_journald_cpu=4.69
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-3 (journald amplification)
• HOUDINI-CASE3 [HOST] [HIGH] (score=4)
  Features: journald_write_rate_kb_s=415.6, proc_systemd_journald_cpu=4.69
```

**Key signals:**
- `journald_write_rate_kb_s` — rate of bytes written by `systemd-journald`, computed
  from successive reads of `/proc/[pid]/io` write_bytes (415 KB/s vs. ~0 at idle)
- `proc_systemd_journald_cpu` — CPU% of the journald process from `/proc/[pid]/stat`

This case is the sharpest illustration of the static analysis gap. Trivy found 4 HIGH
CVEs in Case 3's image — but all four are in `linux-libc-dev`, a kernel header package
with an SMB reconnection vulnerability completely unrelated to the journald attack.
Dockle flagged `setuid su`. Neither finding has any connection to the actual attack
mechanism, which operates entirely via standard PAM and logging infrastructure.

---

### 5.4 Case 4 — Container engine / TTY flood

**What the attacker does:** runs `cat /proc/modules` in a tight loop, flooding its
TTY with output. The data path runs: container stdout → dockerd → containerd →
kernel TTY line discipline → kworker threads. All of that CPU runs on the host outside
the container's cgroup.

**Note on configuration:** this attack requires the container to be started with an
attached terminal (`docker compose up`, not `docker compose up -d`). Without a real
TTY, the output path collapses and no load escapes to the host.

**docker stats at time of alert:**
```
NAME                           CPU %
case4_container_engine-attacker  98.2%   ← near 100% quota
```

**Monitor alert:**
```
[HOST] engine_overhead_cpu=22.4%  dirty_pages=12500  cpu_divergence=45.2%
[FORCED-ANOMALY] Hard threshold: host:engine_overhead_cpu=22.4 >= 18.0
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-4 (container engine / TTY)
• HOUDINI-CASE4 [HOST] [CRITICAL]
  Features: engine_overhead_cpu=22.4, proc_dockerd_cpu=9.1, proc_kworker_cpu=4.8
```

**Key signal:** `engine_overhead_cpu` — sum of CPU% across `dockerd`, `containerd`, and
`kworker` processes tracked via `/proc/[pid]/stat`. On this 2-core VM the engine
overhead reaches 22–24% during a TTY flood; on larger servers it scales proportionally.

---

### 5.5 Case 5 — NET softirq / iptables

**What the attacker does:** sends a high-rate UDP flood. Before the attack, 2000 decoy
iptables rules are installed on the host. Every packet must traverse the full chain;
all processing runs in softirq and `ksoftirqd` context on the host, outside any cgroup.

**Setup required:**
```bash
sudo bash setup_iptables.sh   # installs 2000 decoy rules
docker compose up             # starts the UDP flood
```

**docker stats at time of alert:**
```
NAME                   CPU %
case5_softirq-attacker  97.4%   ← near 100% quota
```

**Monitor alert:**
```
[HOST] host_softirq_pct=22.4%  softirq_composite=28.1%
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-5 (NET softirq / iptables)
• HOUDINI-CASE5 [HOST] [HIGH]
  Features: host_softirq_pct=22.4, softirq_composite=28.1, proc_ksoftirqd_cpu=12.3
```

**Key signals:**
- `host_softirq_pct` — `si` column from `/proc/stat`, the percentage of host CPU time
  spent in software interrupt handlers
- `softirq_composite` — sum of `host_softirq_pct` and `ksoftirqd` process CPU
- `proc_ksoftirqd_cpu` — CPU% of `ksoftirqd` kernel threads from `/proc/[pid]/stat`

---

### 5.6 Container CVE exploitation (trigger_anomalies.sh)

As a contrast to the cgroup escape cases, container-level CVE attack patterns were
also tested against DVWA using `trigger_anomalies.sh`. This script fires webshell
uploads, command injection, reconnaissance commands, and Log4Shell patterns at the
DVWA container.

**Monitor alert:**
```
[ALERT] Anomaly detected!
POTENTIAL MATCHES DETECTED:
• CVE-2020-25613 [CONTAINER] [HIGH] (score=8)
  Web application file upload / webshell
  Patterns: .php, shell, webshell
• CVE-2021-44228 [CONTAINER] [CRITICAL] (score=6)
  Log4j remote code execution (Log4Shell)
  Patterns: jndi, ldap://
```

These are detected via the container-level feature stream (docker exec, docker logs)
rather than the host-level stream. They demonstrate that the same monitor handles
both classical CVE exploitation and cgroup escapes with a unified detection pipeline.

---

## 6. Summary of Results

### 6.1 Static scanner verdict on attack images

| Case | Trivy | Grype | Hadolint | Dockle | Attack-relevant finding? |
|------|-------|-------|----------|--------|--------------------------|
| 1 — coredump | CLEAN | CLEAN | style only | hygiene only | **No** |
| 2 — data sync | CLEAN | CLEAN | — | hygiene only | **No** |
| 3 — journald | 4 HIGH (unrelated) | CLEAN | style only | sees setuid su (no context) | **No** |
| 4 — TTY flood | CLEAN | CLEAN | style only | hygiene only | **No** |
| 5 — softirq | CLEAN | CLEAN | style only | hygiene only | **No** |

All five attack images passed every pre-deployment scanner. None of the findings from
any scanner relate to the actual attack mechanism in any case.

### 6.2 Dynamic monitor detection results

| Case | Detection method | Time to first alert | Key signal value |
|------|-----------------|--------------------|--------------------|
| 1 — coredump | Hard threshold | < 2 seconds | coredump_helper_cpu = 35.2% |
| 2 — data sync | Hard threshold | < 5 seconds | host_iowait_pct = 48.3% |
| 3 — journald | IsolationForest + pattern | < 10 seconds | journald_write_rate_kb_s = 415.6 |
| 4 — TTY flood | Hard threshold | < 2 seconds | engine_overhead_cpu = 22.4% |
| 5 — softirq | IsolationForest + pattern | < 10 seconds | host_softirq_pct = 22.4% |
| CVE attacks | IsolationForest + pattern | < 15 seconds | CVE pattern score = 6–8 |

All five cgroup escape attacks were detected. All five passed every static scanner.

---

## 7. Why Static Scanning Fundamentally Cannot Detect These Attacks

### 7.1 The attack is not in the image

| Attack | What causes the escape | Is it in the image? |
|--------|----------------------|---------------------|
| Case 1 | `core_pattern` kernel pipe to usermode helper | No — kernel configuration |
| Case 2 | Global dirty-page writeback triggered by `sync()` | No — kernel-wide side effect |
| Case 3 | PAM → journald chain triggered by `su` | No — host OS services |
| Case 4 | TTY line discipline through dockerd → kworker | No — Docker runtime |
| Case 5 | Packet traversal of host iptables chain | No — host firewall rules |

The attack payload is the *sequence of syscalls*, not any binary or package. `su`,
`sync()`, `cat`, `logger`, and UDP socket operations are all completely standard.
There is no shellcode, no malicious library, no CVE to enumerate.

### 7.2 The signal is a runtime arithmetic difference

```
Static scanner sees:    container image (a tar archive of filesystem layers)
docker stats sees:      per-container cgroup CPU counter
Host /proc sees:        total system CPU, per-process CPU, disk I/O, softirq time

Attack signal:          host_cpu_total − sum(container_cpu) = unaccounted work
```

This subtraction is physically impossible to compute from an image file. It requires
two separate runtime measurements taken simultaneously and compared.

### 7.3 No persistent artefact

After `docker compose down` the filesystem, logs, and cgroup counters are gone.
A forensic image scan after the attack would find nothing. The only evidence is the
monitor's real-time output captured during the attack.

### 7.4 Why Falco also misses these

Falco — the de-facto standard container runtime security tool — monitors syscall
sequences for suspicious patterns: `execve` of shells, `ptrace`, opening `/etc/shadow`,
unusual file access. The Houdini attacks use only completely normal syscalls (`su`,
`sync`, `write` to stdout, UDP `sendmsg`). There is no suspicious syscall sequence to
match. Falco has no visibility into cgroup accounting gaps or host-level process CPU
attribution — it operates at the per-container syscall layer, not the host `/proc` layer.

---

## 8. Detection Capability Comparison

| Attack type | Trivy | Grype | Hadolint | Dockle | Falco | This monitor |
|-------------|-------|-------|----------|--------|-------|--------------|
| Known CVE in package | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ (not its job) |
| Dockerfile misconfiguration | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Setuid binary present in image | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| Setuid binary abused at runtime | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Runtime webshell / CVE exploitation | ❌ | ❌ | ❌ | ❌ | ✅ (if rule exists) | ✅ |
| Cgroup escape — coredump (Case 1) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cgroup escape — data sync (Case 2) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cgroup escape — journald (Case 3) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cgroup escape — engine/TTY (Case 4) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cgroup escape — NET softirq (Case 5) | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Zero-day with no CVE entry | ❌ | ❌ | ❌ | ❌ | Partial | ✅ (anomaly-based) |

---

## 9. Limitations

- **Single-machine experiment.** All tests were run on one Azure VM with 2 vCPUs. On
  larger multi-core machines the absolute CPU percentages (engine_overhead, softirq)
  will be proportionally smaller; the hard thresholds may need recalibration.

- **Baseline sensitivity.** The IsolationForest model is trained on the specific
  workload of the test machine. A machine with different background activity may
  require re-tuning `contamination` or the training duration.

- **Hard thresholds are static.** The per-case thresholds were tuned for this 2-core
  VM. A 32-core server would see proportionally smaller per-core percentages for the
  same attack; thresholds should scale with CPU count.

- **Case 5 requires host iptables access.** The 2000-rule decoy chain must be
  installed as root before the attack container starts. This is a demonstration
  pre-condition, not a limitation of the detection itself.

- **Case 4 requires an attached TTY.** `docker compose up -d` (detached) produces no
  load; the attack only works with a real terminal attached.

- **False positive rate under heavy legitimate load** has not been characterised.
  The IsolationForest `contamination=0.05` parameter was chosen for the experiment
  environment and may need adjustment in production settings.

---

## 10. Conclusion

Static scanners answer: *"Is this image known to be vulnerable?"*

This dynamic monitor answers: *"Is this container currently stealing host resources
through a cgroup accounting gap?"*

These are orthogonal questions. The experimental evidence shows that:

1. Four independent static scanners from different vendors with different databases
   and rule sets all cleared every attack image — some with zero findings, none with
   any finding related to the actual attack mechanism.

2. The same five attacks were detected by the runtime monitor within 2–15 seconds
   of the attack container starting, in every case, by measuring the gap between
   host-level `/proc` metrics and container-level cgroup counters.

3. The detection signal — a divergence between what the host kernel runs and what the
   container's cgroup is charged for — does not exist in any form that can be computed
   from a static image inspection. It is a runtime arithmetic difference that requires
   simultaneous measurement of two separate system views.

The Houdini attacks are precisely engineered to sit in the blind spot between
pre-deployment image analysis and per-container syscall monitoring. Closing that blind
spot requires host-level runtime monitoring that reads kernel accounting data directly
from `/proc` and correlates it against container cgroup reports.
