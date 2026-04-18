# Cgroup Escape Detection — Complete Demo Guide

This guide takes you from a fresh clone to a fully running live demonstration that proves
static container scanners cannot detect cgroup escape attacks.

**The argument in one sentence:**
> Four independent static scanners (Trivy, Grype, Hadolint, Dockle) clear all five attack
> images. The same images are detected within seconds by the runtime monitor — because the
> escape only exists as a kernel accounting gap, not as anything visible in the image.

---

## What you need before you start

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| OS | Ubuntu 20.04+ (x86-64) | Tested on Ubuntu 24.04 |
| Docker Engine | 20.10+ | Must be running (`docker ps` works) |
| Python | 3.8+ | Miniconda or system Python both work |
| RAM | 4 GB free | Monitor + DVWA + one attack container |
| Disk | 5 GB free | Docker images for all 5 cases |
| Internet | Required once | Tool install + image pull (setup.sh only) |
| sudo | Required | Monitor reads `/proc`; attacks need root for some cases |

---

## Get the project

If you are on the development machine, the project is already at:
```
/home/azureuser/ss-project/
```

If cloning fresh on another machine:
```bash
git clone <repo-url> ss-project
cd ss-project
```

Project layout:
```
ss-project/
├── setup.sh                              ← Run once before the demo
├── demo.sh                               ← The full automated demo
├── requirements.txt                      ← Python dependencies
├── NOTES.md                              ← This guide
├── STATIC_VS_DYNAMIC.md                  ← Research document (evidence)
├── ss_paper_project/
│   ├── docker-compose.yml                ← Starts DVWA (victim web app)
│   ├── monitor/
│   │   ├── monitor.py                    ← Main detection loop
│   │   ├── host_monitor.py               ← Reads /proc for host-level signals
│   │   └── cve_detector.py               ← CVE + Houdini pattern database
│   └── attack/
│       └── trigger_anomalies.sh          ← Fires container-level CVE patterns
└── container_cgroup_escape_exploitation/
    └── attacks/
        ├── case1_exception_handling/     ← Crash loop → coredump helper
        ├── case2_data_sync/              ← sync() flood → global writeback
        ├── case3_journald/               ← su/logger flood → journald
        ├── case4_container_engine/       ← TTY flood → dockerd/kworker
        └── case5_softirq/                ← UDP flood → iptables softirq
```

---

## One-time setup (do this before demo day, NOT during the presentation)

```bash
cd /home/azureuser/ss-project
sudo bash setup.sh
```

This does five things automatically:
1. Checks Docker is running and Python is available
2. Installs Python packages: `pandas`, `scikit-learn`, `numpy`
3. Installs the four static scanner tools: Trivy, Grype, Hadolint, Dockle
4. Pre-warms both vulnerability databases (avoids slow download during demo)
5. Builds all 5 attack Docker images and pulls DVWA

Expected finish:
```
✔ All 13 checks passed. Ready to demo.
```

If any check fails, the script tells you exactly which one and how to fix it.

---

## Verify the machine is ready (quick pre-demo check)

Run this any time to confirm the environment is healthy:

```bash
# All scanners present
trivy --version && grype version | grep Version && hadolint --version && dockle --version

# All images built
docker images | grep -E "(case[1-5]|dvwa)"

# Python packages importable
/home/azureuser/miniconda3/bin/python3 -c "import pandas, sklearn; print('Python OK')"

# DVWA running (start it if not)
docker ps | grep dvwa || (cd ss_paper_project && docker compose up -d)
```

---

## Understand what you are about to demonstrate

**Two phases, one argument:**

```
PHASE 1 — Static Analysis (automated, ~3–5 minutes)
  ┌──────────────────────────────────────────────────────────┐
  │  Run 4 scanners against 5 attack images + DVWA           │
  │  Result: all 5 attack images CLEAN                       │
  │          DVWA: 800+ CVEs (correctly caught)              │
  │  Conclusion: a security team approves the attackers      │
  └──────────────────────────────────────────────────────────┘
            ↓ press ENTER to continue
PHASE 2 — Dynamic Runtime Monitoring (live, ongoing)
  ┌──────────────────────────────────────────────────────────┐
  │  Monitor trains on clean behaviour (~25 seconds)         │
  │  Trigger any attack in Terminal 2                        │
  │  Monitor fires [ALERT] [CGROUP-ESCAPE] within 1–30 s    │
  │  docker stats shows container within CPU quota           │
  │  → The gap between the two views IS the attack           │
  └──────────────────────────────────────────────────────────┘
```

**What each static scanner does:**

| Tool | What it examines | What it misses |
|------|-----------------|----------------|
| Trivy | OS packages in the image → known CVEs | Runtime behaviour |
| Grype | Same (independent database) | Runtime behaviour |
| Hadolint | Dockerfile instructions → style/security rules | What the binary does when run |
| Dockle | Built image → setuid files, root user, CIS rules | Why those files are there at runtime |

---

## Run the full automated demo (recommended for presentations)

Open **two terminals** side by side before starting.

### Terminal 1 — start the demo

```bash
cd /home/azureuser/ss-project
sudo bash demo.sh
```

Phase 1 begins immediately. You will see each of the 5 attack images scanned by all 4 tools.

**What to point out as it runs:**

- Cases 1, 2, 4, 5: `✔ Trivy — 0 HIGH/CRITICAL` and `✔ Grype — 0 HIGH/CRITICAL`
  > *"Two independent CVE scanners from different companies, different databases — both say safe."*

- Hadolint on each case: `⚠ 1 style warning — no security issues`
  > *"Dockerfile linter finds a style issue (unpinned apt version). No security problem."*

- Dockle on each case: `⚠ 0 FATAL, 2 WARN (config hygiene only)`
  > *"CIS benchmark checker sees the container runs as root and uses the 'latest' tag.
  >  In Case 3, it even sees that 'su' is a setuid binary — but it cannot know
  >  su will be called 16 times per second to flood the host's logging daemon."*

- Case 3 Trivy: `✘ Trivy — 4 findings (HIGH: 4, CRITICAL: 0)`
  > *"Trivy finds 4 HIGH CVEs. All four are in linux-libc-dev — a kernel SMB reconnection
  >  bug in a header package that has nothing to do with the journald attack.
  >  The actual attack mechanism has zero CVE signature."*

- DVWA: `✘ Trivy — 806 findings (HIGH: 552, CRITICAL: 254)`
  > *"This is static scanning working correctly. Old Apache, PHP, MySQL — hundreds of
  >  known CVEs. But it still cannot detect when those CVEs are actively exploited at runtime."*

Phase 1 ends with the verdict box:
```
║  All 5 attack images: CLEAN across all 4 scanners               ║
║  DVWA (victim): 805 CVEs — but scanners miss live exploitation  ║
```

**Pause here.** This is the moment to let the evidence sink in before moving to Phase 2.

---

## Transition to Phase 2

When you see:
```
Press ENTER to start Phase 2 — live dynamic detection...
```

Before pressing ENTER, explain what is about to happen:
> *"The monitor reads two views simultaneously:
>  docker stats — what the container is charged.
>  /proc/stat and /proc/[pid]/io — what the host kernel actually runs.
>  The gap between those two views is how a cgroup escape is detected."*

Press **ENTER** in Terminal 1.

---

## Monitor training phase

The monitor prints training progress:
```
[+] Training baseline model on clean behaviour...
[TRAIN] 1/25: divergence=0.0%  softirq=0.1%  iowait=0.2%
[TRAIN] 2/25: ...
...
[TRAIN] 25/25: divergence=0.1%  softirq=0.1%  iowait=0.1%
[+] Baseline established.

[+] Starting real-time detection (container + host)...

[HOST] divergence=0.0%  softirq=0.1%  iowait=0.2%  dirty_pages=45  engine_overhead=2.8%
[OK] Normal
```

**Wait until you see `[OK] Normal` before triggering any attack.**

While waiting (~25 seconds), explain the IsolationForest model:
> *"The monitor builds a statistical baseline of what 'clean' looks like — 25 samples of
>  normal divergence, iowait, softirq, and per-process CPU for journald, dockerd, kworker.
>  Anything that deviates from that baseline is flagged. Hard thresholds bypass the ML
>  entirely for obvious spikes."*

---

## Attack 1: Container-level CVE exploitation (trigger_anomalies.sh)

This is the quickest first attack — exercises the container-side CVE detection against DVWA.

**Terminal 2:**
```bash
cd /home/azureuser/ss-project/ss_paper_project/attack
bash trigger_anomalies.sh
```

**Terminal 1 — watch for:**
```
[WARNING] Suspicious patterns (not anomalous yet):
   • CVE-2020-25613 [HIGH]: Web application file upload / webshell

[ALERT] Anomaly detected!

POTENTIAL MATCHES DETECTED:
• CVE-2020-25613 [CONTAINER] [HIGH] (score=8)
  Web application file upload / webshell
  Patterns: .php, shell, webshell
• CVE-2021-44228 [CONTAINER] [CRITICAL] (score=6)
  Log4j remote code execution (Log4Shell)
  Patterns: jndi, ldap://
```

No cleanup needed — all activity was inside the DVWA container.

---

## Attack 2: Cgroup escape — Case 3 (journald amplification)

**This is the most important attack to show.** It is the clearest proof that the container
looks innocent while the host absorbs the real cost.

**Open a third terminal to show docker stats:**
```bash
# Terminal 3 — show what docker stats reports
docker stats case3_journald-attacker-1
```

**Terminal 2:**
```bash
cd /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/case3_journald
docker compose up attacker
```

**Terminal 3 (docker stats) shows:**
```
NAME                         CPU %   MEM USAGE
case3_journald-attacker-1    34.2%   48MiB / 512MiB   ← within its 35% quota
```

**Terminal 1 (monitor) shows:**
```
[HOST] divergence=0.0%  softirq=0.1%  iowait=0.0%  dirty_pages=45
       journald_write_rate_kb_s=415.6  proc_systemd_journald_cpu=4.69
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-3 (journald amplification)

POTENTIAL MATCHES DETECTED:
• HOUDINI-CASE3 [HOST] [HIGH] (score=4)
  Cgroup escape via journald — host logging daemon absorbs I/O and CPU
  Features: journald_write_rate_kb_s=415.6, proc_systemd_journald_cpu=4.69
```

**What to say:**
> *"docker stats reports 34% CPU — the container is within its 35% quota.
>  It looks perfectly normal. But the host /proc shows systemd-journald running at 4.69%
>  and flushing 415 KB/s to disk — work that was triggered by the container but billed
>  to the host. That is the escape. Static scanners saw the 'su' binary in the image.
>  They could never see this."*

**Cleanup:**
```bash
# Terminal 2
docker compose down --remove-orphans
```

---

## Attack 3: Cgroup escape — Case 4 (container engine / TTY flood)

**Important:** this attack MUST use `docker compose up` (foreground), NOT `-d` (detached).
The TTY flood only works when a real terminal is attached.

**Terminal 2:**
```bash
cd /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/case4_container_engine
docker compose up
```

You will see a wall of `/proc/modules` output scrolling — this IS the attack.

**Terminal 1 (monitor) shows:**
```
[HOST] engine_overhead=22.4%  dirty_pages=12500  cpu_divergence=45.2%
[FORCED-ANOMALY] Hard threshold: host:engine_overhead_cpu=22.4 >= 18.0
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-4 (container engine / TTY)
```

**What to say:**
> *"Every line of output flows from the container through dockerd, then through the kernel's
>  TTY line discipline, to kworker threads on the host. None of that CPU is charged to the
>  container's cgroup. The container appears cheap; the host is saturated."*

**Cleanup:**
```bash
# Terminal 2: Ctrl+C then:
docker compose down --remove-orphans
```

---

## Attack 4: Cgroup escape — Case 5 (NET softirq / iptables)

This requires sudo to install 2000 decoy iptables rules on the host.

**Terminal 2:**
```bash
cd /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/case5_softirq
sudo bash setup_iptables.sh
docker compose up
```

**Terminal 1 (monitor) shows:**
```
[HOST] host_softirq_pct=22.4%  softirq_composite=28.1%
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-5 (NET softirq / iptables)
```

**What to say:**
> *"The container sends UDP packets. Each packet traverses 2000 iptables rules on the host.
>  All packet processing runs in softirq/ksoftirqd context — outside any container cgroup.
>  The container's CPU quota is untouched. The host's 'si' column in top rises steadily."*

**Cleanup:**
```bash
# Terminal 2
docker compose down --remove-orphans
sudo bash cleanup_iptables.sh
```

---

## Attack 5: Cgroup escape — Case 1 (coredump helper)

```bash
cd /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/case1_exception_handling
docker compose up
```

**Terminal 1 (monitor) shows:**
```
[HOST] coredump_helper_cpu=35.2%
[FORCED-ANOMALY] Hard threshold: host:coredump_helper_cpu=35.2 >= 30.0
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-1 (exception/coredump helper)
```

**Cleanup:**
```bash
docker compose down --remove-orphans
```

---

## Attack 6: Cgroup escape — Case 2 (data sync / RFA writeback)

Case 2 uses a victim + attacker pair. Follow these steps in order:

```bash
cd /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/case2_data_sync
mkdir -p io_data
docker compose build
docker compose up -d victim
sleep 10
docker compose run --rm attacker
```

**Terminal 1 (monitor) shows:**
```
[HOST] iowait=48.3%  dirty_pages=6200  writeback_rate_pages_s=8000
[ALERT] Anomaly detected!
[CGROUP-ESCAPE] Likely CASE-2 (data sync / RFA writeback)
```

**Cleanup:**
```bash
docker compose down --remove-orphans --volumes
```

---

## Stop the monitor

In Terminal 1: `Ctrl+C`

---

## Run the automated test suite (optional — for verification, not presentation)

This runs all 5 cases unattended with a fresh monitor per case and prints a pass/fail result.
Useful to verify the system works before the demo day. Takes ~20 minutes.

```bash
cd /home/azureuser/ss-project/ss_paper_project

# Run a single case
sudo PYTHON=/home/azureuser/miniconda3/bin/python3 bash test_cgroup_escape.sh case3

# Run all cases
sudo PYTHON=/home/azureuser/miniconda3/bin/python3 bash test_cgroup_escape.sh all
```

Expected output:
```
[PASS] Smoke: monitor running and emitting host metrics
[PASS] Case 1: coredump helper escape detected
[PASS] Case 2: RFA writeback escape detected
[PASS] Case 3: journald escape detected
[PASS] Case 4: container engine TTY escape detected
[PASS] Case 5: NET softirq escape detected
========================================
Results: 6 passed  0 failed  0 skipped
========================================
```

---

## Manual static scanning (alternative to demo.sh Phase 1)

If you prefer to run each scanner individually and explain as you go:

```bash
# --- Trivy ---
trivy image case3_journald-attacker:latest
# Expected: 4 HIGH (linux-libc-dev SMB CVE — unrelated to attack)

trivy image case1_exception_handling-attacker:latest
# Expected: Total: 0 — completely clean

# --- Grype ---
grype case3_journald-attacker:latest
# Expected: 0 HIGH/CRITICAL

# --- Hadolint ---
hadolint container_cgroup_escape_exploitation/attacks/case3_journald/Dockerfile
# Expected: DL3008 style warning only

# --- Dockle ---
dockle case3_journald-attacker:latest
# Expected: 0 FATAL, 2 WARN (root user + latest tag)
# Note: also lists setuid su — Dockle sees the binary, not the runtime abuse

# --- DVWA for contrast ---
trivy image vulnerables/web-dvwa:latest
# Expected: 800+ HIGH/CRITICAL CVEs (old Apache/PHP/MySQL — correctly caught)
```

---

## Alert output legend

```
[OK]              — normal, no anomaly
[WARNING]         — suspicious pattern seen, below anomaly threshold
[INFO]            — IsolationForest flagged it but no named signal matched
[ALERT]           — anomaly + named escape case or CVE pattern confirmed
[FORCED-ANOMALY]  — hard threshold crossed immediately (no ML needed)
[CGROUP-ESCAPE]   — specific Houdini case identified: CASE-1 through CASE-5
```

---

## Host metrics legend

The `[HOST]` line printed every second:

```
[HOST] divergence=X%  softirq=X%  iowait=X%  dirty_pages=N  engine_overhead=X%  coredump_helper=X%
```

| Field | What it measures | Elevated by |
|-------|-----------------|-------------|
| `divergence` | host CPU − sum of container quotas | Cases 1, 4 |
| `softirq` | % CPU in softirq / ksoftirqd | Case 5 |
| `iowait` | % CPU waiting on disk I/O | Case 2 |
| `dirty_pages` | kernel dirty page backlog | Cases 2, 4 |
| `engine_overhead` | dockerd + containerd + kworker CPU | Case 4 |
| `coredump_helper` | apport / systemd-coredump CPU | Case 1 |

---

## Full cleanup after the demo

```bash
# Stop all attack containers
docker compose down --remove-orphans 2>/dev/null || true

# Clean up any leftover case containers
for dir in /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/*/; do
    (cd "$dir" && docker compose down --remove-orphans --volumes 2>/dev/null || true)
done

# Remove iptables rules if Case 5 was run
cd /home/azureuser/ss-project/container_cgroup_escape_exploitation/attacks/case5_softirq
sudo bash cleanup_iptables.sh 2>/dev/null || true

# Keep DVWA running for next demo, or stop it:
cd /home/azureuser/ss-project/ss_paper_project
docker compose down

# Optional: free disk space
docker system prune -f
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `DVWA is not running` | Container stopped | `cd ss_paper_project && docker compose up -d` |
| `Training did not finish within 150s` | DVWA slow to respond | Wait, or restart DVWA |
| Case 1 is SKIP in test suite | apport/coredump helper inactive | `sudo systemctl enable --now apport` |
| Case 5 is SKIP in test suite | Not running as root | `sudo bash test_cgroup_escape.sh case5` |
| `[INFO]` instead of `[ALERT]` | IsolationForest anomaly but no hard threshold crossed | Normal — the ML flagged it but no named signal matched; hard thresholds fire immediately for clear cases |
| Case 4 produces no engine_overhead | Started with `docker compose up -d` | Must use `docker compose up` (attached, with TTY) |
| `pandas` / `sklearn` not found | Wrong Python binary | Use `sudo /home/azureuser/miniconda3/bin/python3 -u monitor.py` |
| `docker: permission denied` | User not in docker group | `sudo usermod -aG docker $USER && newgrp docker` |
| Dockle hangs in demo.sh | Old stuck process from previous run | `sudo pkill -9 -f dockle && sudo pkill -9 -f demo.sh` |

---

## Key talking points (summary for the professor)

1. **Static scanners answer a different question.**
   They ask: "Is this image known to be vulnerable?" The attack images are not.
   They use standard Ubuntu tools with no CVE record.

2. **The attack is a behaviour pattern, not a binary.**
   `su`, `sync()`, `cat`, `logger` — all completely normal syscalls.
   The escape is in the order and frequency of calls, not in what is called.

3. **The signal only exists at runtime.**
   `cpu_divergence = host_cpu − sum(container_cpu)` cannot be computed from an image.
   It requires reading `/proc/stat` and `docker stats` simultaneously and subtracting.

4. **Even Falco (the leading runtime security tool) misses these.**
   Falco watches syscall sequences for suspicious patterns: `execve`, `ptrace`,
   opening `/etc/shadow`. The Houdini attacks use only legitimate syscalls — there is
   no suspicious sequence to match. The signal is in the accounting gap, not the calls.

5. **Dockle sees the weapon, not the crime.**
   Dockle correctly flags `setuid su` in Case 3. But "su is setuid" is normal on any
   Ubuntu system. Only runtime monitoring reveals that su is being called 16 times per
   second to flood the host's journald daemon.

---

## Quick reference card (print this for the demo day)

```
SETUP (once, before demo day)
  sudo bash setup.sh

DEMO DAY
  Terminal 1:   sudo bash demo.sh
                → Phase 1 (static scans, ~5 min, all attack images CLEAN)
                → Press ENTER for Phase 2
                → Wait for [OK] Normal

  Terminal 2 (after [OK] Normal):
    CVE attacks: cd ss_paper_project/attack && bash trigger_anomalies.sh
    Case 3:      cd attacks/case3_journald && docker compose up attacker
    Case 4:      cd attacks/case4_container_engine && docker compose up
    Case 5:      cd attacks/case5_softirq && sudo bash setup_iptables.sh && docker compose up
    Case 1:      cd attacks/case1_exception_handling && docker compose up
    Case 2:      cd attacks/case2_data_sync && docker compose up -d victim && sleep 10 && docker compose run --rm attacker

  Terminal 3 (contrast view):
    docker stats   ← shows container within its CPU quota while monitor fires ALERT

CLEANUP BETWEEN CASES
  docker compose down --remove-orphans
  sudo bash cleanup_iptables.sh   (Case 5 only)

FULL CLEANUP
  cd /home/azureuser/ss-project && bash -c '
    for d in container_cgroup_escape_exploitation/attacks/*/; do
      (cd "$d" && docker compose down --remove-orphans --volumes 2>/dev/null || true)
    done'
```
