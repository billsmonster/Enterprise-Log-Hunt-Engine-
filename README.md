# ELHE — Enterprise Log Hunt Engine (Single-File Threat Hunting Tool)

A **portfolio-ready** Python threat-hunting engine that ingests **Windows EVTX logs (Security + Sysmon)**, normalizes events, enriches them, and runs **behavioral detections** mapped to **MITRE ATT&CK**. It supports **baseline/anomaly hunting**, **allowlists**, **config files**, and **JSON/JSONL/CSV** export — all in **one file**.

---

## What this tool does

ELHE is built to answer a practical question:

> “If I only had raw endpoint logs, what kinds of attacker behavior could I reliably hunt for?”

###  Ingests

* Windows Event Logs (**EVTX**)

  * `Security.evtx`
  * `Microsoft-Windows-Sysmon%4Operational.evtx` (Sysmon Operational)

###  Normalizes

Converts raw EVTX XML records into a unified `NormEvent` model (timestamp, user, src_ip, process, cmdline, etc.) so rules can be consistent across sources.

###  Enriches (offline)

Without internet or APIs, ELHE adds fast context:

* private/public IP classification
* URL extraction from command lines
* base64-blob detection (obfuscation hint)
* suspicious CLI flag detection (`-enc`, `iex`, `downloadstring`, etc.)

###  Detects (rule-based)

**Lateral movement**

* RDP logons (4624 LogonType 10)
* NTLM network logons (4624 LogonType 3)
* Explicit credential usage (4648)
* Remote service creation / PsExec-style (7045)

**Privilege escalation**

* Special privileges assigned (4672)
* Added to privileged groups (4728 / 4732 / 4756)

**LOLBin abuse**

* PowerShell / EncodedCommand
* rundll32, regsvr32, mshta
* certutil “download”-style usage
* bitsadmin
* wmic process call create

###  Correlates (heuristic)

Detects suspicious parent/child chains like:

* `WINWORD.EXE → powershell.exe`
* `powershell.exe → rundll32.exe / mshta.exe / regsvr32.exe`

###  Baseline / anomaly mode

Two-pass scan (`--baseline`) that highlights:

* **NEW source IP for a user** during logons

###  Outputs

* Console summary (top rules, severities, users, IPs)
* Export findings:

  * `--format json`
  * `--format jsonl`
  * `--format csv`

---

## Installation

### Requirements

* Python 3.10+ recommended (3.8+ should work)
* Windows is recommended for auto-discovery, but you can parse EVTX anywhere.

### Install dependencies

```bash
pip install python-evtx
```

Optional (nice-to-have):

```bash
pip install tqdm pyyaml
```

---

## Quick start

### 1) Run with zero arguments (Windows auto-discovery)

```bash
python Chap10.py
```

ELHE will try:

* `C:\Windows\System32\winevt\Logs\Security.evtx`
* `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`

### 2) Run against explicit logs

```bash
python Chap10.py --logs "C:\Windows\System32\winevt\Logs\Security.evtx"
```

### 3) Baseline + time window + export

```bash
python Chap10.py --baseline --since 2025-12-01T00:00:00Z --until 2025-12-12T23:59:59Z --out findings.json --format json
```

### 4) Export CSV

```bash
python Chap10.py --logs "C:\Windows\System32\winevt\Logs\Security.evtx" --out findings.csv --format csv
```

### 5) List all rules

```bash
python Chap10.py --list-rules
```

### 6) Run built-in self-tests

```bash
python Chap10.py --selftest
```

---

## Filtering and tuning

### Time filters

* `--since` and `--until` accept ISO timestamps:

```bash
python Chap10.py --since 2025-12-01T00:00:00Z
```

### Enable only certain rules

```bash
python Chap10.py --enable-rules LM-RDP-4624-LT10 LOL-POWERSHELL-ENC
```

### Disable noisy rules

```bash
python Chap10.py --disable-rules LM-SMB-NTLM-4624-LT3
```

---

## Allowlists (reduce false positives)

### Allowlist users

Create a file like `allow-users.txt`:

```txt
# service accounts
svc_backup
svc_patch
domain\svc_automation
```

Run:

```bash
python Chap10.py --allow-users allow-users.txt
```

### Allowlist IPs

Create `allow-ips.txt`:

```txt
# jump hosts / management servers
10.0.10.5
10.0.20.6
```

Run:

```bash
python Chap10.py --allow-ips allow-ips.txt
```

---

## Config file support (YAML or JSON)

### Example `elhe.yml`

```yaml
logs:
  - "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
baseline: true
since: "2025-12-01T00:00:00Z"
format: "json"
out: "findings.json"
disable_rules:
  - "LM-SMB-NTLM-4624-LT3"
```

Run:

```bash
python Chap10.py --config elhe.yml
```

> YAML requires `pyyaml` (`pip install pyyaml`). Otherwise use JSON config.

---

## Output format (findings)

Each finding includes:

* rule metadata (ID, title, ATT&CK technique, severity)
* confidence (baseline boosts)
* enrichment fields (URLs, base64 flag, suspicious flags, private/public IP)
* triage fields (why it matters, next steps, tuning)
* full normalized event record

This is designed to be easy to:

* grep/search
* parse into other tools
* import into a SIEM pipeline later

---

## MITRE ATT&CK coverage (examples)

* T1021.001 — Remote Services: RDP
* T1021.002 — SMB/Windows Admin Shares
* T1569.002 — System Services (remote service execution)
* T1059.001 — PowerShell
* T1218.* — Signed Binary Proxy Execution
* T1027 — Obfuscation
* T1098 — Account manipulation / group changes

---

## Known limitations (current version)

* EVTX only (Linux auth + firewall logs not yet implemented in this file)
* `--mp` flag is present but currently reserved (single-process execution for stability)
* Sorting is “best effort” using timestamp strings (could be upgraded to real datetime sort)

---

## Roadmap ideas (great portfolio upgrades)

If you want ELHE to look even more “enterprise”:

* CIDR allowlists (`10.0.0.0/8`)
* Baseline anomalies for:

  * new host for user
  * new process on host
* Rule indexing (run only rules relevant to an event_id)
* Add Sigma rule support (basic YAML Sigma parsing + field mapping)
* Add Linux auth + firewall log ingestion (normalized into the same model)

---

## License

Choose one:

* MIT License (recommended for portfolio)
* Apache 2.0

Built by Derek (portfolio project): threat-hunting focused log engine demonstrating detection engineering, Windows logging knowledge, and analyst-friendly output design.
