# WinSecure — Automated Cybersecurity Assessment & Posture Analysis Platform

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-lightgrey.svg)](https://microsoft.com/windows)
[![Tests: Passing](https://img.shields.io/badge/Tests-43%20Passing-brightgreen.svg)](tests/)
[![Docs: Live](https://img.shields.io/badge/Docs-Live%20Website-blueviolet.svg)](https://kartavyajoshi.github.io/WINSECURE/)

WinSecure is a modular, automated cybersecurity configuration assessment, compliance verification, and threat-exposure analysis platform engineered for Microsoft Windows operating systems. It executes deterministic, non-destructive, read-only diagnostic inspections across core operating system subsystems, correlating low-level telemetry into prioritized risk metrics, compliance mappings, multi-format audit reports, and actionable remediation scripts.

🌐 **Live Interactive Website & Threat Matrix**: [https://kartavyajoshi.github.io/WINSECURE/](https://kartavyajoshi.github.io/WINSECURE/)

---

## 1. Core Architectural Capabilities

- **Deterministic Configuration Analysis**: Evaluates 32 specialized security modules and 55 defensive assertions covering credential protection (LSA RunAsPPL), virtualization-based security (VBS/HVCI), network protocol exposure (SMBv1, LLMNR, RDP NLA), Defender behavioral telemetry, and audit logging policies.
- **Real-Time Execution & Streaming Engine**: Live terminal execution stream with real-time per-test feedback, collector latencies, evidence previews, and continuous progress counters.
- **Multi-Attribute Risk Engine**: Computes objective security posture scores (0–100) using mathematical penalty deduction models weighted by finding severity, detection confidence, and asset importance.
- **Compliance Baseline Mapping**: Maps discovered configurations against CIS Controls v8, CIS Windows 11 Enterprise Benchmarks (v5.0.1), NIST SP 800-53 Rev 5, DISA STIG (v1r3), and Microsoft Security Baselines (23H2).
- **Automated PowerShell Remediation**: Synthesizes syntax-validated, copyable PowerShell hardening commands and generates consolidated master remediation scripts (`WinSecure-Remediation-Master.ps1`).
- **Zero-Cloud Air-Gapped Operation**: 100% offline execution with zero external network callbacks, telemetry leakage, or third-party cloud dependencies.
- **Multi-Format Export**: Generates interactive single-file HTML reports, machine-readable JSON (`scan_results.json`), CSV matrices (`findings.csv`), Markdown summaries (`report.md`), GitHub Security SARIF (`sarif.json`), and execution logs (`logs/latest.log`).

---

## 2. Quickstart & Command Reference

### 2.1 Prerequisites
- **Operating System**: Windows 10, Windows 11, or Windows Server 2016+ (x64 / ARM64)
- **Python**: Version 3.9 or higher
- **Permissions**: Standard User for baseline assessment; Administrator (`Run as Administrator`) recommended for complete low-level registry hive and LSA auditing.

### 2.2 Running a Scan

```bash
# 1. Run standard live security assessment
python run.py scan

# 2. Run scan with verbose telemetry & evidence preview
python run.py scan --verbose

# 3. Run scan and automatically launch interactive report dashboard in browser
python run.py scan --serve

# 4. Run offline synthetic assessment using benchmark fixture
python run.py scan --fixture fixtures/standard_enterprise.json

# 5. Run full automated test suite (43 unit & integration tests)
python run.py test

# 6. Execute benchmark suite
python run.py benchmark --iterations 5
```

---

## 3. CLI Command Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `scan` | Run full Windows security audit | — |
| `--output`, `-o` | Directory for generated report artifacts | `./WinSecure-Report` |
| `--profile`, `-p` | Assessment profile level (`standard`, `hardened`, `quick`, `full`) | `standard` |
| `--fixture` | Path to synthetic test fixture JSON (for offline / CI simulation) | — |
| `--verbose`, `-v` | Display verbose test evidence and remediation details in real time | `False` |
| `--debug`, `-d` | Display full debugging telemetry and stack traces | `False` |
| `--serve`, `-s` | Launch local HTTP server and open report in browser | `False` |
| `--port` | Port to bind for local web server | `8080` |
| `test` | Run complete unit and integration test suite | — |
| `benchmark` | Run performance and check throughput benchmarks | — |
| `version` | Display product version and metadata | — |

---

## 4. Assessment Workflow & Pipeline Architecture

```
User / Operator (CLI / Web UI)
         │
         ▼
[1] Pre-Flight Health Check        (Python Version, Rule Catalogs, Permissions, Logging)
         │
         ▼
[2] Environment Discovery          (OS Build, Architecture, Secure Boot, TPM State)
         │
         ▼
[3] Security Telemetry Collection  (WMI, Registry, Services, Firewall, Accounts, Audit, BitLocker)
         │
         ▼
[4] Configuration Assessment       (32 Modular Scanners evaluate 55 assertions against telemetry)
         │
         ▼
[5] Threat-Exposure Analysis       (Correlate MITRE ATT&CK vectors and network listeners)
         │
         ▼
[6] Compliance Baseline Mapping    (CIS Benchmarks, NIST SP 800-53, DISA STIG, MS Baselines)
         │
         ▼
[7] Risk Deduction Calculus        (Deduction = Severity Penalty x Asset Weight x Confidence)
         │
         ▼
[8] Multi-Format Report Generation (Interactive HTML, JSON, CSV, Markdown, SARIF, PowerShell Fixes)
```

---

## 5. 32 Security Inspection Modules

WinSecure audits 32 core Windows defense subsystems:

1. **Secure Boot & Firmware Security (`WS-SYSTEM`)**: UEFI Secure Boot, TPM 2.0 readiness, Kernel DMA protection.
2. **Microsoft Defender Antivirus (`WS-DEFENDER`)**: Real-time inspection, Cloud intelligence, behavior monitoring, PUA, IOAV.
3. **Windows Firewall Boundary Profiles (`WS-FIREWALL`)**: Domain, Private, and Public inbound block rules.
4. **Local Account & Password Hardening (`WS-ACCOUNTS`)**: Guest account lockouts, Administrator protections, lockout thresholds.
5. **User Rights & Privileges (`WS-PRIVILEGES`)**: Excessive local administrator group memberships and token rights.
6. **Windows Services Security (`WS-SERVICES`)**: Unquoted service binary paths and unprivileged service permissions.
7. **Startup & Registry Persistence (`WS-STARTUP`)**: User Run and RunOnce autorun registry persistence vector analysis.
8. **Scheduled Tasks Security (`WS-TASKS`)**: Tasks executing from user-writable temporary paths (%TEMP%, %APPDATA%).
9. **Windows Registry Hardening (`WS-REGISTRY`)**: LSA Protection (RunAsPPL), WDigest plaintext caching, Safe DLL search.
10. **PowerShell Security Configuration (`WS-POWERSHELL`)**: Script Block Logging (Event 4104), Transcription, Execution Policy.
11. **Windows Audit Policy Hardening (`WS-AUDIT`)**: Process Creation (Event 4688), CLI parameter logging, Logon auditing.
12. **Event Log Infrastructure (`WS-EVENTLOGS`)**: Security event log maximum retention size (>1GB) and overwrite safeguards.
13. **Windows Servicing & Updates (`WS-UPDATES`)**: Pending reboots and critical security cumulative update installation state.
14. **SMB Protocol & Server Security (`WS-SMB`)**: SMBv1 removal, SMB Server packet signing, guest authentication blocking.
15. **Remote Access & RDP Hardening (`WS-REMOTE`)**: Network Level Authentication (NLA) enforcement and RDP encryption levels.
16. **Network Exposure & Name Resolution (`WS-NETWORK`)**: LLMNR multicast poisoning defense and NetBIOS hygiene.
17. **BitLocker Volume Encryption (`WS-BITLOCKER`)**: Full volume encryption with TPM 2.0 hardware-backed PIN protectors.
18. **User Account Control (`WS-UAC`)**: Admin Approval Mode, Consent prompts, Secure Desktop elevation prompts.
19. **Defender SmartScreen Platform (`WS-SMARTSCREEN`)**: Explorer reputation checks and malicious download blocking.
20. **Installed Software Exposure (`WS-SOFTWARE`)**: Vulnerable, deprecated, and end-of-life installed software package audit.
21. **Application Control & AppLocker (`WS-APPLOCKER`)**: Application Identity service (AppIDSvc) and whitelisting readiness.
22. **Virtualization-Based Security (`WS-VBS`)**: Hypervisor-Enforced Code Integrity (HVCI) and Memory Integrity state.
23. **Windows LAPS Solution (`WS-LAPS`)**: Local Administrator Password Solution automatic rotation policy.
24. **Attack Surface Reduction (`WS-ASR`)**: Exploit Guard Attack Surface Reduction rules against macro & script threats.
25. **System Exploit Guard Mitigations (`WS-EXPLOITGUARD`)**: System-wide DEP, ASLR, CFG, and SEHOP memory corruption protection.
26. **Cryptography & TLS Ciphers (`WS-SCHANNEL`)**: Insecure TLS 1.0/1.1 deprecation and TLS 1.2/1.3 enforcement.
27. **Kerberos Authentication (`WS-KERBEROS`)**: Disabling legacy DES/RC4 cipher types in Kerberos ticket exchanges.
28. **Windows Sandbox Isolation (`WS-SANDBOX`)**: Windows Hypervisor container substrate for ephemeral sandboxing.
29. **Print Spooler Hardening (`WS-SPOOLER`)**: Print Spooler service exposure auditing against PrintNightmare RPC vectors.
30. **Microsoft Edge Security Baseline (`WS-BROWSER`)**: Enterprise browser SmartScreen and download security enforcement.
31. **Active Directory Domain Member (`WS-AD`)**: LDAP client signing and Netlogon secure channel session encryption.
32. **Sysmon Advanced Telemetry (`WS-SYSMON`)**: Kernel-level event tracing for process injection and file creations.

---

## 6. Generated Report Artifacts

After each assessment, the output directory (`./WinSecure-Report`) contains:

```
WinSecure-Report/
├── index.html                  # Master interactive standalone SaaS audit dashboard
├── report.js                   # Client-side interactive engine (filters, modal, search)
├── report.css                  # Clean SaaS theme styles (100% offline)
├── scan_results.json           # Machine-readable complete scan telemetry
├── findings.csv                # Tabular finding matrix for spreadsheet import
├── report.md                   # Formatted GitHub Flavored Markdown audit report
└── sarif.json                  # OASIS SARIF v2.1.0 report for CI/CD pipelines
```

---

## 7. Risk Scoring Methodology

The WinSecure risk engine calculates a normalized security score between `0.0` and `100.0`:

$$\text{Deduction} = \text{Base Severity Penalty} \times \text{Asset Weight} \times \text{Detection Confidence}$$

### Posture Classification:
- **EXCELLENT (90.0 – 100.0)**: Comprehensive defensive alignment with zero critical or high-priority defects.
- **STRONG (80.0 – 89.9)**: Strong baseline configurations; minor warnings or low-severity deviations identified.
- **MODERATE (70.0 – 79.9)**: Moderate risk posture; high-priority defects present requiring corrective remediation.
- **DEGRADED (50.0 – 69.9)**: Elevated risk exposure across multiple core defensive subsystems.
- **CRITICAL (0.0 – 49.9)**: Severe misconfigurations present; critical exposure to unauthenticated exploitation.

---

## 8. Security & Operational Safety

- **Read-Only Non-Destructive Operation**: Collection routines query operating system APIs, WMI classes, and registry hives exclusively via non-modifying read operations.
- **Subprocess Isolation & Security**: External tool adapters execute through structured argument arrays rather than raw shell strings, preventing command injection.
- **Air-Gapped Telemetry**: Reports are compiled with self-contained CSS, JavaScript, and pre-rendered HTML; no external CDN requests or remote fonts are required.

---

## 9. License & Author

WinSecure is open-source software developed by **Kartavya Joshi** and licensed under the **Apache-2.0 License**.

- **Author**: Kartavya Joshi
- **GitHub Repository**: [https://github.com/Kartavyajoshi/WINSECURE](https://github.com/Kartavyajoshi/WINSECURE)
- **License**: Consult [`LICENSE`](LICENSE) for complete terms.
