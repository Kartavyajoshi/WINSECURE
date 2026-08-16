# WinSecure — Automated Cybersecurity Assessment & Posture Analysis Platform

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-lightgrey.svg)](https://microsoft.com/windows)
[![Tests: Passing](https://img.shields.io/badge/Tests-37%20Passing-brightgreen.svg)](tests/)

WinSecure is a modular, automated cybersecurity configuration assessment, compliance verification, and threat-exposure analysis platform engineered for Microsoft Windows operating systems. It executes deterministic, non-destructive, read-only diagnostic inspections across core operating system subsystems, correlating low-level telemetry into prioritized risk metrics, compliance mappings, and actionable remediation scripts.

---

## 1. Core Architectural Capabilities

- **Deterministic Configuration Analysis**: Evaluates 30 security domains and 55+ defensive assertions covering credential protection (LSA RunAsPPL), virtualization-based security (VBS/HVCI), network protocol exposure (SMBv1, LLMNR, RDP NLA), Defender behavioral telemetry, and audit logging policies.
- **Context-Aware Processing**: Implements a shared assessment context pipeline where host discovery, service enumeration, and attack surface detection feed sequentially into targeted vulnerability checks and evidence correlation.
- **Multi-Attribute Risk Engine**: Computes objective security posture scores (0-100) using mathematical penalty deduction models weighted by finding severity, detection confidence, and asset importance.
- **Compliance Baseline Mapping**: Maps discovered configurations against CIS Controls v8, CIS Windows 11 Benchmarks, NIST SP 800-53 Rev 5, DISA STIG, and Microsoft Security Baselines.
- **Automated PowerShell Remediation**: Synthesizes syntax-validated, copyable PowerShell hardening commands and generates consolidated master remediation scripts (`WinSecure-Remediation.ps1`).
- **Zero-Cloud Air-Gapped Operation**: 100% offline execution with zero external network callbacks, telemetry telemetry leakage, or third-party cloud dependencies.

---

## 2. Quickstart & Single-Command Launcher

### 2.1 Prerequisites
- Operating System: Windows 10, Windows 11, or Windows Server 2016+ (x64 / ARM64)
- Python: Version 3.9 or higher
- Permissions: Standard user for baseline assessment; local administrator required for full LSA and low-level registry hive auditing.

### 2.2 Launching the Synthetic Demonstration Platform
WinSecure includes a dedicated, reproducible demonstration environment pre-populated with synthetic laboratory assessment data (`LAB-WIN-042`):

```bash
# Clone the repository
git clone https://github.com/Kartavyajoshi/WINSECURE.git
cd WINSECURE

# Launch the synthetic demonstration platform on localhost (default: port 8080)
python run.py demo
```

Open `http://127.0.0.1:8080/` in your browser to interact with the dashboard, findings explorer, compliance mapping, timeline, and report generator.

---

## 3. Command-Line Interface (CLI) Reference

The `winsecure` CLI provides comprehensive subcommands for live system scanning, demonstration hosting, benchmarking, and testing:

```bash
# Execute standard live system scan and launch local web report
python -m winsecure scan --serve

# Execute full audit and output reports to a custom directory
python -m winsecure scan --profile full --output ./Audit-Results

# Run synthetic assessment using an offline fixture JSON
python -m winsecure scan --fixture ./fixtures/synthetic_lab_assessment.json --serve

# Execute automated throughput and latency benchmarks
python -m winsecure benchmark --iterations 10

# Run unit and integration test suite
python run.py test
```

---

## 4. Assessment Workflow & Pipeline Architecture

```
User / Operator (CLI / Web UI)
         │
         ▼
[1] Environment Discovery          (OS Build, Architecture, Secure Boot, TPM State)
         │
         ▼
[2] Security Telemetry Collection  (Registry, Services, Firewall, Accounts, Audit, BitLocker)
         │
         ▼
[3] Configuration Assessment       (30 Modular Scanners evaluate assertions against telemetry)
         │
         ▼
[4] Threat-Exposure Analysis       (Correlate MITRE ATT&CK vectors and network listeners)
         │
         ▼
[5] Compliance Baseline Mapping    (CIS Benchmarks, NIST SP 800-53, DISA STIG, MS Baselines)
         │
         ▼
[6] Risk Deduction Calculus        (Deduction = Penalty x Weight x Confidence)
         │
         ▼
[7] Report & Script Generation     (Synthesize Executive Briefing, Remediation Scripts, Web UI)
         │
         ▼
[8] Artifact Storage & History     (SQLite Database, JSON/HTML Reports, Audit Logs)
```

---

## 5. Modular Adapter & Plugin System

WinSecure decouples collection and analysis logic from external tooling via a standardized adapter contract (`winsecure.adapters.base.BaseAdapter`). Every adapter produces normalized assessment output:

```json
{
  "module": "service_analyzer",
  "version": "1.1.0",
  "capability": "service_and_socket_analysis",
  "target": "LAB-WIN-042",
  "status": "completed",
  "execution_time_ms": 14.80,
  "findings": [
    {
      "id": "SEC-009",
      "title": "Unquoted Service Executable Path Detected",
      "severity": "Medium",
      "confidence": "High",
      "category": "Services",
      "affected_component": "Service: AppManagementHelper",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AppManagementHelper' -Name 'ImagePath' -Value '\"C:\\Program Files\\App Helper\\service.exe\"'"
    }
  ],
  "evidence": [
    {
      "source": "services_collector",
      "total_services_audited": 84,
      "unquoted_count": 1
    }
  ],
  "metadata": {"services_count": 84},
  "risk": {"unquoted_services": 1},
  "timestamp": "2026-08-16T18:04:37Z"
}
```

### Active Core Adapters:
1. `host_discovery` (v1.2.0): System architecture, UEFI Secure Boot, TPM 2.0, and hardware security.
2. `service_analyzer` (v1.1.0): Windows services, binary permissions, and unquoted executable paths.
3. `config_auditor` (v1.3.0): LSA protection, UAC architecture, Defender telemetry, and Firewall profiles.
4. `vulnerability_analyzer` (v1.2.0): Attack surface analysis, legacy protocols (SMBv1, LLMNR), and servicing status.
5. `policy_compliance` (v1.1.0): Consensus baseline and control framework alignment mapping.

---

## 6. Risk Scoring Methodology

The WinSecure risk scoring engine calculates a normalized security score between `0.0` and `100.0` based on evaluated defensive controls:

$$\text{Deduction} = \text{Base Severity Penalty} \times \text{Asset Weight} \times \text{Detection Confidence}$$

### Posture Levels:
- **EXCELLENT (90.0 - 100.0)**: Comprehensive defensive alignment with zero critical or high-priority defects.
- **STRONG (80.0 - 89.9)**: Strong baseline configurations; minor warnings or low-severity deviations identified.
- **MODERATE (70.0 - 79.9)**: Moderate risk posture; high-priority defects present requiring corrective remediation.
- **DEGRADED (50.0 - 69.9)**: Elevated risk exposure across multiple core defensive subsystems.
- **CRITICAL (0.0 - 49.9)**: Severe misconfigurations present; critical exposure to unauthenticated exploitation.

---

## 7. Synthetic Demonstration Dataset Specification

To protect privacy and ensure reproducible evaluations, the demonstration interface and sample reports operate entirely on synthetic laboratory data:

- **Target Identifier**: `LAB-WIN-042`
- **Environment**: `Security Assessment Lab`
- **IP Address**: `192.0.2.42` (RFC 5737 Documentation Range)
- **Assessment Identifier**: `ASSESS-2026-00142`
- **Simulated Score**: `72.0 / 100` (MODERATE)
- **Defect Distribution**: 2 Critical, 7 High, 14 Medium, 19 Low, 11 Informational

---

## 8. Security & Operational Safety

- **Read-Only Safety Guarantee**: Core collection routines query operating system APIs, WMI classes, and registry hives exclusively via non-modifying read operations.
- **Subprocess Isolation**: External tool adapters execute through structured argument arrays rather than shell string concatenation, preventing command injection vulnerabilities.
- **Air-Gapped Telemetry**: Reports are compiled with self-contained CSS, JavaScript, and data payloads; no external CDN requests or remote fonts are required.

---

## 9. Limitations & Scope Boundaries

- **Permissions Boundary**: Certain low-level hives (such as raw SAM database hashes or protected LSA policy keys) require administrative privilege (`Run as Administrator`). Running under an unprivileged user context will mark restricted checks with appropriate access notices.
- **Assessment Scope**: Security assessment scores evaluate configuration posture and known local attack surface exposures; they do not replace full network penetration tests, dynamic application security testing (DAST), or physical security audits.
- **Compliance Wording**: Compliance alignment metrics represent technical mapping against published security recommendations and do not constitute formal regulatory certification.

---

## 10. License & Legal Disclaimers

WinSecure is open-source software developed by **Kartavya Joshi** and licensed under the **Apache-2.0 License**.

- **Trademarks**: *Microsoft, Windows, Windows Defender, BitLocker, PowerShell, CIS Benchmark, NIST, DISA STIG, and MITRE ATT&CK* are trademarks of their respective owners and are referenced under nominative Fair Use for technical identification and diagnostic mapping purposes.
- For full license terms and conditions, consult [`LICENSE`](LICENSE).
