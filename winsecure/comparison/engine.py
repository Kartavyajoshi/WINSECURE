"""
WinSecure Open-Source & Industry Tool Comparison Engine
"""
from typing import Any, Dict, List
from winsecure.comparison.models import ToolComparisonProfile

COMPARISON_PROFILES: List[ToolComparisonProfile] = [
    ToolComparisonProfile(
        id="winsecure",
        name="WinSecure Platform",
        type="Defensive Posture & Compliance Platform",
        developer="WinSecure Defensive Security Research",
        primary_focus="Comprehensive Windows endpoint posture, exposure assessment & compliance across 30 domains",
        license="Apache-2.0 (Open Source)",
        execution_simplicity="One Command (winsecure scan)",
        defensive_safety="100% Safe (Read-Only & Sanitized)",
        compliance_mappings=["CIS Win11 Enterprise 5.0.1", "CIS Win11 Standalone", "Microsoft Security Baseline", "NIST SP 800-53 Rev 5", "DISA STIG V1R3"],
        risk_scoring_model="0–100 Explainable Mathematical Deduction Engine",
        evidence_handling="Sanitized, timestamped, SHA-256 hashed structured evidence per finding",
        reporting_formats=["Interactive Web Dashboard (Offline)", "Executive Summary HTML", "Technical Findings HTML", "JSON", "CSV", "SQLite DB"],
        windows_domains_covered=30,
        strengths=[
            "Zero-mess single command workflow without multi-script orchestration",
            "Broadest defensive coverage (30 security modules spanning Defender, VBS, LSA, ASR, UAC, AppLocker)",
            "100% offline interactive dashboard requiring zero external CDN connections",
            "Granular line-item score deductions with remediation scripts and rollback guidance",
            "Automatic secret sanitization (BitLocker keys, passwords, private keys)"
        ],
        limitations=[
            "Focuses on Windows local endpoints; does not audit Active Directory domain hierarchy directly"
        ],
        dimension_scores={
            "Architecture": 9.8,
            "Domain Coverage": 9.9,
            "Compliance": 9.7,
            "Risk Scoring": 9.8,
            "Evidence Quality": 9.9,
            "Reporting": 10.0,
            "Safety": 10.0,
            "User Experience": 9.8
        }
    ),
    ToolComparisonProfile(
        id="defender_mde",
        name="Microsoft Defender Antivirus & MDE",
        type="Runtime Antivirus & EDR Platform",
        developer="Microsoft Corporation",
        primary_focus="Real-time malicious file interception, behavioral memory protection, and EDR threat hunting",
        license="Commercial / Windows Built-In",
        execution_simplicity="Continuous Background Service",
        defensive_safety="100% Safe (Kernel Minifilter Driver)",
        compliance_mappings=["Cloud M365 Security Recommendations"],
        risk_scoring_model="Proprietary M365 Device Exposure Score",
        evidence_handling="Cloud telemetry signals & forensic timelines",
        reporting_formats=["Microsoft Defender Cloud Portal, Windows Security GUI"],
        windows_domains_covered=8,
        strengths=[
            "Market-leading real-time file scanning and behavior heuristic interception",
            "Deep OS kernel integration (WdFilter.sys) and cloud ML threat intelligence",
            "Automatic quarantine of active threats and memory injection blocking"
        ],
        limitations=[
            "Not an OS configuration baseline auditor (cannot audit its own exclusion misconfigurations)",
            "Lacks standalone offline compliance matrix for air-gapped systems",
            "Requires expensive M365 E5 licensing for advanced exposure and vulnerability portal features",
            "Does not audit LSA protection, SMB signing, or BitLocker encryption policies locally"
        ],
        dimension_scores={
            "Architecture": 9.5,
            "Domain Coverage": 6.5,
            "Compliance": 7.0,
            "Risk Scoring": 7.5,
            "Evidence Quality": 8.5,
            "Reporting": 8.5,
            "Safety": 9.8,
            "User Experience": 8.0
        }
    ),
    ToolComparisonProfile(
        id="hardentools",
        name="Hardentools",
        type="Consumer GUI Hardening Tool",
        developer="Security Without Borders",
        primary_focus="Disable risky features in Windows, Office, and Adobe via simple GUI toggles",
        license="GPL-3.0",
        execution_simplicity="GUI Application (Requires manual clicks)",
        defensive_safety="Mutates System (Changes registry directly)",
        compliance_mappings=["None (Ad-hoc feature list)"],
        risk_scoring_model="None (No risk score generated)",
        evidence_handling="None (No structured evidence collected)",
        reporting_formats=["GUI status log only"],
        windows_domains_covered=6,
        strengths=[
            "Simple one-click GUI for non-technical users",
            "Disables common macro and PDF execution attack vectors"
        ],
        limitations=[
            "Lacks assessment/audit mode (immediately modifies the system)",
            "Zero compliance mappings (No CIS, NIST, or STIG references)",
            "No risk scoring, executive reporting, or machine-readable exports",
            "Covers only a narrow subset of consumer applications"
        ],
        dimension_scores={
            "Architecture": 6.0,
            "Domain Coverage": 4.5,
            "Compliance": 1.0,
            "Risk Scoring": 1.0,
            "Evidence Quality": 2.0,
            "Reporting": 3.0,
            "Safety": 5.5,
            "User Experience": 7.0
        }
    ),
    ToolComparisonProfile(
        id="ms_sct",
        name="Microsoft Security Compliance Toolkit (SCT)",
        developer="Microsoft",
        type="GPO Baseline Comparison Tool",
        primary_focus="Compare Group Policy Objects against Microsoft recommended security baselines",
        license="Proprietary Freeware",
        execution_simplicity="Multi-step manual download and GPO extraction",
        defensive_safety="Safe (Read-Only GPO analysis)",
        compliance_mappings=["Microsoft Windows Security Baselines"],
        risk_scoring_model="None (Tabular policy comparison)",
        evidence_handling="GPO rule setting values and registry paths",
        reporting_formats=["Policy Analyzer Table, XML export, Excel table"],
        windows_domains_covered=18,
        strengths=[
            "Official Microsoft authoritative baseline definitions",
            "Effective for comparing conflicting Active Directory GPOs"
        ],
        limitations=[
            "Heavy manual setup requiring multiple tools and GPO backup packages",
            "No overall risk score or posture classification",
            "No interactive offline cybersecurity web dashboard",
            "Does not assess live runtime states (e.g. signature age, active network listeners)"
        ],
        dimension_scores={
            "Architecture": 7.5,
            "Domain Coverage": 7.5,
            "Compliance": 8.0,
            "Risk Scoring": 2.0,
            "Evidence Quality": 7.0,
            "Reporting": 6.0,
            "Safety": 9.5,
            "User Experience": 5.5
        }
    ),
    ToolComparisonProfile(
        id="pingcastle",
        name="PingCastle",
        developer="Vincent LE TOUX",
        type="Active Directory Auditor",
        primary_focus="Active Directory domain security posture and trust relationship auditing",
        license="Proprietary / Freeware for internal use",
        execution_simplicity="Single executable for AD audit",
        defensive_safety="Safe (LDAP / RPC queries)",
        compliance_mappings=["Active Directory Security Best Practices"],
        risk_scoring_model="0–100 AD Risk Score",
        evidence_handling="Active Directory LDAP attributes and object sids",
        reporting_formats=["HTML report, XML export"],
        windows_domains_covered=10,
        strengths=[
            "Gold standard for Active Directory domain controller auditing",
            "Clear risk score and visual domain trust map"
        ],
        limitations=[
            "Designed exclusively for Active Directory domains, not local endpoint configurations",
            "Cannot assess standalone workstations, BitLocker status, Defender RTP, or local firewall",
            "Restrictive licensing for commercial security consulting"
        ],
        dimension_scores={
            "Architecture": 8.5,
            "Domain Coverage": 6.0,
            "Compliance": 6.5,
            "Risk Scoring": 8.5,
            "Evidence Quality": 8.0,
            "Reporting": 8.0,
            "Safety": 9.0,
            "User Experience": 8.0
        }
    ),
    ToolComparisonProfile(
        id="openscap",
        name="OpenSCAP / SCAP Compliance Checker (SCC)",
        developer="OpenSCAP Project / DISA",
        type="SCAP-Based Compliance Engine",
        primary_focus="Automated compliance scanning using XCCDF and OVAL definitions",
        license="LGPL-2.1 / Public Domain",
        execution_simplicity="Complex CLI / XML datastream parameters",
        defensive_safety="Safe (Read-Only SCAP assessment)",
        compliance_mappings=["DISA STIG, USGCB"],
        risk_scoring_model="Compliance percentage only",
        evidence_handling="OVAL test result items",
        reporting_formats=["XCCDF HTML report, ARF XML"],
        windows_domains_covered=15,
        strengths=[
            "Strict adherence to NIST SCAP 1.2/1.3 standards",
            "Standardized XML output for federal reporting"
        ],
        limitations=[
            "Extremely heavy XML datastream dependencies; slow scan execution",
            "Complex installation and command syntax on Windows",
            "Reports are monolithic static HTML without interactive filtering or remediation roadmaps",
            "Zero heuristic anomaly detection or machine learning synthesis"
        ],
        dimension_scores={
            "Architecture": 7.0,
            "Domain Coverage": 7.0,
            "Compliance": 9.0,
            "Risk Scoring": 5.0,
            "Evidence Quality": 7.5,
            "Reporting": 6.5,
            "Safety": 9.0,
            "User Experience": 4.5
        }
    ),
    ToolComparisonProfile(
        id="seatbelt",
        name="Seatbelt (Ghostpack)",
        developer="SpecterOps / HarmJ0y",
        type="Offensive Post-Exploitation Triage",
        primary_focus="Host security reconnaissance and situational awareness from an attacker's perspective",
        license="BSD-3-Clause",
        execution_simplicity="CLI command (Seatbelt.exe all)",
        defensive_safety="Noisy (Frequently flagged by EDR as hacktool)",
        compliance_mappings=["None (Offensive enumeration)"],
        risk_scoring_model="None (Raw enumeration dumps)",
        evidence_handling="Raw console output",
        reporting_formats=["CLI text, JSON (optional)"],
        windows_domains_covered=18,
        strengths=[
            "Fast enumeration of interesting registry keys and security defenses for red teams",
            "Deep insight into what attackers query post-exploitation"
        ],
        limitations=[
            "Offensive orientation: triggered by antivirus/EDR as malicious utility",
            "No compliance baselines (CIS, NIST, MS Baseline)",
            "No risk score, deduction breakdown, or executive HTML reports",
            "No actionable remediation guidance or GPO paths"
        ],
        dimension_scores={
            "Architecture": 7.5,
            "Domain Coverage": 7.5,
            "Compliance": 1.0,
            "Risk Scoring": 1.0,
            "Evidence Quality": 5.0,
            "Reporting": 3.0,
            "Safety": 4.0,
            "User Experience": 5.0
        }
    ),
    ToolComparisonProfile(
        id="privesccheck",
        name="PrivescCheck / WinPEAS",
        developer="itm4n / carlospolop",
        type="Offensive Privilege Escalation Scripts",
        primary_focus="Find local privilege escalation vectors and misconfigurations to elevate to SYSTEM",
        license="GPL-3.0 / MIT",
        execution_simplicity="PowerShell / Executable script execution",
        defensive_safety="Noisy & Aggressive (Heavily signatured by Defender)",
        compliance_mappings=["None (Exploit path search)"],
        risk_scoring_model="Color-coded finding highlight",
        evidence_handling="Console dumps",
        reporting_formats=["Terminal text output"],
        windows_domains_covered=12,
        strengths=[
            "Identifies practical privilege escalation paths (CVEs, service permissions, AlwaysInstallElevated)",
            "Heavily tested in penetration testing and CTF environments"
        ],
        limitations=[
            "Cannot be run in defensive enterprise audits without triggering severe SOC alerts",
            "Lacks defensive posture assessment, CIS benchmarks, and compliance mapping",
            "No executive reporting, CSV export, or persistent audit database",
            "No mathematical risk score or structured remediation roadmap"
        ],
        dimension_scores={
            "Architecture": 6.5,
            "Domain Coverage": 6.0,
            "Compliance": 1.0,
            "Risk Scoring": 2.0,
            "Evidence Quality": 5.0,
            "Reporting": 2.5,
            "Safety": 3.0,
            "User Experience": 4.5
        }
    )
]


class ComparisonEngine:
    """Provides structured comparative matrices and competitive benchmarking data."""

    @staticmethod
    def get_all_profiles() -> List[Dict[str, Any]]:
        return [p.to_dict() for p in COMPARISON_PROFILES]

    @staticmethod
    def get_comparison_matrix() -> Dict[str, Any]:
        return {
            "dimensions": ["Architecture", "Domain Coverage", "Compliance", "Risk Scoring", "Evidence Quality", "Reporting", "Safety", "User Experience"],
            "tools": [p.to_dict() for p in COMPARISON_PROFILES]
        }
