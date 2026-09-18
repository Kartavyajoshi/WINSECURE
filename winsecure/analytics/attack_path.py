"""
WinSecure Attack Path Synthesis & Blast Radius Analysis Engine
Grounded in peer-reviewed research:
- Noel & Jajodia: "Metrics Suite for Network Attack Graphs" (IEEE/ACM)
- Poolsappasit, Dewri, & Ray: "Bayesian Attack Graphs for Dynamic Risk Management" (IEEE TDSC 2012)
- Milajerdi et al.: "HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows" (IEEE S&P 2019)
"""
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Set
from winsecure.models.finding import Finding, FindingStatus, Severity


@dataclass
class AttackStep:
    phase: str
    control_id: str
    description: str
    mitre_technique: str


@dataclass
class AttackPath:
    id: str
    name: str
    severity: Severity
    description: str
    mitre_tactics: List[str]
    steps: List[AttackStep]
    affected_control_ids: List[str]
    choke_point_control_id: str
    choke_point_remediation: str
    choke_point_powershell: str
    blast_radius_contribution: float  # 0 to 100

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value if hasattr(self.severity, "value") else str(self.severity)
        return d


@dataclass
class ChokePoint:
    control_id: str
    title: str
    paths_severed_count: int
    severed_path_ids: List[str]
    powershell_remediation: str
    risk_reduction_impact: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


ATTACK_PATH_TEMPLATES = [
    {
        "id": "AP-001",
        "name": "LSASS Memory Credential Theft & Domain Lateral Movement",
        "severity": Severity.CRITICAL,
        "description": "Adversaries leverage unhardened LSA process memory and plaintext credential caching to dump Kerberos tickets and NT hashes for domain lateral movement.",
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "required_any_of_group_a": ["WS-REG-001", "WS-REG-002", "WS-CG-001"],
        "required_any_of_group_b": ["WS-PRIV-001", "WS-UAC-001", "WS-UAC-003"],
        "steps": [
            AttackStep("Execution", "WS-UAC-001", "Adversary gains elevated context without desktop prompt", "T1548.002"),
            AttackStep("Credential Access", "WS-REG-001", "LSA RunAsPPL disabled allows read access to lsass.exe process memory", "T1003.001"),
            AttackStep("Credential Access", "WS-REG-002", "WDigest plaintext credentials cached in LSASS memory", "T1003.001"),
            AttackStep("Lateral Movement", "WS-KERB-001", "Extracted tickets permit Kerberoasting and Pass-The-Hash lateral movement", "T1550.002"),
        ],
        "choke_point": "WS-REG-001",
        "choke_title": "Enforce LSA Protection (RunAsPPL) & Credential Guard",
        "powershell": 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord; Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord',
        "base_blast_radius": 28.0,
    },
    {
        "id": "AP-002",
        "name": "Lateral Wormable Spreading via Insecure Protocol Exposure",
        "severity": Severity.CRITICAL,
        "description": "Adversary captures NTLM authentication challenges via multicast poisoning and relays them over unsigned SMB channels for unauthenticated remote code execution.",
        "mitre_tactics": ["Credential Access", "Lateral Movement"],
        "required_any_of_group_a": ["WS-NET-001"],
        "required_any_of_group_b": ["WS-SMB-001", "WS-SMB-002", "WS-FW-001"],
        "steps": [
            AttackStep("Discovery", "WS-NET-001", "LLMNR multicast queries broadcasted across local network segment", "T1557.001"),
            AttackStep("Credential Access", "WS-NET-001", "Adversary captures NetNTLMv2 hashes using Responder/Inveigh", "T1557.001"),
            AttackStep("Lateral Movement", "WS-SMB-002", "SMB signing not enforced allows relay of captured challenge to target host", "T1557.001"),
            AttackStep("Lateral Movement", "WS-SMB-001", "Legacy SMBv1 protocol enables wormable remote exploitation (e.g. EternalBlue)", "T1210"),
        ],
        "choke_point": "WS-SMB-002",
        "choke_title": "Mandate SMB Packet Signing and Disable LLMNR Multicast",
        "powershell": 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force',
        "base_blast_radius": 24.0,
    },
    {
        "id": "AP-003",
        "name": "Ransomware Extortion & Shadow Copy Annihilation Chain",
        "severity": Severity.CRITICAL,
        "description": "Ransomware operators bypass folder shielding, delete Volume Shadow Copies to block recovery, and encrypt user data across all volumes.",
        "mitre_tactics": ["Impact", "Defense Evasion"],
        "required_any_of_group_a": ["WS-RSM-001", "WS-RSM-002"],
        "required_any_of_group_b": ["WS-DEF-001", "WS-DEF-002", "WS-ENC-001"],
        "steps": [
            AttackStep("Defense Evasion", "WS-DEF-001", "Defender Real-Time Protection or Behavior Monitor degraded", "T1562.001"),
            AttackStep("Impact", "WS-RSM-001", "Controlled Folder Access disabled allows arbitrary file encryption", "T1486"),
            AttackStep("Impact", "WS-RSM-002", "Volume Shadow Copies (VSS) unprotected against vssadmin/wmic deletion", "T1490"),
            AttackStep("Impact", "WS-ENC-001", "Unencrypted drive volumes expose unmanaged data to extortion", "T1486"),
        ],
        "choke_point": "WS-RSM-001",
        "choke_title": "Enable Defender Controlled Folder Access & Protect Volume Shadow Copies",
        "powershell": 'Set-MpPreference -EnableControlledFolderAccess Enabled; vssadmin create shadow /for=C:',
        "base_blast_radius": 26.0,
    },
    {
        "id": "AP-004",
        "name": "PrintNightmare & Insecure Service Local Privilege Escalation",
        "severity": Severity.HIGH,
        "description": "Adversary abuses active Print Spooler service on a non-server workstation combined with unquoted service paths to achieve NT AUTHORITY\\SYSTEM execution.",
        "mitre_tactics": ["Privilege Escalation", "Persistence"],
        "required_any_of_group_a": ["WS-SPL-001"],
        "required_any_of_group_b": ["WS-SVC-001", "WS-TASK-001"],
        "steps": [
            AttackStep("Discovery", "WS-SPL-001", "Print Spooler service running exposed on client endpoint", "T1046"),
            AttackStep("Privilege Escalation", "WS-SPL-001", "Adversary injects malicious print driver (PrintNightmare CVE-2021-34527)", "T1068"),
            AttackStep("Persistence", "WS-SVC-001", "Unquoted service binary path hijacked for persistent elevated launch", "T1574.009"),
        ],
        "choke_point": "WS-SPL-001",
        "choke_title": "Disable Spooler Service on Non-Print Server Endpoints",
        "powershell": 'Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled',
        "base_blast_radius": 18.0,
    },
    {
        "id": "AP-005",
        "name": "Living-Off-The-Land (LOLBins) Stealth Script Execution & Evasion",
        "severity": Severity.HIGH,
        "description": "Adversaries execute malicious payloads through trusted native Windows binaries (certutil, mshta) without script logging or language mode restrictions.",
        "mitre_tactics": ["Defense Evasion", "Execution"],
        "required_any_of_group_a": ["WS-LOL-001", "WS-LOL-002"],
        "required_any_of_group_b": ["WS-PS-001", "WS-AUD-001", "WS-ASR-001"],
        "steps": [
            AttackStep("Execution", "WS-LOL-001", "Unrestricted native utilities permit LOLBin payload staging and execution", "T1218"),
            AttackStep("Defense Evasion", "WS-PS-001", "PowerShell Script Block Logging disabled conceals obfuscated invocations", "T1059.001"),
            AttackStep("Defense Evasion", "WS-AUD-001", "Process Creation command-line parameters unlogged, blinding SIEM detection", "T1059"),
        ],
        "choke_point": "WS-LOL-001",
        "choke_title": "Deploy WDAC Recommended Block Rules and Enable Script Block Logging",
        "powershell": 'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord; Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord',
        "base_blast_radius": 16.0,
    },
    {
        "id": "AP-006",
        "name": "Autorun & Unsanitized Task Reboot Persistence",
        "severity": Severity.MEDIUM,
        "description": "Adversary anchors execution persistence in user-writable registry autorun keys and scheduled tasks that launch binaries from temporary directories.",
        "mitre_tactics": ["Persistence", "Privilege Escalation"],
        "required_any_of_group_a": ["WS-START-001"],
        "required_any_of_group_b": ["WS-TASK-001", "WS-REG-003"],
        "steps": [
            AttackStep("Persistence", "WS-START-001", "User Run/RunOnce key contains unsigned launch binary", "T1547.001"),
            AttackStep("Persistence", "WS-TASK-001", "Scheduled task executes binary located in writable temp directory", "T1053.005"),
        ],
        "choke_point": "WS-START-001",
        "choke_title": "Audit and Purge Unapproved Startup Persistence Vectors",
        "powershell": 'Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" | Out-String',
        "base_blast_radius": 10.0,
    }
]


class AttackPathEngine:
    """
    Synthesizes discrete misconfigurations into multi-stage attack paths
    and computes blast radius and choke point optimizations.
    """

    @classmethod
    def analyze(cls, findings: List[Finding]) -> Dict[str, Any]:
        failing_ids: Set[str] = {
            f.id for f in findings if f.status in (FindingStatus.FAIL, FindingStatus.WARN)
        }

        detected_paths: List[AttackPath] = []
        total_blast_radius = 0.0

        for tmpl in ATTACK_PATH_TEMPLATES:
            # Check if group A and group B triggers exist
            group_a = any(cid in failing_ids for cid in tmpl["required_any_of_group_a"])
            group_b = any(cid in failing_ids for cid in tmpl["required_any_of_group_b"])

            if group_a and group_b:
                affected_ids = [s.control_id for s in tmpl["steps"] if s.control_id in failing_ids]
                if not affected_ids:
                    affected_ids = [tmpl["required_any_of_group_a"][0], tmpl["required_any_of_group_b"][0]]

                path = AttackPath(
                    id=tmpl["id"],
                    name=tmpl["name"],
                    severity=tmpl["severity"],
                    description=tmpl["description"],
                    mitre_tactics=tmpl["mitre_tactics"],
                    steps=tmpl["steps"],
                    affected_control_ids=affected_ids,
                    choke_point_control_id=tmpl["choke_point"],
                    choke_point_remediation=tmpl["choke_title"],
                    choke_point_powershell=tmpl["powershell"],
                    blast_radius_contribution=tmpl["base_blast_radius"],
                )
                detected_paths.append(path)
                total_blast_radius += tmpl["base_blast_radius"]

        # Compute normalized Blast Radius Score (0 to 100)
        blast_radius_score = min(100.0, round(total_blast_radius, 1))

        if blast_radius_score >= 70.0:
            blast_level = "CRITICAL BLAST RADIUS"
        elif blast_radius_score >= 45.0:
            blast_level = "HIGH BLAST RADIUS"
        elif blast_radius_score >= 20.0:
            blast_level = "MODERATE BLAST RADIUS"
        elif blast_radius_score > 0.0:
            blast_level = "LOW BLAST RADIUS"
        else:
            blast_level = "MINIMAL (HARDENED)"

        # Calculate Strategic Choke Points
        choke_map: Dict[str, Dict[str, Any]] = {}
        for path in detected_paths:
            cp_id = path.choke_point_control_id
            if cp_id not in choke_map:
                choke_map[cp_id] = {
                    "control_id": cp_id,
                    "title": path.choke_point_remediation,
                    "paths_severed": [],
                    "powershell": path.choke_point_powershell,
                    "impact": 0.0,
                }
            choke_map[cp_id]["paths_severed"].append(path.id)
            choke_map[cp_id]["impact"] += path.blast_radius_contribution

        choke_points = [
            ChokePoint(
                control_id=data["control_id"],
                title=data["title"],
                paths_severed_count=len(data["paths_severed"]),
                severed_path_ids=data["paths_severed"],
                powershell_remediation=data["powershell"],
                risk_reduction_impact=round(data["impact"], 1),
            )
            for data in choke_map.values()
        ]
        # Sort by number of severed paths descending
        choke_points.sort(key=lambda c: (c.paths_severed_count, c.risk_reduction_impact), reverse=True)

        return {
            "blast_radius_score": blast_radius_score,
            "blast_radius_level": blast_level,
            "detected_paths_count": len(detected_paths),
            "attack_paths": [p.to_dict() for p in detected_paths],
            "choke_points": [cp.to_dict() for cp in choke_points],
            "research_citations": [
                "Noel & Jajodia: Metrics Suite for Network Attack Graphs (IEEE/ACM)",
                "Poolsappasit et al.: Bayesian Attack Graphs for Dynamic Risk Management (IEEE TDSC 2012)",
                "Milajerdi et al.: HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows (IEEE S&P 2019)"
            ]
        }
