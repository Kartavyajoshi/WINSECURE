"""
WinSecure MITRE ATT&CK Matrix & Technique Exporter
"""
import json
import os
from typing import Any, Dict, List
from winsecure.models.scan import ScanResult


class MitreAttackExporter:
    """Exports findings categorized by MITRE ATT&CK Enterprise Tactics & Techniques."""

    TACTIC_MAPPINGS = {
        "T1562": "Defense Evasion",
        "T1562.001": "Defense Evasion: Disable or Modify Tools",
        "T1562.002": "Defense Evasion: Disable Windows Event Logging",
        "T1562.004": "Defense Evasion: Disable or Modify System Firewall",
        "T1078": "Valid Accounts",
        "T1078.001": "Valid Accounts: Default Accounts",
        "T1078.003": "Valid Accounts: Local Accounts",
        "T1110": "Credential Access: Brute Force",
        "T1110.001": "Credential Access: Password Guessing",
        "T1003": "Credential Access: OS Credential Dumping",
        "T1003.001": "Credential Access: LSASS Memory",
        "T1548": "Privilege Escalation: Abuse Elevation Control",
        "T1548.002": "Privilege Escalation: Bypass User Account Control",
        "T1210": "Lateral Movement: Exploitation of Remote Services",
        "T1021": "Lateral Movement: Remote Services",
        "T1021.001": "Lateral Movement: Remote Desktop Protocol",
        "T1059": "Execution: Command and Scripting Interpreter",
        "T1059.001": "Execution: PowerShell",
        "T1059.005": "Execution: Visual Basic",
        "T1547": "Persistence: Boot or Logon Autostart Execution",
        "T1547.001": "Persistence: Registry Run Keys / Startup Folder",
        "T1053": "Execution: Scheduled Task/Job",
        "T1053.005": "Execution: Scheduled Task",
        "T1574": "Persistence: Hijack Execution Flow",
        "T1574.001": "Persistence: DLL Search Order Hijacking",
        "T1574.009": "Persistence: Unquoted Service Path",
        "T1557": "Credential Access: Adversary-in-the-Middle",
        "T1557.001": "Credential Access: LLMNR/NBT-NS Poisoning and Relay",
        "T1558": "Credential Access: Steal or Forge Kerberos Tickets",
        "T1558.003": "Credential Access: Kerberoasting",
        "T1204": "Execution: User Execution",
        "T1204.001": "Execution: Malicious Link",
        "T1204.002": "Execution: Malicious File",
        "T1068": "Privilege Escalation: Exploitation for Privilege Escalation",
        "T1190": "Initial Access: Exploit Public-Facing Application",
        "T1005": "Collection: Data from Local System",
        "T1542": "Defense Evasion: Pre-OS Boot",
        "T1542.003": "Defense Evasion: Bootkit",
        "T1203": "Execution: Exploitation for Client Execution",
        "T1055": "Defense Evasion: Process Injection",
    }

    @classmethod
    def export(cls, result: ScanResult, output_dir: str) -> str:
        mitre_path = os.path.join(output_dir, "data", "mitre_attack.json")
        os.makedirs(os.path.dirname(mitre_path), exist_ok=True)

        techniques_map = {}
        for f in result.findings:
            for tech in f.mitre_attack:
                if tech not in techniques_map:
                    tech_name = cls.TACTIC_MAPPINGS.get(tech, "General Technique")
                    tactic = tech_name.split(":")[0] if ":" in tech_name else tech_name
                    techniques_map[tech] = {
                        "technique_id": tech,
                        "technique_name": tech_name,
                        "tactic": tactic,
                        "findings": [],
                        "status": "PASS"
                    }
                techniques_map[tech]["findings"].append({
                    "id": f.id,
                    "title": f.title,
                    "status": f.status.value,
                    "severity": f.severity.value
                })
                if f.status.value == "FAIL":
                    techniques_map[tech]["status"] = "FAIL"

        matrix_data = {
            "total_techniques_mapped": len(techniques_map),
            "failing_techniques_count": sum(1 for t in techniques_map.values() if t["status"] == "FAIL"),
            "techniques": list(techniques_map.values())
        }

        with open(mitre_path, "w", encoding="utf-8") as f:
            json.dump(matrix_data, f, indent=2)

        return mitre_path
