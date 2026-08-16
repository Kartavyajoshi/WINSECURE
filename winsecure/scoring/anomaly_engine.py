"""
WinSecure Configuration Anomaly Detection Engine
"""
from typing import Any, Dict, List
from winsecure.models.finding import Finding, FindingStatus


class AnomalyEngine:
    """
    Detects unusual, high-risk security posture combinations.
    Uses defensive, objective language.
    """

    @staticmethod
    def detect_anomalies(findings: List[Finding]) -> List[Dict[str, Any]]:
        anomalies = []
        status_by_id = {f.id: f.status for f in findings}

        # Anomaly 1: Real-Time Protection Disabled + RDP Exposed
        if status_by_id.get("WS-DEF-001") == FindingStatus.FAIL and status_by_id.get("WS-RDP-001") == FindingStatus.FAIL:
            anomalies.append({
                "id": "ANOMALY-001",
                "title": "Unprotected Remote Access Posture",
                "description": "Microsoft Defender Real-Time Protection is disabled while Remote Desktop is enabled without NLA enforcement.",
                "risk": "High Exposure",
                "recommendation": "Immediately enable Defender RTP and enforce NLA on all remote access ports.",
            })

        # Anomaly 2: Public Firewall Disabled + SMBv1 Enabled
        if status_by_id.get("WS-FW-001") == FindingStatus.FAIL and status_by_id.get("WS-SMB-001") == FindingStatus.FAIL:
            anomalies.append({
                "id": "ANOMALY-002",
                "title": "Unfiltered Legacy Wormable Protocol Exposure",
                "description": "Public firewall profile is inactive while legacy SMBv1 protocol is enabled, creating severe exposure to network worm replication.",
                "risk": "Critical Exposure",
                "recommendation": "Disable SMBv1 immediately and activate the Public firewall profile.",
            })

        # Anomaly 3: UAC Disabled + LSA Protection Disabled
        if status_by_id.get("WS-UAC-001") == FindingStatus.FAIL and status_by_id.get("WS-REG-001") == FindingStatus.FAIL:
            anomalies.append({
                "id": "ANOMALY-003",
                "title": "Severe Credential & Privilege Boundary Weakening",
                "description": "User Account Control is disabled alongside unshielded LSA memory (RunAsPPL=0), allowing unprivileged processes to dump administrative credentials.",
                "risk": "Critical Exposure",
                "recommendation": "Re-enable UAC Admin Approval Mode and enable LSA Protected Process Light.",
            })

        # Anomaly 4: Script Block Logging Disabled + Execution Policy Bypass
        if status_by_id.get("WS-PS-001") == FindingStatus.FAIL and status_by_id.get("WS-PS-002") == FindingStatus.FAIL:
            anomalies.append({
                "id": "ANOMALY-004",
                "title": "Unmonitored Script Execution Environment",
                "description": "PowerShell Script Block Logging is disabled while script execution policy is unrestricted or bypassed.",
                "risk": "Forensic Blindspot",
                "recommendation": "Enable PowerShell Script Block Logging and set ExecutionPolicy to RemoteSigned.",
            })

        return anomalies
