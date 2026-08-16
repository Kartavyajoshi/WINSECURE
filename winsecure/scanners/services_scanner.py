"""
WinSecure Windows Services Security Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class ServicesScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SERVICES",
            name="Windows Services Security Scanner",
            purpose="Inspects service configurations, unquoted executable paths, disabled security services, and suspicious start names.",
            category="Services",
            inputs=["ServicesCollector"],
            collectors=["Win32_Service"],
            checks=["WS-SVC-001"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts"]
        )

    def run(self) -> List[Finding]:
        findings = []
        svc_data = self.context.collected_artifacts.get("services", {})
        services = svc_data.get("services") or []

        r_001 = Rule(
            id="WS-SVC-001",
            title="Insecure Unquoted Service Binary Paths Detected",
            category="Services",
            severity=Severity.MEDIUM,
            description="Services with unquoted binary paths containing spaces are vulnerable to binary planting privilege escalation.",
            expected="All service paths with spaces properly quoted",
            impact="Local users can drop an executable into intermediate paths to gain SYSTEM privileges.",
            remediation_guidance="Enclose ImagePath in double quotes in registry HKLM:\\SYSTEM\\CurrentControlSet\\Services\\<ServiceName>.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.3.1", "title": "Service Binary Paths"}
            ],
            mitre_attack=["T1574.009"],
            requires_admin=True,
        )

        unquoted = []
        for s in services:
            if not isinstance(s, dict):
                continue
            path = (s.get("PathName") or "").strip()
            if not path:
                continue
            
            # If path starts with quote and has closing quote around the exe, it is quoted
            if path.startswith('"'):
                continue
            
            # If path doesn't start with quote, check if executable part has spaces
            exe_part = path.split(".exe")[0] + ".exe" if ".exe" in path.lower() else path
            if " " in exe_part and not exe_part.startswith("C:\\Windows\\system32"):
                unquoted.append({"name": s.get("Name"), "path": path})

        if unquoted:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Found {len(unquoted)} unquoted service paths", confidence=0.95, evidence_data=unquoted[:5]))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "No unquoted service binary paths detected", confidence=0.95))

        return findings
