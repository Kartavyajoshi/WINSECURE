"""
WinSecure Installed Software Inventory & Vulnerability Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class SoftwareScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-SOFTWARE",
            name="Installed Software Inventory & Exposure Scanner",
            purpose="Inventories installed 32-bit and 64-bit applications and detects obsolete, end-of-life software lines.",
            category="Installed Software",
            inputs=["SoftwareCollector"],
            collectors=["Registry Uninstall Keys"],
            checks=["WS-SW-001"],
            requires_admin=False,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53"],
            references=["https://learn.microsoft.com/en-us/windows/client-management/manage-apps-with-intune"]
        )

    def run(self) -> List[Finding]:
        findings = []
        sw_data = self.context.collected_artifacts.get("software", {})
        installed = sw_data.get("installed_software") or []

        r_001 = Rule(
            id="WS-SW-001",
            title="Outdated or End-of-Life Software Detected (Vulnerability Risk)",
            category="Installed Software",
            severity=Severity.MEDIUM,
            description="Installed applications matching deprecated or unsupported lines present unpatched attack surfaces.",
            expected="All installed software updated to supported versions",
            impact="Known CVE vulnerabilities in legacy software can be exploited.",
            remediation_guidance="Uninstall obsolete applications or upgrade to latest vendor release.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.1.1", "title": "Software Inventory"}
            ],
            mitre_attack=["T1190"],
            requires_admin=False,
        )

        deprecated_keywords = ["adobe flash", "java 7", "java 6", "python 2.7", "silverlight", "quicktime"]
        matched = []
        for app in installed:
            if not isinstance(app, dict):
                continue
            name = str(app.get("name", "")).lower()
            if any(k in name for k in deprecated_keywords):
                matched.append(app)

        if matched:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"Detected {len(matched)} deprecated software packages", confidence=0.95, evidence_data=matched))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, "No deprecated/EOL software packages detected", confidence=0.95))

        return findings
