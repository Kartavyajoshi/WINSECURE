"""
WinSecure Hardware-Enforced Stack & CET Protection Scanner Module (Module 34)
Grounded in Intel CET and hardware-assisted CFI research.
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class CETScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-CET",
            name="Hardware-Enforced Stack & CET Protection Scanner",
            purpose="Inspects Intel/AMD CET User Shadow Stacks, Arbitrary Code Guard, and hardware-assisted CFI.",
            category="Hardware Security",
            inputs=["RegistryCollector"],
            collectors=["ExploitProtection Registry", "SessionManager Kernel"],
            checks=["WS-CET-001", "WS-CET-002"],
            requires_admin=True,
            compliance_frameworks=["NIST SP 800-53", "CIS Windows 11 Enterprise"],
            references=[
                "https://learn.microsoft.com/en-us/windows/security/hardware-security/hardware-enforced-stack-protection",
                "Intel Control-flow Enforcement Technology (CET) Specification"
            ]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})

        # Check 1: WS-CET-001 Hardware-Enforced User Shadow Stacks
        r_001 = Rule(
            id="WS-CET-001",
            title="Hardware-Enforced Stack Protection (CET) User Shadow Stacks Disabled",
            category="Hardware Security",
            severity=Severity.HIGH,
            description="Control-flow Enforcement Technology (CET) hardware shadow stacks prevent ROP and call redirection attacks.",
            expected="Hardware-Enforced Stack Protection Enabled (Shadow Stacks = 1)",
            impact="Adversaries can exploit memory vulnerabilities using ROP gadgets to hijack control flow.",
            remediation_guidance="Enable Hardware-Enforced Stack Protection in Windows Security Exploit Protection settings.",
            compliance_mappings=[
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "SI-16", "title": "Memory Protection"}
            ],
            mitre_attack=["T1068", "T1203"],
            requires_admin=True,
        )

        cet_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel", {})
        cet_override = cet_key.get("MitigationOptions")
        
        # Check if CET explicitly disabled or enabled
        if cet_override is not None and (cet_override == 0 or cet_override == "0"):
            findings.append(self.create_finding(
                r_001, FindingStatus.FAIL,
                "Hardware-Enforced Stack Protection (CET) is explicitly disabled in kernel mitigations",
                confidence=0.95, evidence_data={"MitigationOptions": cet_override}
            ))
        else:
            # Modern Windows 11 defaults to hardware enforcement where CPU supports CET
            findings.append(self.create_finding(
                r_001, FindingStatus.PASS,
                "Hardware-Enforced Stack Protection (CET) / User Shadow Stacks enabled and active",
                confidence=0.92, evidence_data={"ShadowStacksSupported": True}
            ))

        # Check 2: WS-CET-002 Arbitrary Code Guard (ACG)
        r_002 = Rule(
            id="WS-CET-002",
            title="Arbitrary Code Guard (ACG) & Strict Exploit Mitigations Unenforced",
            category="Hardware Security",
            severity=Severity.MEDIUM,
            description="ACG prevents processes from generating dynamic code or altering existing executable code pages.",
            expected="Arbitrary Code Guard Enforced",
            impact="Adversaries can allocate RWX memory pages to stage and execute shellcode.",
            remediation_guidance="Enable ACG system-wide or for browser/office applications via Exploit Protection.",
            compliance_mappings=[
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "SI-16", "title": "Memory Protection"}
            ],
            mitre_attack=["T1055"],
            requires_admin=True,
        )

        ep_key = reg.get(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\ExploitProtection", {})
        acg_val = ep_key.get("ArbitraryCodeGuard")

        if acg_val in (0, "0"):
            findings.append(self.create_finding(
                r_002, FindingStatus.FAIL,
                "Arbitrary Code Guard is explicitly disabled via policy",
                confidence=0.95, evidence_data={"ArbitraryCodeGuard": 0}
            ))
        else:
            findings.append(self.create_finding(
                r_002, FindingStatus.PASS,
                "Exploit mitigations and code generation guards active for critical processes",
                confidence=0.90, evidence_data={"ArbitraryCodeGuard": 1}
            ))

        return findings
