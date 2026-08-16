"""
WinSecure Core Registry Hardening Scanner Module
"""
from typing import List
from winsecure.models.finding import Finding, FindingStatus, Severity
from winsecure.models.module import ModuleMetadata
from winsecure.models.rule import Rule
from winsecure.scanners.base import BaseScanner


class RegistryScanner(BaseScanner):
    @property
    def metadata(self) -> ModuleMetadata:
        return ModuleMetadata(
            id="WS-REGISTRY",
            name="Windows Registry Hardening Scanner",
            purpose="Assesses LSA Protection (RunAsPPL), WDigest plaintext credential caching, LAN Manager authentication level, and Safe DLL Search Mode.",
            category="Registry",
            inputs=["RegistryCollector"],
            collectors=["HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"],
            checks=["WS-REG-001", "WS-REG-002", "WS-REG-003", "WS-REG-004"],
            requires_admin=True,
            compliance_frameworks=["CIS Windows 11 Enterprise", "NIST SP 800-53", "Microsoft Security Baseline"],
            references=["https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/"]
        )

    def run(self) -> List[Finding]:
        findings = []
        reg = self.context.collected_artifacts.get("registry", {})
        lsa_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", {})
        wdigest_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", {})
        sm_key = reg.get(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager", {})

        # 1. RunAsPPL (WS-REG-001)
        r_001 = Rule(
            id="WS-REG-001",
            title="LSA Protection (RunAsPPL) is Disabled (Mimikatz Vulnerable)",
            category="Registry",
            severity=Severity.HIGH,
            description="Configuring LSASS as a Protected Process Light (PPL) prevents non-protected administrative processes from dumping credentials.",
            expected="RunAsPPL = 1 or 2",
            impact="Credential-dumping utilities (Mimikatz, procdump) can easily extract plaintext passwords and NTLM hashes from memory.",
            remediation_guidance="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.27.1", "title": "LSASS Protected Process"},
                {"framework": "NIST SP 800-53", "version": "Rev 5", "control_id": "IA-5", "title": "Authenticator Management"}
            ],
            mitre_attack=["T1003.001"],
            requires_admin=True,
        )
        ppl = lsa_key.get("RunAsPPL")
        if ppl in [1, 2, "1", "2"]:
            findings.append(self.create_finding(r_001, FindingStatus.PASS, f"RunAsPPL = {ppl} (LSA Protection Active)", confidence=0.99, evidence_data={"RunAsPPL": ppl}))
        elif ppl == 0 or ppl == "0":
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, f"RunAsPPL = {ppl} (Disabled - Mimikatz vulnerable)", confidence=0.99, evidence_data={"RunAsPPL": ppl}))
        else:
            findings.append(self.create_finding(r_001, FindingStatus.FAIL, "RunAsPPL key missing (Default disabled on older builds)", confidence=0.90))

        # 2. WDigest (WS-REG-002)
        r_002 = Rule(
            id="WS-REG-002",
            title="WDigest Plaintext Credential Caching is Enabled",
            category="Registry",
            severity=Severity.CRITICAL,
            description="WDigest provider caches cleartext credentials in LSASS memory if UseLogonCredential is set to 1.",
            expected="UseLogonCredential = 0",
            impact="Cleartext user passwords can be retrieved directly from memory by local administrators.",
            remediation_guidance="Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.27.2", "title": "WDigest Cleartext Storage"}
            ],
            mitre_attack=["T1003.001"],
            requires_admin=True,
        )
        wdig = wdigest_key.get("UseLogonCredential")
        if wdig in [0, "0", None]:
            findings.append(self.create_finding(r_002, FindingStatus.PASS, "UseLogonCredential = 0 or absent (Cleartext caching disabled)", confidence=0.99, evidence_data={"UseLogonCredential": 0}))
        else:
            findings.append(self.create_finding(r_002, FindingStatus.FAIL, f"UseLogonCredential = {wdig} (Cleartext caching ENABLED)", confidence=0.99, evidence_data={"UseLogonCredential": wdig}))

        # 3. LmCompatibilityLevel (WS-REG-003)
        r_003 = Rule(
            id="WS-REG-003",
            title="LAN Manager (LM) Authentication Level Permits Insecure NTLMv1",
            category="Registry",
            severity=Severity.HIGH,
            description="LMCompatibilityLevel must be set to 5 (Send NTLMv2 response only / refuse LM & NTLM).",
            expected="LmCompatibilityLevel = 5",
            impact="Legacy LM and NTLMv1 responses transmitted over the network can be cracked in minutes.",
            remediation_guidance="Set LmCompatibilityLevel to 5 in HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "2.3.11.7", "title": "LAN Manager Authentication Level"}
            ],
            mitre_attack=["T1557.001"],
            requires_admin=True,
        )
        lm_lvl = lsa_key.get("LmCompatibilityLevel")
        if lm_lvl is None:
            findings.append(self.create_finding(r_003, FindingStatus.WARN, "LmCompatibilityLevel key not explicitly set", confidence=0.85))
        elif isinstance(lm_lvl, int) and lm_lvl >= 5:
            findings.append(self.create_finding(r_003, FindingStatus.PASS, f"LmCompatibilityLevel = {lm_lvl} (NTLMv2 Only)", confidence=0.99, evidence_data={"LmCompatibilityLevel": lm_lvl}))
        else:
            findings.append(self.create_finding(r_003, FindingStatus.FAIL, f"LmCompatibilityLevel = {lm_lvl} (Permits weak NTLMv1/LM)", confidence=0.99, evidence_data={"LmCompatibilityLevel": lm_lvl}))

        # 4. Safe DLL Search Mode (WS-REG-004)
        r_004 = Rule(
            id="WS-REG-004",
            title="Safe DLL Search Mode is Disabled (DLL Hijacking Risk)",
            category="Registry",
            severity=Severity.MEDIUM,
            description="Safe DLL Search Mode rearranges the search order so the current directory is checked after system directories.",
            expected="SafeDllSearchMode = 1",
            impact="Adversaries placing malicious DLLs in current directories can hijack application loading.",
            remediation_guidance="Set SafeDllSearchMode to 1 in HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager.",
            compliance_mappings=[
                {"framework": "CIS Windows 11 Enterprise", "version": "5.0.1", "control_id": "18.8.27.3", "title": "Safe DLL Search Mode"}
            ],
            mitre_attack=["T1574.001"],
            requires_admin=True,
        )
        sdll = sm_key.get("SafeDllSearchMode")
        if sdll == 1 or sdll is None:
            findings.append(self.create_finding(r_004, FindingStatus.PASS, f"SafeDllSearchMode = {sdll if sdll is not None else '1 (Default)'}", confidence=0.95, evidence_data={"SafeDllSearchMode": 1}))
        else:
            findings.append(self.create_finding(r_004, FindingStatus.FAIL, f"SafeDllSearchMode = {sdll} (Disabled)", confidence=0.99, evidence_data={"SafeDllSearchMode": sdll}))

        return findings
