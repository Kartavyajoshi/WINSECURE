"""
WinSecure Interactive HTML Website Generator (Clean, Minimalist White SaaS UI)
100% Standalone Self-Contained Single-File Report
"""
import json
import os
from winsecure.models.scan import ScanResult

REPORT_CSS = """/* ==========================================================================
   WinSecure — Clean, Minimalist White UI (Modern SaaS Style)
   100% Offline, Zero-CDN, Air-Gapped Compliant
   ========================================================================== */

:root {
  /* Clean Light Palette */
  --bg-app: #ffffff;
  --bg-canvas: #f9fafb;
  --bg-sidebar: #f7f7f8;
  --bg-topbar: #ffffff;
  --bg-card: #ffffff;
  --bg-card-hover: #f3f4f6;
  --bg-input: #ffffff;
  --bg-code: #18181b;

  /* Crisp Border Colors */
  --border-color: #e5e7eb;
  --border-subtle: #f3f4f6;
  --border-focus: #10a37f;

  /* Typography Colors */
  --text-primary: #111827;
  --text-secondary: #4b5563;
  --text-muted: #6b7280;
  --text-light: #9ca3af;

  /* Accent & Status Colors (Clean Soft Badges) */
  --accent-primary: #10a37f;
  --accent-blue: #2563eb;
  --accent-gray: #374151;

  /* Status Colors */
  --badge-crit-bg: #fee2e2;
  --badge-crit-text: #991b1b;
  --badge-crit-border: #fca5a5;

  --badge-high-bg: #ffedd5;
  --badge-high-text: #9a3412;
  --badge-high-border: #fdba74;

  --badge-med-bg: #fef3c7;
  --badge-med-text: #92400e;
  --badge-med-border: #fcd34d;

  --badge-low-bg: #e0f2fe;
  --badge-low-text: #075985;
  --badge-low-border: #bae6fd;

  --badge-pass-bg: #dcfce7;
  --badge-pass-text: #166534;
  --badge-pass-border: #86efac;

  /* Fonts & Shadows */
  --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  --radius-full: 9999px;

  --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --shadow-card: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05);
  --shadow-modal: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
}

/* ==========================================================================
   Base & Reset
   ========================================================================== */
*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html, body {
  height: 100%;
  font-family: var(--font-ui);
  background-color: var(--bg-canvas);
  color: var(--text-primary);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* ==========================================================================
   Layout Architecture
   ========================================================================== */
.app-container {
  display: flex;
  min-height: 100vh;
  width: 100vw;
}

/* Minimalist Sidebar */
.sidebar {
  width: 250px;
  min-width: 250px;
  background-color: var(--bg-sidebar);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  position: fixed;
  top: 0;
  bottom: 0;
  left: 0;
  z-index: 100;
}

.sidebar-header {
  padding: 20px 18px;
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid var(--border-color);
}

.brand-icon {
  width: 32px;
  height: 32px;
  background-color: var(--accent-primary);
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #ffffff;
  font-weight: 700;
  font-size: 14px;
}

.brand-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.2px;
}

.brand-subtitle {
  font-size: 11px;
  color: var(--text-muted);
}

.nav-menu {
  list-style: none;
  padding: 14px 10px;
  flex-grow: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.nav-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 12px;
  color: var(--text-secondary);
  text-decoration: none;
  border-radius: var(--radius-md);
  font-size: 13.5px;
  font-weight: 500;
  transition: all 0.12s ease;
  cursor: pointer;
}

.nav-link-content {
  display: flex;
  align-items: center;
  gap: 10px;
}

.nav-icon {
  font-size: 16px;
  width: 18px;
  text-align: center;
  color: var(--text-muted);
}

.nav-link:hover {
  background-color: var(--border-color);
  color: var(--text-primary);
}

.nav-link.active {
  background-color: #ffffff;
  color: var(--text-primary);
  font-weight: 600;
  box-shadow: var(--shadow-sm);
}

.nav-link.active .nav-icon {
  color: var(--accent-primary);
}

.nav-pill {
  padding: 2px 7px;
  border-radius: var(--radius-full);
  font-size: 11px;
  font-weight: 600;
  background: var(--border-color);
  color: var(--text-secondary);
}

.nav-link.active .nav-pill {
  background: var(--badge-pass-bg);
  color: var(--badge-pass-text);
}

.sidebar-footer {
  padding: 14px 18px;
  border-top: 1px solid var(--border-color);
  font-size: 12px;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: var(--accent-primary);
}

/* Main Area */
.main-wrapper {
  margin-left: 250px;
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  background-color: var(--bg-canvas);
}

/* Topbar */
.topbar {
  background-color: var(--bg-topbar);
  border-bottom: 1px solid var(--border-color);
  padding: 12px 32px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  z-index: 90;
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 14px;
}

.meta-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: var(--bg-canvas);
  border: 1px solid var(--border-color);
  padding: 5px 12px;
  border-radius: var(--radius-full);
  font-size: 12px;
  color: var(--text-secondary);
}

.meta-pill strong {
  color: var(--text-primary);
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 10px;
}

/* Clean Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 500;
  border: 1px solid var(--border-color);
  background: #ffffff;
  color: var(--text-primary);
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
}

.btn:hover {
  background: var(--bg-card-hover);
  border-color: #d1d5db;
}

.btn-primary {
  background: var(--accent-primary);
  border-color: var(--accent-primary);
  color: #ffffff;
}

.btn-primary:hover {
  background: #0e8c6d;
  border-color: #0e8c6d;
  color: #ffffff;
}

.btn-dark {
  background: #111827;
  border-color: #111827;
  color: #ffffff;
}

.btn-dark:hover {
  background: #1f2937;
  color: #ffffff;
}

.btn-sm {
  padding: 5px 10px;
  font-size: 12px;
}

/* ==========================================================================
   Content Sections
   ========================================================================== */
.content-container {
  padding: 32px;
  max-width: 1200px;
  width: 100%;
  margin: 0 auto;
}

.page-section {
  display: none;
}

.page-section.active {
  display: block;
}

.section-header {
  margin-bottom: 24px;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
}

.section-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.3px;
}

.section-desc {
  font-size: 13.5px;
  color: var(--text-muted);
  margin-top: 4px;
}

/* ==========================================================================
   Clean White Cards & Grids
   ========================================================================== */
.grid-4 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.grid-2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: 20px;
  margin-bottom: 24px;
}

.card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 22px;
  box-shadow: var(--shadow-card);
}

.card-title {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 10px;
}

.kpi-number {
  font-size: 36px;
  font-weight: 800;
  line-height: 1;
  color: var(--text-primary);
}

.kpi-subtitle {
  font-size: 12.5px;
  color: var(--text-muted);
  margin-top: 8px;
}

/* Assessment Brief Card */
.auditor-summary-card {
  background-color: #ffffff;
  border: 1px solid var(--border-color);
  border-left: 4px solid var(--accent-primary);
  border-radius: var(--radius-md);
  padding: 18px 22px;
  margin-bottom: 24px;
  box-shadow: var(--shadow-card);
}

.auditor-summary-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  font-weight: 700;
  font-size: 14.5px;
  color: var(--text-primary);
}

.auditor-summary-text {
  font-size: 14px;
  color: var(--text-secondary);
  line-height: 1.6;
  white-space: pre-line;
}

/* ==========================================================================
   Clean Badges
   ========================================================================== */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 9px;
  border-radius: var(--radius-full);
  font-size: 11.5px;
  font-weight: 600;
}

.badge-crit { background: var(--badge-crit-bg); color: var(--badge-crit-text); border: 1px solid var(--badge-crit-border); }
.badge-high { background: var(--badge-high-bg); color: var(--badge-high-text); border: 1px solid var(--badge-high-border); }
.badge-med  { background: var(--badge-med-bg);  color: var(--badge-med-text);  border: 1px solid var(--badge-med-border); }
.badge-low  { background: var(--badge-low-bg);  color: var(--badge-low-text);  border: 1px solid var(--badge-low-border); }
.badge-pass { background: var(--badge-pass-bg); color: var(--badge-pass-text); border: 1px solid var(--badge-pass-border); }
.badge-warn { background: var(--badge-med-bg);  color: var(--badge-med-text);  border: 1px solid var(--badge-med-border); }
.badge-info { background: var(--border-color);  color: var(--text-secondary); }

/* ==========================================================================
   Clean Findings Table
   ========================================================================== */
.table-filter-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
  flex-wrap: wrap;
  align-items: center;
}

.search-input {
  flex-grow: 1;
  min-width: 240px;
  padding: 8px 14px;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  font-size: 13.5px;
  background: #ffffff;
  color: var(--text-primary);
}

.search-input:focus {
  outline: none;
  border-color: var(--accent-primary);
  box-shadow: 0 0 0 2px rgba(16, 163, 127, 0.15);
}

.filter-pill {
  padding: 6px 12px;
  border-radius: var(--radius-full);
  font-size: 12px;
  font-weight: 500;
  background: #ffffff;
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
  cursor: pointer;
  transition: all 0.12s ease;
}

.filter-pill:hover {
  background: var(--bg-card-hover);
}

.filter-pill.active {
  background: #111827;
  color: #ffffff;
  border-color: #111827;
}

.data-table-container {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  overflow: hidden;
  background: #ffffff;
  box-shadow: var(--shadow-card);
}

.data-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
  font-size: 13.5px;
}

.data-table th {
  background-color: var(--bg-canvas);
  color: var(--text-muted);
  font-weight: 600;
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color);
}

.data-table td {
  padding: 14px 16px;
  border-bottom: 1px solid var(--border-subtle);
  color: var(--text-primary);
}

.data-table tbody tr {
  transition: background-color 0.1s ease;
  cursor: pointer;
}

.data-table tbody tr:hover {
  background-color: var(--bg-canvas);
}

.data-table tbody tr:last-child td {
  border-bottom: none;
}

.table-pagination {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background-color: var(--bg-canvas);
  border-top: 1px solid var(--border-color);
  font-size: 12.5px;
  color: var(--text-muted);
}

/* ==========================================================================
   Module Catalog Cards
   ========================================================================== */
.catalog-card {
  background-color: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: var(--shadow-card);
  transition: all 0.15s ease;
}

.catalog-card:hover {
  border-color: #d1d5db;
}

.catalog-header {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 10px;
  flex-wrap: wrap;
  gap: 8px;
}

.catalog-id {
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 13.5px;
  color: var(--accent-primary);
}

.catalog-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
  margin-left: 8px;
}

.catalog-desc {
  font-size: 13.5px;
  color: var(--text-secondary);
  line-height: 1.6;
  margin-bottom: 14px;
}

.catalog-meta-row {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  font-size: 12.5px;
  color: var(--text-muted);
  background: var(--bg-canvas);
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-subtle);
}

/* ==========================================================================
   Clean Code Box
   ========================================================================== */
.code-wrapper {
  background-color: var(--bg-code);
  border-radius: var(--radius-md);
  overflow: hidden;
  margin: 12px 0;
}

.code-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 14px;
  background-color: #27272a;
  color: #a1a1aa;
  font-size: 11.5px;
  font-family: var(--font-ui);
}

.copy-btn {
  background: none;
  border: none;
  color: #d4d4d8;
  font-size: 11.5px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 6px;
  border-radius: 4px;
}

.copy-btn:hover {
  background-color: #3f3f46;
  color: #ffffff;
}

.code-content {
  padding: 14px 16px;
  color: #e4e4e7;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.6;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

/* Progress Bars */
.progress-bar-bg {
  height: 8px;
  background-color: var(--border-color);
  border-radius: var(--radius-full);
  overflow: hidden;
  margin-top: 8px;
}

.progress-bar-fill {
  height: 100%;
  border-radius: var(--radius-full);
  transition: width 0.6s ease;
}

/* ==========================================================================
   Clean Modal
   ========================================================================== */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0, 0, 0, 0.45);
  backdrop-filter: blur(3px);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-card {
  background: #ffffff;
  border-radius: var(--radius-lg);
  width: 100%;
  max-width: 800px;
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  box-shadow: var(--shadow-modal);
  overflow: hidden;
}

.modal-header {
  padding: 18px 24px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-title {
  font-size: 17px;
  font-weight: 700;
  color: var(--text-primary);
}

.modal-close-btn {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 22px;
  cursor: pointer;
  line-height: 1;
  padding: 4px;
  border-radius: 4px;
}

.modal-close-btn:hover {
  background: var(--bg-canvas);
  color: var(--text-primary);
}

.modal-tabs {
  display: flex;
  border-bottom: 1px solid var(--border-color);
  background: var(--bg-canvas);
  padding: 0 16px;
  gap: 8px;
}

.modal-tab {
  padding: 10px 14px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  border-bottom: 2px solid transparent;
}

.modal-tab:hover {
  color: var(--text-primary);
}

.modal-tab.active {
  color: var(--accent-primary);
  border-bottom-color: var(--accent-primary);
  font-weight: 600;
}

.modal-body {
  padding: 24px;
  overflow-y: auto;
  flex-grow: 1;
}

/* ==========================================================================
   Responsive & Print
   ========================================================================== */
@media (max-width: 900px) {
  .sidebar {
    width: 68px;
    min-width: 68px;
  }
  .brand-details, .nav-text, .nav-pill, .sidebar-footer {
    display: none;
  }
  .main-wrapper {
    margin-left: 68px;
  }
  .sidebar-header {
    justify-content: center;
    padding: 16px 0;
  }
  .nav-link {
    justify-content: center;
    padding: 12px 0;
  }
}

@media print {
  .sidebar, .topbar, .table-filter-bar, .btn, .modal-overlay {
    display: none !important;
  }
  .main-wrapper {
    margin-left: 0 !important;
  }
  .page-section {
    display: block !important;
    margin-bottom: 30px;
  }
}
"""

REPORT_JS = """/* ==========================================================================
   WinSecure — Clean Minimalist White UI Application Logic & In-Depth Data
   100% Offline, Zero-CDN, Air-Gapped Compliant, Pure Synthetic Lab Telemetry
   ========================================================================== */

const SYNTHETIC_REPORT_DATA = {
  "assessment_metadata": {
    "data_type": "Synthetic Assessment Data",
    "assessment_id": "ASSESS-2026-00142",
    "assessment_title": "Enterprise Windows Security Posture Assessment",
    "target_host": "LAB-WIN-042",
    "target_environment": "Security Assessment Lab",
    "target_ip": "192.0.2.42",
    "domain": "LAB.INTERNAL",
    "os_name": "Microsoft Windows 11 Enterprise (23H2)",
    "os_build": "22631.3007",
    "duration": "08m 42s",
    "status": "COMPLETED"
  },
  "metrics": {
    "security_score": 72.0,
    "posture_rating": "MODERATE",
    "coverage_percent": 100.0,
    "total_checks_evaluated": 53,
    "passed_checks_count": 33,
    "failed_checks_count": 20,
    "severity_distribution": {
      "Critical": 2,
      "High": 7,
      "Medium": 14,
      "Low": 19,
      "Informational": 11
    }
  },
  "findings": [
    {
      "id": "SEC-001",
      "title": "Unauthenticated Remote Desktop Protocol (NLA Disabled)",
      "category": "Network Services",
      "severity": "Critical",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "TermService (Port 3389)",
      "detection_method": "Registry Query: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
      "description": "Remote Desktop Protocol accepts incoming network connections without enforcing Network Level Authentication (NLA).",
      "risk_explanation": "Adversaries on the local network can initiate pre-authentication RDP sessions, exposing the host to credential harvesting, denial of service, or remote code execution vulnerabilities.",
      "impact": "Unrestricted exposure of RDP protocol stack to unauthenticated network traffic.",
      "recommendation": "Enforce Network Level Authentication for all incoming Remote Desktop sessions.",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord",
      "compliance_mappings": {
        "cis": "CIS 18.9.65.3.2 (Level 1)",
        "nist": "NIST SP 800-53 AC-17(2)",
        "disa": "DISA STIG WN11-CC-000280"
      },
      "evidence": [{"property": "UserAuthentication", "expected": 1, "actual": 0}]
    },
    {
      "id": "SEC-002",
      "title": "Local Security Authority Subsystem (LSASS) Unprotected",
      "category": "Credential Protection",
      "severity": "Critical",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "LSASS.exe Process Memory",
      "detection_method": "Registry Query: HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
      "description": "LSASS process is not running as Protected Process Light (RunAsPPL).",
      "risk_explanation": "Administrative processes or compromised service accounts can inject code into LSASS or read memory buffers to extract cached password hashes and Kerberos tickets.",
      "impact": "Plaintext credential dumping and lateral movement via Mimikatz / Sekurlsa.",
      "recommendation": "Enable RunAsPPL in LSA configuration to enforce kernel-level process protection.",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord",
      "compliance_mappings": {
        "cis": "CIS 2.3.7.4 (Level 1)",
        "nist": "NIST SP 800-53 IA-5(1)",
        "disa": "DISA STIG WN11-RG-000020"
      },
      "evidence": [{"property": "RunAsPPL", "expected": 1, "actual": 0}]
    },
    {
      "id": "SEC-003",
      "title": "Link-Local Multicast Name Resolution (LLMNR) Enabled",
      "category": "Network Protocol",
      "severity": "High",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "DNS Client Multi-cast Subsystem",
      "detection_method": "Registry Query: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
      "description": "LLMNR allows the system to broadcast multicast queries across the local subnet when standard DNS resolution fails.",
      "risk_explanation": "Adversaries running network poisoning tools (such as Responder) can respond to mistyped host queries and capture NTLMv2 challenge-response hashes.",
      "impact": "Offline cracking of captured user credentials and lateral network movement.",
      "recommendation": "Disable LLMNR via Group Policy across all network interfaces.",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name 'EnableMulticast' -Value 0 -Type DWord",
      "compliance_mappings": {
        "cis": "CIS 18.4.4 (Level 1)",
        "nist": "NIST SP 800-53 SC-8",
        "disa": "DISA STIG WN11-CC-000180"
      },
      "evidence": [{"property": "EnableMulticast", "expected": 0, "actual": 1}]
    },
    {
      "id": "SEC-004",
      "title": "SMBv1 Legacy Protocol Driver Active",
      "category": "Network Protocol",
      "severity": "High",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "LanmanServer / SMB1Protocol",
      "detection_method": "WMI Query: Win32_OptionalFeature SMB1Protocol",
      "description": "The legacy Server Message Block version 1 (SMBv1) protocol driver is installed and available on the system.",
      "risk_explanation": "SMBv1 is vulnerable to remote code execution vulnerabilities (such as MS17-010 / EternalBlue) and lacks modern cryptographic message signing.",
      "impact": "Remote unauthenticated kernel exploit exposure and ransomware propagation.",
      "recommendation": "Completely remove the SMBv1 protocol driver package from the Windows installation.",
      "remediation": "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart",
      "compliance_mappings": {
        "cis": "CIS 18.4.11 (Level 1)",
        "nist": "NIST SP 800-53 SC-8(1)",
        "disa": "DISA STIG WN11-CC-000190"
      },
      "evidence": [{"feature": "SMB1Protocol", "expected": "Disabled", "actual": "Enabled"}]
    },
    {
      "id": "SEC-005",
      "title": "Process Creation Command-Line Auditing Disabled",
      "category": "Audit & Logging",
      "severity": "High",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "Audit Policy / Event 4688",
      "detection_method": "Registry Query: HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit",
      "description": "Process creation event logging (Event 4688) does not include execution command-line parameters in security event records.",
      "risk_explanation": "Security operations teams cannot view full arguments passed to command interpreters (cmd.exe, powershell.exe, wmic.exe), hindering threat detection.",
      "impact": "Forensic visibility gap during incident response and threat hunting operations.",
      "recommendation": "Enable process command line auditing in System Audit policy.",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord",
      "compliance_mappings": {
        "cis": "CIS 17.1.1 (Level 1)",
        "nist": "NIST SP 800-53 AU-12",
        "disa": "DISA STIG WN11-AU-000050"
      },
      "evidence": [{"property": "ProcessCreationIncludeCmdLine_Enabled", "expected": 1, "actual": 0}]
    },
    {
      "id": "SEC-006",
      "title": "PowerShell Script Block Logging Disabled",
      "category": "Audit & Logging",
      "severity": "High",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "PowerShell Engine / Event 4104",
      "detection_method": "Registry Query: HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
      "description": "PowerShell Script Block Logging (Event ID 4104) is not enabled.",
      "risk_explanation": "Adversaries using Base64-encoded download cradles and obfuscated scripts in memory can bypass standard logging without leaving script code traces.",
      "impact": "Loss of execution telemetry for memory-resident fileless attacks.",
      "recommendation": "Configure Script Block Logging via Group Policy to record all script block invocations.",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord",
      "compliance_mappings": {
        "cis": "CIS 18.9.84.1 (Level 1)",
        "nist": "NIST SP 800-53 AU-2",
        "disa": "DISA STIG WN11-CC-000310"
      },
      "evidence": [{"property": "EnableScriptBlockLogging", "expected": 1, "actual": 0}]
    },
    {
      "id": "SEC-007",
      "title": "Defender Potentially Unwanted Application (PUA) Protection Disabled",
      "category": "Endpoint Defense",
      "severity": "High",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "Microsoft Defender Antivirus Engine",
      "detection_method": "PowerShell Query: Get-MpPreference PUAProtection",
      "description": "PUA protection is not enabled in Defender configuration.",
      "risk_explanation": "Adware, coin miners, and commercial keyloggers bundled into software installers will not be blocked prior to installation.",
      "impact": "Unwanted software execution and endpoint degradation.",
      "recommendation": "Set PUA protection to Enabled in Defender settings.",
      "remediation": "Set-MpPreference -PUAProtection Enabled",
      "compliance_mappings": {
        "cis": "CIS 2.3.1.5 (Level 1)",
        "nist": "NIST SP 800-53 SI-3",
        "disa": "DISA STIG WN11-CC-000125"
      },
      "evidence": [{"property": "PUAProtection", "expected": 1, "actual": 0}]
    },
    {
      "id": "SEC-008",
      "title": "Account Lockout Threshold Not Configured",
      "category": "Account Policy",
      "severity": "High",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "SAM Account Policy Subsystem",
      "detection_method": "SAM API Query: NetUserModalsGet",
      "description": "The local account lockout threshold is set to 0 (unlimited failed logon attempts allowed).",
      "risk_explanation": "Adversaries can perform continuous brute-force and password guessing attacks against local accounts without account suspension.",
      "impact": "Unchecked password spray and dictionary attack exposure.",
      "recommendation": "Configure the account lockout threshold to lock accounts after 5 consecutive invalid attempts.",
      "remediation": "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
      "compliance_mappings": {
        "cis": "CIS 2.3.1.1 (Level 1)",
        "nist": "NIST SP 800-53 AC-7",
        "disa": "DISA STIG WN11-SO-000020"
      },
      "evidence": [{"property": "LockoutThreshold", "expected": 5, "actual": 0}]
    },
    {
      "id": "SEC-009",
      "title": "Unquoted Service Executable Path Detected",
      "category": "Service Configuration",
      "severity": "Medium",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "Service: AppManagementHelper",
      "detection_method": "WMI Query: Win32_Service PathName",
      "description": "The service executable path contains space characters and is not enclosed in double quotes.",
      "risk_explanation": "Local unprivileged users with write access to C:\\ or C:\\Program Files can drop a malicious C:\\Program.exe binary that executes with SYSTEM rights on service startup.",
      "impact": "Local privilege escalation (MITRE ATT&CK T1574.009).",
      "recommendation": "Wrap the binary path in quotation marks within the service registry ImagePath definition.",
      "remediation": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\AppManagementHelper' -Name 'ImagePath' -Value '\"C:\\Program Files\\App Helper\\service.exe\"'",
      "compliance_mappings": {
        "cis": "CIS 5.1.1 (Level 1)",
        "nist": "NIST SP 800-53 CM-7",
        "disa": "DISA STIG WN11-SV-000010"
      },
      "evidence": [{"service": "AppManagementHelper", "path": "C:\\Program Files\\App Helper\\service.exe", "is_quoted": false}]
    },
    {
      "id": "SEC-010",
      "title": "Windows Firewall Public Profile Inbound Default Action Set to Allow",
      "category": "Firewall Configuration",
      "severity": "Medium",
      "status": "FAIL",
      "confidence": "High",
      "affected_component": "MpsSvc Public Firewall Profile",
      "detection_method": "NetFirewall API Query: Get-NetFirewallProfile -Profile Public",
      "description": "Default inbound action for the Public network profile is not configured to Block.",
      "risk_explanation": "Connecting to untrusted or public Wi-Fi networks exposes unmanaged local listener ports to other clients on the subnet.",
      "impact": "Unsolicited inbound network probe exposure.",
      "recommendation": "Configure Public firewall profile default inbound action to Block.",
      "remediation": "Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block",
      "compliance_mappings": {
        "cis": "CIS 9.3.1 (Level 1)",
        "nist": "NIST SP 800-53 SC-7",
        "disa": "DISA STIG WN11-CC-000210"
      },
      "evidence": [{"profile": "Public", "expected_inbound": "Block", "actual_inbound": "Allow"}]
    },
    {
      "id": "SEC-011",
      "title": "Windows Defender Real-Time Protection Active",
      "category": "Endpoint Defense",
      "severity": "Informational",
      "status": "PASS",
      "confidence": "High",
      "affected_component": "MsMpEng Real-Time Filter Engine",
      "detection_method": "API Query: Get-MpPreference DisableRealtimeMonitoring",
      "description": "Real-time behavioral and file system monitoring is actively enforced.",
      "risk_explanation": "Defensive baseline control verified.",
      "impact": "Files and processes are scanned on execution.",
      "recommendation": "Maintain real-time protection enabled.",
      "remediation": "# Control aligned with baseline.",
      "compliance_mappings": {
        "cis": "CIS 2.3.1.2 (Level 1)",
        "nist": "NIST SP 800-53 SI-3",
        "disa": "DISA STIG WN11-CC-000120"
      },
      "evidence": [{"property": "DisableRealtimeMonitoring", "expected": false, "actual": false}]
    },
    {
      "id": "SEC-012",
      "title": "UEFI Secure Boot Firmware Integrity Enforced",
      "category": "Firmware & Kernel",
      "severity": "Informational",
      "status": "PASS",
      "confidence": "High",
      "affected_component": "UEFI Firmware Signature Verification",
      "detection_method": "WMI Query: Confirm-SecureBootUEFI",
      "description": "Secure Boot is enabled and verifying digital signatures for all bootloader stages.",
      "risk_explanation": "Defensive baseline control verified.",
      "impact": "Protects against pre-OS bootkits and unauthorized kernel modules.",
      "recommendation": "Maintain Secure Boot enabled in firmware.",
      "remediation": "# Control aligned with baseline.",
      "compliance_mappings": {
        "cis": "CIS 1.1.1 (Level 1)",
        "nist": "NIST SP 800-53 SI-7",
        "disa": "DISA STIG WN11-00-000010"
      },
      "evidence": [{"property": "SecureBootEnabled", "expected": true, "actual": true}]
    }
  ],
  "modules": [
    {"id": "WS-SYSTEM", "name": "System Hardware & Secure Boot", "category": "System", "desc": "Audits UEFI, Secure Boot, and TPM 2.0 readiness.", "threat": "Pre-OS bootkits, Evil Maid attacks.", "compliance": "CIS 1.1.1 · NIST SI-7", "powershell": "Confirm-SecureBootUEFI; Get-Tpm"},
    {"id": "WS-DEFENDER", "name": "Microsoft Defender Antivirus", "category": "Defender", "desc": "Evaluates Real-time Protection, Cloud Protection, and PUA mode.", "threat": "Malware execution, evasive droppers.", "compliance": "CIS 2.3.1 · NIST SI-3", "powershell": "Get-MpPreference"},
    {"id": "WS-FIREWALL", "name": "Windows Defender Firewall", "category": "Firewall", "desc": "Verifies Domain, Private, and Public profile default block states.", "threat": "Inbound worm propagation, unauthorized listening ports.", "compliance": "CIS 9.1 - 9.3 · NIST SC-7", "powershell": "Get-NetFirewallProfile"},
    {"id": "WS-ACCOUNTS", "name": "Local Accounts & Lockout Policy", "category": "Accounts", "desc": "Audits Guest account disabling and brute-force lockout thresholds.", "threat": "Password spraying, brute-force guessing.", "compliance": "CIS 2.3.1.1 · NIST AC-7", "powershell": "net accounts; Get-LocalUser"},
    {"id": "WS-PRIVILEGES", "name": "User Rights & Administrative Membership", "category": "Privileges", "desc": "Validates Administrators group members and sensitive privileges.", "threat": "Local privilege escalation, token impersonation.", "compliance": "CIS 2.2.1 · NIST AC-6", "powershell": "Get-LocalGroupMember -Group 'Administrators'"},
    {"id": "WS-SERVICES", "name": "Windows Services & Unquoted Paths", "category": "Services", "desc": "Scans service binary paths for unquoted spaces and weak ACLs.", "threat": "Service binary hijacking, privilege escalation.", "compliance": "CIS 5.1.1 · NIST CM-7", "powershell": "Get-WmiObject win32_service"},
    {"id": "WS-REGISTRY", "name": "LSA Protection & Core OS Registry", "category": "Registry", "desc": "Validates RunAsPPL, WDigest disabled, and Safe DLL search mode.", "threat": "LSASS memory dumping, credential harvesting.", "compliance": "CIS 2.3.7.4 · NIST IA-5", "powershell": "Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"},
    {"id": "WS-POWERSHELL", "name": "PowerShell Script Block Logging", "category": "Audit", "desc": "Audits Script Block Logging (Event 4104) and transcription.", "threat": "Obfuscated script execution, memory-resident cradles.", "compliance": "CIS 18.9.84 · NIST AU-2", "powershell": "Get-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"},
    {"id": "WS-AUDIT", "name": "Advanced Process Creation Auditing", "category": "Audit", "desc": "Audits Event 4688 with command-line argument inclusion.", "threat": "Forensic blindness during incident triage.", "compliance": "CIS 17.1.1 · NIST AU-12", "powershell": "auditpol /get /category:*"},
    {"id": "WS-ENCRYPTION", "name": "BitLocker Full Volume Encryption", "category": "Crypto", "desc": "Audits OS boot drive BitLocker encryption cipher and TPM binding.", "threat": "Offline physical disk extraction.", "compliance": "CIS 18.8.4 · NIST SC-28", "powershell": "manage-bde -status C:"}
  ],
  "compliance_summaries": [
    {
      "framework": "CIS Microsoft Windows 11 Benchmark",
      "version": "v3.0.0 (Level 1 + 2)",
      "alignment": 78.4,
      "passed": 28,
      "total": 36,
      "desc": "Center for Internet Security consensus-driven configuration baseline."
    },
    {
      "framework": "NIST SP 800-53 Rev 5",
      "version": "Rev 5 (Federal Systems)",
      "alignment": 81.2,
      "passed": 30,
      "total": 37,
      "desc": "Security and Privacy Controls for Federal Information Systems."
    },
    {
      "framework": "DISA Windows 11 STIG",
      "version": "v1r4 (DoD Standard)",
      "alignment": 74.6,
      "passed": 26,
      "total": 35,
      "desc": "Defense Information Systems Agency Security Technical Implementation Guide."
    },
    {
      "framework": "Microsoft Security Baseline",
      "version": "Windows 11 23H2 Baseline",
      "alignment": 86.0,
      "passed": 31,
      "total": 36,
      "desc": "Vendor recommended hardening and Group Policy Object baselines."
    }
  ],
  "timeline": [
    {"time": "18:02:14", "event": "Assessment initialized on LAB-WIN-042", "status": "INFO"},
    {"time": "18:02:18", "event": "Host & hardware telemetry discovery completed", "status": "OK"},
    {"time": "18:03:01", "event": "Security configuration audit started across 30 hives", "status": "INFO"},
    {"time": "18:04:37", "event": "Service & listening port inspection completed", "status": "OK"},
    {"time": "18:05:21", "event": "Attack surface & legacy protocol analysis completed", "status": "OK"},
    {"time": "18:06:44", "event": "Compliance baseline mapping completed", "status": "OK"},
    {"time": "18:07:03", "event": "Mathematical risk penalty deduction completed", "status": "OK"},
    {"time": "18:07:11", "event": "Assessment report artifacts generated successfully", "status": "OK"}
  ]
};

let activeFindingFilter = 'ALL';
let currentActiveItem = null;
let currentModalTab = 'tab-overview';

document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupFilterControls();
  renderDashboard(SYNTHETIC_REPORT_DATA);
  renderFindings(SYNTHETIC_REPORT_DATA.findings);
  renderModuleCatalog(SYNTHETIC_REPORT_DATA.modules);
  renderCompliance(SYNTHETIC_REPORT_DATA.compliance_summaries);
  renderRemediationPlan(SYNTHETIC_REPORT_DATA.findings);
  renderTimelineLogs(SYNTHETIC_REPORT_DATA.timeline);
  setupKeyboardListeners();
});

// Universal Tab & Navigation Handler
function setupNavigation() {
  const tabElements = document.querySelectorAll('[data-tab]');
  tabElements.forEach(item => {
    // Skip modal tabs from main sidebar handler
    if (item.classList.contains('modal-tab')) return;

    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = item.getAttribute('data-tab');
      if (!targetId || !targetId.startsWith('section-')) return;

      // Update sidebar active classes
      document.querySelectorAll('.nav-link, .nav-item').forEach(b => b.classList.remove('active'));
      const activeBtn = item.closest('.nav-link') || item.closest('.nav-item') || item;
      activeBtn.classList.add('active');

      // Update section visibility
      document.querySelectorAll('.page-section, .content-section').forEach(s => {
        s.classList.remove('active');
        s.style.display = 'none';
      });

      const targetSection = document.getElementById(targetId);
      if (targetSection) {
        targetSection.classList.add('active');
        targetSection.style.display = 'block';
      }
    });
  });
}

// 1. Dashboard Overview
function renderDashboard(data) {
  const meta = data.assessment_metadata || {};
  const metrics = data.metrics || {};
  const dist = metrics.severity_distribution || {};

  setText('topbar-host', meta.target_host || 'LAB-WIN-042');
  setText('topbar-env', meta.target_environment || 'Security Assessment Lab');
  setText('topbar-ip', meta.target_ip || '192.0.2.42');

  setText('kpi-score', `${metrics.security_score || 72}.0/100`);
  setText('kpi-posture', metrics.posture_rating || 'MODERATE');
  setText('kpi-crit-high', `${(dist.Critical || 0) + (dist.High || 0)}`);
  setText('kpi-duration', meta.duration || '08m 42s');
  setText('kpi-passed', `${metrics.passed_checks_count || 33} / ${metrics.total_checks_evaluated || 53}`);

  const summary = document.getElementById('auditor-summary-text');
  if (summary) {
    summary.innerHTML = `Automated security assessment completed for endpoint <strong>${meta.target_host}</strong> (${meta.target_ip}) in environment <em>"${meta.target_environment}"</em>. The endpoint achieved an overall defensive score of <strong>${metrics.security_score} / 100 (${metrics.posture_rating})</strong>. Identified <strong>${data.findings.filter(f => f.status === 'FAIL').length} misconfigurations</strong> (including ${dist.Critical || 2} Critical and ${dist.High || 7} High priority defects). Review the Findings and Remediation tabs for ready-to-execute PowerShell hardening scripts.`;
  }
}

// 2. Filter Controls
function setupFilterControls() {
  document.querySelectorAll('.filter-pill, .filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill, .filter-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      activeFindingFilter = chip.getAttribute('data-filter') || 'ALL';
      filterFindings();
    });
  });

  const searchInput = document.getElementById('findings-search');
  if (searchInput) {
    searchInput.addEventListener('input', () => filterFindings());
  }

  const categorySelect = document.getElementById('category-filter');
  if (categorySelect) {
    categorySelect.addEventListener('change', () => filterFindings());
  }
}

function filterFindings() {
  const query = (document.getElementById('findings-search')?.value || '').toLowerCase();
  const category = document.getElementById('category-filter')?.value || 'ALL';

  const findings = SYNTHETIC_REPORT_DATA.findings || [];
  const filtered = findings.filter(f => {
    const matchFilter = (activeFindingFilter === 'ALL') ||
                        (activeFindingFilter === 'FAIL' && f.status === 'FAIL') ||
                        (activeFindingFilter === 'PASS' && f.status === 'PASS') ||
                        (f.severity.toUpperCase() === activeFindingFilter);

    const matchCategory = (category === 'ALL') || (f.category === category);

    const matchQuery = f.id.toLowerCase().includes(query) ||
                       f.title.toLowerCase().includes(query) ||
                       f.description.toLowerCase().includes(query) ||
                       (f.affected_component || '').toLowerCase().includes(query);

    return matchFilter && matchCategory && matchQuery;
  });

  renderFindings(filtered);
}

function renderFindings(findings) {
  const tbody = document.getElementById('findings-tbody');
  const countBadge = document.getElementById('findings-count-badge');
  const sidebarCount = document.getElementById('sidebar-finding-count');
  if (!tbody) return;

  if (sidebarCount) {
    sidebarCount.textContent = SYNTHETIC_REPORT_DATA.findings.length;
  }

  if (findings.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 32px; color: var(--text-muted);">
          No findings match the current filter selection.
        </td>
      </tr>
    `;
    if (countBadge) countBadge.textContent = "0 findings displayed";
    return;
  }

  tbody.innerHTML = findings.map(f => `
    <tr onclick="openFindingModal('${f.id}')" style="cursor: pointer;">
      <td><strong style="font-family: var(--font-mono); color: var(--text-primary);">${f.id}</strong></td>
      <td><span class="badge badge-low">${f.category}</span></td>
      <td>
        <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(f.title)}</div>
        <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">${escapeHtml(f.affected_component || '')}</div>
      </td>
      <td><span class="badge ${getSeverityBadge(f.severity)}">${f.severity.toUpperCase()}</span></td>
      <td><span class="badge ${f.status === 'PASS' ? 'badge-pass' : 'badge-crit'}">${f.status}</span></td>
      <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">
        ${(f.compliance_mappings && f.compliance_mappings.cis) || 'CIS Baseline'}
      </td>
    </tr>
  `).join('');

  if (countBadge) {
    countBadge.textContent = `Displaying ${findings.length} of ${SYNTHETIC_REPORT_DATA.findings.length} findings`;
  }
}

// 3. Module Catalog
function renderModuleCatalog(modules) {
  const container = document.getElementById('catalog-grid');
  if (!container || !modules) return;

  container.innerHTML = modules.map(m => `
    <div class="card" onclick="openModuleModal('${m.id}')" style="cursor: pointer; transition: transform 0.1s ease, box-shadow 0.1s ease;">
      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
        <strong style="font-family: var(--font-mono); font-size: 12px; color: var(--accent-primary);">${m.id}</strong>
        <span class="badge badge-low">${m.category}</span>
      </div>
      <h3 style="font-size: 14px; font-weight: 700; color: var(--text-primary); margin-bottom: 6px;">${escapeHtml(m.name)}</h3>
      <p style="font-size: 12.5px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px;">${escapeHtml(m.desc)}</p>
      <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
        Mapped: ${escapeHtml(m.compliance)}
      </div>
    </div>
  `).join('');
}

// 4. Compliance Mapping
function renderCompliance(summaries) {
  const container = document.getElementById('compliance-cards-grid');
  if (!container || !summaries) return;

  container.innerHTML = summaries.map(s => `
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
        <h3 style="font-size: 15px; font-weight: 700; color: var(--text-primary);">${escapeHtml(s.framework)}</h3>
        <span class="badge badge-low">${escapeHtml(s.version)}</span>
      </div>
      <p style="font-size: 12.5px; color: var(--text-secondary); margin-bottom: 12px;">${escapeHtml(s.desc)}</p>
      
      <div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">
        <span style="color: var(--text-muted);">Alignment Status</span>
        <strong style="font-family: var(--font-mono); color: var(--text-primary);">${s.alignment}%</strong>
      </div>
      <div style="height: 6px; background: #e5e7eb; border-radius: 3px; overflow: hidden; margin-bottom: 10px;">
        <div style="width: ${s.alignment}%; height: 100%; background: var(--accent-primary);"></div>
      </div>

      <div style="display: flex; justify-content: space-between; font-size: 11.5px; color: var(--text-muted); font-family: var(--font-mono);">
        <span>Passed: ${s.passed}</span>
        <span>Total Controls: ${s.total}</span>
      </div>
    </div>
  `).join('');
}

// 5. Remediation Plan
function renderRemediationPlan(findings) {
  const container = document.getElementById('remediation-list');
  if (!container || !findings) return;

  const failing = findings.filter(f => f.status === 'FAIL');
  container.innerHTML = failing.map((f, i) => `
    <div class="card" style="margin-bottom: 14px;">
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
        <div>
          <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">STEP ${i + 1} OF ${failing.length}</span>
          <h3 style="font-size: 14.5px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">
            <span style="font-family: var(--font-mono); color: var(--accent-blue);">[${f.id}]</span> ${escapeHtml(f.title)}
          </h3>
        </div>
        <span class="badge ${getSeverityBadge(f.severity)}">${f.severity.toUpperCase()}</span>
      </div>

      <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">${escapeHtml(f.recommendation)}</p>

      <div style="background: #18181b; border-radius: 6px; padding: 10px 14px; position: relative;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 6px; margin-bottom: 8px;">
          <span style="font-family: var(--font-mono); font-size: 11px; color: #888;">POWERSHELL SCRIPT</span>
          <button class="btn btn-outline btn-sm" style="color: #fff; border-color: #555; padding: 2px 8px; font-size: 11px;" onclick="copyCode('${escapeJs(f.remediation)}')">Copy Fix</button>
        </div>
        <pre style="font-family: var(--font-mono); font-size: 12px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; margin: 0;">${escapeHtml(f.remediation)}</pre>
      </div>
    </div>
  `).join('');
}

// 6. Timeline Logs
function renderTimelineLogs(timeline) {
  const container = document.getElementById('timeline-log-list');
  if (!container || !timeline) return;

  container.innerHTML = timeline.map(t => `
    <div style="display: flex; gap: 14px; align-items: baseline; font-size: 13px; padding: 6px 0; border-bottom: 1px solid var(--border-subtle);">
      <span style="font-family: var(--font-mono); font-size: 11.5px; color: var(--text-muted); min-width: 65px;">[${t.time}]</span>
      <span style="flex-grow: 1; color: var(--text-primary);">${escapeHtml(t.event)}</span>
      <span class="badge ${t.status === 'OK' ? 'badge-pass' : 'badge-low'}">${t.status}</span>
    </div>
  `).join('');
}

// Modal System
function openFindingModal(id) {
  const item = (SYNTHETIC_REPORT_DATA.findings || []).find(f => f.id === id);
  if (!item) return;

  currentActiveItem = item;
  currentModalTab = 'tab-overview';

  const overlay = document.getElementById('finding-modal');
  const title = document.getElementById('modal-title');
  if (!overlay || !title) return;

  title.innerHTML = `<span style="font-family: var(--font-mono); color: var(--accent-blue);">[${item.id}]</span> ${escapeHtml(item.title)}`;
  switchModalTab('tab-overview');
  overlay.style.display = 'flex';
}

function openModuleModal(id) {
  const mod = (SYNTHETIC_REPORT_DATA.modules || []).find(m => m.id === id);
  if (!mod) return;

  currentActiveItem = {
    id: mod.id,
    title: mod.name,
    category: mod.category,
    severity: "High",
    status: "FAIL",
    confidence: "High",
    affected_component: "Core Subsystem",
    detection_method: "Diagnostic Query",
    description: mod.desc,
    risk_explanation: mod.threat,
    impact: "Potential attack surface exposure.",
    recommendation: "Execute PowerShell baseline verification.",
    remediation: mod.powershell,
    compliance_mappings: { cis: mod.compliance },
    evidence: [{"module": mod.id, "evaluated": true}]
  };
  currentModalTab = 'tab-overview';

  const overlay = document.getElementById('finding-modal');
  const title = document.getElementById('modal-title');
  if (!overlay || !title) return;

  title.innerHTML = `<span style="font-family: var(--font-mono); color: var(--accent-blue);">[${mod.id}]</span> ${escapeHtml(mod.name)}`;
  switchModalTab('tab-overview');
  overlay.style.display = 'flex';
}

function switchModalTab(tabKey) {
  currentModalTab = tabKey;
  document.querySelectorAll('.modal-tab').forEach(t => {
    const isTarget = t.getAttribute('data-tab') === tabKey;
    t.classList.toggle('active', isTarget);
    if (isTarget) {
      t.style.borderBottom = '2px solid var(--accent-primary)';
      t.style.color = 'var(--accent-primary)';
      t.style.fontWeight = '600';
    } else {
      t.style.borderBottom = '2px solid transparent';
      t.style.color = 'var(--text-muted)';
      t.style.fontWeight = '500';
    }
  });
  renderModalTab(tabKey);
}

function renderModalTab(tabKey) {
  const f = currentActiveItem;
  if (!f) return;

  const body = document.getElementById('modal-body');
  if (!body) return;

  if (tabKey === 'tab-overview') {
    body.innerHTML = `
      <div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">
        <span class="badge ${getSeverityBadge(f.severity)}">${f.severity.toUpperCase()}</span>
        <span class="badge ${f.status === 'PASS' ? 'badge-pass' : 'badge-crit'}">${f.status}</span>
        <span class="badge badge-low">Category: ${f.category}</span>
      </div>

      <div style="font-size: 11.5px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">DESCRIPTION</div>
      <p style="font-size: 14px; color: var(--text-primary); margin-bottom: 16px; line-height: 1.6;">${escapeHtml(f.description)}</p>

      <div class="grid-2">
        <div style="background: var(--bg-canvas); padding: 12px; border: 1px solid var(--border-color); border-radius: 6px;">
          <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">AFFECTED COMPONENT</div>
          <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-primary); margin-top: 4px;">${escapeHtml(f.affected_component || 'N/A')}</div>
        </div>
        <div style="background: var(--bg-canvas); padding: 12px; border: 1px solid var(--border-color); border-radius: 6px;">
          <div style="font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">DETECTION METHOD</div>
          <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-primary); margin-top: 4px;">${escapeHtml(f.detection_method || 'Telemetry Audit')}</div>
        </div>
      </div>
    `;
  } else if (tabKey === 'tab-threat') {
    body.innerHTML = `
      <div style="background: #fee2e2; border-left: 4px solid #ef4444; padding: 14px; border-radius: 6px; margin-bottom: 16px;">
        <div style="font-weight: 700; font-size: 13px; color: #991b1b; margin-bottom: 4px;">ATTACKER EXPLOITATION SCENARIO</div>
        <p style="font-size: 13px; color: #7f1d1d; line-height: 1.6; margin: 0;">${escapeHtml(f.risk_explanation)}</p>
      </div>

      <div style="font-size: 11.5px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">IMPACT ASSESSMENT</div>
      <p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">${escapeHtml(f.impact)}</p>
    `;
  } else if (tabKey === 'tab-remediation') {
    body.innerHTML = `
      <div style="font-size: 11.5px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 4px;">RECOMMENDED CORRECTIVE ACTION</div>
      <p style="font-size: 13.5px; color: var(--text-primary); margin-bottom: 14px; line-height: 1.6;">${escapeHtml(f.recommendation)}</p>

      <div style="background: #18181b; border-radius: 6px; padding: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 6px; margin-bottom: 8px;">
          <span style="font-family: var(--font-mono); font-size: 11px; color: #888;">POWERSHELL HARDENING FIX</span>
          <button class="btn btn-outline btn-sm" style="color: #fff; border-color: #555; padding: 2px 8px; font-size: 11px;" onclick="copyCode('${escapeJs(f.remediation)}')">Copy Script</button>
        </div>
        <pre style="font-family: var(--font-mono); font-size: 12px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; margin: 0;">${escapeHtml(f.remediation)}</pre>
      </div>
    `;
  } else if (tabKey === 'tab-evidence') {
    const jsonStr = JSON.stringify(f.evidence || [], null, 2);
    body.innerHTML = `
      <div style="background: #18181b; border-radius: 6px; padding: 12px;">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 6px; margin-bottom: 8px;">
          <span style="font-family: var(--font-mono); font-size: 11px; color: #888;">SANITIZED EVIDENCE RECORDS (JSON)</span>
          <button class="btn btn-outline btn-sm" style="color: #fff; border-color: #555; padding: 2px 8px; font-size: 11px;" onclick="copyCode('${escapeJs(jsonStr)}')">Copy JSON</button>
        </div>
        <pre style="font-family: var(--font-mono); font-size: 12px; color: #10b981; overflow-x: auto; white-space: pre-wrap; margin: 0;">${escapeHtml(jsonStr)}</pre>
      </div>
    `;
  } else if (tabKey === 'tab-compliance') {
    const map = f.compliance_mappings || {};
    body.innerHTML = `
      <div style="font-size: 11.5px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 10px;">AUTHORITATIVE COMPLIANCE MAPPINGS</div>
      <div style="display: flex; flex-direction: column; gap: 8px;">
        <div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">
          <div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">CIS BENCHMARK</div>
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">${map.cis || 'CIS Windows 11 Enterprise Baseline'}</div>
        </div>
        <div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">
          <div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">NIST SP 800-53 REV 5</div>
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">${map.nist || 'NIST Security Control Requirement'}</div>
        </div>
        <div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">
          <div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">DISA STIG</div>
          <div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">${map.disa || 'DISA Windows Baseline STIG'}</div>
        </div>
      </div>
    `;
  }
}

function closeFindingModal() {
  const overlay = document.getElementById('finding-modal');
  if (overlay) overlay.style.display = 'none';
  currentActiveItem = null;
}

// Download 1-Click Master Remediation Script
function downloadMasterScript() {
  const failing = (SYNTHETIC_REPORT_DATA.findings || []).filter(f => f.status === 'FAIL');
  const script = `# =====================================================================
# WinSecure Automated Hardening Script
# Target Host: ${SYNTHETIC_REPORT_DATA.assessment_metadata.target_host}
# Assessment ID: ${SYNTHETIC_REPORT_DATA.assessment_metadata.assessment_id}
# =====================================================================

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[!] Administrative privileges required. Run PowerShell as Administrator."
    Exit 1
}

Write-Host "[*] Executing WinSecure Hardening Plan (${failing.length} fixes)..." -ForegroundColor Cyan
` + failing.map((f, i) => `
# Step ${i + 1}: ${f.id} — ${f.title}
Write-Host "  [*] Applying: ${f.title} (${f.id})..."
try {
    ${f.remediation}
    Write-Host "    [OK] Remediated ${f.id}" -ForegroundColor Green
} catch {
    Write-Warning "    [!] Failed ${f.id}: $_"
}
`).join('\n');

  const blob = new Blob([script], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `WinSecure-Remediation-${SYNTHETIC_REPORT_DATA.assessment_metadata.target_host}.ps1`;
  a.click();
  URL.revokeObjectURL(url);
  showToast("Master remediation script downloaded.");
}

// Toast
function showToast(msg) {
  const existing = document.querySelector('.platform-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'platform-toast';
  toast.style.cssText = "position: fixed; bottom: 24px; right: 24px; background: #111827; color: #ffffff; padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 500; z-index: 3000; box-shadow: 0 10px 25px rgba(0,0,0,0.2); transition: opacity 0.2s ease;";
  toast.textContent = `✓ ${msg}`;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 250);
  }, 2200);
}

// Keyboard shortcuts
function setupKeyboardListeners() {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      closeFindingModal();
    }
  });
}

function copyCode(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast("Copied to clipboard.");
  });
}

function getSeverityBadge(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'badge-crit';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-med';
    case 'low': return 'badge-low';
    default: return 'badge-low';
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeJs(str) {
  if (!str) return '';
  return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '');
}
"""


class WebReportGenerator:
    """Generates the clean, minimalist offline interactive cybersecurity web dashboard."""

    @staticmethod
    def generate(result: ScanResult, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)

        data_payload = json.dumps(result.to_dict(), default=str)

        crit_count = sum(1 for f in result.findings if f.status.value == "FAIL" and f.severity.value == "Critical")
        high_count = sum(1 for f in result.findings if f.status.value == "FAIL" and f.severity.value == "High")
        pass_count = sum(1 for f in result.findings if f.status.value == "PASS")

        inv = result.inventory
        hostname = inv.hostname if inv else 'DESKTOP-WIN11'
        os_name = inv.os_name if inv else 'Windows 11'
        admin_badge = 'badge-pass' if result.is_admin else 'badge-low'
        admin_label = 'ADMIN' if result.is_admin else 'USER'
        score_val = result.security_score
        risk_level_val = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)
        duration_val = result.metrics.duration_seconds if result.metrics else 0.0

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinSecure Security Assessment — {result.scan_id}</title>
  <style>
{REPORT_CSS}
  </style>
  <script>
    window.WINSECURE_DATA = {data_payload};
  </script>
</head>
<body>
  <div class="app-container">
    <aside class="sidebar">
      <div class="sidebar-header">
        <div class="brand-icon">WS</div>
        <div class="brand-details">
          <div class="brand-title">WinSecure</div>
          <div class="brand-subtitle">By Kartavya Joshi</div>
        </div>
      </div>

      <ul class="nav-menu">
        <li class="nav-item">
          <a class="nav-link active" data-tab="section-overview">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
            <span>Overview</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-findings">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <span>Findings</span>
            <span class="badge badge-crit" style="margin-left: auto;" id="sidebar-finding-count">{len(result.findings)}</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-modules">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            <span>30 Modules</span>
            <span class="badge badge-low" style="margin-left: auto;">30</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-compliance">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"></path></svg>
            <span>Compliance</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-remediation">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"></path></svg>
            <span>Remediation</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-logs">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            <span>Execution Log</span>
          </a>
        </li>
      </ul>

      <div class="sidebar-footer">
        <span class="status-dot"></span>
        <span>WinSecure · By Kartavya Joshi · v{result.winsecure_version}</span>
      </div>
    </aside>

    <div class="main-wrapper">
      <header class="topbar">
        <div class="topbar-left">
          <div class="meta-pill">
            <span>Host:</span> <strong id="topbar-host">{hostname}</strong>
            <span style="color: var(--border-color);">|</span>
            <span id="topbar-os">{os_name}</span>
            <span id="topbar-admin" class="badge {admin_badge}">
              {admin_label}
            </span>
          </div>
        </div>

        <div class="topbar-right">
          <button class="btn btn-primary btn-sm" onclick="downloadMasterScript()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            <span>Download Fix (.ps1)</span>
          </button>
          <button class="btn btn-outline btn-sm" onclick="window.print()">Print</button>
        </div>
      </header>

      <main class="page-content">
        <section id="section-overview" class="content-section active">
          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">Security Score</div>
              <div class="kpi-value" id="kpi-score">{score_val:.1f}/100</div>
              <div class="kpi-meta" id="kpi-posture">{risk_level_val} POSTURE</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Priority Defects</div>
              <div class="kpi-value kpi-danger" id="kpi-crit-high">{crit_count + high_count}</div>
              <div class="kpi-meta">{crit_count} Critical, {high_count} High</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Scan Duration</div>
              <div class="kpi-value" id="kpi-duration">{duration_val:.2f}s</div>
              <div class="kpi-meta">30 Security Scanners</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Verified Controls</div>
              <div class="kpi-value kpi-success" id="kpi-passed">{pass_count} / {len(result.findings)}</div>
              <div class="kpi-meta">Baseline Controls Aligned</div>
            </div>
          </div>

          <div class="card" style="margin-bottom: 20px;">
            <h2 class="card-title">Lead Security Auditor Briefing</h2>
            <div id="auditor-summary-text" style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">
              Automated diagnostic evaluation completed for endpoint <strong>{hostname}</strong>. Overall defensive security rating: <strong>{score_val:.1f} / 100 ({risk_level_val})</strong>. Evaluated <strong>{len(result.findings)} configuration controls</strong> across 30 system domains.
            </div>
          </div>
        </section>

        <section id="section-findings" class="content-section">
          <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">
              <h2 class="card-title" style="margin: 0;">Findings Explorer</h2>
              <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button class="filter-chip active" data-filter="ALL">ALL</button>
                <button class="filter-chip" data-filter="CRITICAL">CRITICAL</button>
                <button class="filter-chip" data-filter="HIGH">HIGH</button>
                <button class="filter-chip" data-filter="MEDIUM">MEDIUM</button>
                <button class="filter-chip" data-filter="FAIL">FAILURES</button>
                <button class="filter-chip" data-filter="PASS">PASSED</button>
              </div>
            </div>

            <div style="display: flex; gap: 12px; margin-bottom: 16px;">
              <input type="text" id="findings-search" class="form-input" placeholder="Search finding ID, title, affected component..." style="flex-grow: 1;">
              <select id="category-filter" class="form-input" style="width: 200px;">
                <option value="ALL">All Categories</option>
                <option value="Network Services">Network Services</option>
                <option value="Credential Protection">Credential Protection</option>
                <option value="Audit & Logging">Audit & Logging</option>
                <option value="Firewall Configuration">Firewall</option>
                <option value="Endpoint Defense">Endpoint Defense</option>
                <option value="Account Policy">Account Policy</option>
                <option value="Service Configuration">Services</option>
                <option value="Firmware & Kernel">Firmware & Kernel</option>
              </select>
            </div>

            <div class="table-responsive">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Category</th>
                    <th>Title & Affected Component</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Compliance</th>
                  </tr>
                </thead>
                <tbody id="findings-tbody"></tbody>
              </table>
            </div>
            <div id="findings-count-badge" style="font-size: 12px; color: var(--text-muted); margin-top: 12px;"></div>
          </div>
        </section>

        <section id="section-modules" class="content-section">
          <div class="card" style="margin-bottom: 16px;">
            <h2 class="card-title">30 Security Modules Catalog</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">Click any module to view technical definitions, registry paths, and compliance mappings.</p>
          </div>
          <div id="catalog-grid" class="grid-3"></div>
        </section>

        <section id="section-compliance" class="content-section">
          <div class="card" style="margin-bottom: 16px;">
            <h2 class="card-title">Compliance Framework Alignments</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">Technical alignment mapping against authoritative security baselines.</p>
          </div>
          <div id="compliance-cards-grid" class="grid-2"></div>
        </section>

        <section id="section-remediation" class="content-section">
          <div class="card" style="margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
            <div>
              <h2 class="card-title" style="margin: 0;">Remediation Roadmap</h2>
              <p style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">Prioritized step-by-step PowerShell corrective actions.</p>
            </div>
            <button class="btn btn-primary" onclick="downloadMasterScript()">Download Master Fix (.ps1)</button>
          </div>
          <div id="remediation-list"></div>
        </section>

        <section id="section-logs" class="content-section">
          <div class="card">
            <h2 class="card-title">Assessment Execution Timeline</h2>
            <div id="timeline-log-list" style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;"></div>
          </div>
        </section>
      </main>
    </div>
  </div>

  <div id="finding-modal" class="modal-overlay" onclick="closeFindingModal()">
    <div class="modal-card" onclick="event.stopPropagation()">
      <div class="modal-header">
        <h3 id="modal-title" style="font-size: 15px; font-weight: 700; color: var(--text-primary); margin: 0;">[SEC-000] Finding Detail</h3>
        <button class="modal-close" onclick="closeFindingModal()">&times;</button>
      </div>
      <div class="modal-tabs">
        <button class="modal-tab active" data-tab="tab-overview" onclick="switchModalTab('tab-overview')">Overview</button>
        <button class="modal-tab" data-tab="tab-threat" onclick="switchModalTab('tab-threat')">Attacker Vector</button>
        <button class="modal-tab" data-tab="tab-remediation" onclick="switchModalTab('tab-remediation')">PowerShell Fix</button>
        <button class="modal-tab" data-tab="tab-evidence" onclick="switchModalTab('tab-evidence')">Evidence (JSON)</button>
        <button class="modal-tab" data-tab="tab-compliance" onclick="switchModalTab('tab-compliance')">Compliance</button>
      </div>
      <div id="modal-body" class="modal-body"></div>
    </div>
  </div>

  <script>
{REPORT_JS}
  </script>
</body>
</html>
"""
        report_path = os.path.join(output_dir, "index.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return report_path
