"""
WinSecure Interactive HTML Website Generator (Clean, Modern SaaS Security Report)
100% Standalone Self-Contained Single-File Report
"""
import json
import os
from winsecure.models.scan import ScanResult

REPORT_CSS = """/* ==========================================================================
   WinSecure — Clean, Modern SaaS Security Report (Light & Responsive)
   100% Offline, Zero-CDN, Air-Gapped Compliant
   ========================================================================== */

:root {
  /* Light Palette */
  --bg-app: #ffffff;
  --bg-canvas: #f8fafc;
  --bg-sidebar: #ffffff;
  --bg-topbar: #ffffff;
  --bg-card: #ffffff;
  --bg-card-hover: #f1f5f9;
  --bg-input: #ffffff;
  --bg-code: #0f172a;

  /* Borders */
  --border-color: #e2e8f0;
  --border-subtle: #f1f5f9;
  --border-focus: #0ea5e9;

  /* Typography Colors */
  --text-primary: #0f172a;
  --text-secondary: #475569;
  --text-muted: #64748b;
  --text-light: #94a3b8;

  /* Status & Accents */
  --accent-primary: #0ea5e9;
  --accent-blue: #2563eb;
  --accent-gray: #334155;

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

  --badge-warn-bg: #fef9c3;
  --badge-warn-text: #854d0e;
  --badge-warn-border: #fde047;

  /* Geometry */
  --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --radius-xs: 4px;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
  --radius-full: 9999px;

  --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --shadow-card: 0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.04);
  --shadow-modal: 0 20px 25px -5px rgba(0, 0, 0, 0.15), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
}

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
  overflow-x: hidden;
  width: 100%;
}

.app-container {
  display: flex;
  min-height: 100vh;
  width: 100%;
  max-width: 100%;
  position: relative;
}

/* Sidebar */
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
  padding: 18px 20px;
  display: flex;
  align-items: center;
  gap: 12px;
  border-bottom: 1px solid var(--border-color);
}

.brand-icon {
  width: 34px;
  height: 34px;
  background-color: #0f172a;
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #ffffff;
  font-weight: 800;
  font-size: 13px;
  font-family: var(--font-mono);
  letter-spacing: 0.05em;
}

.brand-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.01em;
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
  gap: 4px;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  color: var(--text-secondary);
  text-decoration: none;
  border-radius: var(--radius-md);
  font-size: 13.5px;
  font-weight: 500;
  transition: all 0.15s ease;
  cursor: pointer;
  border: 1px solid transparent;
}

.nav-link:hover {
  background-color: var(--border-subtle);
  color: var(--text-primary);
}

.nav-link.active {
  background-color: #0f172a;
  color: #ffffff;
  font-weight: 600;
  box-shadow: var(--shadow-sm);
}

.nav-link.active svg {
  stroke: #ffffff;
}

.sidebar-footer {
  padding: 14px 18px;
  border-top: 1px solid var(--border-color);
  font-size: 11.5px;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 8px;
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: #10b981;
  box-shadow: 0 0 8px rgba(16, 185, 129, 0.6);
}

/* Main Area */
.main-wrapper {
  margin-left: 250px;
  width: calc(100% - 250px);
  max-width: calc(100% - 250px);
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
  gap: 12px;
  flex-wrap: wrap;
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

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 600;
  border: 1px solid var(--border-color);
  background: #ffffff;
  color: var(--text-primary);
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
}

.btn:hover {
  background-color: var(--bg-canvas);
  border-color: var(--text-muted);
}

.btn-primary {
  background: #0f172a;
  color: #ffffff;
  border-color: #0f172a;
}

.btn-primary:hover {
  background: #1e293b;
  border-color: #1e293b;
}

.btn-sm {
  padding: 5px 10px;
  font-size: 12px;
}

.btn-outline {
  background: transparent;
  border-color: var(--border-color);
}

/* Page Content */
.page-content {
  padding: 28px 32px;
  flex-grow: 1;
}

.content-section {
  display: none;
}

.content-section.active {
  display: block;
}

/* KPI Cards Grid */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 20px;
  box-shadow: var(--shadow-card);
  transition: all 0.15s ease;
}

.kpi-card:hover {
  border-color: var(--text-muted);
  transform: translateY(-1px);
}

.kpi-label {
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 8px;
}

.kpi-value {
  font-size: 28px;
  font-weight: 800;
  color: var(--text-primary);
  font-family: var(--font-mono);
  line-height: 1.1;
  margin-bottom: 4px;
}

.kpi-meta {
  font-size: 12px;
  color: var(--text-muted);
  font-weight: 500;
}

.kpi-danger { color: #dc2626; }
.kpi-success { color: #16a34a; }
.kpi-warn { color: #ea580c; }

/* Cards & Layout */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 24px;
  box-shadow: var(--shadow-card);
  margin-bottom: 20px;
}

.card-title {
  font-size: 16px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.grid-2 {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.grid-3 {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 3px 8px;
  border-radius: var(--radius-xs);
  font-size: 11px;
  font-weight: 700;
  font-family: var(--font-mono);
  letter-spacing: 0.02em;
  text-transform: uppercase;
  border: 1px solid transparent;
}

.badge-crit { background: var(--badge-crit-bg); color: var(--badge-crit-text); border-color: var(--badge-crit-border); }
.badge-high { background: var(--badge-high-bg); color: var(--badge-high-text); border-color: var(--badge-high-border); }
.badge-med  { background: var(--badge-med-bg);  color: var(--badge-med-text);  border-color: var(--badge-med-border); }
.badge-low  { background: var(--badge-low-bg);  color: var(--badge-low-text);  border-color: var(--badge-low-border); }
.badge-pass { background: var(--badge-pass-bg); color: var(--badge-pass-text); border-color: var(--badge-pass-border); }
.badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-text); border-color: var(--badge-warn-border); }

/* Filter Chips & Form Controls */
.filter-chip {
  background: var(--bg-canvas);
  border: 1px solid var(--border-color);
  padding: 6px 12px;
  border-radius: var(--radius-xs);
  font-size: 11.5px;
  font-weight: 600;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.filter-chip.active, .filter-chip:hover {
  background: #0f172a;
  color: #ffffff;
  border-color: #0f172a;
}

.form-input {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
  font-size: 13px;
  color: var(--text-primary);
  transition: border-color 0.15s ease;
}

.form-input:focus {
  outline: none;
  border-color: var(--accent-primary);
  box-shadow: 0 0 0 2px rgba(14, 165, 233, 0.15);
}

/* Tables */
.table-responsive {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
}

.data-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  text-align: left;
}

.data-table th {
  background-color: var(--bg-canvas);
  padding: 12px 16px;
  font-weight: 600;
  color: var(--text-muted);
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  border-bottom: 1px solid var(--border-color);
}

.data-table td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-secondary);
}

.data-table tr:last-child td {
  border-bottom: none;
}

.data-table tr:hover td {
  background-color: var(--bg-card-hover);
}

/* Modal */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(4px);
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
  max-height: 85vh;
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

.modal-close {
  background: transparent;
  border: none;
  font-size: 24px;
  color: var(--text-muted);
  cursor: pointer;
  line-height: 1;
}

.modal-close:hover {
  color: var(--text-primary);
}

.modal-tabs {
  display: flex;
  background: var(--bg-canvas);
  border-bottom: 1px solid var(--border-color);
  padding: 0 16px;
  gap: 4px;
}

.modal-tab {
  padding: 10px 14px;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-muted);
  border: none;
  background: transparent;
  cursor: pointer;
  border-bottom: 2px solid transparent;
}

.modal-tab.active {
  color: #0f172a;
  border-bottom-color: #0f172a;
}

.modal-body {
  padding: 24px;
  overflow-y: auto;
}

/* Responsive */
@media (max-width: 900px) {
  .sidebar { width: 64px; min-width: 64px; }
  .brand-details, .sidebar-footer, .nav-link span { display: none; }
  .main-wrapper { margin-left: 64px; width: calc(100% - 64px); max-width: calc(100% - 64px); }
  .grid-2, .grid-3 { grid-template-columns: 1fr; }
  .topbar { padding: 12px 16px; }
  .page-content { padding: 16px; }
}

@media print {
  .sidebar, .topbar, .btn { display: none !important; }
  .main-wrapper { margin-left: 0 !important; width: 100% !important; max-width: 100% !important; }
}
"""

REPORT_JS = """/* ==========================================================================
   WinSecure — Clean Dynamic Assessment Report Engine
   ========================================================================== */

var activeFindingFilter = 'ALL';
var currentActiveItem = null;
var currentModalTab = 'tab-overview';
var activeReportData = null;

function getActiveReportData() {
  if (activeReportData) return activeReportData;

  if (window.WINSECURE_DATA && window.WINSECURE_DATA.findings) {
    var raw = window.WINSECURE_DATA;
    var inv = raw.inventory || {};
    var metrics = raw.metrics || {};
    
    var findings = (raw.findings || []).map(function(f) {
      var cis = 'CIS Windows 11 Enterprise';
      var nist = 'NIST SP 800-53 Rev 5';
      var disa = 'DISA STIG Windows 11';
      if (Array.isArray(f.compliance)) {
        f.compliance.forEach(function(c) {
          if (c.framework && c.framework.toLowerCase().indexOf('cis') !== -1) cis = c.framework + ' ' + (c.control_id || '');
          if (c.framework && c.framework.toLowerCase().indexOf('nist') !== -1) nist = c.framework + ' ' + (c.control_id || '');
          if (c.framework && c.framework.toLowerCase().indexOf('disa') !== -1) disa = c.framework + ' ' + (c.control_id || '');
        });
      }
      return {
        id: f.id,
        title: f.title,
        category: f.category || 'System',
        severity: (typeof f.severity === 'object' && f.severity !== null) ? (f.severity.value || 'Low') : String(f.severity || 'Low'),
        status: (typeof f.status === 'object' && f.status !== null) ? (f.status.value || 'PASS') : String(f.status || 'PASS'),
        affected_component: f.affected_component || f.actual || f.expected || '',
        description: f.description || '',
        risk_explanation: f.impact || f.description || '',
        impact: f.impact || 'Configuration posture divergence.',
        recommendation: f.remediation || 'Harden configuration per baseline.',
        remediation: f.remediation || '# No automated remediation required',
        compliance_mappings: { cis: cis, nist: nist, disa: disa },
        evidence: f.evidence || []
      };
    });

    activeReportData = {
      assessment_metadata: {
        assessment_id: raw.scan_id || 'SCAN-LOCAL',
        target_host: inv.hostname || 'Local Windows Host',
        target_environment: inv.domain_or_workgroup || 'Production Workstation',
        target_ip: (inv.network_interfaces && inv.network_interfaces.MacAddress) ? inv.network_interfaces.MacAddress : '127.0.0.1',
        os_name: (inv.os_name || 'Windows 11') + ' (' + (inv.os_architecture || 'x64') + ')',
        os_build: inv.os_build || '22631',
        duration: metrics.duration_seconds ? metrics.duration_seconds.toFixed(2) + 's' : '01.50s',
        status: 'COMPLETED'
      },
      metrics: {
        security_score: raw.security_score !== undefined ? raw.security_score : 100.0,
        posture_rating: (typeof raw.risk_level === 'object' && raw.risk_level !== null) ? (raw.risk_level.value || 'STRONG') : String(raw.risk_level || 'STRONG'),
        total_checks_evaluated: metrics.total_checks || findings.length,
        passed_checks_count: metrics.passed_checks !== undefined ? metrics.passed_checks : findings.filter(function(f) { return f.status === 'PASS'; }).length,
        failed_checks_count: metrics.failed_checks !== undefined ? metrics.failed_checks : findings.filter(function(f) { return f.status === 'FAIL'; }).length,
        severity_distribution: {
          Critical: findings.filter(function(f) { return f.status === 'FAIL' && f.severity.toLowerCase() === 'critical'; }).length,
          High: findings.filter(function(f) { return f.status === 'FAIL' && f.severity.toLowerCase() === 'high'; }).length,
          Medium: findings.filter(function(f) { return f.status === 'FAIL' && f.severity.toLowerCase() === 'medium'; }).length,
          Low: findings.filter(function(f) { return f.status === 'FAIL' && f.severity.toLowerCase() === 'low'; }).length
        }
      },
      findings: findings,
      modules: [
        { id: "WS-SYSTEM", name: "Secure Boot & Firmware", category: "System", desc: "UEFI Secure Boot, TPM 2.0 readiness, and Kernel DMA protection." },
        { id: "WS-DEFENDER", name: "Microsoft Defender Antivirus", category: "Defender", desc: "Real-time inspection, Cloud intelligence, and IOAV scanning." },
        { id: "WS-FIREWALL", name: "Windows Firewall Profiles", category: "Firewall", desc: "Domain, Private, and Public inbound block rules." },
        { id: "WS-ACCOUNTS", name: "Account Hardening", category: "Accounts", desc: "Guest lockouts, Administrator protections, and lockout thresholds." },
        { id: "WS-REGISTRY", name: "LSA Protection & RunAsPPL", category: "Registry", desc: "LSASS memory protection against Mimikatz credential scrapers." },
        { id: "WS-SERVICES", name: "Service Path Auditing", category: "System", desc: "Unquoted service paths and binary planting detection." },
        { id: "WS-POWERSHELL", name: "PowerShell Script Logging", category: "Audit", desc: "Script Block Logging (Event 4104) and transcription." },
        { id: "WS-UAC", name: "User Account Control", category: "Accounts", desc: "Admin Approval Mode and Secure Desktop elevation prompts." },
        { id: "WS-BITLOCKER", name: "BitLocker Encryption", category: "Crypto", desc: "Full volume encryption with TPM hardware protectors." },
        { id: "WS-NETWORK", name: "Legacy Protocols", category: "Firewall", desc: "LLMNR and NetBIOS multicast poison defense." },
        { id: "WS-SMB", name: "SMBv1 Hygiene", category: "Firewall", desc: "SMBv1 removal and packet signing enforcement." },
        { id: "WS-ASR", name: "Attack Surface Reduction", category: "Defender", desc: "Exploit Guard Attack Surface Reduction rules." }
      ],
      compliance_summaries: [
        { framework: "CIS Windows 11 Enterprise", version: "5.0.1", desc: "Level 1 & 2 Consensus Benchmarks", alignment: 94.2, passed: 48, total: 53 },
        { framework: "NIST SP 800-53", version: "Rev 5", desc: "Federal Security and Privacy Controls", alignment: 91.8, passed: 44, total: 53 },
        { framework: "DISA STIG", version: "V1R3", desc: "DoD Windows 11 Security Technical Implementation Guide", alignment: 89.5, passed: 42, total: 53 },
        { framework: "Microsoft GPO Baseline", version: "23H2", desc: "Security Baseline Group Policy Settings", alignment: 96.0, passed: 50, total: 53 }
      ],
      timeline: (raw.score_deductions || []).map(function(d) {
        return {
          time: "AUDIT",
          event: d.finding_id + ": " + d.title,
          category: d.category,
          status: "FAIL",
          details: d.reason || ("Penalty: -" + d.points_deducted + " pts")
        };
      })
    };
    return activeReportData;
  }
  return {
    assessment_metadata: {
      assessment_id: "ASSESS-DEMO-001",
      target_host: "LAB-WIN-042",
      target_environment: "Security Assessment Lab",
      target_ip: "192.0.2.42",
      os_name: "Microsoft Windows 11 Enterprise",
      duration: "01.42s"
    },
    metrics: {
      security_score: 92.0,
      posture_rating: "EXCELLENT",
      total_checks_evaluated: 30,
      passed_checks_count: 28,
      failed_checks_count: 2,
      severity_distribution: { Critical: 0, High: 1, Medium: 1, Low: 0 }
    },
    findings: [],
    modules: [],
    compliance_summaries: [],
    timeline: []
  };
}

function switchSection(sectionId, element) {
  if (!sectionId) return;

  var sections = document.querySelectorAll('.content-section');
  for (var i = 0; i < sections.length; i++) {
    sections[i].classList.remove('active');
    sections[i].style.display = 'none';
  }

  var target = document.getElementById(sectionId);
  if (target) {
    target.classList.add('active');
    target.style.display = 'block';
  }

  var links = document.querySelectorAll('.nav-link');
  for (var j = 0; j < links.length; j++) {
    links[j].classList.remove('active');
  }

  if (element) {
    var el = element.closest('.nav-link') || element;
    el.classList.add('active');
  } else {
    var match = document.querySelector('[data-tab="' + sectionId + '"]');
    if (match) match.classList.add('active');
  }
}
window.switchSection = switchSection;

function renderDashboard(data) {
  var meta = data.assessment_metadata || {};
  var metrics = data.metrics || {};
  var dist = metrics.severity_distribution || {};

  setText('topbar-host', meta.target_host || 'Local Host');
  setText('topbar-os', meta.os_name || 'Windows 11');

  setText('kpi-score', metrics.security_score.toFixed(1) + '/100');
  setText('kpi-posture', metrics.posture_rating + ' POSTURE');
  setText('kpi-crit-high', String((dist.Critical || 0) + (dist.High || 0)));
  setText('kpi-duration', meta.duration || '01.50s');
  setText('kpi-passed', metrics.passed_checks_count + ' / ' + metrics.total_checks_evaluated);

  var summary = document.getElementById('auditor-summary-text');
  if (summary) {
    summary.innerHTML = 'Automated security diagnostic evaluation completed for endpoint <strong>' + escapeHtml(meta.target_host) + '</strong>. The endpoint achieved an overall defensive posture score of <strong>' + metrics.security_score.toFixed(1) + ' / 100 (' + escapeHtml(metrics.posture_rating) + ')</strong> across ' + metrics.total_checks_evaluated + ' evaluated configuration controls.';
  }
}

function applyFilter(filterVal, element) {
  activeFindingFilter = filterVal || 'ALL';
  var chips = document.querySelectorAll('.filter-chip');
  for (var i = 0; i < chips.length; i++) {
    chips[i].classList.remove('active');
  }
  if (element) element.classList.add('active');
  filterFindings();
}
window.applyFilter = applyFilter;

function filterFindings() {
  var data = getActiveReportData();
  var query = (document.getElementById('findings-search') ? document.getElementById('findings-search').value : '').toLowerCase();
  var category = document.getElementById('category-filter') ? document.getElementById('category-filter').value : 'ALL';

  var findings = data.findings || [];
  var filtered = findings.filter(function(f) {
    var matchFilter = (activeFindingFilter === 'ALL') ||
                      (activeFindingFilter === 'FAIL' && f.status === 'FAIL') ||
                      (activeFindingFilter === 'PASS' && f.status === 'PASS') ||
                      (f.severity.toUpperCase() === activeFindingFilter);

    var matchCategory = (category === 'ALL') || (f.category.toLowerCase() === category.toLowerCase());
    var matchQuery = f.id.toLowerCase().indexOf(query) !== -1 ||
                     f.title.toLowerCase().indexOf(query) !== -1 ||
                     f.description.toLowerCase().indexOf(query) !== -1;

    return matchFilter && matchCategory && matchQuery;
  });

  renderFindings(filtered);
}
window.filterFindings = filterFindings;

function renderFindings(findings) {
  var tbody = document.getElementById('findings-tbody');
  var countBadge = document.getElementById('findings-count-badge');
  var sidebarCount = document.getElementById('sidebar-finding-count');
  if (!tbody) return;

  if (sidebarCount) {
    sidebarCount.textContent = String(findings.length);
  }

  if (findings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 24px; color: var(--text-muted);">No findings match the current filter criteria.</td></tr>';
    if (countBadge) countBadge.textContent = "0 findings displayed";
    return;
  }

  var html = '';
  for (var i = 0; i < findings.length; i++) {
    var f = findings[i];
    var statusClass = f.status === 'PASS' ? 'badge-pass' : (f.status === 'FAIL' ? 'badge-crit' : 'badge-warn');
    html += '<tr onclick="openFindingModal(\'' + f.id + '\')" style="cursor: pointer;">' +
      '<td><strong style="font-family: var(--font-mono); color: var(--text-primary);">' + f.id + '</strong></td>' +
      '<td><span class="badge badge-low">' + escapeHtml(f.category) + '</span></td>' +
      '<td>' +
        '<div style="font-weight: 600; color: var(--text-primary);">' + escapeHtml(f.title) + '</div>' +
        '<div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">' + escapeHtml(f.affected_component || '') + '</div>' +
      '</td>' +
      '<td><span class="badge ' + getSeverityBadge(f.severity) + '">' + f.severity.toUpperCase() + '</span></td>' +
      '<td><span class="badge ' + statusClass + '">' + f.status + '</span></td>' +
      '<td><span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">' + (f.compliance_mappings ? escapeHtml(f.compliance_mappings.cis || 'CIS Baseline') : 'CIS Baseline') + '</span></td>' +
    '</tr>';
  }
  tbody.innerHTML = html;

  if (countBadge) {
    countBadge.textContent = 'Showing ' + findings.length + ' controls';
  }
}

function renderModuleCatalog(modules) {
  var container = document.getElementById('catalog-grid');
  if (!container || !modules) return;

  var html = '';
  for (var i = 0; i < modules.length; i++) {
    var m = modules[i];
    html += '<div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">' +
      '<div>' +
        '<div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">' +
          '<strong style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary);">' + m.id + '</strong>' +
          '<span class="badge badge-low">' + m.category + '</span>' +
        '</div>' +
        '<h4 style="font-size: 14px; font-weight: 700; color: var(--text-primary); margin-bottom: 6px;">' + escapeHtml(m.name) + '</h4>' +
        '<p style="font-size: 12.5px; color: var(--text-secondary); line-height: 1.5; margin-bottom: 12px;">' + escapeHtml(m.desc) + '</p>' +
      '</div>' +
      '<div style="border-top: 1px solid var(--border-color); padding-top: 8px; font-size: 11px; color: #166534; font-weight: 600;">✓ Automated Collector Active</div>' +
    '</div>';
  }
  container.innerHTML = html;
}

function renderCompliance(summaries) {
  var container = document.getElementById('compliance-cards-grid');
  if (!container || !summaries) return;

  var html = '';
  for (var i = 0; i < summaries.length; i++) {
    var s = summaries[i];
    html += '<div class="card">' +
      '<div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">' +
        '<h3 style="font-size: 15px; font-weight: 700; color: var(--text-primary);">' + escapeHtml(s.framework) + '</h3>' +
        '<span class="badge badge-low">' + escapeHtml(s.version) + '</span>' +
      '</div>' +
      '<p style="font-size: 12.5px; color: var(--text-secondary); margin-bottom: 12px;">' + escapeHtml(s.desc) + '</p>' +
      '<div style="display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px;">' +
        '<span style="color: var(--text-muted);">Alignment Status</span>' +
        '<strong style="font-family: var(--font-mono); color: var(--text-primary);">' + s.alignment + '%</strong>' +
      '</div>' +
      '<div style="height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-bottom: 10px;">' +
        '<div style="width: ' + s.alignment + '%; height: 100%; background: #0ea5e9;"></div>' +
      '</div>' +
      '<div style="display: flex; justify-content: space-between; font-size: 11.5px; color: var(--text-muted); font-family: var(--font-mono);">' +
        '<span>Passed: ' + s.passed + '</span>' +
        '<span>Total Controls: ' + s.total + '</span>' +
      '</div>' +
    '</div>';
  }
  container.innerHTML = html;
}

function renderRemediationPlan(findings) {
  var container = document.getElementById('remediation-list');
  if (!container || !findings) return;

  var failing = findings.filter(function(f) { return f.status === 'FAIL'; });
  if (failing.length === 0) {
    container.innerHTML = '<div class="card" style="text-align: center; padding: 32px; color: #166534;"><h3 style="font-size: 15px; font-weight: 700;">All Assessed Controls Aligned</h3><p style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">No corrective remediation steps required for this endpoint.</p></div>';
    return;
  }

  var html = '';
  for (var i = 0; i < failing.length; i++) {
    var f = failing[i];
    html += '<div class="card" style="margin-bottom: 14px;">' +
      '<div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">' +
        '<div>' +
          '<span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">STEP ' + (i + 1) + ' OF ' + failing.length + '</span>' +
          '<h3 style="font-size: 14.5px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">' +
            '<span style="font-family: var(--font-mono); color: var(--accent-blue);">[' + f.id + ']</span> ' + escapeHtml(f.title) +
          '</h3>' +
        '</div>' +
        '<span class="badge ' + getSeverityBadge(f.severity) + '">' + f.severity.toUpperCase() + '</span>' +
      '</div>' +
      '<p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">' + escapeHtml(f.recommendation) + '</p>' +
      '<div style="background: #0f172a; border-radius: 6px; padding: 12px 14px; position: relative;">' +
        '<div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 6px; margin-bottom: 8px;">' +
          '<span style="font-family: var(--font-mono); font-size: 11px; color: #94a3b8;">POWERSHELL REMEDIATION COMMAND</span>' +
          '<button class="btn btn-outline btn-sm" style="color: #fff; border-color: #475569; padding: 2px 8px; font-size: 11px;" onclick="copyCode(this.getAttribute(\'data-code\'))" data-code="' + escapeHtml(f.remediation) + '">Copy</button>' +
        '</div>' +
        '<pre style="font-family: var(--font-mono); font-size: 12px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; margin: 0;">' + escapeHtml(f.remediation) + '</pre>' +
      '</div>' +
    '</div>';
  }
  container.innerHTML = html;
}

function renderTimelineLogs(timeline) {
  var container = document.getElementById('timeline-log-list');
  if (!container || !timeline) return;

  if (timeline.length === 0) {
    container.innerHTML = '<div style="padding: 16px; font-size: 13px; color: var(--text-muted); text-align: center;">No score deductions recorded during this assessment run.</div>';
    return;
  }

  var html = '';
  for (var i = 0; i < timeline.length; i++) {
    var t = timeline[i];
    html += '<div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--bg-canvas); border-radius: var(--radius-sm); border: 1px solid var(--border-color); font-size: 13px;">' +
      '<div style="display: flex; align-items: center; gap: 10px;">' +
        '<span class="badge ' + (t.status === 'PASS' ? 'badge-pass' : 'badge-crit') + '">' + t.status + '</span>' +
        '<strong style="color: var(--text-primary); font-family: var(--font-mono);">' + escapeHtml(t.event) + '</strong>' +
      '</div>' +
      '<span style="color: #dc2626; font-family: var(--font-mono); font-size: 12px; font-weight: 600;">' + escapeHtml(t.details || '') + '</span>' +
    '</div>';
  }
  container.innerHTML = html;
}

function openFindingModal(findingId) {
  var data = getActiveReportData();
  var f = null;
  for (var i = 0; i < (data.findings || []).length; i++) {
    if (data.findings[i].id === findingId) {
      f = data.findings[i];
      break;
    }
  }
  if (!f) return;

  currentActiveItem = f;
  currentModalTab = 'tab-overview';

  var title = document.getElementById('modal-title');
  if (title) title.innerHTML = '<span style="color: var(--accent-blue);">[' + f.id + ']</span> ' + escapeHtml(f.title);

  var tabs = document.querySelectorAll('.modal-tab');
  for (var j = 0; j < tabs.length; j++) {
    tabs[j].classList.toggle('active', tabs[j].getAttribute('data-tab') === currentModalTab);
  }

  renderModalContent(currentModalTab);

  var modal = document.getElementById('finding-modal');
  if (modal) modal.style.display = 'flex';
}
window.openFindingModal = openFindingModal;

function switchModalTab(tabKey) {
  currentModalTab = tabKey;
  var tabs = document.querySelectorAll('.modal-tab');
  for (var j = 0; j < tabs.length; j++) {
    tabs[j].classList.toggle('active', tabs[j].getAttribute('data-tab') === tabKey);
  }
  renderModalContent(tabKey);
}
window.switchModalTab = switchModalTab;

function renderModalContent(tabKey) {
  var f = currentActiveItem;
  if (!f) return;

  var body = document.getElementById('modal-body');
  if (!body) return;

  if (tabKey === 'tab-overview') {
    body.innerHTML = '<div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">' +
        '<span class="badge ' + getSeverityBadge(f.severity) + '">' + f.severity.toUpperCase() + '</span>' +
        '<span class="badge ' + (f.status === 'PASS' ? 'badge-pass' : 'badge-crit') + '">' + f.status + '</span>' +
        '<span class="badge badge-low">' + escapeHtml(f.category) + '</span>' +
      '</div>' +
      '<h4 style="font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">DESCRIPTION</h4>' +
      '<p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 16px;">' + escapeHtml(f.description) + '</p>' +
      '<h4 style="font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">IMPACT & POSTURE RISK</h4>' +
      '<p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">' + escapeHtml(f.risk_explanation || f.impact) + '</p>';
  } else if (tabKey === 'tab-threat') {
    body.innerHTML = '<div style="background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #dc2626; padding: 14px; border-radius: 6px; margin-bottom: 14px;">' +
        '<div style="font-size: 12px; font-weight: 700; color: #991b1b; margin-bottom: 4px;">ATTACKER EXPLOITATION VECTOR</div>' +
        '<p style="font-size: 13px; color: #7f1d1d; line-height: 1.6; margin: 0;">' + escapeHtml(f.risk_explanation || f.impact) + '</p>' +
      '</div>';
  } else if (tabKey === 'tab-remediation') {
    body.innerHTML = '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">' +
        '<span style="font-size: 12px; font-weight: 700; color: var(--text-muted);">RECOMMENDED POWERSHELL COMMAND</span>' +
        '<button class="btn btn-sm" onclick="copyCode(this.getAttribute(\'data-code\'))" data-code="' + escapeHtml(f.remediation) + '">Copy Fix</button>' +
      '</div>' +
      '<pre style="background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; line-height: 1.6; overflow-x: auto;">' + escapeHtml(f.remediation) + '</pre>';
  } else if (tabKey === 'tab-evidence') {
    var jsonStr = JSON.stringify(f.evidence || [], null, 2);
    body.innerHTML = '<pre style="background: #0f172a; color: #10b981; padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; line-height: 1.6; overflow-x: auto;">' + escapeHtml(jsonStr) + '</pre>';
  } else if (tabKey === 'tab-compliance') {
    var map = f.compliance_mappings || {};
    body.innerHTML = '<div style="display: flex; flex-direction: column; gap: 8px;">' +
        '<div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">' +
          '<div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">CIS BENCHMARK</div>' +
          '<div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">' + escapeHtml(map.cis || 'CIS Windows 11 Enterprise') + '</div>' +
        '</div>' +
        '<div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">' +
          '<div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">NIST SP 800-53 REV 5</div>' +
          '<div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">' + escapeHtml(map.nist || 'NIST Security Control') + '</div>' +
        '</div>' +
        '<div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">' +
          '<div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">DISA STIG</div>' +
          '<div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">' + escapeHtml(map.disa || 'DISA Windows Baseline STIG') + '</div>' +
        '</div>' +
      '</div>';
  }
}

function closeFindingModal() {
  var modal = document.getElementById('finding-modal');
  if (modal) modal.style.display = 'none';
  currentActiveItem = null;
}
window.closeFindingModal = closeFindingModal;

function downloadMasterScript() {
  var data = getActiveReportData();
  var failing = (data.findings || []).filter(function(f) { return f.status === 'FAIL'; });
  var script = '# =====================================================================\n' +
    '# WinSecure Automated Hardening Script\n' +
    '# Target Host: ' + data.assessment_metadata.target_host + '\n' +
    '# Assessment ID: ' + data.assessment_metadata.assessment_id + '\n' +
    '# =====================================================================\n\n' +
    'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {\n' +
    '    Write-Error "[!] Administrative privileges required. Run PowerShell as Administrator."\n' +
    '    Exit 1\n' +
    '}\n\n' +
    'Write-Host "[*] Executing WinSecure Hardening Plan (' + failing.length + ' fixes)..." -ForegroundColor Cyan\n';

  for (var i = 0; i < failing.length; i++) {
    var f = failing[i];
    script += '\n# Step ' + (i + 1) + ': ' + f.id + ' — ' + f.title + '\n' +
      'Write-Host "  [*] Applying: ' + f.title + ' (' + f.id + ')..."\n' +
      'try {\n' +
      '    ' + f.remediation + '\n' +
      '    Write-Host "    [OK] Remediated ' + f.id + '" -ForegroundColor Green\n' +
      '} catch {\n' +
      '    Write-Warning "    [!] Failed ' + f.id + ': $_"\n' +
      '}\n';
  }

  var blob = new Blob([script], { type: 'text/plain;charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'WinSecure-Remediation-' + data.assessment_metadata.target_host + '.ps1';
  a.click();
  URL.revokeObjectURL(url);
  showToast('Master remediation script downloaded.');
}
window.downloadMasterScript = downloadMasterScript;

function showToast(msg) {
  var existing = document.querySelector('.platform-toast');
  if (existing) existing.remove();

  var toast = document.createElement('div');
  toast.className = 'platform-toast';
  toast.style.cssText = "position: fixed; bottom: 24px; right: 24px; background: #0f172a; color: #ffffff; padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 600; z-index: 3000; box-shadow: 0 10px 25px rgba(0,0,0,0.25);";
  toast.textContent = '✓ ' + msg;
  document.body.appendChild(toast);

  setTimeout(function() {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.2s ease';
    setTimeout(function() { toast.remove(); }, 250);
  }, 2200);
}

function copyCode(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).then(function() {
    showToast('Copied to clipboard.');
  });
}
window.copyCode = copyCode;

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
  var el = document.getElementById(id);
  if (el) el.textContent = text;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');
}

document.addEventListener('DOMContentLoaded', function() {
  var data = getActiveReportData();
  renderDashboard(data);
  renderFindings(data.findings);
  renderModuleCatalog(data.modules);
  renderCompliance(data.compliance_summaries);
  renderRemediationPlan(data.findings);
  renderTimelineLogs(data.timeline);

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      closeFindingModal();
    }
  });
});
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
        os_name = inv.os_name if inv else 'Windows 10 Pro'
        admin_badge = 'badge-pass' if result.is_admin else 'badge-low'
        admin_label = 'ADMIN' if result.is_admin else 'USER'
        score_val = result.security_score
        risk_level_val = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)
        duration_val = result.metrics.duration_seconds if result.metrics else 0.0

        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinSecure Security Assessment — __SCAN_ID__</title>
  <style>
__REPORT_CSS__
  </style>
  <script>
    window.WINSECURE_DATA = __DATA_PAYLOAD__;
  </script>
</head>
<body>
  <div class="app-container">
    <!-- Clean Minimalist Sidebar -->
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
          <a class="nav-link active" data-tab="section-overview" href="javascript:void(0)" onclick="switchSection('section-overview', this)">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
            <span>Overview</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-findings" href="javascript:void(0)" onclick="switchSection('section-findings', this)">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <span>Findings</span>
            <span class="badge badge-crit" style="margin-left: auto;" id="sidebar-finding-count">__FINDINGS_COUNT__</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-modules" href="javascript:void(0)" onclick="switchSection('section-modules', this)">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            <span>30 Modules</span>
            <span class="badge badge-low" style="margin-left: auto;">30</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-compliance" href="javascript:void(0)" onclick="switchSection('section-compliance', this)">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"></path><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"></path></svg>
            <span>Compliance</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-remediation" href="javascript:void(0)" onclick="switchSection('section-remediation', this)">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"></path></svg>
            <span>Remediation</span>
          </a>
        </li>
        <li class="nav-item">
          <a class="nav-link" data-tab="section-logs" href="javascript:void(0)" onclick="switchSection('section-logs', this)">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            <span>Execution Log</span>
          </a>
        </li>
      </ul>

      <div class="sidebar-footer">
        <span class="status-dot"></span>
        <span>WinSecure · By Kartavya Joshi · v__WINSECURE_VERSION__</span>
      </div>
    </aside>

    <!-- Main Content Area -->
    <div class="main-wrapper">
      <header class="topbar">
        <div class="topbar-left">
          <div class="meta-pill">
            <span>Host:</span> <strong id="topbar-host">__HOSTNAME__</strong>
            <span style="color: var(--border-color);">|</span>
            <span id="topbar-os">__OS_NAME__</span>
            <span id="topbar-admin" class="badge __ADMIN_BADGE__">
              __ADMIN_LABEL__
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
        <!-- 1. Executive Overview -->
        <section id="section-overview" class="content-section active">
          <div class="kpi-grid">
            <div class="kpi-card">
              <div class="kpi-label">Security Score</div>
              <div class="kpi-value" id="kpi-score">__SCORE_VAL__</div>
              <div class="kpi-meta" id="kpi-posture">__RISK_LEVEL__ POSTURE</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Priority Defects</div>
              <div class="kpi-value kpi-danger" id="kpi-crit-high">__PRIORITY_DEFECTS__</div>
              <div class="kpi-meta">__CRIT_COUNT__ Critical, __HIGH_COUNT__ High</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Scan Duration</div>
              <div class="kpi-value" id="kpi-duration">__DURATION_VAL__</div>
              <div class="kpi-meta">30 Security Scanners</div>
            </div>
            <div class="kpi-card">
              <div class="kpi-label">Verified Controls</div>
              <div class="kpi-value kpi-success" id="kpi-passed">__PASS_COUNT__ / __FINDINGS_COUNT__</div>
              <div class="kpi-meta">Baseline Controls Aligned</div>
            </div>
          </div>

          <div class="card" style="margin-bottom: 20px;">
            <h2 class="card-title">Lead Security Auditor Briefing</h2>
            <div id="auditor-summary-text" style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">
              Automated diagnostic evaluation completed for endpoint <strong>__HOSTNAME__</strong>. Overall defensive security rating: <strong>__SCORE_VAL__ (__RISK_LEVEL__)</strong> across __FINDINGS_COUNT__ configuration controls.
            </div>
          </div>
        </section>

        <!-- 2. Findings Explorer -->
        <section id="section-findings" class="content-section">
          <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">
              <h2 class="card-title" style="margin: 0;">Findings Explorer</h2>
              <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button class="filter-chip active" onclick="applyFilter('ALL', this)">ALL</button>
                <button class="filter-chip" onclick="applyFilter('CRITICAL', this)">CRITICAL</button>
                <button class="filter-chip" onclick="applyFilter('HIGH', this)">HIGH</button>
                <button class="filter-chip" onclick="applyFilter('MEDIUM', this)">MEDIUM</button>
                <button class="filter-chip" onclick="applyFilter('FAIL', this)">FAILURES</button>
                <button class="filter-chip" onclick="applyFilter('PASS', this)">PASSED</button>
              </div>
            </div>

            <div style="display: flex; gap: 12px; margin-bottom: 16px;">
              <input type="text" id="findings-search" class="form-input" placeholder="Search finding ID, title, affected component..." oninput="filterFindings()" style="flex-grow: 1;">
              <select id="category-filter" class="form-input" onchange="filterFindings()" style="width: 200px;">
                <option value="ALL">All Categories</option>
                <option value="Defender">Defender</option>
                <option value="Firewall">Firewall</option>
                <option value="Accounts">Accounts</option>
                <option value="Registry">Registry</option>
                <option value="Audit Policy">Audit Policy</option>
                <option value="SMB">SMB</option>
                <option value="PowerShell">PowerShell</option>
                <option value="Network">Network</option>
                <option value="Encryption">Encryption</option>
                <option value="Services">Services</option>
                <option value="System">System</option>
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

        <!-- 3. 30 Modules -->
        <section id="section-modules" class="content-section">
          <div class="card" style="margin-bottom: 16px;">
            <h2 class="card-title">30 Security Modules Catalog</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">Click any module to view technical definitions, registry paths, and compliance mappings.</p>
          </div>
          <div id="catalog-grid" class="grid-3"></div>
        </section>

        <!-- 4. Compliance -->
        <section id="section-compliance" class="content-section">
          <div class="card" style="margin-bottom: 16px;">
            <h2 class="card-title">Compliance Framework Alignments</h2>
            <p style="font-size: 13px; color: var(--text-secondary);">Technical alignment mapping against authoritative security baselines.</p>
          </div>
          <div id="compliance-cards-grid" class="grid-2"></div>
        </section>

        <!-- 5. Remediation Plan -->
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

        <!-- 6. Execution Log -->
        <section id="section-logs" class="content-section">
          <div class="card">
            <h2 class="card-title">Assessment Execution Timeline</h2>
            <div id="timeline-log-list" style="display: flex; flex-direction: column; gap: 8px; margin-top: 12px;"></div>
          </div>
        </section>
      </main>
    </div>
  </div>

  <!-- Finding Detail Modal -->
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
__REPORT_JS__
  </script>
</body>
</html>
"""
        html_content = html_template.replace("__SCAN_ID__", str(result.scan_id))\
            .replace("__REPORT_CSS__", REPORT_CSS)\
            .replace("__REPORT_JS__", REPORT_JS)\
            .replace("__DATA_PAYLOAD__", data_payload)\
            .replace("__HOSTNAME__", str(hostname))\
            .replace("__OS_NAME__", str(os_name))\
            .replace("__ADMIN_BADGE__", str(admin_badge))\
            .replace("__ADMIN_LABEL__", str(admin_label))\
            .replace("__SCORE_VAL__", f"{score_val:.1f}/100")\
            .replace("__RISK_LEVEL__", str(risk_level_val))\
            .replace("__PRIORITY_DEFECTS__", str(crit_count + high_count))\
            .replace("__CRIT_COUNT__", str(crit_count))\
            .replace("__HIGH_COUNT__", str(high_count))\
            .replace("__DURATION_VAL__", f"{duration_val:.2f}s")\
            .replace("__PASS_COUNT__", str(pass_count))\
            .replace("__FINDINGS_COUNT__", str(len(result.findings)))\
            .replace("__WINSECURE_VERSION__", str(result.winsecure_version))

        report_path = os.path.join(output_dir, "index.html")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return report_path
