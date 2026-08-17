"""
WinSecure Standalone Findings Report Generator with Full Server-Side Pre-Rendering
Focused directly on Findings, Telemetry, and PowerShell Remediation with link to main website.
"""
import os
import json
import html
from typing import List, Dict, Any
from winsecure.models.scan import ScanResult
from winsecure.models.finding import Finding, FindingStatus, Severity


class WebReportGenerator:
    """Generates a modern, dedicated findings & remediation cybersecurity report."""

    @staticmethod
    def generate(result: ScanResult, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        index_path = os.path.join(output_dir, "index.html")
        js_path = os.path.join(output_dir, "report.js")
        css_path = os.path.join(output_dir, "report.css")

        inv = result.inventory
        hostname = inv.hostname if inv else "WIN-ENDPOINT"
        os_name = inv.os_name if inv else "Windows 11 Enterprise"
        os_arch = inv.os_architecture if inv else "x64"
        duration_sec = result.metrics.duration_seconds if result.metrics else 0.0
        duration_str = f"{duration_sec:.2f}s"

        crit_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in result.findings if f.status == FindingStatus.FAIL and f.severity == Severity.LOW)
        pass_count = sum(1 for f in result.findings if f.status == FindingStatus.PASS)
        warn_count = sum(1 for f in result.findings if f.status == FindingStatus.WARN)
        unknown_count = sum(1 for f in result.findings if f.status in (FindingStatus.UNKNOWN, FindingStatus.NOT_APPLICABLE))
        total_findings = len(result.findings)

        failing_findings = [f for f in result.findings if f.status == FindingStatus.FAIL]
        priority_defects = crit_count + high_count

        admin_badge = "badge-pass" if result.is_admin else "badge-low"
        admin_label = "ADMIN PRIVILEGE" if result.is_admin else "STANDARD USER"

        score_val = result.security_score
        risk_lvl = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)

        # -------------------------------------------------------------
        # Pre-render 1: Findings Table Rows
        # -------------------------------------------------------------
        findings_rows_html = []
        for f in result.findings:
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            st_str = f.status.value if hasattr(f.status, "value") else str(f.status)

            if st_str == "PASS":
                status_badge_class = "badge-pass"
            elif st_str == "FAIL":
                status_badge_class = "badge-crit"
            elif st_str == "WARN":
                status_badge_class = "badge-warn"
            else:
                status_badge_class = "badge-low"

            sev_lower = sev_str.lower()
            if sev_lower == "critical":
                sev_badge_class = "badge-crit"
            elif sev_lower == "high":
                sev_badge_class = "badge-high"
            elif sev_lower == "medium":
                sev_badge_class = "badge-med"
            else:
                sev_badge_class = "badge-low"

            cis_ref = "CIS Windows 11 Enterprise"
            if f.compliance:
                for c in f.compliance:
                    if isinstance(c, dict) and "cis" in c.get("framework", "").lower():
                        cis_ref = f"{c.get('framework', '')} {c.get('control_id', '')}".strip()
                        break

            f_json_escaped = html.escape(json.dumps(f.to_dict(), default=str))

            row_html = f"""<tr class="finding-row" data-id="{html.escape(f.id)}" data-category="{html.escape(f.category)}" data-severity="{html.escape(sev_str)}" data-status="{html.escape(st_str)}" data-finding="{f_json_escaped}" onclick="openFindingModalFromRow(this)" style="cursor: pointer;">
  <td><strong style="font-family: var(--font-mono); color: var(--text-primary);">{html.escape(f.id)}</strong></td>
  <td><span class="badge badge-low">{html.escape(f.category)}</span></td>
  <td>
    <div style="font-weight: 600; color: var(--text-primary);">{html.escape(f.title)}</div>
    <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">{html.escape(f.actual or f.expected)}</div>
  </td>
  <td><span class="badge {sev_badge_class}">{html.escape(sev_str.upper())}</span></td>
  <td><span class="badge {status_badge_class}">{html.escape(st_str)}</span></td>
  <td><span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">{html.escape(cis_ref)}</span></td>
</tr>"""
            findings_rows_html.append(row_html)

        findings_table_body = "\n".join(findings_rows_html)

        # -------------------------------------------------------------
        # Pre-render 2: Remediation Plan Cards
        # -------------------------------------------------------------
        remediation_cards_html = []
        if not failing_findings:
            remediation_cards_html.append("""<div class="card" style="text-align: center; padding: 32px; color: #166534;">
  <h3 style="font-size: 15px; font-weight: 700;">All Assessed Controls Aligned</h3>
  <p style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">No corrective remediation steps required for this endpoint.</p>
</div>""")
        else:
            for i, f in enumerate(failing_findings, 1):
                sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                sev_badge_class = "badge-crit" if sev_str.lower() == "critical" else ("badge-high" if sev_str.lower() == "high" else "badge-med")
                rem_escaped = html.escape(f.remediation or "# No automated remediation specified")

                r_html = f"""<div class="card" style="margin-bottom: 14px;">
  <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; flex-wrap: wrap; gap: 8px;">
    <div>
      <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">STEP {i} OF {len(failing_findings)}</span>
      <h3 style="font-size: 14.5px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">
        <span style="font-family: var(--font-mono); color: var(--accent-blue);">[{html.escape(f.id)}]</span> {html.escape(f.title)}
      </h3>
    </div>
    <span class="badge {sev_badge_class}">{html.escape(sev_str.upper())}</span>
  </div>
  <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">{html.escape(f.description)}</p>
  <div style="background: #0f172a; border-radius: 6px; padding: 12px 14px; position: relative;">
    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 6px; margin-bottom: 8px;">
      <span style="font-family: var(--font-mono); font-size: 11px; color: #94a3b8;">POWERSHELL REMEDIATION COMMAND</span>
      <button class="btn btn-outline btn-sm" style="color: #fff; border-color: #475569; padding: 2px 8px; font-size: 11px;" onclick="copyCode(this.getAttribute('data-code'))" data-code="{rem_escaped}">Copy</button>
    </div>
    <pre style="font-family: var(--font-mono); font-size: 12px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; margin: 0;">{rem_escaped}</pre>
  </div>
</div>"""
                remediation_cards_html.append(r_html)

        remediation_list_body = "\n".join(remediation_cards_html)

        # -------------------------------------------------------------
        # CSS Style definition
        # -------------------------------------------------------------
        css_content = """/* ==========================================================================
   WinSecure — Focused Findings Assessment Report
   Clean, Responsive, Air-Gapped Ready
   ========================================================================== */

:root {
  --bg-app: #ffffff;
  --bg-canvas: #f8fafc;
  --bg-sidebar: #ffffff;
  --bg-topbar: #ffffff;
  --bg-card: #ffffff;
  --bg-card-hover: #f1f5f9;
  --bg-input: #ffffff;
  --bg-code: #0f172a;

  --border-color: #e2e8f0;
  --border-subtle: #f1f5f9;
  --border-focus: #0ea5e9;

  --text-primary: #0f172a;
  --text-secondary: #475569;
  --text-muted: #64748b;
  --text-light: #94a3b8;

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

.container-report {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px;
}

/* Header & Topbar */
.header-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 18px 24px;
  margin-bottom: 20px;
  box-shadow: var(--shadow-card);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 16px;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.brand-badge {
  width: 40px;
  height: 40px;
  background: #0ea5e9;
  color: #fff;
  font-weight: 700;
  border-radius: var(--radius-sm);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
}

.header-title {
  font-size: 18px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.2;
}

.header-subtitle {
  font-size: 12.5px;
  color: var(--text-muted);
  margin-top: 2px;
}

.header-actions {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}

/* Cards & Layout */
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 20px;
  box-shadow: var(--shadow-card);
  margin-bottom: 20px;
}

.card-title {
  font-size: 15px;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 12px;
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 20px;
}

.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  padding: 16px 18px;
  box-shadow: var(--shadow-card);
}

.kpi-label {
  font-size: 11.5px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.kpi-value {
  font-family: var(--font-mono);
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  margin: 4px 0 2px 0;
}

.kpi-value.kpi-danger { color: #dc2626; }
.kpi-value.kpi-success { color: #16a34a; }

.kpi-meta {
  font-size: 12px;
  color: var(--text-muted);
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  font-size: 11px;
  font-weight: 600;
  border-radius: var(--radius-xs);
  line-height: 1.4;
}

.badge-crit { background: var(--badge-crit-bg); color: var(--badge-crit-text); border: 1px solid var(--badge-crit-border); }
.badge-high { background: var(--badge-high-bg); color: var(--badge-high-text); border: 1px solid var(--badge-high-border); }
.badge-med { background: var(--badge-med-bg); color: var(--badge-med-text); border: 1px solid var(--badge-med-border); }
.badge-low { background: var(--badge-low-bg); color: var(--badge-low-text); border: 1px solid var(--badge-low-border); }
.badge-pass { background: var(--badge-pass-bg); color: var(--badge-pass-text); border: 1px solid var(--badge-pass-border); }
.badge-warn { background: var(--badge-warn-bg); color: var(--badge-warn-text); border: 1px solid var(--badge-warn-border); }

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  font-size: 13px;
  font-weight: 600;
  border-radius: var(--radius-sm);
  border: 1px solid transparent;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.15s ease;
}

.btn-primary { background: #0ea5e9; color: #ffffff; }
.btn-primary:hover { background: #0284c7; }
.btn-outline { background: transparent; border-color: var(--border-color); color: var(--text-primary); }
.btn-outline:hover { background: var(--bg-canvas); }
.btn-sm { padding: 5px 10px; font-size: 12px; }

/* Filter Chips & Inputs */
.filter-chip {
  padding: 5px 12px;
  font-size: 12px;
  font-weight: 600;
  border-radius: var(--radius-full);
  background: var(--bg-canvas);
  border: 1px solid var(--border-color);
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s ease;
}

.filter-chip:hover { background: #f1f5f9; color: var(--text-primary); }
.filter-chip.active { background: #0f172a; color: #ffffff; border-color: #0f172a; }

.form-input {
  padding: 8px 12px;
  font-size: 13px;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  background: var(--bg-input);
  color: var(--text-primary);
  outline: none;
}

.form-input:focus { border-color: var(--border-focus); }

/* Data Tables */
.table-responsive { width: 100%; overflow-x: auto; }
.data-table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
.data-table th { padding: 10px 14px; background: var(--bg-canvas); border-bottom: 1px solid var(--border-color); font-weight: 600; font-size: 12px; color: var(--text-muted); }
.data-table td { padding: 12px 14px; border-bottom: 1px solid var(--border-color); }
.data-table tr:hover { background: #f8fafc; }

/* Modal */
.modal-overlay {
  display: none;
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(15, 23, 42, 0.6);
  backdrop-filter: blur(4px);
  z-index: 2000;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-card {
  background: #ffffff;
  border-radius: var(--radius-md);
  width: 100%;
  max-width: 680px;
  max-height: 85vh;
  display: flex;
  flex-direction: column;
  box-shadow: var(--shadow-modal);
  overflow: hidden;
}

.modal-header {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.modal-close {
  background: transparent;
  border: none;
  font-size: 20px;
  cursor: pointer;
  color: var(--text-muted);
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
  color: var(--accent-blue);
  border-bottom-color: var(--accent-blue);
}

.modal-body {
  padding: 20px;
  overflow-y: auto;
  flex-grow: 1;
}

/* Responsive */
@media (max-width: 900px) {
  .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  .container-report { padding: 16px; }
}

@media (max-width: 600px) {
  .kpi-grid { grid-template-columns: 1fr; }
  .header-card { flex-direction: column; align-items: flex-start; }
}

@media print {
  .btn, .filter-chip, .form-input, .header-actions { display: none !important; }
}
"""

        # -------------------------------------------------------------
        # JavaScript Engine definition
        # -------------------------------------------------------------
        js_content = """/* ==========================================================================
   WinSecure — Client-Side Findings Report Engine
   ========================================================================== */

var activeFindingFilter = 'ALL';
var currentActiveFinding = null;
var currentModalTab = 'tab-overview';

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
  var query = (document.getElementById('findings-search') ? document.getElementById('findings-search').value : '').toLowerCase().trim();
  var cat = document.getElementById('category-filter') ? document.getElementById('category-filter').value : 'ALL';
  var rows = document.querySelectorAll('#findings-tbody .finding-row');
  var visibleCount = 0;

  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var rCat = (row.getAttribute('data-category') || '').toLowerCase();
    var rSev = (row.getAttribute('data-severity') || '').toUpperCase();
    var rStatus = (row.getAttribute('data-status') || '').toUpperCase();
    var rText = (row.textContent || '').toLowerCase();

    var matchFilter = (activeFindingFilter === 'ALL') ||
                      (activeFindingFilter === 'FAIL' && rStatus === 'FAIL') ||
                      (activeFindingFilter === 'PASS' && rStatus === 'PASS') ||
                      (activeFindingFilter === 'WARNINGS' && rStatus === 'WARN') ||
                      (rSev === activeFindingFilter);

    var matchCat = (cat === 'ALL') || (rCat === cat.toLowerCase());
    var matchQuery = (!query) || (rText.indexOf(query) !== -1);

    if (matchFilter && matchCat && matchQuery) {
      row.style.display = '';
      visibleCount++;
    } else {
      row.style.display = 'none';
    }
  }

  var badge = document.getElementById('findings-count-badge');
  if (badge) badge.textContent = 'Showing ' + visibleCount + ' findings';
}
window.filterFindings = filterFindings;

function openFindingModalFromRow(row) {
  if (!row) return;
  var rawJson = row.getAttribute('data-finding');
  if (!rawJson) return;

  try {
    var f = JSON.parse(rawJson);
    currentActiveFinding = f;
    currentModalTab = 'tab-overview';

    var title = document.getElementById('modal-title');
    if (title) title.innerHTML = '<span style="color: var(--accent-blue);">[' + escapeHtml(f.id) + ']</span> ' + escapeHtml(f.title);

    var tabs = document.querySelectorAll('.modal-tab');
    for (var j = 0; j < tabs.length; j++) {
      tabs[j].classList.toggle('active', tabs[j].getAttribute('data-tab') === currentModalTab);
    }

    renderModalContent(currentModalTab);

    var modal = document.getElementById('finding-modal');
    if (modal) modal.style.display = 'flex';
  } catch (err) {
    console.error('Error opening finding modal:', err);
  }
}
window.openFindingModalFromRow = openFindingModalFromRow;

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
  var f = currentActiveFinding;
  if (!f) return;

  var body = document.getElementById('modal-body');
  if (!body) return;

  var sevStr = String(f.severity || 'Low').toUpperCase();
  var stStr = String(f.status || 'PASS');

  if (tabKey === 'tab-overview') {
    body.innerHTML = '<div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">' +
        '<span class="badge ' + getSeverityBadge(f.severity) + '">' + sevStr + '</span>' +
        '<span class="badge ' + (stStr === 'PASS' ? 'badge-pass' : 'badge-crit') + '">' + stStr + '</span>' +
        '<span class="badge badge-low">' + escapeHtml(f.category) + '</span>' +
      '</div>' +
      '<h4 style="font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">DESCRIPTION</h4>' +
      '<p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 16px;">' + escapeHtml(f.description) + '</p>' +
      '<h4 style="font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">EVIDENCE / ACTUAL STATE</h4>' +
      '<p style="font-size: 13.5px; color: var(--text-primary); font-weight: 600; margin-bottom: 16px;">' + escapeHtml(f.actual) + '</p>' +
      '<h4 style="font-size: 13px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px;">IMPACT & POSTURE RISK</h4>' +
      '<p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">' + escapeHtml(f.impact || f.description) + '</p>';
  } else if (tabKey === 'tab-threat') {
    body.innerHTML = '<div style="background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #dc2626; padding: 14px; border-radius: 6px; margin-bottom: 14px;">' +
        '<div style="font-size: 12px; font-weight: 700; color: #991b1b; margin-bottom: 4px;">ATTACKER EXPLOITATION VECTOR</div>' +
        '<p style="font-size: 13px; color: #7f1d1d; line-height: 1.6; margin: 0;">' + escapeHtml(f.impact || f.description) + '</p>' +
      '</div>';
  } else if (tabKey === 'tab-remediation') {
    body.innerHTML = '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">' +
        '<span style="font-size: 12px; font-weight: 700; color: var(--text-muted);">RECOMMENDED POWERSHELL COMMAND</span>' +
        '<button class="btn btn-sm" onclick="copyCode(this.getAttribute(\\'data-code\\'))" data-code="' + escapeHtml(f.remediation || '') + '">Copy Fix</button>' +
      '</div>' +
      '<pre style="background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; line-height: 1.6; overflow-x: auto; white-space: pre-wrap;">' + escapeHtml(f.remediation || '# No remediation required') + '</pre>';
  } else if (tabKey === 'tab-evidence') {
    var jsonStr = JSON.stringify(f.evidence || [], null, 2);
    body.innerHTML = '<pre style="background: #0f172a; color: #10b981; padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; line-height: 1.6; overflow-x: auto;">' + escapeHtml(jsonStr) + '</pre>';
  } else if (tabKey === 'tab-compliance') {
    var list = Array.isArray(f.compliance) ? f.compliance : [];
    var compHtml = '<div style="display: flex; flex-direction: column; gap: 8px;">';
    if (list.length === 0) {
      compHtml += '<div style="font-size: 13px; color: var(--text-muted); padding: 12px;">Aligned with standard Windows 11 Enterprise Baseline.</div>';
    } else {
      for (var k = 0; k < list.length; k++) {
        var c = list[k];
        compHtml += '<div style="background: var(--bg-canvas); padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 6px;">' +
            '<div style="font-size: 11px; font-weight: 600; color: var(--text-muted);">' + escapeHtml(c.framework || 'Framework') + ' ' + escapeHtml(c.version || '') + '</div>' +
            '<div style="font-family: var(--font-mono); font-size: 13px; color: var(--text-primary); margin-top: 2px;">' + escapeHtml(c.control_id || '') + ' — ' + escapeHtml(c.title || '') + '</div>' +
          '</div>';
      }
    }
    compHtml += '</div>';
    body.innerHTML = compHtml;
  }
}

function closeFindingModal() {
  var modal = document.getElementById('finding-modal');
  if (modal) modal.style.display = 'none';
  currentActiveFinding = null;
}
window.closeFindingModal = closeFindingModal;

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
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(function() {
      showToast('Copied to clipboard.');
    });
  } else {
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Copied to clipboard.');
  }
}
window.copyCode = copyCode;

function downloadMasterScript() {
  var rows = document.querySelectorAll('#findings-tbody .finding-row');
  var lines = [
    '# =====================================================================',
    '# WinSecure Automated Hardening Script',
    '# Generated for target host',
    '# =====================================================================',
    '',
    'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {',
    '    Write-Error "[!] Administrative privileges required. Run PowerShell as Administrator."',
    '    Exit 1',
    '}',
    '',
    'Write-Host "[*] Executing WinSecure Hardening Plan..." -ForegroundColor Cyan',
    ''
  ];

  var count = 0;
  for (var i = 0; i < rows.length; i++) {
    var rStatus = rows[i].getAttribute('data-status');
    if (rStatus === 'FAIL') {
      count++;
      var f = JSON.parse(rows[i].getAttribute('data-finding') || '{}');
      lines.push('');
      lines.push('# Step ' + count + ': ' + f.id + ' - ' + f.title);
      lines.push('Write-Host "  [*] Applying: ' + f.title + ' (' + f.id + ')..."');
      lines.push('try {');
      lines.push('    ' + (f.remediation || '# No remediation'));
      lines.push('    Write-Host "    [OK] Remediated ' + f.id + '" -ForegroundColor Green');
      lines.push('} catch {');
      lines.push('    Write-Warning "    [!] Failed ' + f.id + ': $_"');
      lines.push('}');
    }
  }

  var script = lines.join(String.fromCharCode(10));
  var blob = new Blob([script], { type: 'text/plain;charset=utf-8' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'WinSecure-Remediation-Master.ps1';
  a.click();
  URL.revokeObjectURL(url);
  showToast('Master remediation script downloaded.');
}
window.downloadMasterScript = downloadMasterScript;

function getSeverityBadge(sev) {
  switch (String(sev || '').toLowerCase()) {
    case 'critical': return 'badge-crit';
    case 'high': return 'badge-high';
    case 'medium': return 'badge-med';
    case 'low': return 'badge-low';
    default: return 'badge-low';
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');
}

document.addEventListener('DOMContentLoaded', function() {
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      closeFindingModal();
    }
  });
});
"""

        # Write separate report.css and report.js files
        with open(css_path, "w", encoding="utf-8") as f:
            f.write(css_content)
        with open(js_path, "w", encoding="utf-8") as f:
            f.write(js_content)

        # -------------------------------------------------------------
        # Master HTML Template Focused Directly on Findings & Pointing to Main Website
        # -------------------------------------------------------------
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinSecure Assessment Findings — {html.escape(result.scan_id)}</title>
  <link rel="stylesheet" href="report.css">
  <style>
{css_content}
  </style>
  <script src="report.js"></script>
  <script>
{js_content}
  </script>
</head>
<body>
  <div class="container-report">
    <!-- Header Topbar pointing to Main Website -->
    <header class="header-card">
      <div class="header-left">
        <div class="brand-badge">WS</div>
        <div>
          <div class="header-title">WinSecure Assessment Findings</div>
          <div class="header-subtitle">
            Host: <strong>{html.escape(hostname)}</strong> &bull; {html.escape(os_name)} ({html.escape(os_arch)}) &bull; <span class="badge {admin_badge}">{html.escape(admin_label)}</span>
          </div>
        </div>
      </div>

      <div class="header-actions">
        <!-- Direct Pointer Link to Main Website -->
        <a href="https://kartavyajoshi.github.io/WINSECURE/" target="_blank" class="btn btn-outline btn-sm">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
          <span>Main Website</span>
        </a>
        <button class="btn btn-primary btn-sm" onclick="downloadMasterScript()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          <span>Download Fix (.ps1)</span>
        </button>
        <button class="btn btn-outline btn-sm" onclick="window.print()">Print</button>
      </div>
    </header>

    <!-- KPI Summary Metrics -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Security Score</div>
        <div class="kpi-value" id="kpi-score">{score_val:.1f}/100</div>
        <div class="kpi-meta" id="kpi-posture">{risk_lvl} POSTURE</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Priority Defects</div>
        <div class="kpi-value kpi-danger" id="kpi-crit-high">{priority_defects}</div>
        <div class="kpi-meta">{crit_count} Critical, {high_count} High</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Scan Duration</div>
        <div class="kpi-value" id="kpi-duration">{duration_str}</div>
        <div class="kpi-meta">32 Security Scanners</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Verified Controls</div>
        <div class="kpi-value kpi-success" id="kpi-passed">{pass_count} / {total_findings}</div>
        <div class="kpi-meta">Baseline Controls Aligned</div>
      </div>
    </div>

    <!-- Findings Explorer (Core Focus) -->
    <section class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">
        <div>
          <h2 class="card-title" style="margin: 0;">Evaluation Findings ({total_findings})</h2>
          <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">Click any finding row to view detailed evidence, attack vectors, and remediation commands.</p>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="filter-chip active" onclick="applyFilter('ALL', this)">ALL ({total_findings})</button>
          <button class="filter-chip" onclick="applyFilter('CRITICAL', this)">CRITICAL ({crit_count})</button>
          <button class="filter-chip" onclick="applyFilter('HIGH', this)">HIGH ({high_count})</button>
          <button class="filter-chip" onclick="applyFilter('MEDIUM', this)">MEDIUM ({med_count})</button>
          <button class="filter-chip" onclick="applyFilter('FAIL', this)">FAILURES ({len(failing_findings)})</button>
          <button class="filter-chip" onclick="applyFilter('PASS', this)">PASSED ({pass_count})</button>
        </div>
      </div>

      <div style="display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;">
        <input type="text" id="findings-search" class="form-input" placeholder="Search finding ID, title, affected component..." oninput="filterFindings()" style="flex-grow: 1; min-width: 240px;">
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
              <th>Title & Evidence</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Benchmark</th>
            </tr>
          </thead>
          <tbody id="findings-tbody">
{findings_table_body}
          </tbody>
        </table>
      </div>
      <div id="findings-count-badge" style="font-size: 12px; color: var(--text-muted); margin-top: 12px;">Showing {total_findings} findings</div>
    </section>

    <!-- Remediation Roadmap Section -->
    <section class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
        <div>
          <h2 class="card-title" style="margin: 0;">Remediation Roadmap ({len(failing_findings)} Actions)</h2>
          <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">Step-by-step PowerShell commands to remediate identified security defects.</p>
        </div>
        <button class="btn btn-primary btn-sm" onclick="downloadMasterScript()">Download Master Script (.ps1)</button>
      </div>
      <div id="remediation-list">
{remediation_list_body}
      </div>
    </section>

    <!-- Footer pointing back to Main Website & GitHub -->
    <footer style="text-align: center; padding: 24px 0 12px; font-size: 12.5px; color: var(--text-muted);">
      <div>WinSecure Assessment Platform &bull; Developed by <strong>Kartavya Joshi</strong></div>
      <div style="margin-top: 6px; display: flex; justify-content: center; gap: 16px;">
        <a href="https://kartavyajoshi.github.io/WINSECURE/" target="_blank" style="color: var(--accent-blue); text-decoration: none;">&larr; Live Documentation & Website</a>
        <a href="https://github.com/Kartavyajoshi/WINSECURE" target="_blank" style="color: var(--accent-blue); text-decoration: none;">GitHub Repository</a>
      </div>
    </footer>
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
</body>
</html>
"""

        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return index_path
