"""
WinSecure Standalone Findings Report Generator with Full Server-Side Pre-Rendering
Enhanced with GUI-Based Visual Analytics, Interactive SVG Charts, Attack Path Flows, and Remediation Roadmap.
"""
import os
import json
import html
from typing import List, Dict, Any, Optional
from winsecure.models.scan import ScanResult
from winsecure.models.finding import Finding, FindingStatus, Severity


class WebReportGenerator:
    """Generates a modern, dedicated findings & remediation cybersecurity report with visual charts."""

    # Live documentation site — finding IDs below have full deep-dive analyses there
    SITE_URL = "https://kartavyajoshi.github.io/WINSECURE/"
    DEEP_DIVE_FINDING_IDS = frozenset({
        "WS-FW-001", "WS-FW-002", "WS-FW-004",
        "WS-DEF-001",
        "WS-REG-001", "WS-REG-002",
        "WS-SMB-001",
        "WS-RDP-001",
        "WS-ENC-001",
        "WS-UAC-001",
        "WS-PS-001",
        "WS-AUD-001",
        "WS-LAPS-001",
    })

    @classmethod
    def deep_dive_url(cls, finding_id: str) -> Optional[str]:
        """Returns the live-site knowledge-base URL for a finding, if one exists."""
        if finding_id in cls.DEEP_DIVE_FINDING_IDS:
            return f"{cls.SITE_URL}#finding-{finding_id}"
        return None

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
        # Category Aggregation for Bar Chart & Filters
        # -------------------------------------------------------------
        category_stats: Dict[str, Dict[str, int]] = {}
        for f in result.findings:
            cat = f.category or "Other"
            if cat not in category_stats:
                category_stats[cat] = {"pass": 0, "fail": 0, "warn": 0, "total": 0}
            category_stats[cat]["total"] += 1
            if f.status == FindingStatus.PASS:
                category_stats[cat]["pass"] += 1
            elif f.status == FindingStatus.FAIL:
                category_stats[cat]["fail"] += 1
            elif f.status == FindingStatus.WARN:
                category_stats[cat]["warn"] += 1

        # -------------------------------------------------------------
        # Visual Chart 1: SVG Severity Donut Chart
        # -------------------------------------------------------------
        circumference = 282.743  # 2 * pi * 45
        donut_slices_svg = []
        total_eval = max(total_findings, 1)
        running_offset = 0.0

        severity_items = [
            ("CRITICAL", crit_count, "#ef4444", "Critical"),
            ("HIGH", high_count, "#f97316", "High"),
            ("MEDIUM", med_count, "#f59e0b", "Medium"),
            ("LOW", low_count, "#0ea5e9", "Low"),
            ("WARN", warn_count, "#eab308", "Warning"),
            ("PASS", pass_count, "#10b981", "Passed"),
        ]

        for code, count, color, label in severity_items:
            if count <= 0:
                continue
            seg_len = (count / total_eval) * circumference
            donut_slices_svg.append(
                f'<circle cx="60" cy="60" r="45" fill="none" stroke="{color}" stroke-width="16" '
                f'stroke-dasharray="{seg_len:.2f} {circumference - seg_len:.2f}" stroke-dashoffset="{-running_offset:.2f}" '
                f'transform="rotate(-90 60 60)" class="donut-segment" data-severity="{code}" '
                f'onclick="applyFilter(&quot;{code}&quot;, null)" style="cursor: pointer; transition: stroke-width 0.2s;" />'
            )
            running_offset += seg_len

        if not donut_slices_svg:
            donut_slices_svg.append(
                '<circle cx="60" cy="60" r="45" fill="none" stroke="#e2e8f0" stroke-width="16" />'
            )

        donut_svg_html = "\n".join(donut_slices_svg)

        # -------------------------------------------------------------
        # Visual Chart 2: Category Compliance Horizontal Stacked Bars
        # -------------------------------------------------------------
        category_bars_html = []
        sorted_cats = sorted(category_stats.items(), key=lambda x: (x[1]["fail"], x[1]["total"]), reverse=True)
        for cat, stats in sorted_cats:
            tot = stats["total"]
            pas = stats["pass"]
            fal = stats["fail"]
            wrn = stats["warn"]
            pass_pct = (pas / tot) * 100 if tot > 0 else 0
            fail_pct = (fal / tot) * 100 if tot > 0 else 0
            warn_pct = (wrn / tot) * 100 if tot > 0 else 0

            category_bars_html.append(f"""
            <div class="cat-bar-row" onclick="filterByCategory(&quot;{html.escape(cat)}&quot;)" title="Click to filter findings by {html.escape(cat)}">
              <div class="cat-bar-header">
                <span class="cat-bar-title">{html.escape(cat)}</span>
                <span class="cat-bar-metrics">{pas}/{tot} Passing ({pass_pct:.0f}%)</span>
              </div>
              <div class="cat-bar-track">
                <div class="cat-bar-fill-pass" style="width: {pass_pct:.1f}%;" title="{pas} Passed"></div>
                <div class="cat-bar-fill-fail" style="width: {fail_pct:.1f}%;" title="{fal} Failed"></div>
                <div class="cat-bar-fill-warn" style="width: {warn_pct:.1f}%;" title="{wrn} Warnings"></div>
              </div>
            </div>
            """)
        category_bars_rendered = "\n".join(category_bars_html)

        # -------------------------------------------------------------
        # Visual Analytics 3: Ransomware Resilience (RDI) & Zero Trust
        # -------------------------------------------------------------
        rdi = result.ransomware_resilience
        if not rdi:
            from winsecure.analytics.ransomware_resilience import RansomwareResilienceEngine
            rdi = RansomwareResilienceEngine.evaluate(result.findings, {})

        rdi_score = rdi.get("ransomware_defense_index", 0.0) if rdi else 0.0
        rdi_status = rdi.get("resilience_level", "STANDARD") if rdi else "STANDARD"
        rdi_pillars = rdi.get("pillars", {}) if rdi else {}

        rdi_cards_html = []
        for pkey, pdata in rdi_pillars.items():
            pscore = pdata.get("score", 0.0)
            pname = pdata.get("name", pkey)
            status_color = "#10b981" if pscore >= 80 else ("#f59e0b" if pscore >= 50 else "#ef4444")
            status_text = "PROTECTED" if pscore >= 80 else ("ATTENTION" if pscore >= 50 else "DEFICIENT")
            rdi_cards_html.append(f"""
            <div class="rdi-pillar-card">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <span style="font-size: 11.5px; font-weight: 700; color: var(--text-primary);">{html.escape(pname)}</span>
                <span class="badge" style="background: {status_color}20; color: {status_color}; border: 1px solid {status_color}40; font-size: 9.5px;">{status_text}</span>
              </div>
              <div style="height: 6px; background: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 4px;">
                <div style="height: 100%; width: {pscore:.0f}%; background: {status_color}; border-radius: 3px;"></div>
              </div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">{html.escape(pdata.get('details', ''))[:70]}</div>
            </div>
            """)
        rdi_pillars_rendered = "\n".join(rdi_cards_html)

        # Zero Trust Maturity
        zt = result.zero_trust_maturity
        if not zt:
            from winsecure.compliance.zero_trust import ZeroTrustEvaluator
            zt = ZeroTrustEvaluator.evaluate(result.findings)

        zt_stage = zt.get("maturity_stage", "INITIAL") if zt else "INITIAL"
        zt_score = zt.get("overall_score", 0.0) if zt else 0.0

        # -------------------------------------------------------------
        # Visual Analytics 4: Attack Path Kill-Chain Flow Visualizer
        # -------------------------------------------------------------
        attack_paths = result.attack_paths or []
        choke_points = result.choke_points or []
        blast_radius = result.blast_radius_score or 0.0

        attack_paths_html = []
        if not attack_paths:
            attack_paths_html.append("""
            <div style="padding: 24px; text-align: center; color: #166534; background: #f0fdf4; border-radius: 8px; border: 1px solid #bbf7d0;">
              <strong style="font-size: 14px;">Defensive Perimeter Resilient</strong>
              <div style="font-size: 12px; color: #15803d; margin-top: 4px;">No multi-stage Bayesian exploit paths synthesized. Core attack vectors remain obstructed.</div>
            </div>
            """)
        else:
            for idx, ap in enumerate(attack_paths[:3], 1):
                p_name = ap.get("name", f"Attack Path {idx}")
                p_steps = ap.get("path_steps", [])
                p_choke = ap.get("choke_point", "N/A")
                p_target = ap.get("target_asset", "Host Compromise")
                p_prob = ap.get("likelihood_probability", 0.8) * 100

                steps_visual = []
                for s_idx, step in enumerate(p_steps):
                    is_choke = (step == p_choke)
                    steps_visual.append(f"""
                    <div class="ap-step-node {'ap-node-choke' if is_choke else ''}">
                      <div class="ap-node-num">STAGE {s_idx + 1}</div>
                      <div class="ap-node-title">{html.escape(step)}</div>
                      {'<div class="ap-choke-tag">CHOKE POINT</div>' if is_choke else ''}
                    </div>
                    """)
                    if s_idx < len(p_steps) - 1:
                        steps_visual.append('<div class="ap-arrow">&rarr;</div>')

                flow_rendered = "".join(steps_visual)

                attack_paths_html.append(f"""
                <div class="attack-path-flow-card">
                  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
                    <div>
                      <span style="font-family: var(--font-mono); font-size: 11px; color: #dc2626; font-weight: 700;">KILL-CHAIN {idx}</span>
                      <h4 style="font-size: 14px; font-weight: 700; color: var(--text-primary); margin: 0;">{html.escape(p_name)}</h4>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                      <span class="badge badge-crit">Probability: {p_prob:.0f}%</span>
                      <span class="badge badge-high">Target: {html.escape(p_target)}</span>
                    </div>
                  </div>
                  <div class="ap-flow-container">
                    {flow_rendered}
                  </div>
                  <div style="margin-top: 10px; font-size: 11.5px; color: var(--text-secondary); background: #f8fafc; border: 1px solid var(--border-color); border-radius: 6px; padding: 8px 12px;">
                    <strong>Strategic Choke-Point Remediation:</strong> Remediating <code style="font-family: var(--font-mono); color: #dc2626; font-weight: 700;">{html.escape(p_choke)}</code> immediately severs this exploit kill-chain.
                  </div>
                </div>
                """)
        attack_paths_rendered = "\n".join(attack_paths_html)

        # -------------------------------------------------------------
        # Pre-render: Findings Table Rows
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
            deep_dive = WebReportGenerator.deep_dive_url(f.id)
            deep_dive_link = (
                f'<a href="{deep_dive}" target="_blank" rel="noopener" title="Full in-depth analysis on the live WinSecure knowledge base" '
                f'onclick="event.stopPropagation()" style="font-family: var(--font-mono); font-size: 10px; color: #2563eb; text-decoration: none; margin-top: 3px; display: inline-flex; align-items: center; gap: 4px;">'
                f'<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-1px"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg> DEEP-DIVE ANALYSIS &rarr;</a>'
            ) if deep_dive else ""

            row_html = f"""<tr class="finding-row" data-id="{html.escape(f.id)}" data-category="{html.escape(f.category)}" data-severity="{html.escape(sev_str)}" data-status="{html.escape(st_str)}" data-finding="{f_json_escaped}" onclick="openFindingModalFromRow(this)" style="cursor: pointer;">
  <td><strong style="font-family: var(--font-mono); color: var(--text-primary);">{html.escape(f.id)}</strong></td>
  <td><span class="badge badge-low">{html.escape(f.category)}</span></td>
  <td>
    <div style="font-weight: 600; color: var(--text-primary);">{html.escape(f.title)}</div>
    <div style="font-size: 11.5px; color: var(--text-muted); margin-top: 2px;">{html.escape(f.actual or f.expected)}</div>
    {deep_dive_link}
  </td>
  <td><span class="badge {sev_badge_class}">{html.escape(sev_str.upper())}</span></td>
  <td><span class="badge {status_badge_class}">{html.escape(st_str)}</span></td>
  <td><span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">{html.escape(cis_ref)}</span></td>
</tr>"""
            findings_rows_html.append(row_html)

        findings_table_body = "\n".join(findings_rows_html)

        # -------------------------------------------------------------
        # Pre-render: Remediation Plan Cards
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
  {f'<a href="{WebReportGenerator.deep_dive_url(f.id)}" target="_blank" rel="noopener" style="display: inline-flex; align-items: center; gap: 6px; margin-top: 10px; font-family: var(--font-mono); font-size: 11.5px; color: #2563eb; text-decoration: none; font-weight: 600;"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-1px"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg> FULL IN-DEPTH ANALYSIS: ATTACK CHAIN, GPO PATH &amp; VERIFICATION &rarr;</a>' if WebReportGenerator.deep_dive_url(f.id) else ''}
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
  max-width: 1240px;
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

/* Charts Grid */
.charts-grid {
  display: grid;
  grid-template-columns: 340px 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

.donut-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 10px 0;
}

.donut-legend {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
  width: 100%;
  margin-top: 14px;
}

.legend-chip {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: var(--text-secondary);
  background: var(--bg-canvas);
  padding: 5px 8px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-color);
  cursor: pointer;
  transition: background 0.15s ease;
}

.legend-chip:hover {
  background: #f1f5f9;
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.cat-bar-row {
  margin-bottom: 11px;
  padding: 4px 6px;
  border-radius: 6px;
  transition: background 0.15s ease;
}

.cat-bar-row:hover {
  background: #f1f5f9;
}

.cat-bar-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
  margin-bottom: 4px;
}

.cat-bar-title {
  font-weight: 600;
  color: var(--text-primary);
}

.cat-bar-metrics {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}

.cat-bar-track {
  height: 8px;
  background: #e2e8f0;
  border-radius: 4px;
  overflow: hidden;
  display: flex;
}

.cat-bar-fill-pass { background: #10b981; }
.cat-bar-fill-fail { background: #ef4444; }
.cat-bar-fill-warn { background: #f59e0b; }

/* Analytics 2-col Grid */
.analytics-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
  margin-bottom: 20px;
}

.rdi-pillar-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-top: 12px;
}

.rdi-pillar-card {
  background: var(--bg-canvas);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
}

/* Attack Path Kill-Chain Flow Nodes */
.attack-path-flow-card {
  background: var(--bg-canvas);
  border: 1px solid #fecaca;
  border-left: 4px solid #ef4444;
  border-radius: var(--radius-sm);
  padding: 14px 16px;
  margin-bottom: 12px;
}

.ap-flow-container {
  display: flex;
  align-items: center;
  gap: 8px;
  overflow-x: auto;
  padding: 6px 0;
}

.ap-step-node {
  background: #ffffff;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 8px 12px;
  min-width: 140px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
}

.ap-step-node.ap-node-choke {
  border-color: #ef4444;
  background: #fef2f2;
}

.ap-node-num {
  font-family: var(--font-mono);
  font-size: 9.5px;
  color: var(--text-muted);
}

.ap-node-title {
  font-size: 12px;
  font-weight: 700;
  color: var(--text-primary);
  margin-top: 2px;
}

.ap-choke-tag {
  display: inline-block;
  font-size: 9px;
  font-weight: 700;
  color: #dc2626;
  margin-top: 4px;
}

.ap-arrow {
  color: #94a3b8;
  font-weight: 700;
  font-size: 16px;
}

/* Stepper for Zero Trust */
.zt-stepper {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-top: 14px;
}

.zt-step-card {
  background: var(--bg-canvas);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 12px;
  text-align: center;
}

.zt-step-card.active {
  background: #ecfdf5;
  border-color: #10b981;
  box-shadow: 0 0 0 2px #10b98120;
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
@media (max-width: 960px) {
  .charts-grid { grid-template-columns: 1fr; }
  .analytics-grid { grid-template-columns: 1fr; }
  .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  .container-report { padding: 16px; }
  .zt-stepper { grid-template-columns: repeat(2, 1fr); }
}

@media (max-width: 600px) {
  .kpi-grid { grid-template-columns: 1fr; }
  .header-card { flex-direction: column; align-items: flex-start; }
  .rdi-pillar-grid { grid-template-columns: 1fr; }
  .zt-stepper { grid-template-columns: 1fr; }
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

var SITE_URL = '__SITE_URL__';
var DEEP_DIVE_IDS = __DEEP_DIVE_IDS_JSON__;

var activeFindingFilter = 'ALL';
var currentActiveFinding = null;
var currentModalTab = 'tab-overview';

function applyFilter(filterVal, element) {
  activeFindingFilter = filterVal || 'ALL';
  var chips = document.querySelectorAll('.filter-chip');
  for (var i = 0; i < chips.length; i++) {
    chips[i].classList.remove('active');
  }
  if (element) {
    element.classList.add('active');
  } else {
    for (var j = 0; j < chips.length; j++) {
      if (chips[j].getAttribute('data-filter') === activeFindingFilter) {
        chips[j].classList.add('active');
      }
    }
  }
  filterFindings();
}
window.applyFilter = applyFilter;

function filterByCategory(catName) {
  var catSelect = document.getElementById('category-filter');
  if (catSelect) {
    catSelect.value = catName;
    filterFindings();
    var section = document.getElementById('findings-section');
    if (section) section.scrollIntoView({ behavior: 'smooth' });
  }
}
window.filterByCategory = filterByCategory;

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
    var kbLink = (DEEP_DIVE_IDS.indexOf(f.id) !== -1)
      ? '<a href="' + SITE_URL + '#finding-' + encodeURIComponent(f.id) + '" target="_blank" rel="noopener" style="display: inline-flex; align-items: center; gap: 8px; margin-top: 16px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 10px 14px; font-family: var(--font-mono); font-size: 12px; color: #1d4ed8; font-weight: 600; text-decoration: none;"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></svg> FULL IN-DEPTH ANALYSIS ON LIVE SITE &mdash; ATTACK KILL-CHAIN, GPO PATH &amp; VERIFICATION &rarr;</a>'
      : '';
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
      '<p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.6;">' + escapeHtml(f.impact || f.description) + '</p>' +
      kbLink;
  } else if (tabKey === 'tab-threat') {
    body.innerHTML = '<div style="background: #fef2f2; border: 1px solid #fecaca; border-left: 4px solid #dc2626; padding: 14px; border-radius: 6px; margin-bottom: 14px;">' +
        '<div style="font-size: 12px; font-weight: 700; color: #991b1b; margin-bottom: 4px;">ATTACKER EXPLOITATION VECTOR</div>' +
        '<p style="font-size: 13px; color: #7f1d1d; line-height: 1.6; margin: 0;">' + escapeHtml(f.impact || f.description) + '</p>' +
      '</div>';
  } else if (tabKey === 'tab-remediation') {
    body.innerHTML = '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">' +
        '<span style="font-size: 12px; font-weight: 700; color: var(--text-muted);">RECOMMENDED POWERSHELL COMMAND</span>' +
        '<button class="btn btn-sm" onclick="copyCode(this.getAttribute(\'data-code\'))" data-code="' + escapeHtml(f.remediation || '') + '">Copy Fix</button>' +
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
  toast.style.cssText = "position: fixed; bottom: 24px; right: 24px; background: #0f172a; color: #ffffff; padding: 10px 18px; border-radius: 8px; font-size: 13px; font-weight: 600; z-index: 3000; box-shadow: 0 10px 25px rgba(0,0,0,0.25); display: inline-flex; align-items: center; gap: 8px;";
  toast.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> ' + escapeHtml(msg);
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

        # Inject live-site knowledge base constants into the report engine
        js_content = (
            js_content
            .replace("__SITE_URL__", WebReportGenerator.SITE_URL)
            .replace("__DEEP_DIVE_IDS_JSON__", json.dumps(sorted(WebReportGenerator.DEEP_DIVE_FINDING_IDS)))
        )

        with open(css_path, "w", encoding="utf-8") as f:
            f.write(css_content)
        with open(js_path, "w", encoding="utf-8") as f:
            f.write(js_content)

        # -------------------------------------------------------------
        # Master HTML Template
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
        <div class="kpi-meta">36 Security Modules</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Verified Controls</div>
        <div class="kpi-value kpi-success" id="kpi-passed">{pass_count} / {total_findings}</div>
        <div class="kpi-meta">Baseline Controls Aligned</div>
      </div>
    </div>

    <!-- GUI-BASED VISUAL ANALYSIS & INTERACTIVE CHARTS -->
    <div class="charts-grid">
      <!-- Chart 1: Severity Breakdown Donut Chart -->
      <div class="card" style="margin-bottom: 0;">
        <h2 class="card-title" style="margin-bottom: 4px;">Severity Distribution</h2>
        <p style="font-size: 11.5px; color: var(--text-muted); margin-bottom: 12px;">Interactive SVG donut chart — click slices or legend to filter.</p>
        
        <div class="donut-container">
          <svg width="170" height="170" viewBox="0 0 120 120">
            {donut_svg_html}
            <text x="60" y="55" text-anchor="middle" font-size="16" font-weight="700" fill="var(--text-primary)" font-family="var(--font-mono)">{score_val:.0f}</text>
            <text x="60" y="70" text-anchor="middle" font-size="9" font-weight="600" fill="var(--text-muted)" text-transform="uppercase">SCORE</text>
          </svg>
          
          <div class="donut-legend">
            <div class="legend-chip" onclick="applyFilter('CRITICAL', null)">
              <span class="legend-dot" style="background: #ef4444;"></span>
              <span>Critical: <strong>{crit_count}</strong></span>
            </div>
            <div class="legend-chip" onclick="applyFilter('HIGH', null)">
              <span class="legend-dot" style="background: #f97316;"></span>
              <span>High: <strong>{high_count}</strong></span>
            </div>
            <div class="legend-chip" onclick="applyFilter('MEDIUM', null)">
              <span class="legend-dot" style="background: #f59e0b;"></span>
              <span>Medium: <strong>{med_count}</strong></span>
            </div>
            <div class="legend-chip" onclick="applyFilter('LOW', null)">
              <span class="legend-dot" style="background: #0ea5e9;"></span>
              <span>Low: <strong>{low_count}</strong></span>
            </div>
            <div class="legend-chip" onclick="applyFilter('WARN', null)">
              <span class="legend-dot" style="background: #eab308;"></span>
              <span>Warn: <strong>{warn_count}</strong></span>
            </div>
            <div class="legend-chip" onclick="applyFilter('PASS', null)">
              <span class="legend-dot" style="background: #10b981;"></span>
              <span>Pass: <strong>{pass_count}</strong></span>
            </div>
          </div>
        </div>
      </div>

      <!-- Chart 2: Domain Risk & Compliance Bar Chart -->
      <div class="card" style="margin-bottom: 0;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <div>
            <h2 class="card-title" style="margin-bottom: 2px;">Security Domain Compliance</h2>
            <p style="font-size: 11.5px; color: var(--text-muted);">Pass vs. Failure distribution across audit categories — click to filter.</p>
          </div>
          <div style="display: flex; gap: 8px; font-size: 11px;">
            <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #10b981; border-radius: 2px;"></span> Passed</span>
            <span style="display: flex; align-items: center; gap: 4px;"><span style="width: 8px; height: 8px; background: #ef4444; border-radius: 2px;"></span> Failed</span>
          </div>
        </div>
        <div style="max-height: 290px; overflow-y: auto; padding-right: 4px;">
          {category_bars_rendered}
        </div>
      </div>
    </div>

    <!-- RESEARCH-GRADE ANALYTICS COCKPIT: RANSOMWARE & ZERO TRUST -->
    <div class="analytics-grid">
      <!-- Panel 1: Ransomware Resilience Index (ShieldFS Model) -->
      <div class="card" style="margin-bottom: 0;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <h3 class="card-title" style="margin-bottom: 2px;">Ransomware Defense Index (RDI)</h3>
            <p style="font-size: 11.5px; color: var(--text-muted);">Grounded in Continella et al. (ACSAC) ShieldFS resilience architecture.</p>
          </div>
          <div style="text-align: right;">
            <div style="font-family: var(--font-mono); font-size: 20px; font-weight: 700; color: {'#16a34a' if rdi_score >= 80 else ('#dc2626' if rdi_score < 50 else '#d97706')};">{rdi_score:.1f}%</div>
            <span class="badge {'badge-pass' if rdi_score >= 80 else ('badge-crit' if rdi_score < 50 else 'badge-med')}" style="font-size: 10px;">{rdi_status}</span>
          </div>
        </div>
        <div class="rdi-pillar-grid">
          {rdi_pillars_rendered}
        </div>
      </div>

      <!-- Panel 2: CISA Zero Trust Maturity Model (ZTMM v2.0) -->
      <div class="card" style="margin-bottom: 0;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <h3 class="card-title" style="margin-bottom: 2px;">CISA Zero Trust Device Maturity</h3>
            <p style="font-size: 11.5px; color: var(--text-muted);">NIST SP 800-207 & CISA ZTMM v2.0 Device Pillar progression.</p>
          </div>
          <div style="text-align: right;">
            <div style="font-family: var(--font-mono); font-size: 20px; font-weight: 700; color: #0284c7;">{zt_score:.1f}%</div>
            <span class="badge badge-low" style="font-size: 10px;">{zt_stage}</span>
          </div>
        </div>
        <div class="zt-stepper">
          <div class="zt-step-card {'active' if zt_stage == 'TRADITIONAL' else ''}">
            <div style="font-size: 10px; font-weight: 700; color: var(--text-muted);">TIER 1</div>
            <div style="font-size: 12px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">Traditional</div>
            <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Static perimeter</div>
          </div>
          <div class="zt-step-card {'active' if zt_stage == 'INITIAL' else ''}">
            <div style="font-size: 10px; font-weight: 700; color: var(--text-muted);">TIER 2</div>
            <div style="font-size: 12px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">Initial</div>
            <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Baseline controls</div>
          </div>
          <div class="zt-step-card {'active' if zt_stage == 'ADVANCED' else ''}">
            <div style="font-size: 10px; font-weight: 700; color: var(--text-muted);">TIER 3</div>
            <div style="font-size: 12px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">Advanced</div>
            <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Hardware & VBS</div>
          </div>
          <div class="zt-step-card {'active' if zt_stage == 'OPTIMAL' else ''}">
            <div style="font-size: 10px; font-weight: 700; color: var(--text-muted);">TIER 4</div>
            <div style="font-size: 12px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">Optimal</div>
            <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Continuous health</div>
          </div>
        </div>
        <div style="margin-top: 14px; background: var(--bg-canvas); border: 1px solid var(--border-color); border-radius: 6px; padding: 10px 12px; font-size: 12px; color: var(--text-secondary);">
          <strong>Active Stage: {zt_stage}</strong> — Enforce Hardware CET, Credential Guard, and WDAC policies to reach optimal zero-trust device posture.
        </div>
      </div>
    </div>

    <!-- BAYESIAN ATTACK PATH FLOW VISUALIZER -->
    <section class="card" style="margin-top: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h2 class="card-title" style="margin-bottom: 2px;">Bayesian Attack Path Synthesis & Choke Points</h2>
          <p style="font-size: 12px; color: var(--text-muted);">Grounded in Poolsappasit et al. (IEEE TDSC 2012) — identifies multi-stage adversary kill-chains and critical choke points.</p>
        </div>
        <div>
          <span class="badge {'badge-crit' if blast_radius > 60 else ('badge-high' if blast_radius > 30 else 'badge-pass')}" style="font-size: 12px; padding: 4px 10px;">
            Blast Radius: {blast_radius:.1f}/100
          </span>
        </div>
      </div>
      {attack_paths_rendered}
    </section>

    <!-- Findings Explorer (Core Focus) -->
    <section class="card" id="findings-section">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 12px;">
        <div>
          <h2 class="card-title" style="margin: 0;">Evaluation Findings ({total_findings})</h2>
          <p style="font-size: 12.5px; color: var(--text-muted); margin-top: 2px;">Click any finding row to view detailed evidence, attack vectors, and remediation commands.</p>
        </div>
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="filter-chip active" data-filter="ALL" onclick="applyFilter('ALL', this)">ALL ({total_findings})</button>
          <button class="filter-chip" data-filter="CRITICAL" onclick="applyFilter('CRITICAL', this)">CRITICAL ({crit_count})</button>
          <button class="filter-chip" data-filter="HIGH" onclick="applyFilter('HIGH', this)">HIGH ({high_count})</button>
          <button class="filter-chip" data-filter="MEDIUM" onclick="applyFilter('MEDIUM', this)">MEDIUM ({med_count})</button>
          <button class="filter-chip" data-filter="FAIL" onclick="applyFilter('FAIL', this)">FAILURES ({len(failing_findings)})</button>
          <button class="filter-chip" data-filter="PASS" onclick="applyFilter('PASS', this)">PASSED ({pass_count})</button>
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
          <option value="Hardware Security">Hardware Security</option>
          <option value="Ransomware Defense">Ransomware Defense</option>
          <option value="Application Control">Application Control</option>
          <option value="Credential Defense">Credential Defense</option>
          <option value="Active Directory">Active Directory</option>
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
