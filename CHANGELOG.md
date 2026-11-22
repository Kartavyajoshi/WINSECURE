# Changelog

All notable changes to the **WinSecure** platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.6.0] - 2026-11-22 — Aegis Vanguard

### Added
- **Native Desktop GUI Cockpit**: Complete local Tkinter-based desktop interface (`python run.py gui`) with real-time audit triggers, severity donut charts, compliance breakdowns, domain comparison bars, and finding drill-downs.
- **Pure Vector SVG Design System**: Complete website and UI overhaul featuring a modern cyber-obsidian aesthetic, 100% SVG vector iconography, and zero unicode emojis for crisp, professional rendering across all displays.
- **Empirical Comparative Benchmarking Engine**: Built-in comparator (`python run.py compare`) generating head-to-head performance and coverage metrics against previous milestones and 7 industry security tools.
- **Full Verification Suite (`run.py suite`)**: Orchestrated 4-stage pipeline combining 108 unit/integration tests, platform integrity validation, end-to-end synthetic scans, and plugin registry verification.

### Changed
- Bumped package release to **v2.6.0 Aegis Vanguard**.
- Synchronized package metadata across `pyproject.toml`, `setup.py`, `winsecure/version.py`, `index.html`, and `README.md`.
- Enhanced offline reporting with deep-link navigation between interactive single-file HTML reports and local module documentation.

---

## [2.5.0] - 2026-09-18 — Aegis Prime

### Added
- **Academic Research Foundations**: Integrated principles from 5 peer-reviewed cybersecurity papers (*IEEE TDSC*, *IEEE S&P*, *ACM ACSAC*, *USENIX Security*, *NIST SP 800-207*).
- **Bayesian Attack Path Synthesis**: Algorithmic generation of multi-step adversary kill-chains, blast radius scoring (0–100), and strategic choke-point remediation discovery.
- **Ransomware Defense Index (RDI)**: 6-pillar assessment measuring Controlled Folder Access, Volume Shadow Copy protection, BitLocker encryption, and tripwire viability.
- **CISA Zero Trust Maturity Model (ZTMM v2.0)**: Device pillar evaluation mapping endpoints to Traditional, Initial, Advanced, or Optimal stages.
- **Hardware CET & Application Control Modules**:
  - `WS-CET-001` / `WS-CET-002`: Intel/AMD Control-flow Enforcement Technology shadow stacks and Arbitrary Code Guard.
  - `WS-LOL-001` / `WS-LOL-002`: Windows Defender Application Control (WDAC) Recommended Block Rules and PowerShell Constrained Language Mode (CLM).
  - `WS-CG-001`: Virtualization-Based Credential Guard (LSA Isolated User Mode).

---

## [2.0.0] - 2026-08-16 — Enterprise Baseline

### Added
- **Multi-Format Reporting**: Automated generation of interactive HTML dashboards, machine-readable JSON telemetry, CSV audit matrices, Markdown executive summaries, and GitHub Security SARIF.
- **Historical Drift & Trend Analytics**: Persistent SQLite history storage with posture drift tracking (IMPROVING / STABLE / DECLINING) and failure recurrence detection.
- **REST API & Webhook Service**: Localhost daemon (`winsecure api`) offering authenticated REST endpoints for scan results and automated HTTP webhook notifications on scan completion.
- **Automated PowerShell Remediation**: Synthesized fix, rollback, and verification scripts for every discovered finding, bundled into a master executor (`WinSecure-Remediation-Master.ps1`).
- **Extensible Plugin Framework**: Plugin hook lifecycle (`pre_scan`, `post_finding`, `post_scan`, `on_report`) with report-forwarder reference plugin.

---

## [1.0.0] - 2026-08-15 — Initial Release

### Added
- **Core Windows Security Auditor**: Deterministic, non-destructive audit engine evaluating Defender, Firewall, Account Policies, User Privileges, Services, and Registry hardening.
- **Compliance Baseline Mapping**: CIS Controls v8, NIST SP 800-53 Rev 5, and Microsoft Security Baselines.
- **Zero-Cloud Air-Gapped Architecture**: 100% offline local execution with zero network dependency or telemetry egress.
