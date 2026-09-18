"""
WinSecure Native Desktop GUI Application
Cyber-Graphite Modern Dark Interface with Interactive Canvas Charts, Posture Gauges,
Live Real-Time Scanner, Findings Explorer, and One-Click Remediation.
"""
import os
import sys
import json
import queue
import threading
import webbrowser
from typing import Optional, Dict, Any, List

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from winsecure.version import __version__, __product_name__, __codename__
from winsecure.models.scan import ScanResult
from winsecure.models.finding import Finding, FindingStatus, Severity


class ChartUtils:
    """Helper utilities for rendering mathematical charts directly on Tkinter Canvas."""

    @staticmethod
    def draw_donut(canvas: tk.Canvas, width: int, height: int, slices: List[Dict[str, Any]], center_text: str = "", sub_text: str = ""):
        canvas.delete("all")
        if not slices:
            return

        cx, cy = width // 2, height // 2 - 15
        radius = min(width, height) // 3
        inner_radius = int(radius * 0.62)

        total = sum(s["value"] for s in slices)
        if total <= 0:
            total = 1

        start_angle = 90.0
        bbox = (cx - radius, cy - radius, cx + radius, cy + radius)
        inner_bbox = (cx - inner_radius, cy - inner_radius, cx + inner_radius, cy + inner_radius)

        for s in slices:
            val = s["value"]
            if val <= 0:
                continue
            extent = (val / total) * 360.0
            canvas.create_arc(
                bbox,
                start=start_angle,
                extent=-extent,
                fill=s["color"],
                outline="#1e293b",
                width=1,
            )
            start_angle -= extent

        # Inner cutout circle for donut effect
        canvas.create_oval(inner_bbox, fill="#1e293b", outline="#334155", width=1)

        if center_text:
            canvas.create_text(cx, cy - 6, text=center_text, fill="#f8fafc", font=("Segoe UI", 16, "bold"))
        if sub_text:
            canvas.create_text(cx, cy + 12, text=sub_text, fill="#94a3b8", font=("Segoe UI", 8, "bold"))

    @staticmethod
    def draw_bar_chart(canvas: tk.Canvas, width: int, height: int, categories: List[Dict[str, Any]]):
        canvas.delete("all")
        if not categories:
            return

        margin_left = 130
        margin_right = 70
        margin_top = 10
        row_height = 24
        bar_max_width = width - margin_left - margin_right

        y = margin_top
        for cat in categories[:12]:
            name = cat.get("name", "Other")
            passed = cat.get("pass", 0)
            failed = cat.get("fail", 0)
            warn = cat.get("warn", 0)
            total = cat.get("total", 1) or 1

            pass_w = int((passed / total) * bar_max_width)
            fail_w = int((failed / total) * bar_max_width)
            warn_w = int((warn / total) * bar_max_width)

            pct = int((passed / total) * 100)

            # Category Label
            display_name = name[:16] + ".." if len(name) > 16 else name
            canvas.create_text(margin_left - 10, y + 8, text=display_name, anchor="e", fill="#cbd5e1", font=("Segoe UI", 8, "bold"))

            # Track background
            track_x0 = margin_left
            track_x1 = margin_left + bar_max_width
            canvas.create_rectangle(track_x0, y + 3, track_x1, y + 13, fill="#334155", outline="")

            # Segments
            cur_x = track_x0
            if pass_w > 0:
                canvas.create_rectangle(cur_x, y + 3, cur_x + pass_w, y + 13, fill="#10b981", outline="")
                cur_x += pass_w
            if fail_w > 0:
                canvas.create_rectangle(cur_x, y + 3, cur_x + fail_w, y + 13, fill="#ef4444", outline="")
                cur_x += fail_w
            if warn_w > 0:
                canvas.create_rectangle(cur_x, y + 3, cur_x + warn_w, y + 13, fill="#f59e0b", outline="")

            # Percentage Metric
            metric_str = f"{pct}% ({passed}/{total})"
            canvas.create_text(track_x1 + 8, y + 8, text=metric_str, anchor="w", fill="#94a3b8", font=("Consolas", 8))

            y += row_height


class WinSecureApp:
    """Main WinSecure Desktop Application Window."""

    def __init__(self, root: tk.Tk, report_dir: str = "./WinSecure-Report"):
        self.root = root
        self.report_dir = os.path.abspath(report_dir)
        self.current_result: Optional[ScanResult] = None
        self.is_scanning = False
        self.scan_thread: Optional[threading.Thread] = None
        self.msg_queue = queue.Queue()

        self.root.title(f"{__product_name__} v{__version__} — Security Control Cockpit")
        self.root.geometry("1100x720")
        self.root.minsize(960, 640)
        self.root.configure(bg="#0f172a")

        self._configure_styles()
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

        # Try to load existing report data if present
        self._load_existing_report()

        # Periodic queue checker for thread safety
        self.root.after(100, self._process_queue)

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background="#0f172a", foreground="#f8fafc", font=("Segoe UI", 9))
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground="#94a3b8", padding=[16, 8], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#0ea5e9")], foreground=[("selected", "#ffffff")])

        style.configure("Card.TFrame", background="#1e293b", relief="flat")
        style.configure("TProgressbar", thickness=8, troughcolor="#1e293b", background="#0ea5e9")

        # Treeview styling
        style.configure("Treeview", background="#1e293b", foreground="#f8fafc", fieldbackground="#1e293b", borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background="#0f172a", foreground="#94a3b8", font=("Segoe UI", 8, "bold"))
        style.map("Treeview", background=[("selected", "#0369a1")])

    def _build_header(self):
        header = tk.Frame(self.root, bg="#1e293b", height=64, padx=20, pady=10)
        header.pack(fill="x", side="top")

        # Left branding
        left_box = tk.Frame(header, bg="#1e293b")
        left_box.pack(side="left")

        badge = tk.Label(left_box, text="WS", bg="#0ea5e9", fg="#ffffff", font=("Segoe UI", 12, "bold"), width=3, height=1)
        badge.pack(side="left", padx=(0, 12))

        titles = tk.Frame(left_box, bg="#1e293b")
        titles.pack(side="left")
        lbl_title = tk.Label(titles, text="WinSecure Defense Cockpit", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 13, "bold"))
        lbl_title.pack(anchor="w")
        self.lbl_subtitle = tk.Label(titles, text="Ready for audit | 36 Modules | 62+ Controls", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8))
        self.lbl_subtitle.pack(anchor="w")

        # Right actions
        right_box = tk.Frame(header, bg="#1e293b")
        right_box.pack(side="right")

        self.btn_scan = tk.Button(
            right_box,
            text="Run System Scan",
            bg="#0ea5e9",
            fg="#ffffff",
            activebackground="#0284c7",
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=14,
            pady=6,
            cursor="hand2",
            command=self.start_live_scan,
        )
        self.btn_scan.pack(side="left", padx=6)

        btn_report = tk.Button(
            right_box,
            text="Open HTML Report",
            bg="#334155",
            fg="#f8fafc",
            activebackground="#475569",
            activeforeground="#ffffff",
            font=("Segoe UI", 9),
            relief="flat",
            padx=12,
            pady=6,
            cursor="hand2",
            command=self.open_web_report,
        )
        btn_report.pack(side="left", padx=6)

    def _build_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=12)

        # Tab 1: Overview & Posture
        self.tab_overview = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_overview, text="System Overview")
        self._build_tab_overview()

        # Tab 2: Visual Charts & Analytics
        self.tab_charts = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_charts, text="Visual Charts & Analytics")
        self._build_tab_charts()

        # Tab 3: Findings Explorer
        self.tab_findings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_findings, text="Findings Explorer")
        self._build_tab_findings()

        # Tab 4: Attack Paths & Choke Points
        self.tab_attacks = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_attacks, text="Attack Paths & Choke Points")
        self._build_tab_attacks()

        # Tab 5: Remediation Studio
        self.tab_remedy = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_remedy, text="Remediation Studio")
        self._build_tab_remediation()

    def _build_tab_overview(self):
        # KPI Container
        kpi_frame = tk.Frame(self.tab_overview, bg="#0f172a")
        kpi_frame.pack(fill="x", pady=(8, 14))

        self.kpi_boxes = {}
        kpi_defs = [
            ("score", "SECURITY SCORE", "--/100", "#0ea5e9", "Overall Posture"),
            ("critical", "CRITICAL DEFECTS", "0", "#ef4444", "Immediate Exploits"),
            ("high", "HIGH SEVERITY", "0", "#f97316", "Significant Exposure"),
            ("passed", "VERIFIED CONTROLS", "0 / 62", "#10b981", "Baseline Aligned"),
        ]

        for idx, (key, title, val, color, sub) in enumerate(kpi_defs):
            box = tk.Frame(kpi_frame, bg="#1e293b", padx=16, pady=12, highlightthickness=1, highlightbackground="#334155")
            box.pack(side="left", fill="both", expand=True, padx=(0 if idx == 0 else 8, 0))

            lbl_t = tk.Label(box, text=title, bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8, "bold"))
            lbl_t.pack(anchor="w")

            lbl_v = tk.Label(box, text=val, bg="#1e293b", fg=color, font=("Consolas", 20, "bold"))
            lbl_v.pack(anchor="w", pady=2)

            lbl_s = tk.Label(box, text=sub, bg="#1e293b", fg="#64748b", font=("Segoe UI", 8))
            lbl_s.pack(anchor="w")

            self.kpi_boxes[key] = (lbl_v, lbl_s)

        # Split frame: System Info & Live Log
        content = tk.Frame(self.tab_overview, bg="#0f172a")
        content.pack(fill="both", expand=True)

        # Left: System specs card
        left_card = tk.Frame(content, bg="#1e293b", padx=16, pady=16, highlightthickness=1, highlightbackground="#334155")
        left_card.pack(side="left", fill="both", expand=True, padx=(0, 8))

        tk.Label(left_card, text="Host Environment & Inventory", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 10))

        self.lbl_host = tk.Label(left_card, text="Host: WIN-ENDPOINT", bg="#1e293b", fg="#cbd5e1", font=("Segoe UI", 9))
        self.lbl_host.pack(anchor="w", pady=3)
        self.lbl_os = tk.Label(left_card, text="Operating System: Windows 11 Enterprise (x64)", bg="#1e293b", fg="#cbd5e1", font=("Segoe UI", 9))
        self.lbl_os.pack(anchor="w", pady=3)
        self.lbl_priv = tk.Label(left_card, text="Privilege Context: Detecting...", bg="#1e293b", fg="#cbd5e1", font=("Segoe UI", 9))
        self.lbl_priv.pack(anchor="w", pady=3)
        self.lbl_modules = tk.Label(left_card, text="Loaded Modules: 36 Specialized Security Modules", bg="#1e293b", fg="#cbd5e1", font=("Segoe UI", 9))
        self.lbl_modules.pack(anchor="w", pady=3)

        tk.Label(left_card, text="Research Baseline Grounding", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(14, 6))
        papers = [
            "• Poolsappasit et al. (IEEE TDSC): Bayesian Attack Graphs",
            "• Continella et al. (ACSAC): ShieldFS Ransomware Resilience",
            "• NIST SP 800-207 & CISA: Zero Trust Maturity Model v2.0",
            "• Intel & Microsoft: Control-flow Enforcement (CET)",
        ]
        for p in papers:
            tk.Label(left_card, text=p, bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8)).pack(anchor="w", pady=1)

        # Right: Live Execution Console Log
        right_card = tk.Frame(content, bg="#1e293b", padx=16, pady=16, highlightthickness=1, highlightbackground="#334155")
        right_card.pack(side="right", fill="both", expand=True, padx=(8, 0))

        tk.Label(right_card, text="Live Telemetry & Diagnostics", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))

        self.txt_log = tk.Text(right_card, bg="#0f172a", fg="#38bdf8", font=("Consolas", 8), borderwidth=0, padx=8, pady=8)
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.insert("end", "[*] WinSecure Cockpit initialized.\n[*] Ready to execute system audit or view previous reports.\n")

    def _build_tab_charts(self):
        charts_frame = tk.Frame(self.tab_charts, bg="#0f172a")
        charts_frame.pack(fill="both", expand=True, pady=6)

        # Left Canvas: Severity Donut
        donut_box = tk.Frame(charts_frame, bg="#1e293b", padx=16, pady=14, highlightthickness=1, highlightbackground="#334155")
        donut_box.pack(side="left", fill="both", expand=True, padx=(0, 8))

        tk.Label(donut_box, text="Severity Distribution", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(donut_box, text="Defect distribution across critical, high, medium, and low tiers", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 8))

        self.canvas_donut = tk.Canvas(donut_box, bg="#1e293b", borderwidth=0, highlightthickness=0, width=320, height=220)
        self.canvas_donut.pack(fill="both", expand=True)

        self.lbl_donut_legend = tk.Label(donut_box, text="Pass: 0 | Critical: 0 | High: 0 | Medium: 0 | Low: 0", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8))
        self.lbl_donut_legend.pack(anchor="center", pady=(4, 0))

        # Right Canvas: Domain Compliance Bars
        bar_box = tk.Frame(charts_frame, bg="#1e293b", padx=16, pady=14, highlightthickness=1, highlightbackground="#334155")
        bar_box.pack(side="right", fill="both", expand=True, padx=(8, 0))

        tk.Label(bar_box, text="Domain Security Compliance", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(bar_box, text="Green: Passed checks | Red: Failed misconfigurations", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8)).pack(anchor="w", pady=(0, 8))

        self.canvas_bars = tk.Canvas(bar_box, bg="#1e293b", borderwidth=0, highlightthickness=0, width=440, height=240)
        self.canvas_bars.pack(fill="both", expand=True)

    def _build_tab_findings(self):
        filter_bar = tk.Frame(self.tab_findings, bg="#1e293b", padx=12, pady=8, highlightthickness=1, highlightbackground="#334155")
        filter_bar.pack(fill="x", pady=(0, 8))

        tk.Label(filter_bar, text="Filter:", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8, "bold")).pack(side="left", padx=(0, 6))

        self.ent_search = tk.Entry(filter_bar, bg="#0f172a", fg="#f8fafc", insertbackground="#f8fafc", font=("Segoe UI", 9), width=24, relief="flat")
        self.ent_search.pack(side="left", padx=4)
        self.ent_search.bind("<KeyRelease>", lambda e: self._refresh_findings_table())

        self.filter_sev = tk.StringVar(value="ALL")
        for s in ["ALL", "FAIL", "PASS", "CRITICAL", "HIGH", "MEDIUM"]:
            rb = tk.Radiobutton(
                filter_bar,
                text=s,
                value=s,
                variable=self.filter_sev,
                command=self._refresh_findings_table,
                bg="#1e293b",
                fg="#cbd5e1",
                selectcolor="#0f172a",
                activebackground="#1e293b",
                font=("Segoe UI", 8),
            )
            rb.pack(side="left", padx=4)

        # PanedWindow: Top Table, Bottom Detail
        paned = tk.PanedWindow(self.tab_findings, orient="vertical", bg="#0f172a", sashwidth=4)
        paned.pack(fill="both", expand=True)

        # Table
        cols = ("id", "severity", "category", "status", "title")
        self.tree = ttk.Treeview(paned, columns=cols, show="headings", height=9)
        self.tree.heading("id", text="ID")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("category", text="Category")
        self.tree.heading("status", text="Status")
        self.tree.heading("title", text="Finding Title")

        self.tree.column("id", width=100, anchor="w")
        self.tree.column("severity", width=80, anchor="center")
        self.tree.column("category", width=120, anchor="w")
        self.tree.column("status", width=70, anchor="center")
        self.tree.column("title", width=480, anchor="w")

        paned.add(self.tree, minsize=140)

        # Detail Box
        detail_card = tk.Frame(paned, bg="#1e293b", padx=14, pady=10)
        paned.add(detail_card, minsize=140)

        self.lbl_detail_title = tk.Label(detail_card, text="Select a finding to inspect telemetry evidence & remediation", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 10, "bold"))
        self.lbl_detail_title.pack(anchor="w")

        self.txt_detail = tk.Text(detail_card, bg="#0f172a", fg="#38bdf8", font=("Consolas", 8), height=6, borderwidth=0, padx=8, pady=6)
        self.txt_detail.pack(fill="both", expand=True, pady=4)

        btn_copy = tk.Button(
            detail_card,
            text="Copy Remediation Command",
            bg="#0ea5e9",
            fg="#ffffff",
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            command=self._copy_selected_remediation,
        )
        btn_copy.pack(side="right")

        self.tree.bind("<<TreeviewSelect>>", self._on_finding_select)

    def _build_tab_attacks(self):
        container = tk.Frame(self.tab_attacks, bg="#0f172a")
        container.pack(fill="both", expand=True, pady=6)

        top_info = tk.Frame(container, bg="#1e293b", padx=16, pady=12, highlightthickness=1, highlightbackground="#334155")
        top_info.pack(fill="x", pady=(0, 10))

        tk.Label(top_info, text="Bayesian Multi-Stage Exploit Kill-Chains", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.lbl_blast = tk.Label(top_info, text="Blast Radius: --/100 | Strategic Choke Points: --", bg="#1e293b", fg="#ef4444", font=("Segoe UI", 9, "bold"))
        self.lbl_blast.pack(anchor="w", pady=(2, 0))

        self.txt_attacks = tk.Text(container, bg="#1e293b", fg="#f8fafc", font=("Consolas", 9), borderwidth=0, padx=14, pady=12)
        self.txt_attacks.pack(fill="both", expand=True)

    def _build_tab_remediation(self):
        container = tk.Frame(self.tab_remedy, bg="#0f172a")
        container.pack(fill="both", expand=True, pady=6)

        actions_bar = tk.Frame(container, bg="#1e293b", padx=14, pady=10, highlightthickness=1, highlightbackground="#334155")
        actions_bar.pack(fill="x", pady=(0, 10))

        tk.Label(actions_bar, text="Automated PowerShell Hardening Script", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 10, "bold")).pack(side="left")

        btn_save = tk.Button(
            actions_bar,
            text="Save as .ps1 File",
            bg="#10b981",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            command=self._save_script_to_file,
        )
        btn_save.pack(side="right", padx=6)

        btn_copy_all = tk.Button(
            actions_bar,
            text="Copy Master Script",
            bg="#0ea5e9",
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=4,
            command=self._copy_all_script,
        )
        btn_copy_all.pack(side="right", padx=6)

        self.txt_remedy = tk.Text(container, bg="#0f172a", fg="#38bdf8", font=("Consolas", 8), borderwidth=0, padx=12, pady=10)
        self.txt_remedy.pack(fill="both", expand=True)

    def _build_status_bar(self):
        status_bar = tk.Frame(self.root, bg="#1e293b", height=28, padx=12)
        status_bar.pack(fill="x", side="bottom")

        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=160)
        self.progress.pack(side="left", padx=(0, 10))

        self.lbl_status = tk.Label(status_bar, text="WinSecure Engine Idle", bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8))
        self.lbl_status.pack(side="left")

        ver_lbl = tk.Label(status_bar, text=f"v{__version__} {__codename__}", bg="#1e293b", fg="#64748b", font=("Consolas", 8))
        ver_lbl.pack(side="right")

    def _load_existing_report(self):
        json_path = os.path.join(self.report_dir, "scan_result.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.current_result = ScanResult.from_dict(data)
                self._update_ui_with_results(self.current_result)
                self.lbl_status.config(text=f"Loaded existing assessment: {self.current_result.scan_id}")
            except Exception as e:
                self.txt_log.insert("end", f"[!] Note: Could not parse previous scan_result.json: {e}\n")

    def start_live_scan(self):
        if self.is_scanning:
            return

        self.is_scanning = True
        self.btn_scan.config(state="disabled", text="Scanning...")
        self.progress.start(10)
        self.lbl_status.config(text="Live assessment executing across 36 modules...")

        def _worker():
            try:
                from winsecure.core.config import ScanConfig
                from winsecure.core.context import ScanContext
                from winsecure.engine.pipeline import ScanPipeline
                from winsecure.reporting.generator import ReportGenerator

                config = ScanConfig(output_dir=self.report_dir)
                context = ScanContext(config=config)
                pipeline = ScanPipeline(context=context)

                def on_test(finding, idx, total, stats):
                    self.msg_queue.put(("log", f"[{finding.status.value}] [{idx}/{total}] {finding.id}: {finding.title}\n"))

                def on_step(idx, total, desc):
                    self.msg_queue.put(("status", f"Stage {idx}/{total}: {desc}"))

                res = pipeline.run(test_callback=on_test, progress_callback=on_step)
                ReportGenerator.generate_all(res, self.report_dir)
                self.msg_queue.put(("complete", res))
            except Exception as ex:
                self.msg_queue.put(("error", str(ex)))

        self.scan_thread = threading.Thread(target=_worker, daemon=True)
        self.scan_thread.start()

    def _process_queue(self):
        try:
            while not self.msg_queue.empty():
                msg_type, payload = self.msg_queue.get_nowait()
                if msg_type == "log":
                    self.txt_log.insert("end", payload)
                    self.txt_log.see("end")
                elif msg_type == "status":
                    self.lbl_status.config(text=str(payload))
                elif msg_type == "complete":
                    self.is_scanning = False
                    self.progress.stop()
                    self.btn_scan.config(state="normal", text="Run System Scan")
                    self.current_result = payload
                    self._update_ui_with_results(payload)
                    self.lbl_status.config(text="Scan Complete & Reports Generated!")
                    messagebox.showinfo("Assessment Complete", f"Scan finished successfully!\nSecurity Score: {payload.security_score:.1f}/100")
                elif msg_type == "error":
                    self.is_scanning = False
                    self.progress.stop()
                    self.btn_scan.config(state="normal", text="Run System Scan")
                    self.lbl_status.config(text=f"Error: {payload}")
                    messagebox.showerror("Scan Error", f"Assessment failed: {payload}")
        finally:
            self.root.after(100, self._process_queue)

    def _update_ui_with_results(self, res: ScanResult):
        crit_count = sum(1 for f in res.findings if f.status == FindingStatus.FAIL and f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in res.findings if f.status == FindingStatus.FAIL and f.severity == Severity.HIGH)
        med_count = sum(1 for f in res.findings if f.status == FindingStatus.FAIL and f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in res.findings if f.status == FindingStatus.FAIL and f.severity == Severity.LOW)
        pass_count = sum(1 for f in res.findings if f.status == FindingStatus.PASS)
        warn_count = sum(1 for f in res.findings if f.status == FindingStatus.WARN)
        total_count = len(res.findings)

        # Update KPIs
        self.kpi_boxes["score"][0].config(text=f"{res.security_score:.1f}/100")
        self.kpi_boxes["score"][1].config(text=f"{res.risk_level.value if hasattr(res.risk_level, 'value') else res.risk_level} POSTURE")
        self.kpi_boxes["critical"][0].config(text=str(crit_count))
        self.kpi_boxes["high"][0].config(text=str(high_count))
        self.kpi_boxes["passed"][0].config(text=f"{pass_count} / {total_count}")

        # Update Host info
        if res.inventory:
            self.lbl_host.config(text=f"Host: {res.inventory.hostname}")
            self.lbl_os.config(text=f"OS: {res.inventory.os_name} ({res.inventory.os_architecture})")
        self.lbl_priv.config(text=f"Privilege Context: {'Administrative (Elevated)' if res.is_admin else 'Standard User'}")

        # Update Charts
        slices = [
            {"label": "Critical", "value": crit_count, "color": "#ef4444"},
            {"label": "High", "value": high_count, "color": "#f97316"},
            {"label": "Medium", "value": med_count, "color": "#f59e0b"},
            {"label": "Low", "value": low_count, "color": "#0ea5e9"},
            {"label": "Warn", "value": warn_count, "color": "#eab308"},
            {"label": "Passed", "value": pass_count, "color": "#10b981"},
        ]
        ChartUtils.draw_donut(self.canvas_donut, 320, 220, slices, f"{res.security_score:.0f}", "SCORE")
        self.lbl_donut_legend.config(text=f"Pass: {pass_count} | Crit: {crit_count} | High: {high_count} | Med: {med_count} | Low: {low_count}")

        # Category stats
        cat_stats: Dict[str, Dict[str, int]] = {}
        for f in res.findings:
            c = f.category or "Other"
            if c not in cat_stats:
                cat_stats[c] = {"name": c, "pass": 0, "fail": 0, "warn": 0, "total": 0}
            cat_stats[c]["total"] += 1
            if f.status == FindingStatus.PASS:
                cat_stats[c]["pass"] += 1
            elif f.status == FindingStatus.FAIL:
                cat_stats[c]["fail"] += 1
            elif f.status == FindingStatus.WARN:
                cat_stats[c]["warn"] += 1

        cats_sorted = sorted(cat_stats.values(), key=lambda x: (x["fail"], x["total"]), reverse=True)
        ChartUtils.draw_bar_chart(self.canvas_bars, 440, 240, cats_sorted)

        # Update Findings Table
        self._refresh_findings_table()

        # Update Attack Paths
        self.txt_attacks.delete("1.0", "end")
        ap_list = res.attack_paths or []
        blast = res.blast_radius_score or 0.0
        self.lbl_blast.config(text=f"Blast Radius Score: {blast:.1f}/100 | Synthesized Kill-Chains: {len(ap_list)}")

        if not ap_list:
            self.txt_attacks.insert("end", "[OK] Defensive perimeter solid. No active Bayesian multi-stage attack paths discovered.\n")
        else:
            for idx, ap in enumerate(ap_list, 1):
                self.txt_attacks.insert("end", f"=== ATTACK PATH {idx}: {ap.get('name')} ===\n")
                self.txt_attacks.insert("end", f"  Likelihood: {ap.get('likelihood_probability', 0)*100:.0f}%  |  Target: {ap.get('target_asset')}\n")
                self.txt_attacks.insert("end", f"  Path: {' -> '.join(ap.get('path_steps', []))}\n")
                self.txt_attacks.insert("end", f"  [!] STRATEGIC CHOKE POINT: {ap.get('choke_point')} (Fix this control to disrupt entire chain)\n\n")

        # Update Remediation Script
        self.txt_remedy.delete("1.0", "end")
        fails = [f for f in res.findings if f.status == FindingStatus.FAIL]
        lines = [
            "# WinSecure Automated Remediation Master Script",
            "# Run in PowerShell as Administrator",
            "",
        ]
        for idx, f in enumerate(fails, 1):
            lines.append(f"# Step {idx}: {f.id} - {f.title}")
            lines.append(f.remediation or "# No remediation specified")
            lines.append("")
        self.txt_remedy.insert("end", "\n".join(lines))

    def _refresh_findings_table(self):
        if not self.current_result:
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        sev_filter = self.filter_sev.get()
        search_term = self.ent_search.get().lower().strip()

        for f in self.current_result.findings:
            sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            st_str = f.status.value if hasattr(f.status, "value") else str(f.status)

            if sev_filter == "FAIL" and st_str != "FAIL":
                continue
            if sev_filter == "PASS" and st_str != "PASS":
                continue
            if sev_filter in ("CRITICAL", "HIGH", "MEDIUM") and sev_str.upper() != sev_filter:
                continue

            if search_term:
                match_text = f"{f.id} {f.title} {f.category} {f.description}".lower()
                if search_term not in match_text:
                    continue

            self.tree.insert("", "end", values=(f.id, sev_str, f.category, st_str, f.title), tags=(f.id,))

    def _on_finding_select(self, event):
        sel = self.tree.selection()
        if not sel or not self.current_result:
            return

        item = self.tree.item(sel[0])
        fid = item["values"][0]

        finding = next((f for f in self.current_result.findings if f.id == fid), None)
        if not finding:
            return

        self.lbl_detail_title.config(text=f"[{finding.id}] {finding.title}")
        self.txt_detail.delete("1.0", "end")
        details = [
            f"Category: {finding.category} | Severity: {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity} | Status: {finding.status.value if hasattr(finding.status, 'value') else finding.status}",
            f"Description: {finding.description}",
            f"Actual State: {finding.actual or 'N/A'}",
            f"Impact: {finding.impact or 'N/A'}",
            "",
            "PowerShell Remediation:",
            f"{finding.remediation or '# No remediation required'}",
        ]
        self.txt_detail.insert("end", "\n".join(details))

    def _copy_selected_remediation(self):
        sel = self.tree.selection()
        if not sel or not self.current_result:
            return
        fid = self.tree.item(sel[0])["values"][0]
        finding = next((f for f in self.current_result.findings if f.id == fid), None)
        if finding and finding.remediation:
            self.root.clipboard_clear()
            self.root.clipboard_append(finding.remediation)
            messagebox.showinfo("Copied", f"Copied remediation command for {finding.id} to clipboard!")

    def _copy_all_script(self):
        script = self.txt_remedy.get("1.0", "end").strip()
        if script:
            self.root.clipboard_clear()
            self.root.clipboard_append(script)
            messagebox.showinfo("Copied", "Master hardening script copied to clipboard!")

    def _save_script_to_file(self):
        script = self.txt_remedy.get("1.0", "end").strip()
        if not script:
            messagebox.showwarning("Empty Script", "No remediation commands available to save.")
            return

        out_file = filedialog.asksaveasfilename(
            defaultextension=".ps1",
            filetypes=[("PowerShell Script", "*.ps1"), ("All Files", "*.*")],
            initialfile="WinSecure-Hardening-Master.ps1",
        )
        if out_file:
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(script)
            messagebox.showinfo("Saved", f"Hardening script saved to:\n{out_file}")

    def open_web_report(self):
        html_file = os.path.join(self.report_dir, "index.html")
        if os.path.exists(html_file):
            webbrowser.open(f"file://{html_file}")
        else:
            messagebox.showwarning("Report Not Found", f"HTML report not found at {html_file}. Please run a scan first.")


def launch_gui(report_dir: str = "./WinSecure-Report", autostart_scan: bool = False):
    """Launch the WinSecure Native Desktop GUI application."""
    root = tk.Tk()
    app = WinSecureApp(root, report_dir=report_dir)
    if autostart_scan:
        root.after(500, app.start_live_scan)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
