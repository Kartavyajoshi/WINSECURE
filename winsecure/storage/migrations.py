"""
WinSecure SQLite Database Schema & Migrations
"""
import sqlite3

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    winsecure_version TEXT NOT NULL,
    profile TEXT NOT NULL,
    is_admin INTEGER NOT NULL,
    security_score REAL NOT NULL,
    risk_level TEXT NOT NULL,
    total_checks INTEGER NOT NULL,
    passed_checks INTEGER NOT NULL,
    failed_checks INTEGER NOT NULL,
    warn_checks INTEGER NOT NULL,
    unknown_checks INTEGER NOT NULL,
    error_checks INTEGER NOT NULL,
    duration_seconds REAL NOT NULL,
    hostname TEXT,
    os_name TEXT,
    os_build TEXT,
    privilege_coverage REAL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT,
    scan_id TEXT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence REAL NOT NULL,
    description TEXT,
    expected TEXT,
    actual TEXT,
    impact TEXT,
    remediation TEXT,
    requires_admin INTEGER DEFAULT 0,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (id, scan_id),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    scan_id TEXT,
    finding_id TEXT,
    source TEXT NOT NULL,
    collector TEXT NOT NULL,
    data_json TEXT,
    command_executed TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    framework TEXT NOT NULL,
    version TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_title TEXT NOT NULL,
    profile TEXT,
    status TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    finding_id TEXT NOT NULL,
    title TEXT NOT NULL,
    priority TEXT NOT NULL,
    what_is_wrong TEXT,
    why_it_matters TEXT,
    how_to_fix TEXT,
    powershell_script TEXT,
    validation_command TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_benchmarks (
    scan_id TEXT PRIMARY KEY,
    cpu_percent_avg REAL,
    peak_memory_mb REAL,
    checks_per_second REAL,
    duration_seconds REAL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    module TEXT NOT NULL,
    check_id TEXT,
    error_message TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_compliance_scan ON compliance_assessments(scan_id);
"""


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Applies schema migrations to ensure database tables are up to date."""
    cursor = conn.cursor()
    cursor.executescript(SCHEMA_V1)
    
    # Check version
    cursor.execute("SELECT version FROM schema_version WHERE version = 1")
    row = cursor.fetchone()
    if not row:
        cursor.execute("INSERT INTO schema_version (version) VALUES (1)")
    conn.commit()
