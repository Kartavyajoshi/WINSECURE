"""
WinSecure Standalone Technical Report Generator
"""
import os
from winsecure.models.scan import ScanResult


class TechnicalReportGenerator:
    """Generates a technical findings HTML report for security engineers and auditors."""

    @staticmethod
    def generate(result: ScanResult, output_dir: str) -> str:
        path = os.path.join(output_dir, "Technical_Report.html")
        rows = "".join([f"""
          <tr style="border-bottom: 1px solid #e2e8f0;">
            <td style="padding: 10px;"><strong>{f.id}</strong></td>
            <td style="padding: 10px;">{f.category}</td>
            <td style="padding: 10px;">{f.title}</td>
            <td style="padding: 10px;">{f.severity.value}</td>
            <td style="padding: 10px;"><strong>{f.status.value}</strong></td>
            <td style="padding: 10px;">{f.actual}</td>
          </tr>
        """ for f in result.findings])

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>WinSecure Technical Security Report — {result.scan_id}</title>
  <style>
    body {{ font-family: Consolas, monospace, sans-serif; background: #ffffff; color: #1e293b; padding: 30px; font-size: 13px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th {{ background: #f1f5f9; text-align: left; padding: 10px; border-bottom: 2px solid #cbd5e1; }}
  </style>
</head>
<body>
  <h1>WinSecure Technical Findings Report</h1>
  <p>Scan ID: <strong>{result.scan_id}</strong> | Total Evaluated Checks: <strong>{len(result.findings)}</strong> across <strong>30 Security Modules</strong></p>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Category</th>
        <th>Title</th>
        <th>Severity</th>
        <th>Status</th>
        <th>Observed State</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
