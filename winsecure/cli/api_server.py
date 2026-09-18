"""
WinSecure REST API & Webhook Server
Exposes scan history, findings, trends, and webhook notifications over HTTP
using only the Python standard library (air-gapped friendly).
"""
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

from winsecure.storage.db import DatabaseManager
from winsecure.storage.repository import ScanRepository
from winsecure.analytics.drift_trend import DriftTrendEngine
from winsecure.version import __version__, __product_name__


class ApiBadRequest(Exception):
    """Raised by routes when a client supplies an invalid query parameter."""


class WebhookDispatcher:
    """Fires JSON POST webhooks when triggered (e.g., after a new scan)."""

    def __init__(self, timeout_seconds: int = 5):
        self.endpoints: List[str] = []
        self.timeout_seconds = timeout_seconds

    def register(self, url: str) -> None:
        """Registers a webhook endpoint URL."""
        if url and url not in self.endpoints:
            self.endpoints.append(url)

    def dispatch(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """POSTs the payload to all registered endpoints; returns per-endpoint results."""
        results = []
        if not self.endpoints:
            return results

        try:
            from urllib import request as urllib_request
            body = json.dumps(payload).encode("utf-8")
        except Exception:
            return results

        for url in self.endpoints:
            outcome = {"url": url, "delivered": False, "status": None, "error": None}
            try:
                req = urllib_request.Request(
                    url,
                    data=body,
                    headers={"Content-Type": "application/json", "User-Agent": f"{__product_name__}/{__version__}"},
                    method="POST",
                )
                with urllib_request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    outcome["delivered"] = True
                    outcome["status"] = resp.status
            except Exception as e:
                outcome["error"] = str(e)
            results.append(outcome)
        return results


class ApiRequestHandler(BaseHTTPRequestHandler):
    """Handles WinSecure API routes. Data access goes through class-level providers."""

    # Injected by ApiServer at startup
    repository: Optional[ScanRepository] = None
    db_manager: Optional[DatabaseManager] = None
    trend_engine: Optional[DriftTrendEngine] = None
    webhook_dispatcher: Optional[WebhookDispatcher] = None
    api_token: Optional[str] = None

    def log_message(self, fmt: str, *args: Any) -> None:
        return  # Silence default stderr logging; CLI handles its own output

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        """Checks bearer token when an API token is configured (timing-safe)."""
        if not ApiRequestHandler.api_token:
            return True
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(token.strip(), ApiRequestHandler.api_token)

    def _query_param(self, name: str, default: Optional[str] = None) -> Optional[str]:
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        values = qs.get(name)
        return values[0] if values else default

    def _int_param(self, name: str, default: int, minimum: int, maximum: int) -> int:
        """Parses an integer query parameter, clamped to [minimum, maximum]."""
        raw = self._query_param(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            raise ApiBadRequest(f"'{name}' must be an integer, got '{raw}'")
        if value < minimum or value > maximum:
            raise ApiBadRequest(f"'{name}' must be between {minimum} and {maximum}")
        return value

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/") or "/"

        routes = {
            "/": self._route_index,
            "/api/health": self._route_health,
            "/api/scans": self._route_scans,
            "/api/findings": self._route_findings,
            "/api/trend": self._route_trend,
            "/api/webhooks": self._route_webhooks_info,
        }

        handler = routes.get(path)
        if handler is None:
            self._send_json({"error": "Not found", "path": path}, status=404)
            return

        if not self._authorized():
            self._send_json({"error": "Unauthorized"}, status=401)
            return

        try:
            handler()
        except ApiBadRequest as e:
            self._send_json({"error": str(e)}, status=400)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def do_POST(self) -> None:
        path = self.path.split("?")[0].rstrip("/") or "/"

        if not self._authorized():
            self._send_json({"error": "Unauthorized"}, status=401)
            return

        if path == "/api/webhooks":
            self._route_register_webhook()
        elif path == "/api/test-webhooks":
            self._route_test_webhook()
        else:
            self._send_json({"error": "Not found", "path": path}, status=404)

    # ------------------------------------------------------------------
    # Route implementations
    # ------------------------------------------------------------------

    def _route_index(self) -> None:
        self._send_json({
            "product": __product_name__,
            "version": __version__,
            "endpoints": [
                "GET /api/health",
                "GET /api/scans?limit=N",
                "GET /api/findings?scan_id=SCAN-XXXX&status=FAIL&limit=N",
                "GET /api/trend?limit=N",
                "GET /api/webhooks",
                "POST /api/webhooks {\"url\": \"https://...\"}",
                "POST /api/test-webhooks",
            ],
        })

    def _route_health(self) -> None:
        healthy = self.db_manager.check_integrity() if self.db_manager else False
        self._send_json({
            "status": "ok" if healthy else "degraded",
            "database_healthy": healthy,
            "version": __version__,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })

    def _route_scans(self) -> None:
        limit = self._int_param("limit", default=10, minimum=1, maximum=100)
        scans = self.repository.get_latest_scans(limit=limit)
        self._send_json({"count": len(scans), "scans": scans})

    def _route_findings(self) -> None:
        scan_id = self._query_param("scan_id")
        status_filter = self._query_param("status")
        limit = self._int_param("limit", default=100, minimum=1, maximum=500)

        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM findings"
            conditions, params = [], []
            if scan_id:
                conditions.append("scan_id = ?")
                params.append(scan_id)
            if status_filter:
                conditions.append("status = ?")
                params.append(status_filter.upper())
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            cursor.execute(query, tuple(params))
            rows = [dict(row) for row in cursor.fetchall()]

        self._send_json({"count": len(rows), "findings": rows})

    def _route_trend(self) -> None:
        limit = self._int_param("limit", default=20, minimum=2, maximum=100)
        report = self.trend_engine.build_full_report(limit=limit)
        self._send_json(report)

    def _route_webhooks_info(self) -> None:
        dispatcher = self.webhook_dispatcher
        self._send_json({
            "registered_endpoints": list(dispatcher.endpoints) if dispatcher else [],
        })

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _route_register_webhook(self) -> None:
        body = self._read_json_body()
        url = body.get("url", "")
        if not url:
            self._send_json({"error": "'url' is required"}, status=400)
            return
        self.webhook_dispatcher.register(url)
        self._send_json({"registered": url, "total_endpoints": len(self.webhook_dispatcher.endpoints)})

    def _route_test_webhook(self) -> None:
        payload = {
            "event": "webhook.test",
            "product": __product_name__,
            "version": __version__,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        results = self.webhook_dispatcher.dispatch(payload)
        self._send_json({"results": results})


class ApiServer:
    """Runs the WinSecure REST API server."""

    def __init__(self, db_path: str, port: int = 8443, host: str = "127.0.0.1",
                 api_token: Optional[str] = None):
        self.db_path = db_path
        self.port = port
        self.host = host
        self.api_token = api_token
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

        self.db_manager = DatabaseManager(db_path)
        self.repository = ScanRepository(self.db_manager)
        self.trend_engine = DriftTrendEngine(db_path)
        self.webhook_dispatcher = WebhookDispatcher()

    def start(self, open_browser: bool = False) -> None:
        """Starts the API server (blocking unless run in background thread)."""
        ApiRequestHandler.repository = self.repository
        ApiRequestHandler.db_manager = self.db_manager
        ApiRequestHandler.trend_engine = self.trend_engine
        ApiRequestHandler.webhook_dispatcher = self.webhook_dispatcher
        ApiRequestHandler.api_token = self.api_token

        try:
            self.httpd = ThreadingHTTPServer((self.host, self.port), ApiRequestHandler)
        except OSError as e:
            hint = (
                f"Port {self.port} is already in use or cannot be bound "
                f"(use --port to pick another)."
            )
            raise OSError(f"{hint} Original error: {e}") from e
        print(f"[API] {__product_name__} v{__version__} API listening on http://{self.host}:{self.port}", flush=True)
        print(f"[API] Docs: http://{self.host}:{self.port}/", flush=True)
        if open_browser:
            import webbrowser
            webbrowser.open(f"http://{self.host}:{self.port}/")
        self.httpd.serve_forever()

    def start_background(self) -> None:
        """Starts the API server on a daemon thread and returns immediately."""
        self.thread = threading.Thread(target=self.start, daemon=True)
        self.thread.start()
        time.sleep(0.3)  # Give the socket a moment to bind

    def stop(self) -> None:
        """Shuts down the server and releases resources."""
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        self.trend_engine.close()
        self.db_manager.close()

    def notify_scan_complete(self, scan_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Pushes a scan-completed event to all registered webhooks."""
        payload = {
            "event": "scan.completed",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **scan_summary,
        }
        return self.webhook_dispatcher.dispatch(payload)
