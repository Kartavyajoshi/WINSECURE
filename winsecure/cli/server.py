"""
WinSecure Local Web Dashboard Server
"""
import functools
import http.server
import os
import socket
import sys
import threading
import time
import webbrowser
from winsecure.utils.formatting import Colors, colorize


def find_free_port(start_port: int = 8080, max_tries: int = 50) -> int:
    """Finds an available TCP port starting from start_port."""
    for port in range(start_port, start_port + max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start_port


class QuietHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP request handler with clean logging and proper MIME types."""

    def log_message(self, format, *args):
        # Suppress verbose 200 GET logs, only log errors or custom events
        if len(args) > 1 and str(args[1]) not in ("200", "304"):
            sys.stderr.write(f"[{colorize('HTTP', Colors.CYAN)}] {args[0]} - {args[1]}\n")

    def end_headers(self):
        # Prevent caching during live assessment sessions
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()


def start_server(directory: str, port: int = 8080, open_browser: bool = True) -> None:
    """Starts a local HTTP server serving the generated WinSecure Web Dashboard."""
    abs_dir = os.path.abspath(directory)
    if not os.path.exists(abs_dir):
        print(colorize(f"[!] Error: Report directory '{abs_dir}' does not exist.", Colors.RED))
        print(colorize("[*] Tip: Run 'winsecure scan' first to generate a report.", Colors.YELLOW))
        return

    index_file = os.path.join(abs_dir, "index.html")
    if not os.path.exists(index_file):
        print(colorize(f"[!] Warning: 'index.html' not found in '{abs_dir}'.", Colors.YELLOW))

    actual_port = find_free_port(port)
    handler = functools.partial(QuietHTTPRequestHandler, directory=abs_dir)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", actual_port), handler)
    url = f"http://127.0.0.1:{actual_port}/"

    print(colorize("\n" + "=" * 58, Colors.CYAN))
    print(colorize("   WinSecure Wazuh-Style Web Dashboard Server", Colors.BOLD + Colors.CYAN))
    print(colorize("=" * 58, Colors.CYAN))
    print(f"  * Status:    {colorize('ONLINE (Active)', Colors.GREEN + Colors.BOLD)}")
    print(f"  * Dashboard: {colorize(url, Colors.CYAN + Colors.UNDERLINE + Colors.BOLD)}")
    print(f"  * Directory: {colorize(abs_dir, Colors.DIM)}")
    print(colorize("=" * 58, Colors.CYAN))
    print(colorize("  Press Ctrl+C to stop the dashboard server.\n", Colors.DIM))

    if open_browser:
        def _open():
            time.sleep(0.4)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(colorize("\n[*] WinSecure Web Server stopped.", Colors.YELLOW))
    finally:
        server.server_close()
