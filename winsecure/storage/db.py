"""
WinSecure SQLite Database Manager (Cross-Platform & Filesystem-Resilient)
"""
import os
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from typing import Optional, Generator
from winsecure.storage.migrations import apply_migrations
from winsecure.core.exceptions import StorageException


class DatabaseManager:
    """Manages SQLite connection lifecycle, migrations, and resilient persistence."""

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._temp_staging: Optional[str] = None
        self._use_staging = False

        # Test if direct connection works on target filesystem
        try:
            test_conn = sqlite3.connect(self.db_path, timeout=5.0)
            test_conn.execute("CREATE TABLE IF NOT EXISTS _fs_test (id INT)")
            test_conn.execute("DROP TABLE _fs_test")
            test_conn.close()
        except sqlite3.OperationalError:
            # Filesystem (e.g. 9p/NFS) lacks POSIX lock support, use local temp staging
            self._use_staging = True
            fd, self._temp_staging = tempfile.mkstemp(suffix=".db")
            os.close(fd)
            if os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0:
                shutil.copy2(self.db_path, self._temp_staging)

        self._init_db()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yields a configured SQLite connection and guarantees closure."""
        target_path = self._temp_staging if self._use_staging else self.db_path
        conn = None
        try:
            conn = sqlite3.connect(target_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            yield conn
        except Exception as e:
            raise StorageException(f"Failed to connect to database at {target_path}: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _init_db(self) -> None:
        """Initializes tables and schema migrations."""
        with self.get_connection() as conn:
            apply_migrations(conn)
        self.sync_to_disk()

    def sync_to_disk(self) -> None:
        """Synchronizes staged changes to the target database file."""
        if self._use_staging and self._temp_staging and os.path.exists(self._temp_staging):
            try:
                with open(self._temp_staging, "rb") as src, open(self.db_path, "wb") as dst:
                    dst.write(src.read())
            except Exception:
                pass

    def check_integrity(self) -> bool:
        """Performs PRAGMA integrity_check."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            rows = cursor.fetchall()
            return len(rows) == 1 and rows[0][0] == "ok"

    def close(self) -> None:
        """Cleans up any temporary staging files."""
        if self._temp_staging and os.path.exists(self._temp_staging):
            try:
                os.unlink(self._temp_staging)
            except Exception:
                pass
