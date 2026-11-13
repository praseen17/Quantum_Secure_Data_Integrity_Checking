#!/usr/bin/env python3
"""Loopback-only browser interface for local Q-SAFE file workflows."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
import uuid
from urllib.parse import parse_qs, quote, urlparse

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 128 * 1024 * 1024
SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
RUN_LOCK = Lock()


def safe_filename(candidate: str) -> str:
    leaf = Path(candidate.replace("\\", "/")).name
    leaf = "".join(ch for ch in leaf if ch.isprintable() and ch not in '\\/:"<>|?*')
    leaf = leaf.strip(" .")[:180]
    return leaf or "uploaded-file.bin"


class Handler(BaseHTTPRequestHandler):
    server_version = "QSAFEInterface/2.0"

    def _send(self, status: int, payload: bytes, content_type: str,
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _json(self, status: int, value: dict) -> None:
        self._send(status, json.dumps(value).encode(), "application/json; charset=utf-8")

    def _allowed_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return False
        parsed = urlparse(origin)
        return (parsed.scheme == "http" and
                parsed.hostname in {"localhost", "127.0.0.1"} and
                parsed.port == self.server.server_address[1])

    def _read_json(self) -> dict | None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            return None
        if length < 1 or length > 4096:
            return None
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _session_dir(self, session_id: str) -> Path | None:
        if not SESSION_RE.fullmatch(session_id):
            return None
        path = self.server.data_root / session_id
        return path if path.is_dir() else None

    def _record(self, session_dir: Path) -> dict | None:
        try:
            record = json.loads((session_dir / "record.json").read_text(encoding="utf-8"))
            return record if isinstance(record, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _save_record(self, session_dir: Path, record: dict) -> None:
        target = session_dir / "record.json"
        temporary = session_dir / "record.json.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        temporary.replace(target)

    def _run_vault(self, *args: str, timeout: int = 180) -> tuple[dict | None, str | None]:
        try:
            result = subprocess.run(
                [str(self.server.vault_binary), *args], cwd=ROOT,
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return None, "Q-SAFE operation exceeded its time limit."
        except OSError as exc:
            return None, f"Could not start Q-SAFE: {exc}"
        output = result.stdout.strip()
        if result.returncode != 0:
            error = result.stderr.strip() or output or "Q-SAFE operation failed."
            try:
                parsed = json.loads(error)
                error = parsed.get("error", error)
            except json.JSONDecodeError:
                pass
            return None, error[-1200:]
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return None, "Q-SAFE returned an invalid response."
        return payload, None

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/status":
            self._json(200, {"ready": self.server.vault_binary.is_file(),
                "max_upload_bytes": MAX_UPLOAD_BYTES,
                "stored_files": sum(1 for item in self.server.data_root.iterdir()
                                    if item.is_dir() and (item / "record.json").is_file())})
            return
        if path == "/api/files":
            files = []
            for item in self.server.data_root.iterdir():
                if item.is_dir():
                    record = self._record(item)
                    if record:
                        files.append(record)
            files.sort(key=lambda item: item.get("created_at", ""), reverse=True)
            self._json(200, {"files": files})
            return
        if path == "/guide":
            guide = ROOT / "docs/USER_AND_DEPLOYMENT_GUIDE.md"
            self._send(200, guide.read_bytes(), "text/markdown; charset=utf-8")
            return
        match = re.fullmatch(r"/api/files/([0-9a-f]{32})(?:/(download))?", path)
        if match:
            session_id, action = match.groups()
            session_dir = self._session_dir(session_id)
            if session_dir is None:
                self._json(404, {"error": "Stored file was not found."})
                return
            if action == "download":
                restored = session_dir / "recovered.bin"
                try:
                    data = restored.read_bytes()
                except OSError:
                    self._json(404, {"error": "Recover the file before downloading it."})
                    return
                self._send(200, data, "application/octet-stream",
                    {"Content-Disposition": 'attachment; filename="recovered-file.bin"'})
                return
            record = self._record(session_dir)
            details, error = self._run_vault("inspect", str(session_dir / "workspace"))
            if error:
                self._json(500, {"error": error})
            else:
                self._json(200, {**(record or {}), **(details or {})})
            return
        static_routes = {"/": ("index.html", "text/html; charset=utf-8"),
            "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8")}
        static = static_routes.get(path)
        if static:
            name, content_type = static
            self._send(200, (WEB_ROOT / name).read_bytes(), content_type)
            return
        self._json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        if not self._allowed_origin():
            self._json(403, {"error": "A same-origin browser request is required."})
            return
        if not RUN_LOCK.acquire(blocking=False):
            self._json(409, {"error": "Another Q-SAFE operation is already running."})
            return
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/api/files":
                self._ingest(parse_qs(parsed.query))
                return
            match = re.fullmatch(r"/api/files/([0-9a-f]{32})/(audit|loss|recover)", parsed.path)
            if not match:
                self._json(404, {"error": "Not found."})
                return
            session_id, action = match.groups()
            session_dir = self._session_dir(session_id)
            if session_dir is None:
                self._json(404, {"error": "Stored file was not found."})
                return
            body = self._read_json()
            if body is None:
                self._json(400, {"error": "A small JSON request body is required."})
                return
            workspace = str(session_dir / "workspace")
            if action == "audit":
                record = self._record(session_dir) or {}
                count = body.get("sample_count")
                total = int(record.get("total_shards", 0))
                if count is None:
                    count = min(total, max(1, (total + 19) // 20))
                if not isinstance(count, int) or isinstance(count, bool) or count < 1 or count > total:
                    self._json(400, {"error": f"Choose a sample count from 1 to {total}."})
                    return
                result, error = self._run_vault("audit", workspace, str(count))
                self._json(500 if error else 200, {"error": error} if error else result)
                return
            index = body.get("shard_index")
            if not isinstance(index, int) or isinstance(index, bool) or index < 0:
                self._json(400, {"error": "Choose a non-negative shard index."})
                return
            record = self._record(session_dir) or {}
            if index >= int(record.get("total_shards", 0)):
                self._json(400, {"error": "Shard index is outside this file's manifest."})
                return
            if action == "loss":
                result, error = self._run_vault("lose", workspace, str(index))
                self._json(500 if error else 200, {"error": error} if error else result)
                return
            result, error = self._run_vault("recover", workspace, str(index),
                str(session_dir / "recovered.bin"))
            if not error:
                record["recovered"] = True
                record["download_url"] = f"/api/files/{session_id}/download"
                self._save_record(session_dir, record)
            self._json(500 if error else 200,
                {"error": error} if error else {**(result or {}), "download_url": f"/api/files/{session_id}/download"})
        finally:
            RUN_LOCK.release()

    def _ingest(self, query: dict[str, list[str]]) -> None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_UPLOAD_BYTES:
            self._json(413, {"error": "Files must be 128 MiB or smaller."})
            return
        raw_name = query.get("name", ["uploaded-file.bin"])[0]
        name = safe_filename(raw_name)
        session_id = uuid.uuid4().hex
        session_dir = self.server.data_root / session_id
        workspace = session_dir / "workspace"
        try:
            session_dir.mkdir(mode=0o700)
            upload = session_dir / "upload.tmp"
            remaining = length
            with upload.open("wb") as output:
                while remaining:
                    block = self.rfile.read(min(1024 * 1024, remaining))
                    if not block:
                        raise OSError("upload ended before all bytes were received")
                    output.write(block)
                    remaining -= len(block)
            os.chmod(upload, 0o600)
            result, error = self._run_vault("ingest", str(upload), str(workspace), timeout=240)
            if error:
                raise ValueError(error)
            upload.unlink(missing_ok=True)
            record = {"session_id": session_id, "file_name": name,
                "original_bytes": result["original_bytes"],
                "source_shards": result["source_shards"],
                "total_shards": result["total_shards"], "shard_size": result["shard_size"],
                "file_id": result["file_id"], "root": result["root"],
                "created_at": datetime.now(timezone.utc).isoformat()}
            self._save_record(session_dir, record)
            self._json(201, record)
        except (OSError, ValueError, KeyError) as exc:
            if session_dir.exists():
                for child in session_dir.iterdir():
                    if child.is_file():
                        child.unlink(missing_ok=True)
                import shutil
                shutil.rmtree(session_dir, ignore_errors=True)
            self._json(400, {"error": str(exc)[:1200]})

    def log_message(self, fmt: str, *args) -> None:
        print(f"[q-safe-ui] {self.address_string()} {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (loopback only).")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--binary", type=Path, default=None, help="Path to qsafe_vault executable.")
    parser.add_argument("--data-dir", type=Path, default=None,
        help="Persistent local workspace directory; defaults to ~/.local/share/qsafe-ui.")
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost"}:
        parser.error("The interface is local-only; use a loopback host.")
    default_binary = ROOT / "build/current/qsafe_vault"
    if not default_binary.exists():
        default_binary = ROOT / "build/clean/qsafe_vault"
    binary = (args.binary or default_binary).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        parser.error(f"Q-SAFE vault executable is missing or not executable: {binary}. Run scripts/build.sh.")
    data_root = (args.data_dir or Path.home() / ".local/share/qsafe-ui").expanduser().resolve()
    data_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(data_root, 0o700)
    os.umask(0o077)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.vault_binary = binary
    server.data_root = data_root
    print(f"Q-SAFE local file workspace at http://{args.host}:{args.port} (Ctrl+C to stop)")
    print(f"Stored data directory: {data_root}")
    print(f"Q-SAFE vault executable: {binary}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Q-SAFE interface.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
