from __future__ import annotations

import json
import sqlite3
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any

from infosec_rest.auth import Session, SessionStore


class Api:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.sessions = SessionStore()
        self._db_lock = threading.RLock()

    def handler(self) -> type[BaseHTTPRequestHandler]:
        api = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "InfosecRestAPI/0.1"

            def do_GET(self) -> None:
                if self.path == "/health":
                    self._send_json(HTTPStatus.OK, {"status": "ok"})
                    return
                if self.path == "/api/data":
                    session = self._require_session()
                    if session is None:
                        return
                    posts = api.list_posts()
                    self._send_json(HTTPStatus.OK, {"data": posts, "user": session.username})
                    return
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

            def do_POST(self) -> None:
                if self.path == "/auth/login":
                    payload = self._read_json()
                    username = str(payload.get("username", ""))
                    password = str(payload.get("password", ""))
                    user = api.find_user(username, password)
                    if user is None:
                        self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"})
                        return
                    session = api.sessions.create(user_id=user["id"], username=user["username"])
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "access_token": session.token,
                            "token_type": "Bearer",
                            "expires_at": session.expires_at.isoformat(),
                        },
                    )
                    return

                if self.path == "/api/posts":
                    session = self._require_session()
                    if session is None:
                        return
                    payload = self._read_json()
                    title = str(payload.get("title", "")).strip()
                    body = str(payload.get("body", "")).strip()
                    if not title or not body:
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": "Both title and body are required"},
                        )
                        return
                    post = api.create_post(title=title, body=body, author_id=session.user_id)
                    self._send_json(HTTPStatus.CREATED, {"post": post})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _read_json(self) -> dict[str, Any]:
                content_length = int(self.headers.get("Content-Length", "0"))
                if content_length == 0:
                    return {}
                raw_body = self.rfile.read(content_length)
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON"})
                    return {}
                if isinstance(payload, dict):
                    return payload
                return {}

            def _require_session(self) -> Session | None:
                authorization = self.headers.get("Authorization", "")
                token_type, _, token = authorization.partition(" ")
                if token_type != "Bearer" or not token:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Missing bearer token"})
                    return None
                session = api.sessions.get(token)
                if session is None:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid bearer token"})
                    return None
                return session

            def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler

    def find_user(self, username: str, password: str) -> sqlite3.Row | None:
        with self._db_lock:
            cursor = self.connection.execute(
                "SELECT id, username FROM users WHERE username = ? AND password = ?",
                (username, password),
            )
            return cursor.fetchone()

    def list_posts(self) -> list[dict[str, Any]]:
        with self._db_lock:
            cursor = self.connection.execute(
                """
                SELECT posts.id, posts.title, posts.body, posts.created_at, users.username AS author
                FROM posts
                JOIN users ON users.id = posts.author_id
                ORDER BY posts.id ASC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def create_post(self, title: str, body: str, author_id: int) -> dict[str, Any]:
        with self._db_lock:
            cursor = self.connection.execute(
                "INSERT INTO posts (title, body, author_id) VALUES (?, ?, ?)",
                (title, body, author_id),
            )
            self.connection.commit()
            post_id = cursor.lastrowid
            row = self.connection.execute(
                """
                SELECT posts.id, posts.title, posts.body, posts.created_at, users.username AS author
                FROM posts
                JOIN users ON users.id = posts.author_id
                WHERE posts.id = ?
                """,
                (post_id,),
            ).fetchone()
            return dict(row)
