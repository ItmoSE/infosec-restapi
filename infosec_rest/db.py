from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

from infosec_rest.auth import hash_password


DEFAULT_DB_PATH = Path("data/app.db")


def connect(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    path = Path(db_path)
    if path != Path(":memory:"):
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def initialize(connection: sqlite3.Connection, admin_password: str | None = None) -> None:
    _migrate_users_table(connection)
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id)
        );
        """
    )
    if admin_password is None:
        admin_password = secrets.token_urlsafe(24)
    connection.execute(
        "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
        ("admin", hash_password(admin_password)),
    )
    connection.execute(
        """
        INSERT OR IGNORE INTO posts (id, title, body, author_id)
        VALUES (?, ?, ?, ?)
        """,
        (1, "Welcome", "First demo post", 1),
    )
    connection.commit()


def _migrate_users_table(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = ? AND name = ?",
        ("table", "users"),
    ).fetchone()
    if table is None:
        return

    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(users)").fetchall()
    }
    if "password_hash" in columns:
        return
    if "password" not in columns:
        raise RuntimeError("Unsupported users table schema")

    connection.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    users = connection.execute("SELECT id, password FROM users").fetchall()
    for user in users:
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(user["password"]), user["id"]),
        )
    connection.commit()
