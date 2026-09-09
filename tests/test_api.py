from __future__ import annotations

import pytest

from infosec_rest.app import Api, sanitize_payload
from infosec_rest.db import connect, initialize


@pytest.fixture()
def api() -> Api:
    connection = connect(":memory:")
    initialize(connection, admin_password="admin123")
    try:
        yield Api(connection)
    finally:
        connection.close()


def test_login_issues_jwt(api: Api) -> None:
    user = api.find_user("admin", "admin123")

    assert user is not None

    token = api.jwt.issue(user_id=user["id"], username=user["username"])
    verified_user = api.jwt.verify(token)

    assert token.count(".") == 2
    assert verified_user is not None
    assert verified_user.username == "admin"


def test_invalid_login_is_rejected(api: Api) -> None:
    user = api.find_user("admin", "wrong-password")

    assert user is None


def test_login_query_is_not_vulnerable_to_sqli(api: Api) -> None:
    user = api.find_user("admin' OR 1=1 --", "anything")

    assert user is None


def test_password_is_not_stored_as_plain_text(api: Api) -> None:
    row = api.connection.execute("SELECT password_hash FROM users WHERE username = ?", ("admin",)).fetchone()

    assert row["password_hash"] != "admin123"
    assert row["password_hash"].startswith("scrypt$")


def test_legacy_plain_password_is_migrated() -> None:
    connection = connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
        INSERT INTO users (username, password) VALUES ('legacy', 'secret');
        """
    )

    try:
        initialize(connection, admin_password="admin123")
        api = Api(connection)
        row = connection.execute("SELECT password_hash FROM users WHERE username = ?", ("legacy",)).fetchone()

        assert row["password_hash"].startswith("scrypt$")
        assert api.find_user("legacy", "secret") is not None
    finally:
        connection.close()


def test_list_posts(api: Api) -> None:
    posts = api.list_posts()

    assert posts[0]["title"] == "Welcome"
    assert posts[0]["author"] == "admin"


def test_create_post(api: Api) -> None:
    post = api.create_post("Second post", "Created through API", author_id=1)

    assert post["title"] == "Second post"
    assert post["body"] == "Created through API"
    assert post["author"] == "admin"


def test_user_content_is_escaped_before_return(api: Api) -> None:
    post = sanitize_payload(api.create_post("<script>alert(1)</script>", "<b>xss</b>", author_id=1))

    assert post["title"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert post["body"] == "&lt;b&gt;xss&lt;/b&gt;"


def test_tampered_jwt_is_rejected(api: Api) -> None:
    token = api.jwt.issue(user_id=1, username="admin")
    header, payload, _ = token.split(".")

    assert api.jwt.verify(f"{header}.{payload}.invalid") is None
