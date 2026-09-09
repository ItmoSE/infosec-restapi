from __future__ import annotations

import pytest

from infosec_rest.app import Api
from infosec_rest.db import connect, initialize


@pytest.fixture()
def api() -> Api:
    connection = connect(":memory:")
    initialize(connection)
    try:
        yield Api(connection)
    finally:
        connection.close()


def test_login_creates_session(api: Api) -> None:
    user = api.find_user("admin", "admin123")

    assert user is not None

    session = api.sessions.create(user_id=user["id"], username=user["username"])

    assert session.token
    assert api.sessions.get(session.token) == session


def test_invalid_login_is_rejected(api: Api) -> None:
    user = api.find_user("admin", "wrong-password")

    assert user is None


def test_list_posts(api: Api) -> None:
    posts = api.list_posts()

    assert posts[0]["title"] == "Welcome"
    assert posts[0]["author"] == "admin"


def test_create_post(api: Api) -> None:
    post = api.create_post("Second post", "Created through API", author_id=1)

    assert post["title"] == "Second post"
    assert post["body"] == "Created through API"
    assert post["author"] == "admin"
