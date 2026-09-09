from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class Session:
    token: str
    user_id: int
    username: str
    expires_at: datetime


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create(self, user_id: int, username: str) -> Session:
        token = secrets.token_urlsafe(32)
        session = Session(
            token=token,
            user_id=user_id,
            username=username,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self._sessions[token] = session
        return session

    def get(self, token: str) -> Session | None:
        session = self._sessions.get(token)
        if session is None:
            return None
        if session.expires_at <= datetime.now(timezone.utc):
            self._sessions.pop(token, None)
            return None
        return session

