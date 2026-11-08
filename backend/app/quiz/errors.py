"""Quiz service errors. Each carries the HTTP status the router answers with."""

from __future__ import annotations


class QuizError(Exception):
    status_code = 400

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class SessionMissing(QuizError):
    status_code = 404


class QuizMissing(QuizError):
    status_code = 404


class NotAllowed(QuizError):
    status_code = 403


class Conflict(QuizError):
    status_code = 409


class BadInput(QuizError):
    status_code = 422
