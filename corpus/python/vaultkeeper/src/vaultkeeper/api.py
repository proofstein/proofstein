"""HTTP surface for the vaultkeeper daemon.

Health and readiness endpoints only. Nothing in this module performs, selects or
configures cryptography: key material never reaches it, and the daemon's KEM,
envelope and identity paths live in kem.py, envelope.py and identity.py.

This module carries no ground-truth entry, deliberately. It is a negative case;
what it tests, and why, is recorded in docs/pending-review.md entry 9. The
explanation is kept there rather than here on purpose, so that no cryptographic
name appears anywhere in this file. A negative case that names the algorithm it
is testing for is not a negative case.
"""

from __future__ import annotations

import falcon

from .settings import Settings


class HealthResource:
    """Liveness probe. Returns static content."""

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.media = {"status": "ok"}
        resp.status = falcon.HTTP_200


class ReadyResource:
    """Readiness probe. Reports which storage backend the daemon resolved."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        backend = self._settings.backend
        resp.media = {"ready": bool(backend), "backend": backend}
        resp.status = falcon.HTTP_200 if backend else falcon.HTTP_503


def build_app(settings: Settings) -> falcon.App:
    """Assemble the admin API."""
    app = falcon.App()
    app.add_route("/healthz", HealthResource())
    app.add_route("/readyz", ReadyResource(settings))
    return app
