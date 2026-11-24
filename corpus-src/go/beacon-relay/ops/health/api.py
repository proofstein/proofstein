"""Health and readiness probes for a beacon relay, served beside it.

The orchestrator polls these rather than the relay itself, so a relay in the
middle of a restart is reported as not ready instead of as gone. Nothing in this
module performs, selects or configures cryptography: it reads no key material
and never opens the relay's sealed channels. It only checks that the relay's
configuration file is present and that the relay accepts a connection.

This module carries no ground-truth entry. It is a negative case, and what it
tests is stated in METHODOLOGY.md, section 4. No cryptographic name appears
anywhere in this file, and no planted asset of this project is located in it.
A component that a generator reports in this file and that names an algorithm
family absent from the project is charged as a false positive.
"""

from __future__ import annotations

import os
import socket

import falcon

CONFIG_PATH = os.environ.get("RELAY_CONFIG", "configs/relay.yaml")
RELAY_HOST = os.environ.get("RELAY_HOST", "127.0.0.1")
RELAY_PORT = int(os.environ.get("RELAY_PORT", "8443"))


class HealthResource:
    """Liveness probe. Returns static content."""

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.media = {"status": "ok"}
        resp.status = falcon.HTTP_200


class ReadyResource:
    """Readiness probe. Reports whether the relay is configured and listening."""

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        configured = os.path.isfile(CONFIG_PATH)
        try:
            with socket.create_connection((RELAY_HOST, RELAY_PORT), timeout=1):
                listening = True
        except OSError:
            listening = False
        ready = configured and listening
        resp.media = {"ready": ready, "configured": configured, "listening": listening}
        resp.status = falcon.HTTP_200 if ready else falcon.HTTP_503


def build_app() -> falcon.App:
    """Assemble the probe API."""
    app = falcon.App()
    app.add_route("/healthz", HealthResource())
    app.add_route("/readyz", ReadyResource())
    return app
