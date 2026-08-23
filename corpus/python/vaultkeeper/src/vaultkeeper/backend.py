"""Storage backends for sealed secrets.

Backends are looked up by the name in the config file rather than constructed
directly, so that adding a backend does not mean touching the daemon.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from . import envelope


class Backend(Protocol):
    """What the daemon needs from a storage backend."""

    def put(self, key: str, blob: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...


class SealedStore:
    """An in-memory store that seals every value before it is written."""

    def __init__(self, data_key: bytes) -> None:
        self._data_key = data_key
        self._items: dict[str, bytes] = {}

    def put(self, key: str, blob: bytes) -> None:
        sealed = envelope.seal(self._data_key, blob, key.encode())
        self._items[key] = sealed.to_wire()

    def get(self, key: str) -> bytes:
        wire = self._items[key]
        return envelope.open_envelope(self._data_key, envelope.Envelope.from_wire(wire), key.encode())


def _build_sealed_store(data_key: bytes) -> SealedStore:
    return SealedStore(data_key)


#: Backend names as they appear in config/vaultkeeper.yaml.
REGISTRY: dict[str, Callable[[bytes], Backend]] = {
    "sealed-memory": _build_sealed_store,
    "sealed-scratch": _build_sealed_store,
}


def open_backend(name: str, data_key: bytes) -> Backend:
    """Resolve a backend by config name."""
    try:
        factory = REGISTRY[name]
    except KeyError:
        raise ValueError(f"backend: unknown backend {name!r}") from None
    return factory(data_key)
