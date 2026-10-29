"""
Key management and JWKS resolution for AgentOnboard token verification.

Bounded key cache (max 8 sources), cooldown on unknown kids, and stale-key fallback
per ADR 0002.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from jwt.algorithms import RSAAlgorithm

MAX_CACHED_KEY_SOURCES = 8
COOLDOWN_DURATION_SECONDS = 30.0
CACHE_MAX_AGE_SECONDS = 3600.0

BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class KeySourceUnavailableError(Exception):
    """Raised when public signing keys cannot be obtained or are malformed."""


class KeyNotFoundError(Exception):
    """Raised when the specific kid is not present in an otherwise valid JWKS."""


def is_base64url(val: Any) -> bool:
    return isinstance(val, str) and bool(val) and bool(BASE64URL_RE.match(val))


def is_usable_key_entry(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    kid = entry.get("kid")
    kty = entry.get("kty")
    if not isinstance(kid, str) or not kid:
        return False
    if not isinstance(kty, str) or not kty:
        return False
    if kty != "RSA":
        return True
    return is_base64url(entry.get("n")) and is_base64url(entry.get("e"))


def assert_jwk_set(value: Any) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, dict) or "keys" not in value:
        raise KeySourceUnavailableError("JWKS is not a { keys: [...] } set of usable key entries")
    keys = value.get("keys")
    if not isinstance(keys, list) or not all(is_usable_key_entry(k) for k in keys):
        raise KeySourceUnavailableError("JWKS is not a { keys: [...] } set of usable key entries")
    return {"keys": [dict(k) for k in keys]}


def parse_rsa_key(jwk: dict[str, Any]) -> RSAPublicKey:
    try:
        key = RSAAlgorithm.from_jwk(jwk)
    except Exception as exc:
        raise KeySourceUnavailableError(f"Failed to parse RSA key: {exc}") from exc

    if not isinstance(key, RSAPublicKey):
        raise KeySourceUnavailableError("Signing key is not an RSA public key")

    if key.key_size < 2048:
        raise KeySourceUnavailableError(
            f"JWKS key is RSA {key.key_size}-bit; this SDK verifies RS256 at 2048 bits or larger"
        )
    return key


class KeySource:
    """Manages JWKS retrieval with caching, cooldown, and last-known-good fallback."""

    def __init__(
        self,
        url: str | None = None,
        jwks: dict[str, Any] | None = None,
        fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
        fetch_jwks_async: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    ) -> None:
        self.url = url
        self.supplied_jwks = jwks
        self.fetch_jwks = fetch_jwks
        self.fetch_jwks_async = fetch_jwks_async

        self.last_known_good: dict[str, list[dict[str, Any]]] | None = None
        self.last_fetch_time: float = 0.0
        self.last_cooldown_attempt: float = 0.0

    def _select_key(self, jwks: dict[str, Any], kid: str) -> RSAPublicKey:
        valid_set = assert_jwk_set(jwks)
        matching = [k for k in valid_set["keys"] if k.get("kid") == kid]
        if len(matching) > 1:
            raise KeySourceUnavailableError(
                "the JWKS published more than one usable key for the token's kid, "
                "so no single signing key can be selected"
            )
        if not matching:
            raise KeyNotFoundError(f"Key with kid {kid} not found")

        jwk = matching[0]
        if jwk.get("kty") != "RSA":
            raise KeySourceUnavailableError("Signing key algorithm must be RSA")
        return parse_rsa_key(jwk)

    def get_key(self, kid: str) -> RSAPublicKey:
        if self.supplied_jwks is not None:
            return self._select_key(self.supplied_jwks, kid)

        if not self.url:
            raise KeySourceUnavailableError("No URL or JWKS supplied")

        now = time.time()
        should_fetch = (
            self.last_known_good is None or (now - self.last_fetch_time) > CACHE_MAX_AGE_SECONDS
        )

        if not should_fetch and self.last_known_good is not None:
            try:
                return self._select_key(self.last_known_good, kid)
            except KeyNotFoundError:
                # Unknown kid: check cooldown before refetching
                if (now - self.last_cooldown_attempt) < COOLDOWN_DURATION_SECONDS:
                    raise
                should_fetch = True
                self.last_cooldown_attempt = now

        if should_fetch:
            try:
                if self.fetch_jwks:
                    raw = self.fetch_jwks(self.url)
                else:
                    with httpx.Client(timeout=5.0) as client:
                        resp = client.get(self.url)
                        if resp.status_code != 200:
                            raise KeySourceUnavailableError(
                                f"JWKS endpoint responded {resp.status_code} {resp.reason_phrase}"
                            )
                        raw = resp.json()

                checked = assert_jwk_set(raw)
                self.last_known_good = checked
                self.last_fetch_time = time.time()
                self.last_cooldown_attempt = self.last_fetch_time
            except KeySourceUnavailableError:
                if self.last_known_good:
                    try:
                        return self._select_key(self.last_known_good, kid)
                    except KeyNotFoundError:
                        pass
                raise
            except Exception as exc:
                if self.last_known_good:
                    try:
                        return self._select_key(self.last_known_good, kid)
                    except KeyNotFoundError:
                        pass
                raise KeySourceUnavailableError(
                    "the key set could not be obtained, and this SDK does not report the error that stopped it"
                ) from exc

        if self.last_known_good is not None:
            return self._select_key(self.last_known_good, kid)

        raise KeySourceUnavailableError(
            "the key set could not be obtained, and this SDK does not report the error that stopped it"
        )

    async def get_key_async(self, kid: str) -> RSAPublicKey:
        if self.supplied_jwks is not None:
            return self._select_key(self.supplied_jwks, kid)

        if not self.url:
            raise KeySourceUnavailableError("No URL or JWKS supplied")

        now = time.time()
        should_fetch = (
            self.last_known_good is None or (now - self.last_fetch_time) > CACHE_MAX_AGE_SECONDS
        )

        if not should_fetch and self.last_known_good is not None:
            try:
                return self._select_key(self.last_known_good, kid)
            except KeyNotFoundError:
                if (now - self.last_cooldown_attempt) < COOLDOWN_DURATION_SECONDS:
                    raise
                should_fetch = True
                self.last_cooldown_attempt = now

        if should_fetch:
            try:
                if self.fetch_jwks_async:
                    raw = await self.fetch_jwks_async(self.url)
                elif self.fetch_jwks:
                    raw = self.fetch_jwks(self.url)
                else:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.get(self.url)
                        if resp.status_code != 200:
                            raise KeySourceUnavailableError(
                                f"JWKS endpoint responded {resp.status_code} {resp.reason_phrase}"
                            )
                        raw = resp.json()

                checked = assert_jwk_set(raw)
                self.last_known_good = checked
                self.last_fetch_time = time.time()
                self.last_cooldown_attempt = self.last_fetch_time
            except KeySourceUnavailableError:
                if self.last_known_good:
                    try:
                        return self._select_key(self.last_known_good, kid)
                    except KeyNotFoundError:
                        pass
                raise
            except Exception as exc:
                if self.last_known_good:
                    try:
                        return self._select_key(self.last_known_good, kid)
                    except KeyNotFoundError:
                        pass
                raise KeySourceUnavailableError(
                    "the key set could not be obtained, and this SDK does not report the error that stopped it"
                ) from exc

        if self.last_known_good is not None:
            return self._select_key(self.last_known_good, kid)

        raise KeySourceUnavailableError(
            "the key set could not be obtained, and this SDK does not report the error that stopped it"
        )


class KeySourceCache:
    """In-process LRU cache for at most MAX_CACHED_KEY_SOURCES distinct key sources."""

    def __init__(self, max_size: int = MAX_CACHED_KEY_SOURCES) -> None:
        self.max_size = max_size
        self._cache: OrderedDict[Any, KeySource] = OrderedDict()

    def get_or_create(
        self,
        key: Any,
        create_fn: Callable[[], KeySource],
    ) -> KeySource:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]

        source = create_fn()
        self._cache[key] = source
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)
        return source


# Global process-wide LRU cache
_DEFAULT_KEY_CACHE = KeySourceCache()


def get_cached_key_source(
    *,
    url: str | None = None,
    jwks: dict[str, Any] | None = None,
    fetch_jwks: Callable[[str], dict[str, Any]] | None = None,
    fetch_jwks_async: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    cache: KeySourceCache | None = None,
) -> KeySource:
    target_cache = cache or _DEFAULT_KEY_CACHE

    if jwks is not None:
        cache_key: Any = id(jwks)
        return target_cache.get_or_create(
            cache_key,
            lambda: KeySource(jwks=jwks),
        )

    if not url:
        raise KeySourceUnavailableError("Neither URL nor JWKS supplied")

    url_cache_key: Any = (url, fetch_jwks, fetch_jwks_async)
    return target_cache.get_or_create(
        url_cache_key,
        lambda: KeySource(
            url=url,
            fetch_jwks=fetch_jwks,
            fetch_jwks_async=fetch_jwks_async,
        ),
    )
