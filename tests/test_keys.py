import pytest

from agentonboard.keys import (
    KeyNotFoundError,
    KeySource,
    KeySourceCache,
    KeySourceUnavailableError,
    assert_jwk_set,
)


def test_assert_jwk_set_validation():
    # Valid JWKS
    valid = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "k1",
                "n": "AQAB",
                "e": "AQAB",
            }
        ]
    }
    assert assert_jwk_set(valid) == valid

    # Missing keys field
    with pytest.raises(KeySourceUnavailableError):
        assert_jwk_set({"other": []})

    # Empty kid
    with pytest.raises(KeySourceUnavailableError):
        assert_jwk_set({"keys": [{"kty": "RSA", "kid": "", "n": "a", "e": "b"}]})

    # Invalid base64url characters in RSA n
    with pytest.raises(KeySourceUnavailableError):
        assert_jwk_set({"keys": [{"kty": "RSA", "kid": "k1", "n": "not+valid=b64url", "e": "AQAB"}]})


def test_lru_cache_bounded_to_max():
    cache = KeySourceCache(max_size=8)
    for i in range(12):
        cache.get_or_create(f"key_{i}", lambda: KeySource(jwks={"keys": []}))

    assert len(cache._cache) == 8
    # Keys 0-3 should have been evicted
    for i in range(4):
        assert f"key_{i}" not in cache._cache
    # Keys 4-11 should be present
    for i in range(4, 12):
        assert f"key_{i}" in cache._cache


def test_stale_key_fallback(fixture_data):
    active_jwks = fixture_data["keys"]["active"]["jwks"]

    call_count = 0

    def mock_fetch(url: str):
        nonlocal call_count
        call_count += 1
        if call_count > 1:
            raise ConnectionError("Endpoint down!")
        return active_jwks

    source = KeySource(url="https://agentonboard.test/.well-known/jwks.json", fetch_jwks=mock_fetch)

    # First fetch succeeds and populates last_known_good
    key1 = source.get_key("aon_fixture_v1")
    assert key1 is not None
    assert call_count == 1

    # Force expiration of cacheMaxAge
    source.last_fetch_time = 0.0

    # Second fetch raises ConnectionError, but fallback to last_known_good succeeds
    key2 = source.get_key("aon_fixture_v1")
    assert key2 is not None
    assert call_count == 2


def test_unknown_kid_cooldown():
    call_count = 0

    def mock_fetch(url: str):
        nonlocal call_count
        call_count += 1
        return {"keys": [{"kty": "RSA", "kid": "known_key", "n": "AQAB", "e": "AQAB"}]}

    source = KeySource(url="https://agentonboard.test/jwks.json", fetch_jwks=mock_fetch)
    # First fetch
    with pytest.raises(KeyNotFoundError):
        source.get_key("unknown_kid_1")
    assert call_count == 1

    # Immediate second call with unknown kid should be throttled by cooldown and not re-fetch
    with pytest.raises(KeyNotFoundError):
        source.get_key("unknown_kid_2")
    assert call_count == 1
