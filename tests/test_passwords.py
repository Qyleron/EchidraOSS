import pytest

from classifier.passwords import hash_password, validate_password_format, verify_password


def test_hash_round_trips_and_is_salted():
    first = hash_password("Correct1horse")
    second = hash_password("Correct1horse")

    assert first.startswith("pbkdf2_sha256$")
    assert first != second  # different salt each time
    assert verify_password("Correct1horse", first)
    assert verify_password("Correct1horse", second)
    assert not verify_password("Wrong1horse", first)


@pytest.mark.parametrize("stored", ["", "not-a-hash", "md5$1$salt$digest", "pbkdf2_sha256$abc$salt$digest"])
def test_verify_rejects_malformed_hashes(stored):
    assert not verify_password("Correct1horse", stored)


@pytest.mark.parametrize(
    "password, message",
    [
        ("Short1", "at least 8 characters"),
        ("A1" * 65, "at most 128 characters"),
        ("Has space 1", "spaces"),
        ("12345678", "a letter"),
        ("NoDigitsHere", "a number"),
    ],
)
def test_validate_rejects_weak_passwords(password, message):
    with pytest.raises(ValueError, match=message):
        validate_password_format(password)


def test_validate_accepts_a_valid_password():
    validate_password_format("Correct1horse")
