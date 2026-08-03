from app.admin_auth import hash_password, verify_password


def test_hash_password_produces_a_bcrypt_hash():
    password_hash = hash_password("correct-horse-battery-staple")
    assert password_hash.startswith("$2b$")
    assert password_hash != "correct-horse-battery-staple"


def test_verify_password_accepts_the_correct_password():
    password_hash = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", password_hash) is True


def test_verify_password_rejects_the_wrong_password():
    password_hash = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", password_hash) is False
