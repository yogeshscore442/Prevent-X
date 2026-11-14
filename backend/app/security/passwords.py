"""
PREVENT-X Password Security Module
Implements Argon2id modern password hashing and verification.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Configure enterprise Argon2id parameters
# Time cost (iterations): 3, Memory: 64MB (65536 KB), Parallelism: 4
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
)


def hash_password(password: str) -> str:
    """Hashes a plaintext password using Argon2id."""
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def check_needs_rehash(hashed_password: str) -> bool:
    """Checks whether the password hash needs upgrading based on hasher configuration."""
    try:
        return _hasher.check_needs_rehash(hashed_password)
    except Exception:
        return True
