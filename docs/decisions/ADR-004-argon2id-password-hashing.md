# ADR-004: Adoption of Argon2id for Password Hashing

## Status
Accepted

## Context
Legacy algorithms like MD5, SHA-1, and unsalted SHA-256 are completely unacceptable for an enterprise cybersecurity product. Even bcrypt and standard PBKDF2 have lower resistance to GPU and ASIC acceleration compared to memory-hard functions.

## Decision
We adopted **Argon2id** via `argon2-cffi`. Argon2id is the primary recommendation of OWASP and the winner of the Password Hashing Competition.

### Enforced Configuration:
- Type: `Type.ID`
- Memory: 64 MiB (65,536 KiB)
- Iterations (Time Cost): 3
- Parallelism: 4 threads
- Output length: 32 bytes

## Consequences
- **Positive**:
  - State-of-the-art protection against brute-force, dictionary, GPU, and ASIC cracking attacks.
  - Automatic salt generation and constant-time verification.
- **Negative**:
  - Slightly higher CPU and memory overhead during user authentication. Thoroughly offset by rate limiting and normal SMB concurrency profiles.
