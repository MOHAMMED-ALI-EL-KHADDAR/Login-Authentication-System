# Login Authentication System

A production-style CLI authentication system built in Python, demonstrating
secure credential storage, rate-limited login, and session simulation.

## Setup

```bash
pip install -r requirements.txt
python main.py
```

Python 3.10+ required (uses `X | None` type hints and `list[str]`).
A SQLite file `auth_system.db` is created automatically in the project
folder on first run.

## Authentication Workflow

1. **Register**
   - Username validated against `^[A-Za-z0-9_]{3,20}$` and checked for
     uniqueness via a parameterized `SELECT`.
   - Password is entered twice with `getpass.getpass()` (no terminal echo)
     and compared with `hmac.compare_digest()` (constant-time) to avoid
     leaking match length through timing.
   - Password must pass the **quality gate** (see below) before the
     account is created.
   - The password is hashed with Argon2id and the hash — never the plain
     password — is stored.

2. **Login**
   - Username is looked up with a parameterized query.
   - If the account is currently locked out, login is rejected immediately
     with the remaining wait time.
   - If found, the submitted password is verified against the stored
     Argon2id hash with `PasswordHasher.verify()`.
   - **If the username doesn't exist**, the system still runs a dummy
     Argon2 verification against a pre-computed random hash before
     returning the same generic "Invalid username or password" message.
     This equalizes response time between "wrong password" and "no such
     user" so an attacker can't enumerate valid usernames by measuring
     response latency.
   - A failed attempt increments `failed_attempts`; on the
     `MAX_FAILED_ATTEMPTS`-th failure the account locks (see rate
     limiting below).
   - A successful login resets `failed_attempts`, clears any lock, and
     stamps `last_login`. If the stored hash was created with weaker
     Argon2 parameters than the app currently uses, it is transparently
     rehashed with `check_needs_rehash()`.

3. **Session dashboard (simulated)**
   - After login, the user sees a mock authenticated session with options
     to change their password (re-verifies the current password first) or
     log out. No real session tokens are issued — this is a local CLI
     demo, so "session" == staying inside the post-login menu loop.

## Database Schema (SQLite)

```sql
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,   -- full Argon2id encoded hash (algorithm,
                                     -- params, salt, and digest all embedded)
    created_at      TEXT NOT NULL,   -- ISO-8601 UTC timestamp
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,            -- ISO-8601 UTC timestamp, NULL if unlocked
    last_login      TEXT             -- ISO-8601 UTC timestamp, NULL until first login
);
```

No separate `salt` column exists because Argon2's encoded hash format
(`$argon2id$v=19$m=...,t=...,p=...$<salt>$<digest>`) already embeds a
unique, randomly generated 16-byte salt per user — that's the standard
way libraries like `argon2-cffi` and `bcrypt` handle salting, and it's
what `PasswordHasher.verify()` consumes directly.

## Security Mechanisms

### Password hashing — Argon2id
- Uses `argon2-cffi`'s `PasswordHasher`, configured with `time_cost=3`,
  `memory_cost=65536` (64 MB), `parallelism=4` — in line with OWASP's
  minimum-strength recommendations for Argon2id as of their Password
  Storage Cheat Sheet.
- Argon2id is memory-hard, which makes GPU/ASIC brute-forcing
  significantly more expensive than with bcrypt or PBKDF2.
- Every call to `ph.hash()` generates a fresh random salt internally —
  two users with the same password get completely different hashes.
- Plaintext passwords are never written to disk, logged, or stored in the
  database — only the resulting hash.

### Password quality gate
`check_password_strength()` enforces, before an account can be created or
a password changed:
- Minimum length (10 characters)
- At least one lowercase, one uppercase, one digit, one special character
- Rejects passwords on a local common-password list
- Rejects passwords containing the username
- Rejects 4+ repeated characters in a row (`aaaa`, `1111`)
- Rejects obvious sequential runs (`1234`, `abcd`)

This is a basic, self-contained implementation. In production you'd swap
the local `COMMON_PASSWORDS` set for a real breach corpus check (e.g. the
k-anonymity range API from Have I Been Pwned) rather than a hardcoded
list.

### Rate limiting & account lockout
- After `MAX_FAILED_ATTEMPTS` (5) consecutive failed logins, the account
  locks.
- Lockout duration grows exponentially with each additional failure past
  the threshold: `BASE_LOCKOUT_SECONDS * 2^(attempts - MAX_FAILED_ATTEMPTS)`,
  capped at `MAX_LOCKOUT_SECONDS` (15 minutes) — classic exponential
  backoff to blunt brute-force and credential-stuffing attempts.
- A successful login clears the counter and any active lock.

### SQL injection protection
- Every query in `main.py` uses `?` placeholders with parameters passed
  separately to `sqlite3` — usernames and passwords are never
  string-interpolated into SQL. This includes lookups, inserts, and
  updates.

### Timing-attack mitigation
- `hmac.compare_digest()` is used for the password-confirmation and
  password-match checks in the CLI (registration and password change)
  instead of `==`, which is not constant-time.
- Argon2's `verify()` itself is inherently resistant to timing attacks on
  the hash comparison.
- The dummy-hash verification described above equalizes timing between
  "user not found" and "user found, wrong password" so login responses
  don't leak which usernames are registered.

### Secure input handling
- All password entry uses `getpass.getpass()`, which suppresses terminal
  echo so passwords aren't visible or captured in shell scrollback.

## Files

| File               | Purpose                                   |
|--------------------|--------------------------------------------|
| `main.py`          | Complete CLI application                  |
| `requirements.txt` | `argon2-cffi`, `rich`                     |
| `README.md`        | This document                             |
| `auth_system.db`   | Created at runtime (not shipped)          |

## Known Limitations (by design, for a CLI demo)

- No real session tokens/expiry — the "dashboard" is just a menu loop
  after a successful `verify_login()` call.
- Common-password list is small and local rather than a live breach feed.
- No multi-factor authentication, password reset flow, or admin tooling.
- SQLite is unencrypted at rest; for stronger at-rest protection, pair
  with OS-level disk encryption or SQLCipher.
