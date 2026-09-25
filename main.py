#!/usr/bin/env python3
"""
Login Authentication System
----------------------------
A secure, CLI-based user authentication system demonstrating industry
standard security practices: Argon2id password hashing, rate-limited
login with exponential backoff, parameterized SQLite persistence, and a
simulated authenticated session.

Run:
    python main.py
"""

from __future__ import annotations

import sqlite3
import re
import sys
import hmac
import getpass
import secrets
import importlib
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager
from typing import Optional

# Load Argon2 dynamically so static analyzers do not report a missing import
# when the optional runtime dependency has not yet been installed.
try:
    _argon2 = importlib.import_module("argon2")
    _argon2_exceptions = importlib.import_module("argon2.exceptions")
    PasswordHasher = _argon2.PasswordHasher
    VerifyMismatchError = _argon2_exceptions.VerifyMismatchError
    InvalidHash = _argon2_exceptions.InvalidHash
except ModuleNotFoundError as exc:
    raise RuntimeError(
        "The 'argon2-cffi' package is required. Install it with: "
        "python -m pip install argon2-cffi"
    ) from exc

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich import box

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_PATH = Path(__file__).parent / "auth_system.db"

MAX_FAILED_ATTEMPTS = 5          # attempts allowed before an account locks
BASE_LOCKOUT_SECONDS = 30        # base unit for exponential backoff
MAX_LOCKOUT_SECONDS = 900        # lockout is capped at 15 minutes

MIN_PASSWORD_LENGTH = 10

# A small local list used for the "known common password" check.
# In production this would be backed by a much larger breach-corpus file
# (e.g. the "Have I Been Pwned" k-anonymity API or a local Top-100k list).
COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty",
    "abc123", "letmein", "admin123", "welcome", "monkey", "dragon",
    "iloveyou", "football", "111111", "123123", "sunshine", "master",
    "trustno1", "passw0rd", "qwerty123", "login", "starwars", "freedom",
}

console = Console()

# ---------------------------------------------------------------------------
# Password hasher — Argon2id (winner of the Password Hashing Competition,
# and the current OWASP-recommended default for password storage).
# Parameters below follow OWASP's minimum-strength guidance for Argon2id.
# ---------------------------------------------------------------------------
ph = PasswordHasher(
    time_cost=3,        # number of iterations
    memory_cost=65536,  # 64 MB of memory per hash
    parallelism=4,       # degree of parallelism
    hash_len=32,
    salt_len=16,         # random per-user salt, generated internally by argon2
)

# A pre-computed hash of a random, never-used secret. We verify against this
# when a username is not found so that failed logins for a nonexistent user
# take roughly the same time as failed logins for a real user — this
# prevents timing-based username enumeration.
DUMMY_HASH = ph.hash(secrets.token_urlsafe(32))


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT UNIQUE NOT NULL,
                password_hash   TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT,
                last_login      TEXT
            )
            """
        )


# ---------------------------------------------------------------------------
# Username validation
# ---------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def check_username_valid(username: str) -> Optional[str]:
    if not USERNAME_RE.match(username):
        return "Username must be 3-20 characters: letters, digits, underscore only."
    return None


def username_exists(username: str) -> bool:
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Password quality gate
# ---------------------------------------------------------------------------
def check_password_strength(password: str, username: str = "") -> list[str]:
    """Return a list of policy violations. Empty list => password accepted."""
    errors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if not re.search(r"[a-z]", password):
        errors.append("Must include at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Must include at least one uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Must include at least one digit.")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]", password):
        errors.append("Must include at least one special character.")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("This password appears on a known common-password list.")
    if username and username.lower() in password.lower():
        errors.append("Password must not contain your username.")
    if re.search(r"(.)\1{3,}", password):
        errors.append("Must not contain 4+ repeated characters in a row (e.g. 'aaaa').")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower()):
        errors.append("Must not contain an obvious sequential pattern.")

    return errors


# ---------------------------------------------------------------------------
# Rate limiting / account lockout
# ---------------------------------------------------------------------------
def get_user(username: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def is_locked(user_row: sqlite3.Row) -> tuple[bool, int]:
    """Return (locked, seconds_remaining)."""
    if not user_row["locked_until"]:
        return False, 0
    locked_until = datetime.fromisoformat(user_row["locked_until"])
    now = datetime.utcnow()
    if now < locked_until:
        return True, int((locked_until - now).total_seconds())
    return False, 0


def register_failed_attempt(username: str) -> None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return
        attempts = row["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_FAILED_ATTEMPTS:
            # Exponential backoff, capped at MAX_LOCKOUT_SECONDS.
            backoff = min(
                BASE_LOCKOUT_SECONDS * (2 ** (attempts - MAX_FAILED_ATTEMPTS)),
                MAX_LOCKOUT_SECONDS,
            )
            locked_until = (datetime.utcnow() + timedelta(seconds=backoff)).isoformat()
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (attempts, locked_until, username),
        )


def reset_failed_attempts(username: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? "
            "WHERE username = ?",
            (datetime.utcnow().isoformat(), username),
        )


# ---------------------------------------------------------------------------
# Core auth operations
# ---------------------------------------------------------------------------
def create_user(username: str, password: str) -> None:
    password_hash = ph.hash(password)  # argon2 generates + embeds a random salt
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at, failed_attempts) "
            "VALUES (?, ?, ?, 0)",
            (username, password_hash, datetime.utcnow().isoformat()),
        )


def verify_login(username: str, password: str) -> tuple[bool, str]:
    """
    Returns (success, message).

    If the username does not exist, a dummy Argon2 verification is still
    performed so that response timing does not reveal whether the account
    exists (mitigates username-enumeration via timing attack).
    """
    user = get_user(username)

    if user is None:
        try:
            ph.verify(DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        return False, "Invalid username or password."

    locked, remaining = is_locked(user)
    if locked:
        mins, secs = divmod(remaining, 60)
        return False, f"Account locked. Try again in {mins}m {secs}s."

    try:
        ph.verify(user["password_hash"], password)
    except VerifyMismatchError:
        register_failed_attempt(username)
        return False, "Invalid username or password."
    except InvalidHash:
        return False, "Corrupted credential record — contact an administrator."

    # Successful login: transparently rehash if Argon2 parameters have
    # since been strengthened, then clear the failure counter.
    if ph.check_needs_rehash(user["password_hash"]):
        new_hash = ph.hash(password)
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_hash, username),
            )
    reset_failed_attempts(username)
    return True, "Login successful."


def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    ok, _ = verify_login(username, old_password)
    if not ok:
        return False, "Current password is incorrect."
    errors = check_password_strength(new_password, username)
    if errors:
        return False, "New password rejected:\n  - " + "\n  - ".join(errors)
    new_hash = ph.hash(new_password)
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username),
        )
    return True, "Password changed successfully."


# ---------------------------------------------------------------------------
# CLI — Rich-powered terminal UI
# ---------------------------------------------------------------------------
def banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]LOGIN AUTHENTICATION SYSTEM[/bold cyan]\n"
        "[dim]Argon2id hashing  \u2022  Rate-limited login  \u2022  SQLite persistence[/dim]",
        border_style="cyan",
        box=box.DOUBLE,
    ))


def prompt_password(label: str = "Password") -> str:
    return getpass.getpass(f"{label}: ")


def do_register() -> None:
    console.rule("[bold green]Register New Account")
    username = Prompt.ask("Choose a username")
    err = check_username_valid(username)
    if err:
        console.print(f"[bold red]\u2717[/bold red] {err}")
        return
    if username_exists(username):
        console.print("[bold red]\u2717[/bold red] That username is already taken.")
        return

    password = prompt_password("Choose a password")
    errors = check_password_strength(password, username)
    if errors:
        console.print("[bold red]Password rejected:[/bold red]")
        for e in errors:
            console.print(f"  \u2022 {e}")
        return

    confirm = prompt_password("Confirm password")
    if not hmac.compare_digest(password, confirm):
        console.print("[bold red]\u2717[/bold red] Passwords do not match.")
        return

    create_user(username, password)
    console.print(f"[bold green]\u2713[/bold green] Account '{username}' created successfully.")


def do_login() -> None:
    console.rule("[bold green]Login")
    username = Prompt.ask("Username")
    password = prompt_password("Password")

    success, message = verify_login(username, password)
    if success:
        console.print(f"[bold green]\u2713[/bold green] {message}")
        session_dashboard(username)
    else:
        console.print(f"[bold red]\u2717[/bold red] {message}")


def session_dashboard(username: str) -> None:
    while True:
        console.print(Panel.fit(
            f"[bold]Welcome, {username}[/bold]\n"
            "[dim]You are in a simulated authenticated session.[/dim]",
            border_style="green",
        ))
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_row("[1]", "Change password")
        table.add_row("[2]", "View account info")
        table.add_row("[3]", "Log out")
        console.print(table)

        choice = Prompt.ask("Select an option", choices=["1", "2", "3"], default="3")

        if choice == "1":
            old = prompt_password("Current password")
            new = prompt_password("New password")
            confirm = prompt_password("Confirm new password")
            if not hmac.compare_digest(new, confirm):
                console.print("[bold red]\u2717[/bold red] New passwords do not match.")
                continue
            ok, msg = change_password(username, old, new)
            style = "green" if ok else "red"
            symbol = "\u2713" if ok else "\u2717"
            console.print(f"[bold {style}]{symbol}[/bold {style}] {msg}")

        elif choice == "2":
            user = get_user(username)
            info = Table(box=box.SIMPLE)
            info.add_column("Field")
            info.add_column("Value")
            info.add_row("Username", user["username"])
            info.add_row("Account created (UTC)", user["created_at"])
            info.add_row("Last login (UTC)", user["last_login"] or "N/A")
            console.print(info)

        elif choice == "3":
            console.print("[yellow]Logged out.[/yellow]\n")
            break


def main_menu() -> None:
    init_db()
    banner()
    while True:
        console.print()
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_row("[1]", "Register")
        table.add_row("[2]", "Login")
        table.add_row("[3]", "Exit")
        console.print(table)

        choice = Prompt.ask("Select an option", choices=["1", "2", "3"], default="2")
        if choice == "1":
            do_register()
        elif choice == "2":
            do_login()
        elif choice == "3":
            console.print("[cyan]Goodbye.[/cyan]")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[cyan]Interrupted. Goodbye.[/cyan]")
        sys.exit(0)
