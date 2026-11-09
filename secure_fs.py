#!/usr/bin/env python3
"""Secure file system simulator: RBAC, Unix-style file
permissions, SHA-256 integrity checks and audit logging.
Run: python3 secure_fs.py (demo) or --interactive.
Passwords are hashed, never stored in plain text."""
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# --- Roles: higher rank = more senior. Admin > Doctor > Nurse > Guest.
ROLES = {"Admin": 3, "Doctor": 2, "Nurse": 1, "Guest": 0}
ROLE_PERMS = {  # which file operations each role may attempt at all
    "Admin": {"create", "read", "write", "delete"},
    "Doctor": {"create", "read", "write"},
    "Nurse": {"create", "read"},
    "Guest": set(),
}
MAX_FAILED = 3  # lock a user after 3 failed logins
USERS = [("admin1", "AdminPass1!", "Admin"), ("doctor1", "DoctorPass1!", "Doctor"),
         ("nurse1", "NursePass1!", "Nurse"), ("guest1", "GuestPass1!", "Guest")]

def hash_password(password):
    """Salted hash: bcrypt if installed, else PBKDF2 fallback."""
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except ImportError:
        s = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), s, 200_000)
        return f"pbkdf2_sha256$200000${s.hex()}${dk.hex()}"

def check_password(password, stored):
    """Check a password against its stored hash."""
    try:
        if stored.startswith(("$2b$", "$2a$")):
            import bcrypt
            return bcrypt.checkpw(password.encode(), stored.encode())
        _, it, salt, exp = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt), int(it))
        return hmac.compare_digest(dk, bytes.fromhex(exp))
    except Exception:
        return False

def sha256_file(path):
    """SHA-256 hash of a file's contents."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

class SecureFS:
    """One secure file system: users, files, hashes and audit log."""

    def __init__(self, base="demo_fs"):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self.users_file = self.base / "users.json"
        self.hash_file = self.base / "hashes.json"
        self.meta_file = self.base / "files.json"
        self.audit_file = self.base / "audit.log"
        self.users = self._load(self.users_file, {})
        self.hashes = self._load(self.hash_file, {})
        self.files = self._load(self.meta_file, {})  # name -> owner, perms
        self.current = None  # logged-in username

    @staticmethod
    def _load(path, default):
        return json.loads(Path(path).read_text()) if Path(path).exists() else default

    def save_all(self):
        for path, data in [(self.users_file, self.users),
                           (self.hash_file, self.hashes),
                           (self.meta_file, self.files)]:
            Path(path).write_text(json.dumps(data, indent=2))

    # --- Audit logging and alerts ---
    def audit(self, user, action, name, result):
        """One audit line, in the project's format."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] User: {user} | Action: {action} | File: {name} | Result: {result}"
        with open(self.audit_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def alert(self, msg):
        print(f"ALERT: {msg}")
        self.audit(self.current or "system", "ALERT", "-", "FAILURE")

    # --- Users and authentication ---
    def register(self, username, password, role):
        if username in self.users:
            print(f"Register: {username} already exists.")
            return False
        if role not in ROLES or len(password) < 8:
            print("Register: bad role, or password under 8 characters.")
            return False
        self.users[username] = {"password_hash": hash_password(password),
                                "role": role, "failed": 0, "locked": False}
        self.save_all()
        print(f"Register: {username} created as {role}.")
        return True

    def login(self, username, password):
        user = self.users.get(username)
        if not user:
            print(f"Login: unknown user {username}.")
            return False
        if user["locked"]:
            print(f"Login: {username} is LOCKED after {MAX_FAILED} failed attempts.")
            self.audit(username, "LOGIN", "-", "DENIED")
            return False
        if check_password(password, user["password_hash"]):
            user["failed"] = 0
            self.current = username
            self.save_all()
            self.audit(username, "LOGIN", "-", "SUCCESS")
            print(f"Login: {username} ({user['role']}) logged in.")
            return True
        user["failed"] += 1
        self.audit(username, "LOGIN", "-", "FAILURE")
        self.save_all()
        if user["failed"] >= MAX_FAILED:
            user["locked"] = True
            self.save_all()
            self.alert(f"{username} locked after {MAX_FAILED} failed login attempts.")
        else:
            print(f"Login: wrong password ({user['failed']}/{MAX_FAILED}).")
        return False

    def role(self, username=None):
        return self.users[(username or self.current)]["role"]

    # --- Permission checks (RBAC + file permissions) ---
    def _allowed(self, operation, name):
        """True only if role allows the op AND file perms allow it."""
        user, role = self.current, self.role()
        if operation not in ROLE_PERMS[role]:
            return False, f"role {role} may not {operation} files"
        if operation == "create":
            return True, ""
        meta = self.files.get(name)
        if not meta:
            return False, f"file {name} does not exist"
        if operation == "delete":
            if user != meta["owner"] and role != "Admin":
                return False, "only the owner or Admin may delete a file"
            return True, ""
        letter = {"read": "r", "write": "w"}[operation]
        if operation == "write" and user != meta["owner"] \
                and ROLES[role] <= ROLES[self.role(meta["owner"])]:
            return False, "only the owner or a senior role may write"
        if letter not in meta["perms"]:
            return False, f"file permissions {meta['perms']} deny {operation}"
        return True, ""

    def _deny(self, operation, name, reason):
        self.alert(f"unauthorized {operation} on {name} by {self.current}: {reason}")
        self.audit(self.current, operation.upper(), name, "DENIED")
        print(f"Access DENIED: {reason}.")
        return False

    # --- Secure file operations ---
    def create(self, name, content, perms="rw-"):
        ok, reason = self._allowed("create", name)
        if not ok:
            return self._deny("create", name, reason)
        if name in self.files:
            print(f"Create: {name} already exists.")
            return False
        (self.base / name).write_text(content, encoding="utf-8")
        self.files[name] = {"owner": self.current, "perms": perms}
        self.hashes[name] = sha256_file(self.base / name)
        self.save_all()
        self.audit(self.current, "CREATE", name, "SUCCESS")
        print(f"Create: {name} owned by {self.current}, perms {perms}.")
        return True

    def read(self, name):
        ok, reason = self._allowed("read", name)
        if not ok:
            return self._deny("read", name, reason)
        if not self.verify(name):  # integrity check on every read
            return None
        text = (self.base / name).read_text(encoding="utf-8")
        self.audit(self.current, "READ", name, "SUCCESS")
        print(f"Read: {name} -> {text!r}")
        return text

    def write(self, name, content):
        ok, reason = self._allowed("write", name)
        if not ok:
            return self._deny("write", name, reason)
        (self.base / name).write_text(content, encoding="utf-8")
        self.hashes[name] = sha256_file(self.base / name)  # new hash
        self.save_all()
        self.audit(self.current, "WRITE", name, "SUCCESS")
        print(f"Write: {name} updated, new SHA-256 hash stored.")
        return True

    def delete(self, name):
        ok, reason = self._allowed("delete", name)
        if not ok:
            return self._deny("delete", name, reason)
        (self.base / name).unlink()
        self.files.pop(name, None)
        self.hashes.pop(name, None)
        self.save_all()
        self.audit(self.current, "DELETE", name, "SUCCESS")
        print(f"Delete: {name} removed.")
        return True

    # --- Integrity verification ---
    def verify(self, name):
        """Compare the file's current hash with the stored hash."""
        if sha256_file(self.base / name) != self.hashes.get(name):
            self.alert(f"integrity breach on {name}: HASH mismatch, file may have been tampered with.")
            self.audit(self.current, "READ", name, "FAILURE")
            print("Integrity check: FAIL - hash does not match.")
            return False
        print("Integrity check: PASS - hash matches.")
        return True

    def list_files(self):
        print("Files:")
        for n, m in self.files.items():
            print(f"  {n} -> Owner: {m['owner']}, Permissions: {m['perms']}")

def header(title):
    print("=" * 68 + "\n" + title + "\n" + "=" * 68)

def demo():
    """End-to-end demo: allowed and denied operations, tampering, lockout."""
    import shutil
    if Path("demo_fs").exists():
        shutil.rmtree("demo_fs")
    fs = SecureFS("demo_fs")

    header("4.1 RBAC - roles and hierarchy (Admin > Doctor > Nurse > Guest)")
    for user, pw, role in USERS:
        fs.register(user, pw, role)
    print("Role permissions (rank: Admin 3, Doctor 2, Nurse 1, Guest 0):")
    for role in ["Admin", "Doctor", "Nurse", "Guest"]:
        print(f"  {role}: {sorted(ROLE_PERMS[role]) or 'no file operations'}")
    print("Passwords stored as hashes only, never in plain text.")

    header("4.2/4.3 Create + Write - doctor1 creates patient.txt (rw-)")
    fs.login("doctor1", "DoctorPass1!")
    fs.create("patient.txt", "Patient: A. Smith, BP 120/80.", "rw-")
    fs.write("patient.txt", "Patient: A. Smith, BP 120/80, HR 72.")
    fs.list_files()

    header("4.3 Read - nurse1 reads patient.txt (allowed)")
    fs.login("nurse1", "NursePass1!")
    fs.read("patient.txt")

    header("4.2/4.6 Deny - nurse1 tries to write doctor1's file")
    fs.write("patient.txt", "Nurse edit attempt.")

    header("4.2/4.6 Deny - guest1 tries to read patient.txt")
    fs.login("guest1", "GuestPass1!")
    fs.read("patient.txt")

    header("4.4 Integrity - tamper with patient.txt, then read it")
    fs.login("doctor1", "DoctorPass1!")
    (Path("demo_fs") / "patient.txt").write_text("TAMPERED DATA.")
    print("File changed on disk outside the system.")
    fs.read("patient.txt")

    header("4.5 Audit log - every operation is logged")
    print(Path("demo_fs/audit.log").read_text())

    header("4.6 Lockout - 3 wrong passwords lock guest1")
    for _ in range(3):
        fs.login("guest1", "WrongPass1!")
    fs.login("guest1", "GuestPass1!")

    header("4.3 Delete - admin1 deletes patient.txt")
    fs.login("admin1", "AdminPass1!")
    fs.delete("patient.txt")
    fs.list_files()
    print("Demo done. Files: users.json, files.json, hashes.json, audit.log")
    return 0

def interactive():
    """Interactive mode: log in, then choose operations from a menu."""
    fs = SecureFS("demo_fs")
    if not fs.users:
        for u, pw, r in USERS:
            fs.register(u, pw, r)
    print("Secure File System - log in to continue.")
    for _ in range(3):
        if fs.login(input("Username: ").strip(), input("Password: ").strip()):
            break
    else:
        print("Too many failed logins.")
        return 1
    while True:
        print("\n1 create  2 read  3 write  4 delete  5 list  6 quit")
        c = input("Choose: ").strip()
        name = input("File name: ").strip() if c in "1234" else ""
        if c == "1":
            fs.create(name, input("Content: "), "rw-")
        elif c == "2":
            fs.read(name)
        elif c == "3":
            fs.write(name, input("New content: "))
        elif c == "4":
            fs.delete(name)
        elif c == "5":
            fs.list_files()
        elif c == "6":
            print("Goodbye.")
            return 0
        else:
            print("Unknown choice.")


if __name__ == "__main__":
    raise SystemExit(interactive() if "--interactive" in sys.argv else demo())
