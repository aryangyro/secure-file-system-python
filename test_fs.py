#!/usr/bin/env python3
"""Small checks for secure_fs.py. Run: python3 test_fs.py"""
import shutil
from pathlib import Path

from secure_fs import SecureFS

passed = failed = 0


def check(name, ok):
    global passed, failed
    print(("PASS" if ok else "FAIL"), "-", name)
    if ok:
        passed += 1
    else:
        failed += 1


if Path("test_fs").exists():
    shutil.rmtree("test_fs")
fs = SecureFS("test_fs")

# Registration and login
check("register admin", fs.register("admin1", "AdminPass1!", "Admin"))
check("register doctor", fs.register("doctor1", "DoctorPass1!", "Doctor"))
check("register nurse", fs.register("nurse1", "NursePass1!", "Nurse"))
check("register guest", fs.register("guest1", "GuestPass1!", "Guest"))
check("duplicate register rejected", not fs.register("admin1", "AdminPass1!", "Admin"))
check("weak password rejected", not fs.register("x1", "short", "Nurse"))
check("no plain-text password stored",
      "password" not in fs.users["admin1"]
      and "AdminPass1!" not in str(fs.users["admin1"]))
check("correct login works", fs.login("doctor1", "DoctorPass1!"))
check("wrong password rejected", not fs.login("doctor1", "WrongPass1!"))

# Lockout after 3 failed attempts
fs.login("guest1", "WrongPass1!")
fs.login("guest1", "WrongPass1!")
fs.login("guest1", "WrongPass1!")
check("locked after 3 failures", fs.users["guest1"]["locked"])
check("locked user cannot log in", not fs.login("guest1", "GuestPass1!"))

# File operations: happy path
fs.login("doctor1", "DoctorPass1!")
check("doctor creates file", fs.create("patient.txt", "BP 120/80.", "rw-"))
check("hash stored on create", "patient.txt" in fs.hashes)
check("owner recorded", fs.files["patient.txt"]["owner"] == "doctor1")
check("doctor reads own file", fs.read("patient.txt") == "BP 120/80.")
check("doctor writes own file", fs.write("patient.txt", "BP 120/80, HR 72."))
check("read back new content", fs.read("patient.txt") == "BP 120/80, HR 72.")

# RBAC / permission denials
fs.login("nurse1", "NursePass1!")
check("nurse reads doctor's file", fs.read("patient.txt") is not None)
check("nurse cannot write doctor's file",
      not fs.write("patient.txt", "nurse edit"))
check("nurse cannot delete", not fs.delete("patient.txt"))
check("nurse can create own file", fs.create("notes.txt", "shift notes", "rw-"))
check("admin can delete", fs.login("admin1", "AdminPass1!")
      and fs.delete("notes.txt"))

# Integrity: tamper, then read must fail
fs.login("doctor1", "DoctorPass1!")
(Path("test_fs") / "patient.txt").write_text("TAMPERED.")
check("tampered file detected on read", fs.read("patient.txt") is None)
check("hash mismatch caught", not fs.verify("patient.txt"))

# Audit log format
log = Path("test_fs/audit.log").read_text()
check("audit log has SUCCESS and DENIED",
      "SUCCESS" in log and "DENIED" in log)
check("audit line format",
      "User: nurse1 | Action: READ | File: patient.txt | Result: SUCCESS" in log)

print(f"\n{passed} passed, {failed} failed.")
raise SystemExit(1 if failed else 0)
