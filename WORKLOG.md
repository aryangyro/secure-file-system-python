# Work log — Nov 8, 2026

## What I did today
- Built a secure file system simulator in Python: role-based access
  control (Admin > Doctor > Nurse > Guest), Unix-style file
  permissions (r/w/x with an owner per file), create/read/write/delete
  with permission checks, SHA-256 integrity hashes checked on every
  read, an audit log in a fixed format, and lockout after 3 failed
  logins.
- Wrote `secure_fs.py` (320 lines) with a demo mode that walks
  through allowed operations, denied operations, tampering, the audit
  log, lockout and an admin delete, plus an interactive mode.
- Wrote 26 automated tests in `test_fs.py`, covering registration,
  login, lockout, the happy path, denials, tamper detection and the
  audit log format.
- Wrote the research analysis that goes with the code: why RBAC over
  ABAC, why SHA-256, three vulnerabilities (insider threats, log
  tampering, privilege escalation), and suggested enhancements.

## Test results
- Demo (`python3 secure_fs.py`): exit 0. Allowed operations succeed
  (doctor creates/writes, nurse reads, admin deletes); denied
  operations fail with an alert and a DENIED log entry (nurse writing
  a doctor's file, guest reading); a tampered file is detected on
  read (hash mismatch); lockout after 3 wrong passwords, and the
  correct password is refused while locked.
- `test_fs.py`: 26 passed, 0 failed.
- Interactive mode: scripted session (admin login, list, quit) exit 0.

## Challenges
- Admin delete was first denied because delete was checked against
  the file's `x` permission. In Unix, deleting is about the
  directory, not executing the file, so delete now only needs
  owner-or-Admin.
- The script came out at 320 lines, slightly over the 250–300 aim,
  because there are six separate components (roles, permissions,
  operations, integrity, audit, lockout) plus demo and interactive
  modes; trimming further would have cut features or readability.
- One test failed at first, but it was a bug in the test itself
  ("password" is a substring of "password_hash"), not in the code.
