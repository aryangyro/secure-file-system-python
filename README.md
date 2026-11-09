# Secure File System in Python

A small, complete file system that shows how real systems protect
sensitive files. It answers one question: **who is allowed to do what,
to which file — and how do we know if something went wrong?**

It was built around a healthcare example — patient records that
doctors, nurses, administrators and guests all need to use
differently — but the ideas apply to any system that stores files
people should not all be able to see or change.

If you are new to this, start at the top and read down. Every idea is
explained in plain English before the code that uses it.

## What this project does

- **Role-based access control (RBAC):** four roles — Admin, Doctor,
  Nurse, Guest — arranged in a hierarchy. What you can do depends on
  who you are.
- **Unix-style file permissions:** every file has an owner and
  read/write/execute permissions, like `rw-`. Permissions are checked
  before every operation.
- **Secure file operations:** create, read, write and delete. Each one
  checks the role and the file permissions first, logs what happened,
  and raises an alert if someone tries something they are not allowed
  to do.
- **Integrity checking:** every file gets a SHA-256 hash when it is
  created or changed. The hash is checked every time the file is read,
  so tampering is caught.
- **Audit logging:** every action is written to `audit.log` with a
  timestamp, the user, the action, the file, and SUCCESS or FAILURE.
- **Lockout:** three wrong passwords in a row lock an account.

## The files

| File | What it is |
| --- | --- |
| `secure_fs.py` | The whole project, 320 lines. Roles, permissions, file operations, integrity, audit log, lockout, demo and interactive mode. |
| `test_fs.py` | 26 automated tests for the project. Run it with `python3 test_fs.py`. |
| `README.md` | This file. |
| `WORKLOG.md` | What was built on Nov 8, 2026, test results, and challenges. |
| `demo_fs/` | Created when you run the program. The simulated file system: `users.json`, `files.json`, `hashes.json`, `audit.log`, plus the files themselves. Ignored by git. |

## Quick start

You need Python 3. No libraries are required — password hashing uses
`bcrypt` when it is installed, and falls back to PBKDF2 from Python's
standard library when it is not.

Run the demo — it walks through the whole flow by itself:

```bash
python3 secure_fs.py
```

Or run it interactively, logging in and choosing operations yourself:

```bash
python3 secure_fs.py --interactive
```

Run the tests:

```bash
python3 test_fs.py
```

### Demo users

The demo creates four users, one per role. Their passwords are demo
values only — never use passwords like these for real:

| User | Role | Password |
| --- | --- | --- |
| admin1 | Admin | AdminPass1! |
| doctor1 | Doctor | DoctorPass1! |
| nurse1 | Nurse | NursePass1! |
| guest1 | Guest | GuestPass1! |

Passwords are stored only as hashes, never in plain text.

## Part 1: RBAC — who you are decides what you can do

**Role-based access control** means permissions belong to roles, not
to individual people. A person gets a role, and the role decides what
they may attempt. This is simpler and safer than giving every person
their own list of permissions: when someone changes job, you change
their role, and their permissions follow.

### The roles

The roles form a hierarchy — a senior role can do everything a junior
role can do, and more:

```
Admin  (rank 3) — create, read, write, delete
Doctor (rank 2) — create, read, write
Nurse  (rank 1) — create, read
Guest  (rank 0) — no file operations
```

A Guest can log in, but cannot open any file. A Nurse can read files
and create new ones, but cannot write to someone else's file or delete
anything. A Doctor can create, read and write. Only an Admin can
delete, and only the file's owner or an Admin may delete a particular
file.

### Why roles, and why a hierarchy?

Imagine a hospital with hundreds of staff. Giving each person
individual permissions means hundreds of lists to maintain, and every
mistake is a security hole. With roles, there are four lists. A new
nurse gets the Nurse role and instantly has exactly the right access —
no more, no less.

The hierarchy adds one more idea: seniority. A Doctor outranks a
Nurse, so a Doctor may write to a file a Nurse owns, but a Nurse may
not write to a file a Doctor owns. That matches how the real world
works — a senior clinician can correct a record, a junior member of
staff cannot overwrite a senior's work.

### Authentication first

Nobody does anything without logging in. Registration stores the
password as a salted hash (bcrypt when installed, PBKDF2-HMAC-SHA256
with 200,000 iterations as a fallback). The program never stores a
plain-text password, and never prints one.

## Part 2: Unix-style file permissions — r, w, x

Every file in the system stores two things besides its contents:

- **Owner** — the user who created it.
- **Permissions** — three letters, read, write, execute, like `rw-`.

`rw-` means: read yes, write yes, execute no. A file created by
doctor1 looks like this in the metadata:

```json
"patient.txt": {"owner": "doctor1", "perms": "rw-"}
```

This is the same idea Unix and Linux have used for decades, simplified
to one set of permissions per file instead of the usual three sets
(owner / group / others). The simplification keeps the project readable;
the principle is identical.

### Two checks, every time

Before any operation, the system runs **two** checks:

1. **Role check:** does this role allow this operation at all? A Guest
   may not read anything, a Nurse may not delete anything — no matter
   whose file it is.
2. **File permission check:** does this file's permission string allow
   this operation? And, for writing, is the user the owner, or a
   senior role?

Only if both pass does the operation run. If either fails, the system
prints `Access DENIED`, raises an alert, and writes a DENIED line to
the audit log.

One detail worth knowing: deleting a file does not check the file's
`x` (execute) permission. In Unix, deleting is about the directory
the file lives in, not about executing the file itself — so here,
delete only needs the user to be the owner or an Admin.

## Part 3: the four file operations

| Operation | What it does | Checks before running |
| --- | --- | --- |
| Create | Makes a new file with given contents and permissions (default `rw-`) | Role allows create |
| Read | Returns the file's contents | Role allows read, file perms allow `r`, integrity hash matches |
| Write | Replaces the file's contents | Role allows write, file perms allow `w`, user is owner or senior |
| Delete | Removes the file | User is owner or Admin |

Every operation follows the same pattern: **check, do, log** — and
**alert** if the check fails. The demo shows all four, including two
denied operations:

- nurse1 tries to write doctor1's `patient.txt` — denied, because a
  Nurse may not write a Doctor's file.
- guest1 tries to read `patient.txt` — denied, because a Guest may
  not read anything.

## Part 4: SHA-256 integrity — catching tampering

A permission system stops people doing things they should not do
*through* the system. It does not stop someone changing a file
directly on disk, outside the system. That is what integrity checking
is for.

### How it works

1. When a file is created or written, the program computes its
   **SHA-256 hash** — a 64-character fingerprint of its contents —
   and stores it in `hashes.json`.
2. Every time a file is read, the program recomputes the hash and
   compares it with the stored one.
3. If they match: `Integrity check: PASS - hash matches.` and the
   read goes ahead.
4. If they do not match: an alert is printed, a FAILURE line is
   written to the audit log, and the read is refused. The file may
   have been tampered with, and the system will not serve
   untrustworthy data.

The demo shows this: `patient.txt` is changed on disk outside the
system, and the next read fails the integrity check.

### Why SHA-256?

SHA-256 is a **cryptographic hash**: a one-way fingerprint. Change one
character in a file and the hash changes completely, so even a tiny
tamper is obvious. It is also **collision-resistant** — it is
practically impossible to find two different files with the same hash,
so an attacker cannot craft a fake file that matches the stored hash.
It is fast, standard, and built into Python's `hashlib`, which is why
it is used here instead of a weaker or slower alternative.

One honest limitation: the hashes are stored in a plain file,
`hashes.json`. If an attacker can change a file *and* update its
stored hash to match, the check would pass. A stronger design would
store the hashes with a secret key (an HMAC) or in a separate,
protected store — see the enhancements in the research summary below.

## Part 5: audit logging — a record of everything

Every action is written to `audit.log`, one line per action, in this
format:

```
[2026-04-08 10:15:32] User: nurse1 | Action: READ | File: patient.txt | Result: DENIED
```

Each line has a timestamp, the user, the action (LOGIN, CREATE, READ,
WRITE, DELETE, ALERT), the file name, and the result — SUCCESS,
FAILURE, or DENIED. Successes are logged as well as failures: a log
that only records failures cannot show what normal behaviour looks
like, and cannot prove who did what after the fact.

Audit logs matter for two reasons. First, **detection**: many DENIED
lines for one user is the signature of someone probing the system.
Second, **accountability**: after an incident, the log reconstructs
exactly what happened, when, and by whom. That is also why systems
like this one exist in healthcare — regulations like HIPAA require
that access to patient data can be audited.

## Part 6: unauthorized access detection and lockout

The system treats three things as security incidents:

- **Unauthorized file access** — a user trying an operation their
  role does not allow.
- **Permission violations** — a user trying an operation a file's
  permissions do not allow.
- **Integrity breaches** — a file whose hash does not match.

In every case the response is the same three steps: log the incident,
print an `ALERT:` message, and deny the operation.

There is one more defence, at the login stage: **lockout**. Three
wrong passwords in a row lock an account. While locked, even the
correct password is refused. The demo shows this with guest1 — three
wrong attempts, then the right password is still rejected.

Lockout has a trade-off worth knowing: an attacker who knows a
username can lock that person out on purpose. Real systems handle
that with unlock steps (a waiting time, an email reset, an admin
unlock). This project keeps the simple version — lock after 3 — so
the idea is easy to see.

## How to run the demo, step by step

Running `python3 secure_fs.py` does this, in order:

1. **Registers the four users** and prints the role permissions and
   the hierarchy (Admin 3, Doctor 2, Nurse 1, Guest 0).
2. **doctor1 creates `patient.txt`** with permissions `rw-`, then
   writes to it. Both succeed.
3. **nurse1 reads `patient.txt`** — allowed, and the integrity check
   passes.
4. **nurse1 tries to write to it** — denied, alert raised, DENIED
   logged.
5. **guest1 tries to read it** — denied, alert raised, DENIED logged.
6. **The file is tampered with on disk**, then doctor1 reads it —
   the hash does not match, the read is refused.
7. **The audit log is printed**, showing every action so far.
8. **guest1 enters three wrong passwords** — the account locks, and
   the correct password is then refused.
9. **admin1 deletes `patient.txt`** and lists the (now empty) files.

The demo ends by listing the files it created: `users.json`,
`files.json`, `hashes.json`, `audit.log`. Open them and look at what
is inside — that is the best way to understand the project.

Interactive mode is a conversation instead: it asks for a username
and password, then offers a menu — 1 create, 2 read, 3 write,
4 delete, 5 list, 6 quit.

## Tests

`test_fs.py` runs 26 checks and prints `PASS` or `FAIL` for each,
then a total. It covers:

- Registration (including duplicate and weak-password rejection) and
  login (correct works, wrong rejected, no plain-text password stored).
- Lockout after 3 failures, and a locked user cannot log in.
- The happy path: doctor creates, reads and writes a file; the hash
  is stored; the owner is recorded.
- Denials: nurse reads but cannot write or delete a doctor's file;
  nurse can create her own file; admin can delete it.
- Integrity: a tampered file is detected on read, and `verify()`
  returns False.
- Audit log: contains SUCCESS and DENIED lines, in the exact format
  shown above.

Result on Nov 8, 2026: **26 passed, 0 failed.**

```bash
python3 test_fs.py
```

## Research summary

A short version of the analysis that goes with this code.

### Why RBAC over ABAC?

**ABAC** (attribute-based access control) decides access from
attributes — time of day, department, device, location, and so on.
It is more flexible, but also more complex: every decision needs a
policy engine, and policies are hard to write, test and audit.

**RBAC** was chosen here because the problem is role-shaped: a
hospital has a small number of well-defined jobs, and what a person
may do follows directly from their job. Four roles, one hierarchy,
and the permissions are easy to read, easy to explain to an auditor,
and easy to get right. ABAC would be the better choice for a system
where access depends on many changing conditions — but for this one,
its extra complexity would add risk, not safety.

### Why SHA-256?

SHA-256 is fast, standard, and collision-resistant: changing one
byte changes the hash completely, and nobody can craft a different
file with the same hash. Weaker hashes (MD5, SHA-1) have known
collisions, so they are no longer trusted for integrity. Slower
hashes (bcrypt, Argon2) are right for passwords, where slowness is
a feature — but for files, which may be large and checked often,
SHA-256's speed is the point.

### Vulnerabilities

| Threat | What happens | Mitigation in this project |
| --- | --- | --- |
| Insider threats | A legitimate user abuses access they genuinely have — a nurse reading records she has no reason to read. | Roles limit what each person can do, and the audit log records every access, so abuse leaves a trail. But RBAC alone cannot tell a legitimate read from a nosy one. |
| Log tampering | An attacker who changes a file also edits `audit.log` to hide it. | The log exists and is complete — but it is a plain file, so it is not tamper-proof. See enhancements. |
| Privilege escalation | A user gains a higher role than they should have — for example, by exploiting a bug in registration or role assignment. | Roles are assigned at registration and checked on every operation; there is no operation in the system that changes a user's role. But the code that assigns roles must itself be protected. |

### Enhancements

- **Keyed hashes (HMAC):** store file hashes signed with a secret
  key, so an attacker who changes a file cannot also fix its hash.
- **Protected audit log:** write the log to append-only storage, or
  sign each line, so tampering with the log is detectable.
- **Narrower access:** add per-file access lists on top of roles,
  so a nurse only sees the patients on her ward.
- **Second factor for admins:** require an extra check before
  admin operations like delete.
- **Unlock flow:** add a waiting time or admin unlock for locked
  accounts, so lockout cannot be used to deny service.
- **Attack testing:** test the system against deliberate attacks,
  not just correct use — fuzzing inputs, trying to escalate roles,
  and attempting to bypass the permission checks.

## Glossary

| Term | Meaning |
| --- | --- |
| RBAC | Role-based access control — permissions belong to roles, people get roles. |
| ABAC | Attribute-based access control — permissions decided from attributes like time, department or device. |
| Hierarchy | Roles ranked by seniority; a senior role can do what junior roles can do, and more. |
| Unix-style permissions | Read (r), write (w), execute (x) flags stored with each file, with an owner. |
| SHA-256 | A cryptographic hash function producing a 64-character fingerprint of data. |
| Integrity check | Recomputing a file's hash and comparing it with the stored hash, to detect tampering. |
| Hash | A one-way fingerprint of data. You can check data against it, but you cannot reverse it. |
| HMAC | A hash signed with a secret key, so only someone with the key can produce a valid hash. |
| Audit log | A record of every action, with who, what, when and the result. |
| Lockout | Blocking an account after too many failed login attempts. |
| Insider threat | Harm done by someone who already has legitimate access. |
| Privilege escalation | Gaining more access than you are supposed to have. |
| HIPAA | US healthcare privacy law — used here as an example of why access to patient data must be auditable. |

## Limitations

- The demo passwords are written in the code — fine for learning,
  unsafe for production. Use properly chosen passwords, stored
  outside the code.
- The hashes and the audit log are plain files. A stronger design
  would protect them with a secret key or separate storage.
- Permissions are one set per file, not the full Unix owner/group/
  others model. That keeps the code readable; the principle is the
  same.
- A locked account has no unlock flow here — you would add a reset
  or a waiting period in a real system.
- `demo_fs/` is a folder on disk, not a real file system. It
  simulates one; it does not handle many users at once or
  concurrent writes.


## Try it yourself

- Log in as nurse1 and try to write to a file owned by doctor1. You should get an access denied alert, and a DENIED line in `audit.log`.
- Change a file directly on disk, outside the program, then read it through the program. The integrity check should fail.
- Enter the wrong password three times for guest1, then try the correct password. The account should stay locked.
