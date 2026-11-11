# Common mistakes in secure file systems

Mistakes I kept running into while building this project — and what
each one would actually cost in a real system.

## 1. Checking the role once, at login, and never again

It is tempting to check "is this person a Doctor?" when they log in
and then trust them for the rest of the session. The problem: roles
change, sessions get hijacked, and a check done once is a check that
can go stale. This project checks the role on *every* operation —
read, write, execute, delete — because the question is never "who
logged in?", it is "who is doing *this* right now?"

## 2. Running everything as Admin while testing

When something does not work, the quick fix is to run it as Admin and
move on. Then the Admin path is the only path anyone ever tests, and
the Nurse and Guest paths break silently. The demo users in this
project exist for exactly this reason: test the weakest role first,
because that is the one that has to fail safely.

## 3. Trusting the file name instead of the file

A file called `report.pdf` is not necessarily a PDF, and a file in a
folder called `private` is not necessarily private. Access control
has to live in the system — the role, the permission bits, the audit
log — not in names and folders that anyone can change.

## 4. Hashing a file once and never checking it again

Computing a SHA-256 hash when a file is written is only half the job.
If nobody checks the hash when the file is read, tampering goes
unnoticed forever. This project checks the hash on every read, which
is the part that actually catches the problem.

## 5. Logging successes but not failures

A log full of "user read file X" is not very useful. The lines that
matter are the denied ones — who tried to open what they should not
have, and how many times. Three failed attempts in a row is the
pattern this project locks on, and it only works because the failures
are written down.

## 6. Treating the audit log as just another file

If anyone who can read the files can also edit the log, the log proves
nothing. In a real system the log goes somewhere the users cannot
reach — a separate service, append-only storage, or at least a file
with tighter permissions than the data it describes. This demo keeps
the log in a plain file so you can read it, but do not copy that part
into production.
