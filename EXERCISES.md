# Exercises: Secure File System

These exercises use the code in `secure_fs.py` and a throwaway copy of
the demo data, so a mistake costs nothing. Run the demo first
(`python3 secure_fs.py`) so you know what normal looks like, then try
to break it.

## 1. Be the guest who tries everything

Log in as `guest1` (password `GuestPass1!`) in interactive mode and try
every operation: create a file, read one, write to one, delete one.
Write down which ones fail and what the error message says.

Then check `demo_fs/audit.log`. How many FAILURE lines did your
attempts create? Is there enough information in each line to work out
who tried what, and when?

**What to notice:** a system that silently refuses is harder to
investigate than one that logs the refusal. The audit log is what turns
"someone tried something" into evidence.

## 2. Tamper with a file and watch the hash catch it

Run the demo, then open one of the files in `demo_fs/` with a text
editor and change a single character — do not use the program to do it,
edit the file directly, the way an attacker with disk access would.

Now run the demo again, or log in and try to read that file. What
happens? What does the audit log say?

**What to notice:** the file looks fine when you open it in the editor.
Only the hash check reveals that it changed. Integrity checking only
works if it runs on every read, not just once at startup.

## 3. Break the lockout, then think about who it hurts

Try logging in as `doctor1` with the wrong password three times in a
row. What happens on the fourth try, even with the right password?

Now think about it from the other side: if you were an attacker, how
would you use this lockout against a real doctor? (Hint: you do not
need their password to lock them out.) Write down one change that keeps
the protection against guessing but makes the denial-of-service harder
— for example, a delay that grows with each failure instead of a hard
lock, or a lockout that only applies to one IP address.

**What to notice:** every security control has a cost, and lockout is a
good example. It stops guessing, but it hands an attacker a way to lock
real users out. A control is only good if you have thought about both
sides of it.

## 4. Add a fifth role

The system has four roles: Admin, Doctor, Nurse, Guest. Add a fifth —
`Auditor` — who can read files and read the audit log, but cannot
create, write or delete anything. You will need to:

1. Add the role to the hierarchy in `secure_fs.py`, between Nurse and
   Doctor or wherever you think it belongs — and be ready to defend
   the rank you chose.
2. Add an auditor demo user.
3. Make sure the auditor cannot write, even to a file they own.

Run `python3 test_fs.py` after your change. Do the existing tests still
pass? If one breaks, work out whether the test was wrong or your change
was.

**What to notice:** adding a role should be a small, boring change. If
you find yourself editing permission checks in five different places,
the design is wrong — permissions should come from the role, in one
place, not be scattered through the code.

## 5. The missing audit entry

Go through `secure_fs.py` and list every operation that changes
something: create, write, delete, password change, lockout. For each
one, check whether it writes to the audit log.

Now find one thing the system does that is *not* logged, and decide
whether it should be. A good candidate: a successful login. If nobody
logs successful logins, how would you ever notice that a stolen
password was used at 3 a.m.?

Add the missing log entry, run the tests, and write one sentence in
`WORKLOG.md` about why you added it.

**What to notice:** logs are only useful if they record the events you
will actually need during an investigation. "Log everything" sounds
safe, but a log full of noise hides the signal — the skill is choosing
which events matter.

## 6. Permissions vs roles: which one stopped you?

Pick a file in the demo, and try to write to it as `nurse1`. It should
fail. Now answer, without guessing: did it fail because of the nurse's
*role*, or because of the file's *Unix permissions*?

Change one thing at a time to find out: first give the nurse a higher
role (temporarily, in the demo data), then put the role back and loosen
the file's permissions instead. Which change lets the write through?

**What to notice:** this system checks two things, and either one can
say no. When access is denied in a real system, knowing *which* check
refused is the difference between a five-minute fix and an afternoon
of guessing.
