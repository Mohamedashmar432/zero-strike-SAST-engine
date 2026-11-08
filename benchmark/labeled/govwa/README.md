# govwa labels

Source of truth: the lesson handlers under `vulnerability/` (sqli, xss, idor, csa) and their own comments ("here is the vulnerable
query", "vulnerable function", "here is the mistake"), read at the pinned commit. Low level is the vulnerable path, high level is the
fixed path; the high-level code is labeled safe (prepared statements, `HTMLEscapeString`).

Not labeled, with the reason:
- `vulnerability/xxe/xxe.go`: a stub that prints "tes"; the README strikes XXE from its to-do list but no XXE code exists.
- Client side authentication (`csa`): only the hardcoded OTP digest and the MD5 comparison have code lines; the client-side check is in
  templates and JavaScript.
- Level selection through the `Level` cookie (`util/cookie.go: CheckLevel`) is the lesson's own switch, not a vulnerability.
- Setup page database reset beyond the missing `AuthCheck`: no further line.
- Dockerfile, docker-compose and the CI workflow: no vulnerable code line.
Labels outside the lessons (cookie flags, CORS wildcard, panic message, setup route without auth, shipped credentials) are evident from the
code but not listed in the README; they are the least documented labels in this set.
