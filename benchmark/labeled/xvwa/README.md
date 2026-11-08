# XVWA labels

Source of truth: the module list in XVWA's README and each `vulnerabilities/<module>/home.php`, read at the pinned commit (see SOURCE.txt).
Labels sit at the dangerous statement. Safe labels are XVWA's own correct code next to the vulnerable code (prepared statements,
`htmlspecialchars` output, the PBKDF2 `create_hash` example, `session_destroy` on logout).

Documented but not labeled:
- Insecure direct object reference is labeled at the lookup only; XVWA has no authorization code to point at.
- `php.ini` (`allow_url_include`, `allow_url_fopen`): configuration with no code line.
- `config.php` (empty database root password): not part of a documented module.
- `PasswordHash.php`: third-party PBKDF2 helper, treated as the safe example only.
- `mcrypt_encrypt` use itself (deprecated cipher API): no distinct CWE sink beyond the hardcoded key and IV labeled.
