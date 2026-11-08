# fastify-a

Synthetic application written from OWASP weakness classes for scanner measurement. It is not meant to run. Secrets are obvious placeholders.

Labels: 20 vulnerable, 16 safe look-alikes. Line numbers refer to the files as committed; ground truth is in `ground-truth.json`.

| id | file | line | class | label |
|---|---|---|---|---|
| fastify-a-01 | `src/config.ts` | 1 | secret (CWE-798) | vulnerable |
| fastify-a-02 | `src/config.ts` | 5 | secret (CWE-798) | safe |
| fastify-a-03 | `src/server.ts` | 15 | cors (CWE-942) | vulnerable |
| fastify-a-04 | `src/server.ts` | 20 | debug (CWE-489) | vulnerable |
| fastify-a-05 | `src/routes/auth.ts` | 8 | redirect (CWE-601) | vulnerable |
| fastify-a-06 | `src/routes/auth.ts` | 13 | redirect (CWE-601) | safe |
| fastify-a-07 | `src/routes/auth.ts` | 17 | cookieflag (CWE-614) | vulnerable |
| fastify-a-08 | `src/routes/auth.ts` | 22 | cookieflag (CWE-614) | safe |
| fastify-a-09 | `src/routes/files.ts` | 8 | path (CWE-22) | vulnerable |
| fastify-a-10 | `src/routes/files.ts` | 13 | path (CWE-22) | vulnerable |
| fastify-a-11 | `src/routes/files.ts` | 23 | path (CWE-22) | safe |
| fastify-a-12 | `src/routes/proxy.ts` | 5 | ssrf (CWE-918) | vulnerable |
| fastify-a-13 | `src/routes/proxy.ts` | 10 | ssrf (CWE-918) | vulnerable |
| fastify-a-14 | `src/routes/proxy.ts` | 15 | ssrf (CWE-918) | safe |
| fastify-a-15 | `src/routes/tools.ts` | 11 | cmdi (CWE-78) | vulnerable |
| fastify-a-16 | `src/routes/tools.ts` | 16 | cmdi (CWE-78) | safe |
| fastify-a-17 | `src/routes/tools.ts` | 23 | deser (CWE-502) | vulnerable |
| fastify-a-18 | `src/routes/tools.ts` | 27 | deser (CWE-502) | safe |
| fastify-a-19 | `src/routes/users.ts` | 40 | xss (CWE-79) | vulnerable |
| fastify-a-20 | `src/routes/users.ts` | 45 | xss (CWE-79) | safe |
| fastify-a-21 | `src/services/crypto.ts` | 5 | weakhash (CWE-328) | vulnerable |
| fastify-a-22 | `src/services/crypto.ts` | 9 | weakhash (CWE-328) | safe |
| fastify-a-23 | `src/services/crypto.ts` | 13 | weakcrypto (CWE-327) | vulnerable |
| fastify-a-24 | `src/services/crypto.ts` | 19 | weakcrypto (CWE-327) | safe |
| fastify-a-25 | `src/services/crypto.ts` | 24 | weakrand (CWE-330) | vulnerable |
| fastify-a-26 | `src/services/crypto.ts` | 28 | weakrand (CWE-330) | safe |
| fastify-a-27 | `src/services/shell.ts` | 6 | cmdi (CWE-78) | safe |
| fastify-a-28 | `src/services/userService.ts` | 9 | sqli (CWE-89) | vulnerable |
| fastify-a-29 | `src/services/userService.ts` | 14 | sqli (CWE-89) | safe |
| fastify-a-30 | `src/services/userService.ts` | 19 | sqli (CWE-89) | vulnerable |
| fastify-a-31 | `src/services/userService.ts` | 24 | sqli (CWE-89) | safe |
| fastify-a-32 | `src/services/userService.ts` | 30 | nosqli (CWE-943) | vulnerable |
| fastify-a-33 | `src/services/userService.ts` | 35 | nosqli (CWE-943) | safe |
| fastify-a-34 | `views/profile.ejs` | 5 | xss (CWE-79) | safe |
| fastify-a-35 | `views/profile.ejs` | 6 | xss (CWE-79) | vulnerable |
| fastify-a-36 | `views/profile.ejs` | 8 | xss (CWE-79) | vulnerable |
