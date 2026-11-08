# fastify-b

Synthetic application written from OWASP weakness classes for scanner measurement. It is not meant to run. Secrets are obvious placeholders.

Labels: 20 vulnerable, 17 safe look-alikes. Line numbers refer to the files as committed; ground truth is in `ground-truth.json`.

| id | file | line | class | label |
|---|---|---|---|---|
| fastify-b-01 | `server.js` | 9 | secret (CWE-798) | vulnerable |
| fastify-b-02 | `server.js` | 10 | secret (CWE-798) | safe |
| fastify-b-03 | `server.js` | 14 | cors (CWE-942) | vulnerable |
| fastify-b-04 | `server.js` | 27 | debug (CWE-489) | vulnerable |
| fastify-b-05 | `lib/shell.js` | 8 | cmdi (CWE-78) | safe |
| fastify-b-06 | `plugins/auth.js` | 7 | weakhash (CWE-328) | vulnerable |
| fastify-b-07 | `plugins/auth.js` | 9 | weakhash (CWE-328) | safe |
| fastify-b-08 | `plugins/auth.js` | 11 | weakrand (CWE-330) | vulnerable |
| fastify-b-09 | `plugins/auth.js` | 13 | weakrand (CWE-330) | safe |
| fastify-b-10 | `plugins/auth.js` | 16 | weakcrypto (CWE-327) | vulnerable |
| fastify-b-11 | `plugins/auth.js` | 22 | weakcrypto (CWE-327) | safe |
| fastify-b-12 | `plugins/auth.js` | 34 | cookieflag (CWE-614) | vulnerable |
| fastify-b-13 | `plugins/auth.js` | 40 | cookieflag (CWE-614) | safe |
| fastify-b-14 | `routes/admin.js` | 11 | cmdi (CWE-78) | vulnerable |
| fastify-b-15 | `routes/admin.js` | 17 | cmdi (CWE-78) | safe |
| fastify-b-16 | `routes/admin.js` | 27 | deser (CWE-502) | vulnerable |
| fastify-b-17 | `routes/admin.js` | 31 | deser (CWE-502) | safe |
| fastify-b-18 | `routes/admin.js` | 35 | redirect (CWE-601) | vulnerable |
| fastify-b-19 | `routes/admin.js` | 40 | redirect (CWE-601) | safe |
| fastify-b-20 | `routes/orders.js` | 5 | sqli (CWE-89) | vulnerable |
| fastify-b-21 | `routes/orders.js` | 10 | sqli (CWE-89) | safe |
| fastify-b-22 | `routes/orders.js` | 15 | sqli (CWE-89) | vulnerable |
| fastify-b-23 | `routes/orders.js` | 20 | nosqli (CWE-943) | vulnerable |
| fastify-b-24 | `routes/orders.js` | 24 | nosqli (CWE-943) | safe |
| fastify-b-25 | `routes/orders.js` | 33 | xss (CWE-79) | vulnerable |
| fastify-b-26 | `routes/orders.js` | 38 | xss (CWE-79) | safe |
| fastify-b-27 | `routes/reports.js` | 10 | path (CWE-22) | vulnerable |
| fastify-b-28 | `routes/reports.js` | 15 | path (CWE-22) | vulnerable |
| fastify-b-29 | `routes/reports.js` | 23 | path (CWE-22) | safe |
| fastify-b-30 | `routes/webhooks.js` | 9 | ssrf (CWE-918) | vulnerable |
| fastify-b-31 | `routes/webhooks.js` | 14 | ssrf (CWE-918) | vulnerable |
| fastify-b-32 | `routes/webhooks.js` | 19 | ssrf (CWE-918) | safe |
| fastify-b-33 | `routes/webhooks.js` | 28 | ssrf (CWE-918) | safe |
| fastify-b-34 | `views/order.hbs` | 2 | xss (CWE-79) | safe |
| fastify-b-35 | `views/order.hbs` | 3 | xss (CWE-79) | safe |
| fastify-b-36 | `views/order.hbs` | 4 | xss (CWE-79) | vulnerable |
| fastify-b-37 | `views/order.hbs` | 5 | xss (CWE-79) | vulnerable |
