# php-app

Synthetic application written from OWASP weakness classes for scanner measurement. It is not meant to run. Secrets are obvious placeholders.

Labels: 23 vulnerable, 18 safe look-alikes. Line numbers refer to the files as committed; ground truth is in `ground-truth.json`.

| id | file | line | class | label |
|---|---|---|---|---|
| php-app-01 | `app/Http/Controllers/AuthController.php` | 14 | redirect (CWE-601) | vulnerable |
| php-app-02 | `app/Http/Controllers/AuthController.php` | 23 | redirect (CWE-601) | safe |
| php-app-03 | `app/Http/Controllers/AuthController.php` | 32 | cookieflag (CWE-614) | vulnerable |
| php-app-04 | `app/Http/Controllers/AuthController.php` | 39 | cookieflag (CWE-614) | safe |
| php-app-05 | `app/Http/Controllers/FileController.php` | 12 | path (CWE-22) | vulnerable |
| php-app-06 | `app/Http/Controllers/FileController.php` | 18 | path (CWE-22) | vulnerable |
| php-app-07 | `app/Http/Controllers/FileController.php` | 29 | path (CWE-22) | safe |
| php-app-08 | `app/Http/Controllers/ProxyController.php` | 12 | ssrf (CWE-918) | vulnerable |
| php-app-09 | `app/Http/Controllers/ProxyController.php` | 18 | ssrf (CWE-918) | vulnerable |
| php-app-10 | `app/Http/Controllers/ProxyController.php` | 25 | ssrf (CWE-918) | safe |
| php-app-11 | `app/Http/Controllers/ProxyController.php` | 31 | ssrf (CWE-918) | safe |
| php-app-12 | `app/Http/Controllers/ToolController.php` | 12 | cmdi (CWE-78) | vulnerable |
| php-app-13 | `app/Http/Controllers/ToolController.php` | 18 | cmdi (CWE-78) | safe |
| php-app-14 | `app/Http/Controllers/ToolController.php` | 29 | cmdi (CWE-78) | vulnerable |
| php-app-15 | `app/Http/Controllers/ToolController.php` | 35 | deser (CWE-502) | vulnerable |
| php-app-16 | `app/Http/Controllers/ToolController.php` | 41 | deser (CWE-502) | safe |
| php-app-17 | `app/Http/Controllers/UserController.php` | 14 | sqli (CWE-89) | vulnerable |
| php-app-18 | `app/Http/Controllers/UserController.php` | 20 | sqli (CWE-89) | safe |
| php-app-19 | `app/Http/Controllers/UserController.php` | 26 | sqli (CWE-89) | vulnerable |
| php-app-20 | `app/Http/Controllers/UserController.php` | 32 | sqli (CWE-89) | safe |
| php-app-21 | `app/Http/Controllers/UserController.php` | 40 | weakhash (CWE-328) | vulnerable |
| php-app-22 | `app/Http/Controllers/UserController.php` | 49 | weakhash (CWE-328) | safe |
| php-app-23 | `app/Services/Helpers.php` | 10 | cmdi (CWE-78) | safe |
| php-app-24 | `config/app.php` | 6 | debug (CWE-489) | vulnerable |
| php-app-25 | `config/app.php` | 8 | secret (CWE-798) | vulnerable |
| php-app-26 | `config/cors.php` | 6 | cors (CWE-942) | vulnerable |
| php-app-27 | `config/services.php` | 6 | secret (CWE-798) | vulnerable |
| php-app-28 | `config/services.php` | 9 | secret (CWE-798) | safe |
| php-app-29 | `public/search.php` | 7 | xss (CWE-79) | vulnerable |
| php-app-30 | `public/search.php` | 8 | xss (CWE-79) | safe |
| php-app-31 | `public/search.php` | 10 | sqli (CWE-89) | vulnerable |
| php-app-32 | `public/search.php` | 12 | xss (CWE-79) | safe |
| php-app-33 | `public/search.php` | 15 | sqli (CWE-89) | safe |
| php-app-34 | `public/search.php` | 19 | lfi (CWE-98) | vulnerable |
| php-app-35 | `public/widget.html` | 9 | xss (CWE-79) | vulnerable |
| php-app-36 | `public/widget.html` | 10 | xss (CWE-79) | vulnerable |
| php-app-37 | `public/widget.html` | 11 | xss (CWE-79) | safe |
| php-app-38 | `resources/views/comments.blade.php` | 7 | xss (CWE-79) | safe |
| php-app-39 | `resources/views/comments.blade.php` | 8 | xss (CWE-79) | vulnerable |
| php-app-40 | `resources/views/comments.blade.php` | 11 | xss (CWE-79) | vulnerable |
| php-app-41 | `resources/views/comments.blade.php` | 12 | xss (CWE-79) | safe |
