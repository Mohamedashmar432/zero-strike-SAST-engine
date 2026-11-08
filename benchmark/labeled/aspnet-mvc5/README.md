# aspnet-mvc5

Synthetic application written from OWASP weakness classes for scanner measurement. It is not meant to run. Secrets are obvious placeholders.

Labels: 27 vulnerable, 17 safe look-alikes. Line numbers refer to the files as committed; ground truth is in `ground-truth.json`.

| id | file | line | class | label |
|---|---|---|---|---|
| aspnet-mvc5-01 | `Default.aspx` | 11 | xss (CWE-79) | vulnerable |
| aspnet-mvc5-02 | `Default.aspx` | 12 | xss (CWE-79) | safe |
| aspnet-mvc5-03 | `Default.aspx.cs` | 12 | xss (CWE-79) | vulnerable |
| aspnet-mvc5-04 | `Default.aspx.cs` | 14 | xss (CWE-79) | safe |
| aspnet-mvc5-05 | `Default.aspx.cs` | 18 | sqli (CWE-89) | vulnerable |
| aspnet-mvc5-06 | `Web.Release.config` | 5 | debug (CWE-489) | safe |
| aspnet-mvc5-07 | `Web.Release.config` | 6 | cookieflag (CWE-614) | safe |
| aspnet-mvc5-08 | `Web.config` | 4 | secret (CWE-798) | vulnerable |
| aspnet-mvc5-09 | `Web.config` | 7 | secret (CWE-798) | vulnerable |
| aspnet-mvc5-10 | `Web.config` | 11 | debug (CWE-489) | vulnerable |
| aspnet-mvc5-11 | `Web.config` | 13 | debug (CWE-489) | vulnerable |
| aspnet-mvc5-12 | `Web.config` | 14 | cookieflag (CWE-614) | vulnerable |
| aspnet-mvc5-13 | `Web.config` | 15 | secret (CWE-798) | vulnerable |
| aspnet-mvc5-14 | `Web.config` | 20 | cors (CWE-942) | vulnerable |
| aspnet-mvc5-15 | `Controllers/HomeController.cs` | 27 | sqli (CWE-89) | vulnerable |
| aspnet-mvc5-16 | `Controllers/HomeController.cs` | 36 | sqli (CWE-89) | safe |
| aspnet-mvc5-17 | `Controllers/HomeController.cs` | 43 | sqli (CWE-89) | vulnerable |
| aspnet-mvc5-18 | `Controllers/HomeController.cs` | 49 | sqli (CWE-89) | safe |
| aspnet-mvc5-19 | `Controllers/HomeController.cs` | 55 | path (CWE-22) | vulnerable |
| aspnet-mvc5-20 | `Controllers/HomeController.cs` | 64 | path (CWE-22) | safe |
| aspnet-mvc5-21 | `Controllers/HomeController.cs` | 69 | redirect (CWE-601) | vulnerable |
| aspnet-mvc5-22 | `Controllers/HomeController.cs` | 75 | redirect (CWE-601) | safe |
| aspnet-mvc5-23 | `Controllers/HomeController.cs` | 81 | xss (CWE-79) | vulnerable |
| aspnet-mvc5-24 | `Controllers/HomeController.cs` | 87 | xss (CWE-79) | safe |
| aspnet-mvc5-25 | `Controllers/HomeController.cs` | 93 | cmdi (CWE-78) | vulnerable |
| aspnet-mvc5-26 | `Controllers/HomeController.cs` | 105 | deser (CWE-502) | vulnerable |
| aspnet-mvc5-27 | `Controllers/HomeController.cs` | 112 | deser (CWE-502) | vulnerable |
| aspnet-mvc5-28 | `Controllers/HomeController.cs` | 119 | deser (CWE-502) | safe |
| aspnet-mvc5-29 | `Controllers/HomeController.cs` | 126 | weakhash (CWE-328) | vulnerable |
| aspnet-mvc5-30 | `Controllers/HomeController.cs` | 131 | weakhash (CWE-328) | safe |
| aspnet-mvc5-31 | `Controllers/HomeController.cs` | 137 | weakcrypto (CWE-327) | vulnerable |
| aspnet-mvc5-32 | `Controllers/HomeController.cs` | 145 | weakcrypto (CWE-327) | safe |
| aspnet-mvc5-33 | `Controllers/HomeController.cs` | 155 | xxe (CWE-611) | vulnerable |
| aspnet-mvc5-34 | `Controllers/HomeController.cs` | 165 | xxe (CWE-611) | safe |
| aspnet-mvc5-35 | `Controllers/HomeController.cs` | 173 | ssrf (CWE-918) | vulnerable |
| aspnet-mvc5-36 | `Controllers/HomeController.cs` | 179 | ssrf (CWE-918) | safe |
| aspnet-mvc5-37 | `Controllers/HomeController.cs` | 189 | cmdi (CWE-78) | safe |
| aspnet-mvc5-38 | `Controllers/ItemsApiController.cs` | 19 | sqli (CWE-89) | vulnerable |
| aspnet-mvc5-39 | `Controllers/ItemsApiController.cs` | 29 | sqli (CWE-89) | safe |
| aspnet-mvc5-40 | `Controllers/ItemsApiController.cs` | 38 | path (CWE-22) | vulnerable |
| aspnet-mvc5-41 | `Controllers/ItemsApiController.cs` | 48 | ssrf (CWE-918) | vulnerable |
| aspnet-mvc5-42 | `Views/Home/Details.cshtml` | 3 | xss (CWE-79) | safe |
| aspnet-mvc5-43 | `Views/Home/Details.cshtml` | 4 | xss (CWE-79) | vulnerable |
| aspnet-mvc5-44 | `Views/Home/Details.cshtml` | 5 | xss (CWE-79) | vulnerable |
