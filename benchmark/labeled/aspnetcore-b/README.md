# aspnetcore-b

Synthetic application written from OWASP weakness classes for scanner measurement. It is not meant to run. Secrets are obvious placeholders.

Labels: 19 vulnerable, 13 safe look-alikes. Line numbers refer to the files as committed; ground truth is in `ground-truth.json`.

| id | file | line | class | label |
|---|---|---|---|---|
| aspnetcore-b-01 | `Program.cs` | 10 | secret (CWE-798) | vulnerable |
| aspnetcore-b-02 | `Program.cs` | 16 | cors (CWE-942) | vulnerable |
| aspnetcore-b-03 | `Program.cs` | 19 | debug (CWE-489) | vulnerable |
| aspnetcore-b-04 | `Program.cs` | 24 | secret (CWE-798) | safe |
| aspnetcore-b-05 | `Program.cs` | 29 | sqli (CWE-89) | vulnerable |
| aspnetcore-b-06 | `Program.cs` | 39 | sqli (CWE-89) | safe |
| aspnetcore-b-07 | `Program.cs` | 49 | sqli (CWE-89) | vulnerable |
| aspnetcore-b-08 | `Program.cs` | 55 | sqli (CWE-89) | safe |
| aspnetcore-b-09 | `Program.cs` | 62 | path (CWE-22) | vulnerable |
| aspnetcore-b-10 | `Program.cs` | 70 | path (CWE-22) | safe |
| aspnetcore-b-11 | `Program.cs` | 75 | ssrf (CWE-918) | vulnerable |
| aspnetcore-b-12 | `Program.cs` | 81 | ssrf (CWE-918) | safe |
| aspnetcore-b-13 | `Program.cs` | 85 | redirect (CWE-601) | vulnerable |
| aspnetcore-b-14 | `Program.cs` | 90 | redirect (CWE-601) | safe |
| aspnetcore-b-15 | `Program.cs` | 95 | cmdi (CWE-78) | vulnerable |
| aspnetcore-b-16 | `Program.cs` | 106 | weakrand (CWE-330) | vulnerable |
| aspnetcore-b-17 | `Program.cs` | 107 | cookieflag (CWE-614) | vulnerable |
| aspnetcore-b-18 | `Program.cs` | 114 | cookieflag (CWE-614) | safe |
| aspnetcore-b-19 | `Program.cs` | 120 | deser (CWE-502) | vulnerable |
| aspnetcore-b-20 | `Program.cs` | 126 | deser (CWE-502) | safe |
| aspnetcore-b-21 | `Program.cs` | 132 | weakhash (CWE-328) | vulnerable |
| aspnetcore-b-22 | `Program.cs` | 139 | weakhash (CWE-328) | safe |
| aspnetcore-b-23 | `Program.cs` | 145 | weakcrypto (CWE-327) | vulnerable |
| aspnetcore-b-24 | `Program.cs` | 151 | weakcrypto (CWE-327) | safe |
| aspnetcore-b-25 | `appsettings.json` | 4 | secret (CWE-798) | vulnerable |
| aspnetcore-b-26 | `Pages/Search.cshtml` | 5 | xss (CWE-79) | vulnerable |
| aspnetcore-b-27 | `Pages/Search.cshtml` | 6 | xss (CWE-79) | safe |
| aspnetcore-b-28 | `Pages/Search.cshtml` | 11 | xss (CWE-79) | safe |
| aspnetcore-b-29 | `Pages/Search.cshtml` | 15 | xss (CWE-79) | vulnerable |
| aspnetcore-b-30 | `Pages/Search.cshtml.cs` | 22 | path (CWE-22) | vulnerable |
| aspnetcore-b-31 | `Pages/Search.cshtml.cs` | 30 | sqli (CWE-89) | vulnerable |
| aspnetcore-b-32 | `Services/GitRunner.cs` | 13 | cmdi (CWE-78) | safe |
