# aspnetcore-a

Synthetic application written from OWASP weakness classes for scanner measurement. It is not meant to run. Secrets are obvious placeholders.

Labels: 21 vulnerable, 19 safe look-alikes. Line numbers refer to the files as committed; ground truth is in `ground-truth.json`.

| id | file | line | class | label |
|---|---|---|---|---|
| aspnetcore-a-01 | `Program.cs` | 13 | cors (CWE-942) | vulnerable |
| aspnetcore-a-02 | `Program.cs` | 18 | debug (CWE-489) | vulnerable |
| aspnetcore-a-03 | `Program.cs` | 28 | secret (CWE-798) | vulnerable |
| aspnetcore-a-04 | `Program.cs` | 29 | secret (CWE-798) | safe |
| aspnetcore-a-05 | `appsettings.json` | 3 | secret (CWE-798) | vulnerable |
| aspnetcore-a-06 | `Controllers/AccountController.cs` | 11 | redirect (CWE-601) | vulnerable |
| aspnetcore-a-07 | `Controllers/AccountController.cs` | 21 | redirect (CWE-601) | safe |
| aspnetcore-a-08 | `Controllers/AccountController.cs` | 28 | weakrand (CWE-330) | vulnerable |
| aspnetcore-a-09 | `Controllers/AccountController.cs` | 29 | cookieflag (CWE-614) | vulnerable |
| aspnetcore-a-10 | `Controllers/AccountController.cs` | 30 | redirect (CWE-601) | safe |
| aspnetcore-a-11 | `Controllers/AccountController.cs` | 37 | weakrand (CWE-330) | safe |
| aspnetcore-a-12 | `Controllers/AccountController.cs` | 38 | cookieflag (CWE-614) | safe |
| aspnetcore-a-13 | `Controllers/FilesController.cs` | 14 | path (CWE-22) | vulnerable |
| aspnetcore-a-14 | `Controllers/FilesController.cs` | 21 | path (CWE-22) | vulnerable |
| aspnetcore-a-15 | `Controllers/FilesController.cs` | 34 | path (CWE-22) | safe |
| aspnetcore-a-16 | `Controllers/ProxyController.cs` | 15 | ssrf (CWE-918) | vulnerable |
| aspnetcore-a-17 | `Controllers/ProxyController.cs` | 22 | ssrf (CWE-918) | vulnerable |
| aspnetcore-a-18 | `Controllers/ProxyController.cs` | 29 | ssrf (CWE-918) | safe |
| aspnetcore-a-19 | `Controllers/ProxyController.cs` | 40 | ssrf (CWE-918) | safe |
| aspnetcore-a-20 | `Controllers/ToolsController.cs` | 22 | cmdi (CWE-78) | vulnerable |
| aspnetcore-a-21 | `Controllers/ToolsController.cs` | 34 | cmdi (CWE-78) | safe |
| aspnetcore-a-22 | `Controllers/ToolsController.cs` | 45 | deser (CWE-502) | vulnerable |
| aspnetcore-a-23 | `Controllers/ToolsController.cs` | 53 | deser (CWE-502) | vulnerable |
| aspnetcore-a-24 | `Controllers/ToolsController.cs` | 60 | deser (CWE-502) | safe |
| aspnetcore-a-25 | `Controllers/ToolsController.cs` | 68 | xxe (CWE-611) | vulnerable |
| aspnetcore-a-26 | `Controllers/ToolsController.cs` | 76 | xxe (CWE-611) | safe |
| aspnetcore-a-27 | `Controllers/UsersController.cs` | 34 | sqli (CWE-89) | vulnerable |
| aspnetcore-a-28 | `Controllers/UsersController.cs` | 46 | sqli (CWE-89) | safe |
| aspnetcore-a-29 | `Controllers/UsersController.cs` | 57 | sqli (CWE-89) | vulnerable |
| aspnetcore-a-30 | `Controllers/UsersController.cs` | 64 | sqli (CWE-89) | safe |
| aspnetcore-a-31 | `Controllers/UsersController.cs` | 71 | weakhash (CWE-328) | vulnerable |
| aspnetcore-a-32 | `Controllers/UsersController.cs` | 80 | weakhash (CWE-328) | safe |
| aspnetcore-a-33 | `Controllers/UsersController.cs` | 89 | nosqli (CWE-943) | vulnerable |
| aspnetcore-a-34 | `Controllers/UsersController.cs` | 96 | nosqli (CWE-943) | safe |
| aspnetcore-a-35 | `Services/ShellRunner.cs` | 11 | cmdi (CWE-78) | safe |
| aspnetcore-a-36 | `Views/Notes/Index.cshtml` | 3 | xss (CWE-79) | safe |
| aspnetcore-a-37 | `Views/Notes/Index.cshtml` | 4 | xss (CWE-79) | safe |
| aspnetcore-a-38 | `Views/Notes/Index.cshtml` | 10 | xss (CWE-79) | vulnerable |
| aspnetcore-a-39 | `Views/Notes/Index.cshtml` | 15 | xss (CWE-79) | vulnerable |
| aspnetcore-a-40 | `Views/Notes/Index.cshtml` | 16 | xss (CWE-79) | safe |
