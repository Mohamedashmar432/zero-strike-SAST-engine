# Accuracy Report — v0.14.0

| Metric | Value |
|---|---|
| True Positives | 12 |
| False Positives | 0 |
| False Negatives | 41 |
| Precision | 100.00% |
| Recall | 22.64% |

## Per-Language Recall

| Language | TP | FN | Recall |
|---|---|---|---|
| csharp | 0 | 6 | 0.00% |
| go | 0 | 5 | 0.00% |
| java | 0 | 9 | 0.00% |
| javascript | 0 | 5 | 0.00% |
| php | 0 | 5 | 0.00% |
| python | 0 | 8 | 0.00% |
| typescript | 0 | 3 | 0.00% |

## Per-Modality

| Modality | TP | FP | FN |
|---|---|---|---|
| config | 4 | 0 | 0 |
| sast | 0 | 0 | 41 |
| sca | 3 | 0 | 0 |
| secret | 5 | 0 | 0 |

## Per-Rule Precision

| Rule | TP | FP | Precision |
|---|---|---|---|
| ZS-CFG-001 | 1 | 0 | 100.00% |
| ZS-CFG-002 | 1 | 0 | 100.00% |
| ZS-CFG-003 | 1 | 0 | 100.00% |
| ZS-CFG-004 | 1 | 0 | 100.00% |
| ZS-CS-001 | 0 | 0 | 100.00% |
| ZS-CS-002 | 0 | 0 | 100.00% |
| ZS-CS-003 | 0 | 0 | 100.00% |
| ZS-CS-004 | 0 | 0 | 100.00% |
| ZS-CS-005 | 0 | 0 | 100.00% |
| ZS-CS-006 | 0 | 0 | 100.00% |
| ZS-GO-001 | 0 | 0 | 100.00% |
| ZS-GO-002 | 0 | 0 | 100.00% |
| ZS-GO-003 | 0 | 0 | 100.00% |
| ZS-GO-004 | 0 | 0 | 100.00% |
| ZS-GO-005 | 0 | 0 | 100.00% |
| ZS-JAVA-001 | 0 | 0 | 100.00% |
| ZS-JAVA-002 | 0 | 0 | 100.00% |
| ZS-JAVA-003 | 0 | 0 | 100.00% |
| ZS-JAVA-004 | 0 | 0 | 100.00% |
| ZS-JAVA-005 | 0 | 0 | 100.00% |
| ZS-JAVA-006 | 0 | 0 | 100.00% |
| ZS-JAVA-007 | 0 | 0 | 100.00% |
| ZS-JAVA-008 | 0 | 0 | 100.00% |
| ZS-JAVA-009 | 0 | 0 | 100.00% |
| ZS-JS-001 | 0 | 0 | 100.00% |
| ZS-JS-006 | 0 | 0 | 100.00% |
| ZS-JS-007 | 0 | 0 | 100.00% |
| ZS-JS-008 | 0 | 0 | 100.00% |
| ZS-JS-010 | 0 | 0 | 100.00% |
| ZS-PHP-001 | 0 | 0 | 100.00% |
| ZS-PHP-002 | 0 | 0 | 100.00% |
| ZS-PHP-003 | 0 | 0 | 100.00% |
| ZS-PHP-004 | 0 | 0 | 100.00% |
| ZS-PHP-005 | 0 | 0 | 100.00% |
| ZS-PY-001 | 0 | 0 | 100.00% |
| ZS-PY-002 | 0 | 0 | 100.00% |
| ZS-PY-003 | 0 | 0 | 100.00% |
| ZS-PY-005 | 0 | 0 | 100.00% |
| ZS-PY-007 | 0 | 0 | 100.00% |
| ZS-PY-008 | 0 | 0 | 100.00% |
| ZS-PY-010 | 0 | 0 | 100.00% |
| ZS-PY-020 | 0 | 0 | 100.00% |
| ZS-SEC-001 | 1 | 0 | 100.00% |
| ZS-SEC-002 | 1 | 0 | 100.00% |
| ZS-SEC-003 | 1 | 0 | 100.00% |
| ZS-SEC-004 | 1 | 0 | 100.00% |
| ZS-SEC-005 | 1 | 0 | 100.00% |
| ZS-TS-001 | 0 | 0 | 100.00% |
| ZS-TS-004 | 0 | 0 | 100.00% |
| ZS-TS-005 | 0 | 0 | 100.00% |
| dependency Go/github.com/dgrijalva/jwt-go | 1 | 0 | 100.00% |
| dependency Maven/org.apache.logging.log4j:log4j-core | 1 | 0 | 100.00% |
| dependency npm/lodash | 1 | 0 | 100.00% |

## Mismatches

- **csharp/cases/vuln_process_start.cs**: expected ZS-CS-001 (min_count=1), matched 0
- **csharp/cases/vuln_sqli.cs**: expected ZS-CS-002 (min_count=1), matched 0
- **csharp/cases/vuln_deserialization.cs**: expected ZS-CS-003 (min_count=1), matched 0
- **csharp/cases/vuln_xss.cs**: expected ZS-CS-004 (min_count=1), matched 0
- **csharp/cases/vuln_crypto.cs**: expected ZS-CS-005 (min_count=1), matched 0
- **csharp/cases/vuln_hardcoded_secret.cs**: expected ZS-CS-006 (min_count=2), matched 0
- **go/testdata/vuln_cmdi.go**: expected ZS-GO-001 (min_count=1), matched 0
- **go/testdata/vuln_sqli.go**: expected ZS-GO-002 (min_count=1), matched 0
- **go/testdata/vuln_traversal.go**: expected ZS-GO-003 (min_count=1), matched 0
- **go/testdata/vuln_crypto.go**: expected ZS-GO-004 (min_count=1), matched 0
- **go/testdata/vuln_secret.go**: expected ZS-GO-005 (min_count=1), matched 0
- **java/cases/vuln_sqli.java**: expected ZS-JAVA-001 (min_count=1), matched 0
- **java/cases/vuln_deserialization.java**: expected ZS-JAVA-002 (min_count=1), matched 0
- **java/cases/vuln_xxe.java**: expected ZS-JAVA-003 (min_count=1), matched 0
- **java/cases/vuln_crypto.java**: expected ZS-JAVA-004 (min_count=1), matched 0
- **java/cases/vuln_secret.java**: expected ZS-JAVA-005 (min_count=1), matched 0
- **java/cases/vuln_traversal.java**: expected ZS-JAVA-006 (min_count=1), matched 0
- **java/cases/vuln_noop_password_encoder.java**: expected ZS-JAVA-007 (min_count=1), matched 0
- **java/cases/vuln_weak_jwt_secret.java**: expected ZS-JAVA-008 (min_count=1), matched 0
- **java/cases/vuln_stax_xxe.java**: expected ZS-JAVA-009 (min_count=1), matched 0
- **js/cases/vuln_eval.js**: expected ZS-JS-001 (min_count=1), matched 0
- **js/cases/vuln_tls.js**: expected ZS-JS-006 (min_count=1), matched 0
- **js/cases/vuln_hardcoded.js**: expected ZS-JS-007 (min_count=1), matched 0
- **js/cases/vuln_jwt.js**: expected ZS-JS-008 (min_count=1), matched 0
- **js/cases/vuln_empty_catch.js**: expected ZS-JS-010 (min_count=1), matched 0
- **php/cases/vuln_cmdi.php**: expected ZS-PHP-001 (min_count=1), matched 0
- **php/cases/vuln_sqli.php**: expected ZS-PHP-002 (min_count=1), matched 0
- **php/cases/vuln_deserialize.php**: expected ZS-PHP-003 (min_count=1), matched 0
- **php/cases/vuln_xss.php**: expected ZS-PHP-004 (min_count=1), matched 0
- **php/cases/vuln_secret.php**: expected ZS-PHP-005 (min_count=1), matched 0
- **python/cases/vuln_eval.py**: expected ZS-PY-001 (min_count=1), matched 0
- **python/cases/vuln_pickle.py**: expected ZS-PY-002 (min_count=1), matched 0
- **python/cases/vuln_subprocess.py**: expected ZS-PY-003 (min_count=1), matched 0
- **python/cases/vuln_os_system.py**: expected ZS-PY-005 (min_count=1), matched 0
- **python/cases/vuln_hashlib.py**: expected ZS-PY-007 (min_count=1), matched 0
- **python/cases/vuln_path_traversal.py**: expected ZS-PY-008 (min_count=1), matched 0
- **python/cases/vuln_yaml.py**: expected ZS-PY-010 (min_count=1), matched 0
- **python/cases/vuln_hardcoded.py**: expected ZS-PY-020 (min_count=2), matched 0
- **ts/cases/vuln_eval.ts**: expected ZS-TS-001 (min_count=1), matched 0
- **ts/cases/vuln_tls.ts**: expected ZS-TS-004 (min_count=1), matched 0
- **ts/cases/vuln_empty_catch.ts**: expected ZS-TS-005 (min_count=1), matched 0
