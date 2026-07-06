public class VulnWeakJwtSecret {
    void sign() {
        // ZS-JAVA-008: short, hardcoded JWT signing secret.
        // Named jwtSigningKey (not jwtSecret) so this fixture triggers only
        // ZS-JAVA-008 — "jwtSecret" also matches ZS-JAVA-005's broader
        // "secret"-in-name pattern, which would double-fire here and break
        // the benchmark's --max-fp 0 gate (the manifest only expects one).
        String jwtSigningKey = "s3cr3t12";
        System.out.println(jwtSigningKey);
    }
}
