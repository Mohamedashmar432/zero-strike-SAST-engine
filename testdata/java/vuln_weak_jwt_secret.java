public class VulnWeakJwtSecret {
    void sign() {
        // ZS-JAVA-008: short, hardcoded JWT signing secret.
        // Named jwtSigningKey, not jwtSecret — see the benchmark fixture's
        // comment for why (avoids double-firing ZS-JAVA-005 too).
        String jwtSigningKey = "s3cr3t12";
        System.out.println(jwtSigningKey);
    }
}
