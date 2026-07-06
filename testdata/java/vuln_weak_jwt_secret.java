public class VulnWeakJwtSecret {
    void sign() {
        // ZS-JAVA-008: short, hardcoded JWT signing secret
        String jwtSecret = "s3cr3t12";
        System.out.println(jwtSecret);
    }
}
