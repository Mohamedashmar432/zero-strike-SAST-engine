import javax.crypto.spec.DESKeySpec;

public class VulnCrypto {
    DESKeySpec makeKey(byte[] keyBytes) throws Exception {
        // ZS-JAVA-004: weak crypto — DES is not safe for security-sensitive encryption
        return new DESKeySpec(keyBytes);
    }
}
