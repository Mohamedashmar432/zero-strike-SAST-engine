import javax.crypto.spec.SecretKeySpec;

public class VulnSecretKeySpecDes {
    // ZS-JAVA-042: DES is a broken cipher (56-bit key)
    SecretKeySpec key(byte[] raw) {
        return new SecretKeySpec(raw, "DES");
    }
}
