import javax.crypto.Cipher;

public class VulnWeakCipherGetInstance {
    // ZS-JAVA-035: 3DES is deprecated (Sweet32, NIST withdrawal)
    Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
