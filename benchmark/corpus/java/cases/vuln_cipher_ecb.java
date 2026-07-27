import javax.crypto.Cipher;

public class VulnCipherEcb {
    // ZS-JAVA-036: AES in ECB mode leaks plaintext structure
    Cipher ecbCipher() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
