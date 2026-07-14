import java.security.MessageDigest;

public class VulnWeakHash {
    byte[] hash(byte[] data) throws Exception {
        // ZS-JAVA-022: weak cryptographic hash — MD5 is broken for collision resistance
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(data);
    }
}
