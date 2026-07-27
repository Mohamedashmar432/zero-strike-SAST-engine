import org.apache.commons.codec.digest.DigestUtils;

public class VulnDigestUtilsSha1 {
    // ZS-JAVA-044: SHA-1 is broken for collision resistance
    String hash(String data) {
        return DigestUtils.sha1(data).toString();
    }
}
