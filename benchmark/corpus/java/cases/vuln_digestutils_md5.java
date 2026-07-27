import org.apache.commons.codec.digest.DigestUtils;

public class VulnDigestUtilsMd5 {
    // ZS-JAVA-043: MD5 is broken for collision resistance
    String hash(String data) {
        return DigestUtils.md5(data).toString();
    }
}
