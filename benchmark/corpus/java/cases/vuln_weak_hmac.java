import javax.crypto.Mac;

public class VulnWeakHmac {
    void sign() throws Exception {
        // ZS-JAVA-050: weak HMAC algorithm.
        Mac mac = Mac.getInstance("HmacMD5");
    }
}
