import javax.net.ssl.SSLContext;

public class VulnWeakTls {
    void configure() throws Exception {
        // ZS-JAVA-033: deprecated protocol pinned — POODLE-vulnerable SSLv3
        SSLContext legacy = SSLContext.getInstance("SSLv3");
        // safe: modern protocol must NOT be flagged
        SSLContext modern = SSLContext.getInstance("TLSv1.3");
    }
}
