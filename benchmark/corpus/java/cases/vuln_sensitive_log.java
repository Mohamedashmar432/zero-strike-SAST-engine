import org.slf4j.Logger;

public class VulnSensitiveLog {
    void audit(Logger logger, String apiKey) {
        // ZS-JAVA-032: sensitive-looking value written to the application log
        logger.info(apiKey);
    }
}
