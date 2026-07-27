import org.slf4j.Logger;

public class VulnSensitiveLogError {
    // ZS-JAVA-045: credential-shaped value written to error logs
    void handle(Logger logger, String username, String password) {
        logger.error("login failed for " + username, password);
    }
}
