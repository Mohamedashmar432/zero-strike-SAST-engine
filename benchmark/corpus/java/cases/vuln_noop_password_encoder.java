import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class VulnNoopPasswordEncoder {
    PasswordEncoder encoder() {
        // ZS-JAVA-007: NoOpPasswordEncoder stores/compares passwords in plaintext
        return NoOpPasswordEncoder.getInstance();
    }
}
