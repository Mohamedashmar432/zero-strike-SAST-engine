// Negative fixture: none of the ZS-JAVA rules should fire here.
import java.security.MessageDigest;

public class Clean {
    void run() throws Exception {
        String greeting = "hello";
        System.out.println(greeting);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(greeting.getBytes());
    }
}
