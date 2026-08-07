import javax.servlet.http.HttpServletRequest;

public class VulnFormatString {
    String greet(HttpServletRequest request) {
        String username = request.getParameter("username");
        // ZS-JAVA-024: the FORMAT STRING itself is attacker-controlled, so the
        // user chooses the format specifiers. Note this is deliberately not
        // String.format("User: %s", username) — that idiom is safe and the
        // rule must not fire on it (see clean.java).
        return String.format("User: " + username);
    }
}
