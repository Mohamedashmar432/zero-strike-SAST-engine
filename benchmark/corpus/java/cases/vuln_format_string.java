import javax.servlet.http.HttpServletRequest;

public class VulnFormatString {
    String greet(HttpServletRequest request) {
        String username = request.getParameter("username");
        // ZS-JAVA-024: tainted format string — String.format() called with a tainted argument
        return String.format("User: %s", username);
    }
}
