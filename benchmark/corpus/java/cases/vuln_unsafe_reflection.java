import javax.servlet.http.HttpServletRequest;

public class VulnUnsafeReflection {
    void handle(HttpServletRequest request) throws Exception {
        String className = request.getParameter("handler");
        // ZS-JAVA-028: unsafe reflection — attacker-controlled class name
        Class.forName(className);
    }
}
