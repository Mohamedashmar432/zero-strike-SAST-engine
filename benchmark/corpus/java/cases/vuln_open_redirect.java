import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnOpenRedirect {
    void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("next");
        // ZS-JAVA-021: open redirect — tainted destination passed to sendRedirect()
        response.sendRedirect(target);
    }
}
