import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnCors {
    void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String origin = request.getParameter("origin");
        // ZS-JAVA-023: CORS misconfiguration — tainted origin reflected into Access-Control-Allow-Origin
        response.setHeader("Access-Control-Allow-Origin", origin);
    }
}
