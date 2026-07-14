import java.net.URL;
import javax.servlet.http.HttpServletRequest;

public class VulnUrlSsrf {
    URL fetch(HttpServletRequest request) throws Exception {
        String target = request.getParameter("url");
        // ZS-JAVA-019: SSRF — tainted URL passed to the java.net.URL constructor
        return new URL(target);
    }
}
