import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class VulnTraversal {
    void readFile(HttpServletRequest request) {
        String path = request.getParameter("path");
        // ZS-JAVA-006: path traversal — path traces back to a request parameter
        File file = new File(path);
    }
}
