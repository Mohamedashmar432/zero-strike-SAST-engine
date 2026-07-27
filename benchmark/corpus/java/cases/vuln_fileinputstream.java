import java.io.FileInputStream;
import javax.servlet.http.HttpServletRequest;

public class VulnFileInputStream {
    // ZS-JAVA-048: new FileInputStream() on a tainted path (path traversal)
    void handle(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        new FileInputStream(name);
    }
}
