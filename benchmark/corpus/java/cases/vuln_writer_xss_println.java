import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnWriterXssPrintln {
    void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        // ZS-JAVA-013: reflected XSS — tainted value written via out.println()
        out.println(name);
    }
}
