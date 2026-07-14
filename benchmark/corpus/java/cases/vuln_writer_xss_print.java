import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnWriterXssPrint {
    void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        // ZS-JAVA-014: reflected XSS — tainted value written via out.print()
        out.print(name);
    }
}
