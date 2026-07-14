import javax.servlet.http.HttpServletRequest;

public class VulnProcessBuilder {
    Process run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        // ZS-JAVA-011: command injection — tainted argument passed to ProcessBuilder
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
        return pb.start();
    }
}
