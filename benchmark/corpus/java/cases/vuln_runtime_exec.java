import javax.servlet.http.HttpServletRequest;

public class VulnRuntimeExec {
    Process run(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        // ZS-JAVA-012: command injection — tainted argument passed to Runtime.getRuntime().exec()
        return Runtime.getRuntime().exec(cmd);
    }
}
