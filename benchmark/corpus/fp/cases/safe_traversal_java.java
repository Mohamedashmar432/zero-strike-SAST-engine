// Negative fixture for the path-traversal rule family (ZS-JAVA-006/048).
// Every filesystem path below is a compile-time constant. What is
// request-derived is the file *contents* — writing tainted bytes to a fixed
// path is not CWE-22.
//
// ZS-JAVA-006 (new File) is deliberately left unindexed because every File
// constructor argument is itself a path component, so this fixture proves
// the broad form still does not fire on constant paths.
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;

public class SafeTraversalJava {
    private static final String AUDIT_LOG = "/var/log/app/audit.log";

    void appendAudit(HttpServletRequest request) throws Exception {
        String note = request.getParameter("note");
        File target = new File(AUDIT_LOG);
        try (FileOutputStream out = new FileOutputStream(target, true)) {
            out.write(note.getBytes(StandardCharsets.UTF_8));
        }
    }

    void loadBundledConfig() throws Exception {
        try (FileInputStream in = new FileInputStream("config/app.properties")) {
            in.read();
        }
    }

    File reportDirectory() {
        return new File("/srv/app/reports");
    }
}
