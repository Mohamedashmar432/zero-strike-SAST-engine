import java.sql.Connection;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class VulnSqliExecute {
    // ZS-JAVA-037: stmt.execute() with a tainted, concatenated query
    void handle(Connection conn, HttpServletRequest request) throws Exception {
        String id = request.getParameter("id");
        Statement stmt = conn.createStatement();
        stmt.execute("SELECT * FROM users WHERE id = " + id);
    }
}
