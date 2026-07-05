import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class VulnSqli {
    void handle(Connection conn, HttpServletRequest request) throws SQLException {
        String id = request.getParameter("id");
        Statement stmt = conn.createStatement();
        // ZS-JAVA-001: SQL injection — query built by concatenating tainted id
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
