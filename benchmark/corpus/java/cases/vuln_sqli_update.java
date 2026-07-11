import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class VulnSqliUpdate {
    void handle(Connection conn, HttpServletRequest request) throws SQLException {
        String id = request.getParameter("id");
        Statement stmt = conn.createStatement();
        // ZS-JAVA-010: SQL injection — query built by concatenating tainted id
        stmt.executeUpdate("UPDATE users SET active = 0 WHERE id = " + id);
    }
}
