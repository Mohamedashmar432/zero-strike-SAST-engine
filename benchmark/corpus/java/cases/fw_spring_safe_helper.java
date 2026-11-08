package demo;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// The helper's parameter only ever receives a constant from the handler and
// the framework binds nothing to it: no finding.
@RestController
public class AdminController {
    private Connection conn;

    @GetMapping("/admin")
    public String admin() throws SQLException {
        lookup("admin");
        return "ok";
    }

    private void lookup(String role) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE role = " + role);
    }
}
