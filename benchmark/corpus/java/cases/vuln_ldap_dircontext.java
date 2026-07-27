import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

public class VulnLdapDirContext {
    // ZS-JAVA-047: DirContext.search() with a tainted filter (LDAP injection)
    void handle(DirContext dirContext, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String filter = "(uid=" + name + ")";
        dirContext.search("", filter, null);
    }
}
