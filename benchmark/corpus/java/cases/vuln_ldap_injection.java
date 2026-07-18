import javax.naming.directory.DirContext;
import javax.servlet.http.HttpServletRequest;

public class VulnLdapInjection {
    void handle(HttpServletRequest request, DirContext ctx) throws Exception {
        String uid = request.getParameter("uid");
        // ZS-JAVA-026: LDAP injection — filter built by concatenating tainted uid
        ctx.search("ou=people,dc=example,dc=com", "(uid=" + uid + ")", null);
    }
}
