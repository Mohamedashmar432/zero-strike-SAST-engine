import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.core.LdapTemplate;

public class VulnLdapTemplate {
    // ZS-JAVA-046: LdapTemplate.search() with a tainted filter (LDAP injection)
    void handle(LdapTemplate ldapTemplate, HttpServletRequest request) {
        String name = request.getParameter("name");
        String filter = "(uid=" + name + ")";
        ldapTemplate.search("", filter, null);
    }
}
