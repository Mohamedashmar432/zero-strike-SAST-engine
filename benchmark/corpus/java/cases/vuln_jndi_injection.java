import javax.naming.Context;
import javax.servlet.http.HttpServletRequest;

public class VulnJndiInjection {
    void handle(HttpServletRequest request, Context ctx) throws Exception {
        String name = request.getParameter("name");
        // ZS-JAVA-027: JNDI injection — attacker-controlled lookup name (log4shell-class)
        ctx.lookup(name);
    }
}
