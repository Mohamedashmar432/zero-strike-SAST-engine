import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import org.w3c.dom.Document;

public class VulnXpathInjection {
    void handle(HttpServletRequest request, XPath xpath, Document doc) throws Exception {
        String user = request.getParameter("user");
        // ZS-JAVA-025: XPath injection — expression built by concatenating tainted user
        xpath.evaluate("//users/user[@name='" + user + "']", doc);
    }
}
