import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;

public class VulnXpathCompile {
    // ZS-JAVA-049: xpath.compile() with a tainted expression (XPath injection)
    void handle(XPath xpath, HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        xpath.compile("//user[name/text()='" + name + "']");
    }
}
