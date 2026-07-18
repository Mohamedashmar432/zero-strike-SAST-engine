import com.thoughtworks.xstream.XStream;
import javax.servlet.http.HttpServletRequest;

public class VulnXstream {
    void handle(HttpServletRequest request, XStream xstream) {
        String payload = request.getParameter("payload");
        // ZS-JAVA-031: XStream deserialization of attacker-controlled XML
        Object obj = xstream.fromXML(payload);
    }
}
