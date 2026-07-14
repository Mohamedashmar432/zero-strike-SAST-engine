import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class VulnRestTemplateSsrf {
    RestTemplate restTemplate = new RestTemplate();

    String fetch(HttpServletRequest request) {
        String target = request.getParameter("url");
        // ZS-JAVA-020: SSRF — tainted URL passed to restTemplate.getForObject()
        return restTemplate.getForObject(target, String.class);
    }
}
