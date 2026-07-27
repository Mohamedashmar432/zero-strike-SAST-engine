import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

public class VulnSsrfPostForObject {
    // ZS-JAVA-040: RestTemplate.postForObject() to a tainted URL (SSRF)
    void handle(RestTemplate restTemplate, HttpServletRequest request) {
        String url = request.getParameter("url");
        restTemplate.postForObject(url, null, String.class);
    }
}
