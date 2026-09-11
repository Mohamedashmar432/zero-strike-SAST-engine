import java.net.URL;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.client.RestTemplate;

// SSRF family negative fixture (ZS-JAVA-019, ZS-JAVA-020, ZS-JAVA-040).
//
// Every call below sends its request to a destination that is a compile-time
// constant. What is attacker-controlled is a request body or a URI template
// variable -- neither decides where the request goes, so neither is CWE-918.
//
// Before the RestTemplate rules were pinned with tainted_argument_index,
// "tainted_argument: true" was satisfied by any tainted identifier anywhere
// in the call's subtree, so both RestTemplate calls were reported as SSRF.
class SafeSsrfJava {

    private static final String AUDIT_URL = "https://audit.internal.example.com/v1/events";
    private static final String LOOKUP_URL = "https://audit.internal.example.com/v1/records/{id}";

    // postForObject(url, request, responseType): argument 1 is the request
    // BODY. Forwarding user-supplied data to a fixed, trusted collector is
    // the ordinary case, not request forgery.
    String forwardEvent(RestTemplate restTemplate, HttpServletRequest request) {
        String payload = request.getParameter("payload");
        return restTemplate.postForObject(AUDIT_URL, payload, String.class);
    }

    // getForObject(url, responseType, uriVariables...): arguments 2+ are URI
    // template variables. RestTemplate encodes them into the path, so they
    // cannot change the scheme or host of a constant template.
    String lookup(RestTemplate restTemplate, HttpServletRequest request) {
        String id = request.getParameter("id");
        return restTemplate.getForObject(LOOKUP_URL, String.class, id);
    }

    // NOTE: this fixture deliberately contains no java.net.URL case.
    //
    // One was tried -- new URL(AUDIT_URL + path), where path is an ordinary
    // method parameter -- on the theory that appending to a constant base
    // cannot change scheme or host. It was removed because the engine cannot
    // tell that shape apart from WebGoat's real SSRF lesson,
    // SSRFTask2.furBall(String url) { new URL(url) }, which is also nothing
    // more than a method parameter reaching the constructor. Asserting this
    // as a required non-finding forced require_real_source onto ZS-JAVA-019,
    // which silently deleted that lesson and the JWT jku attack from a real
    // WebGoat scan while this corpus still reported 100%.
    //
    // Any future URL case here must be one the engine can actually
    // distinguish -- a literal destination, not a constrained-looking one.
}
