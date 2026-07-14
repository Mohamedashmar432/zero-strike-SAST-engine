import org.springframework.http.ResponseCookie;

public class VulnInsecureResponseCookie {
    ResponseCookie makeSessionCookie(String sessionId) {
        // ZS-JAVA-018: insecure cookie — httpOnly/secure never chained onto the builder
        ResponseCookie cookie = ResponseCookie.from("SESSIONID", sessionId).path("/").build();
        return cookie;
    }
}
