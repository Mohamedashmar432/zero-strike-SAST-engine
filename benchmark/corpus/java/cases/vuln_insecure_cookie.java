import javax.servlet.http.Cookie;

public class VulnInsecureCookie {
    Cookie makeSessionCookie(String sessionId) {
        // ZS-JAVA-017: insecure cookie — HttpOnly/Secure never set
        Cookie cookie = new Cookie("SESSIONID", sessionId);
        return cookie;
    }
}
