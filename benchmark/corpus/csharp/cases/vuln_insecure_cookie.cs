using System.Web;
using System.Web.Security;

public class CookieManager
{
    public static HttpCookie SetCookie(FormsAuthenticationTicket ticket)
    {
        string encryptedTicket = FormsAuthentication.Encrypt(ticket);
        HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket); // ZS-CS-013: insecure cookie
        return cookie;
    }
}
