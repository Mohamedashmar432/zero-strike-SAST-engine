using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

// ZS-CS-035 look-alike: CookieOptions carries the flags.
public class SessionSafeController : Controller
{
    [HttpPost]
    public IActionResult SignIn(string token)
    {
        Response.Cookies.Append("sid", token, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        return Ok();
    }
}
