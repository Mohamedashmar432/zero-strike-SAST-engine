using Microsoft.AspNetCore.Mvc;

// ZS-CS-035: cookie appended without CookieOptions.
public class SessionController : Controller
{
    [HttpPost]
    public IActionResult SignIn(string token)
    {
        Response.Cookies.Append("sid", token);
        return Ok();
    }
}
