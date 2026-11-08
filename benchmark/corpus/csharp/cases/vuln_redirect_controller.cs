using Microsoft.AspNetCore.Mvc;

// ZS-CS-034: the controller redirects to a request-supplied URL.
public class AccountController : Controller
{
    [HttpGet]
    public IActionResult Login(string returnUrl)
    {
        return Redirect(returnUrl);
    }
}
