using Microsoft.AspNetCore.Mvc;

// ZS-CS-034 look-alike: LocalRedirect, and a Redirect guarded by Url.IsLocalUrl.
public class AccountSafeController : Controller
{
    [HttpGet]
    public IActionResult Login(string returnUrl)
    {
        return LocalRedirect(returnUrl);
    }

    [HttpGet]
    public IActionResult Continue(string returnUrl)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return RedirectToAction("Index", "Home");
        }
        return Redirect(returnUrl);
    }
}
