using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace NotesApi.Controllers;

public class AccountController : Controller
{
    [HttpGet]
    public IActionResult Login(string returnUrl)
    {
        return Redirect(returnUrl);
    }

    [HttpGet]
    public IActionResult LoginLocal(string returnUrl)
    {
        if (!Url.IsLocalUrl(returnUrl))
        {
            return RedirectToAction("Index", "Notes");
        }
        return LocalRedirect(returnUrl);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult SignIn(string email, string password)
    {
        var token = new Random().Next().ToString("x");
        Response.Cookies.Append("sid", token);
        return RedirectToAction("Index", "Notes");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult SignInSecure(string email, string password)
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        Response.Cookies.Append("sid", token, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict });
        return RedirectToAction("Index", "Notes");
    }
}
