public class RedirectPage
{
    public void Handle()
    {
        var returnUrl = Request.QueryString["returnUrl"];
        Response.Redirect(returnUrl); // ZS-CS-017: open redirect
    }
}
