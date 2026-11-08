using System.Web.Mvc;

// ZS-CS-015: System.IO.File.ReadAllText reached through its full namespace.
public class ManualController : Controller
{
    public ActionResult Manual()
    {
        var text = System.IO.File.ReadAllText(Server.MapPath("~/docs/" + Request.QueryString["f"]));
        return Content(text);
    }
}
