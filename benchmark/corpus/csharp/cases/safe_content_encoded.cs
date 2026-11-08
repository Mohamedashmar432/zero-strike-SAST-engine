using System.Web;
using System.Web.Mvc;

// ZS-CS-044 look-alike: encoded value, and a JSON body.
public class FeedbackSafeController : Controller
{
    [HttpPost]
    public ActionResult Feedback()
    {
        return Content("<p>Thanks, " + HttpUtility.HtmlEncode(Request.Form["name"]) + "</p>");
    }

    [HttpPost]
    public ActionResult Echo(string name)
    {
        return Content("{\"hello\": \"" + name + "\"}", "application/json");
    }
}
