using System.Web.Mvc;

// ZS-CS-044: HTML literal concatenated with a form value, default content type.
public class FeedbackController : Controller
{
    [HttpPost]
    public ActionResult Feedback()
    {
        return Content("<p>Thanks, " + Request.Form["name"] + "</p>");
    }
}
