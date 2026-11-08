using System.Diagnostics;
using System.Web.Mvc;

// ASP.NET MVC 5 controller reading the query string directly.
public class ToolsController : Controller
{
    public ActionResult Run()
    {
        var cmd = Request.QueryString["cmd"];
        Process.Start(cmd); // ZS-CS-001: command injection
        return Content("started");
    }
}
