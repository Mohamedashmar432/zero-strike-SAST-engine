using System.Diagnostics;
using System.Web.Mvc;

// Same shape, but the helper only receives a constant: no finding.
public class VersionController : Controller
{
    public ActionResult Version()
    {
        Launch("--version");
        return Content("ok");
    }

    private void Launch(string flag)
    {
        Process.Start("tool", flag);
    }
}
