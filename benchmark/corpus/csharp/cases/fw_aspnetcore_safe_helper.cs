using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

// The helper's parameter only ever receives a constant from the action, and
// the framework binds nothing to it: no finding.
[ApiController]
public class VersionController : ControllerBase
{
    [HttpGet("version")]
    public IActionResult Version()
    {
        Launch("--version");
        return Ok();
    }

    private void Launch(string flag)
    {
        Process.Start("tool", flag);
    }
}
