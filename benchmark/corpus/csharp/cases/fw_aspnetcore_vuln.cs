using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

// ASP.NET Core controller: the action parameter is bound from the request.
[ApiController]
[Route("api/[controller]")]
public class ToolsController : ControllerBase
{
    [HttpGet("run")]
    public IActionResult Run(string cmd)
    {
        Process.Start(cmd); // ZS-CS-001: command injection
        return Ok();
    }
}
