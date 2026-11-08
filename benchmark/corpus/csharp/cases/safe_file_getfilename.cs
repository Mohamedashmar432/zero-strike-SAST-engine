using System.IO;
using Microsoft.AspNetCore.Mvc;

// ZS-CS-036 and ZS-CS-015 look-alike: the name is reduced with Path.GetFileName.
[ApiController]
[Route("api/[controller]")]
public class FilesSafeController : ControllerBase
{
    private static readonly string Root = Path.Combine(System.AppContext.BaseDirectory, "attachments");

    [HttpGet("read")]
    public IActionResult Read([FromQuery] string name)
    {
        var safeName = Path.GetFileName(name);
        var bytes = System.IO.File.ReadAllBytes(Path.Combine(Root, safeName));
        var text = System.IO.File.ReadAllText(Path.Combine(Root, Path.GetFileName(name)));
        return Ok(text.Length + bytes.Length);
    }
}
