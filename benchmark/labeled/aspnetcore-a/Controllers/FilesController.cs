using Microsoft.AspNetCore.Mvc;

namespace NotesApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class FilesController : ControllerBase
{
    private static readonly string Root = Path.Combine(AppContext.BaseDirectory, "attachments");

    [HttpGet("read")]
    public IActionResult Read([FromQuery] string name)
    {
        var bytes = System.IO.File.ReadAllBytes(Path.Combine(Root, name));
        return File(bytes, "application/octet-stream");
    }

    [HttpDelete("remove")]
    public IActionResult Remove([FromQuery] string path)
    {
        System.IO.File.Delete(Path.Combine(Root, path));
        return NoContent();
    }

    [HttpGet("read-confined")]
    public IActionResult ReadConfined([FromQuery] string name)
    {
        var safeName = Path.GetFileName(name);
        var full = Path.GetFullPath(Path.Combine(Root, safeName));
        if (!full.StartsWith(Root, StringComparison.Ordinal))
        {
            return BadRequest();
        }
        var bytes = System.IO.File.ReadAllBytes(full);
        return File(bytes, "application/octet-stream");
    }
}
