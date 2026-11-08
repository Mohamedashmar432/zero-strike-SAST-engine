using System.IO;
using Microsoft.AspNetCore.Mvc;

// ZS-CS-036: request value joined into a path read and deleted by File methods.
[ApiController]
[Route("api/[controller]")]
public class FilesController : ControllerBase
{
    private static readonly string Root = Path.Combine(System.AppContext.BaseDirectory, "attachments");

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
}
