using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

// ZS-CS-037 look-alike: interpolated and placeholder forms are parameterised.
[ApiController]
[Route("api/[controller]")]
public class UsersSafeController : ControllerBase
{
    private readonly AppContext _db = new AppContext();

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string name)
    {
        var a = _db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name LIKE '%{name}%'").ToList();
        var b = _db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = {0}", name).ToList();
        return Ok(a.Count + b.Count);
    }
}
