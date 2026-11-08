using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

// ZS-CS-037: request values built into EF raw SQL text.
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly AppContext _db = new AppContext();

    [HttpGet("search")]
    public IActionResult Search([FromQuery] string name)
    {
        var users = _db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name LIKE '%{name}%'").ToList();
        return Ok(users);
    }

    [HttpGet("legacy")]
    public IActionResult Legacy([FromQuery] string name)
    {
        var rows = _db.Database.SqlQuery<User>("SELECT * FROM Users WHERE Name = '" + name + "'").ToList();
        return Ok(rows);
    }
}
