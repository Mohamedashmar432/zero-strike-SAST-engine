using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using MongoDB.Bson;
using MongoDB.Driver;
using NotesApi.Data;
using NotesApi.Models;

namespace NotesApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly NotesContext _db;
    private readonly IConfiguration _config;
    private readonly IMongoCollection<BsonDocument> _audit;

    public UsersController(NotesContext db, IConfiguration config, IMongoDatabase mongo)
    {
        _db = db;
        _config = config;
        _audit = mongo.GetCollection<BsonDocument>("audit");
    }

    [HttpGet("by-email")]
    public async Task<IActionResult> ByEmail([FromQuery] string email)
    {
        using var conn = new SqlConnection(_config.GetConnectionString("Notes"));
        await conn.OpenAsync();
        var cmd = new SqlCommand("SELECT Id, Name FROM Users WHERE Email = '" + email + "'", conn);
        using var reader = await cmd.ExecuteReaderAsync();
        var names = new List<string>();
        while (await reader.ReadAsync()) names.Add(reader.GetString(1));
        return Ok(names);
    }

    [HttpGet("by-email-safe")]
    public async Task<IActionResult> ByEmailSafe([FromQuery] string email)
    {
        using var conn = new SqlConnection(_config.GetConnectionString("Notes"));
        await conn.OpenAsync();
        var cmd = new SqlCommand("SELECT Id, Name FROM Users WHERE Email = @email", conn);
        cmd.Parameters.AddWithValue("@email", email);
        using var reader = await cmd.ExecuteReaderAsync();
        var names = new List<string>();
        while (await reader.ReadAsync()) names.Add(reader.GetString(1));
        return Ok(names);
    }

    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string name)
    {
        var users = await _db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name LIKE '%{name}%'").ToListAsync();
        return Ok(users);
    }

    [HttpGet("search-safe")]
    public async Task<IActionResult> SearchSafe([FromQuery] string name)
    {
        var users = await _db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name LIKE '%{name}%'").ToListAsync();
        return Ok(users);
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest body)
    {
        var hash = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(body.Password));
        _db.Users.Add(new User { Email = body.Email, PasswordHash = Convert.ToHexString(hash) });
        await _db.SaveChangesAsync();
        return Created("", null);
    }

    [HttpPost("register-safe")]
    public async Task<IActionResult> RegisterSafe([FromBody] RegisterRequest body)
    {
        var hash = new PasswordHasher<User>().HashPassword(new User(), body.Password);
        _db.Users.Add(new User { Email = body.Email, PasswordHash = hash });
        await _db.SaveChangesAsync();
        return Created("", null);
    }

    [HttpPost("audit/query")]
    public IActionResult AuditQuery([FromBody] string filterJson)
    {
        var rows = _audit.Find(BsonDocument.Parse(filterJson)).ToList();
        return Ok(rows.Select(r => r.ToString()));
    }

    [HttpGet("audit/by-actor")]
    public IActionResult AuditByActor([FromQuery] string actor)
    {
        var rows = _audit.Find(Builders<BsonDocument>.Filter.Eq("actor", actor)).ToList();
        return Ok(rows.Select(r => r.ToString()));
    }
}
