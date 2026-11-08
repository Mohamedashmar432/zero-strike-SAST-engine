using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;

// ZS-CS-042: a request-supplied JSON filter is parsed straight into the query.
[ApiController]
[Route("api/[controller]")]
public class AuditController : ControllerBase
{
    private readonly IMongoCollection<BsonDocument> _audit = null;

    [HttpPost("query")]
    public IActionResult Query([FromBody] string filterJson)
    {
        var rows = _audit.Find(BsonDocument.Parse(filterJson)).ToList();
        return Ok(rows.Count);
    }
}
